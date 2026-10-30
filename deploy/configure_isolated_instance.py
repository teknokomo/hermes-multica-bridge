#!/usr/bin/env python3
"""Create or update one operator-owned Isolated bridge instance without exposing secrets."""

from __future__ import annotations

import argparse
import base64
import fcntl
import getpass
import json
import os
import pwd
import re
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bridge.configuration import connection_from_mapping, validate_systemd_unit
from bridge.errors import BridgeError
from bridge.routes import bridge_config_from_mapping, parse_isolated_route_identity
from bridge.validation import MAX_MULTICA_PAT_BYTES
from bridge.webhook import webhook_url_fingerprint

USER_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
MAX_CONFIGURE_JOURNAL_BYTES = 1_000_000
MAX_CONFIGURE_SNAPSHOT_BYTES = 128_000


def _value(current: str | None, prompt: str) -> str:
    if current:
        return current.strip()
    return input(prompt).strip()


def _validate_directory_chain(path: Path, trusted_root: Path, expected_owner_uid: int) -> None:
    """Create/check every directory from trusted_root to path as operator-owned and safe."""
    root = trusted_root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise OSError("unsafe directory boundary") from exc
    current = root
    for part in (None, *relative.parts):
        if part is not None:
            current = current / part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o022
        ):
            raise OSError(f"unsafe directory: {current}")


def _atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    *,
    trusted_root: Path,
    expected_owner_uid: int,
) -> None:
    _validate_directory_chain(path.parent, trusted_root, expected_owner_uid)
    temp: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp = Path(name)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, mode)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def _configuration_journal_path(config_path: Path) -> Path:
    return config_path.with_name(f".{config_path.name}.configure-journal")


def _rotation_journal_path(config_path: Path) -> Path:
    return config_path.with_name(f".{config_path.name}.rotation-journal")


def _rotation_journal_pending(path: Path) -> bool:
    """Check for a pending rotation journal without following symlinks."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


@contextmanager
def _instance_update_lock(
    config_path: Path,
    *,
    trusted_root: Path,
    expected_owner_uid: int,
) -> Iterator[None]:
    """Serialize full instance configuration with credential rotation."""
    lock_path = config_path.with_name(f".{config_path.name}.rotation.lock")
    _validate_directory_chain(lock_path.parent, trusted_root, expected_owner_uid)
    fd = os.open(
        lock_path,
        os.O_CREAT
        | os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise OSError("unsafe instance update lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _snapshot_file(
    path: Path,
    *,
    expected_owner_uid: int,
    max_bytes: int = MAX_CONFIGURE_SNAPSHOT_BYTES,
) -> dict[str, object]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"existed": False, "mode": 0, "data": ""}
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_owner_uid
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or info.st_size > max_bytes
    ):
        raise OSError("unsafe existing instance file")
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        current = os.fstat(fd)
        if current.st_ino != info.st_ino or current.st_dev != info.st_dev:
            raise OSError("instance file changed while snapshotting")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > max_bytes:
        raise OSError("existing instance file is too large")
    return {
        "existed": True,
        "mode": stat.S_IMODE(info.st_mode),
        "data": base64.b64encode(data).decode("ascii"),
    }


def _snapshot_configuration_files(
    paths: list[Path],
    *,
    trusted_root: Path,
    expected_owner_uid: int,
) -> list[dict[str, object]]:
    root = trusted_root.resolve()
    snapshots: list[dict[str, object]] = []
    for path in paths:
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise OSError("instance file escapes trusted root") from exc
        record = _snapshot_file(path, expected_owner_uid=expected_owner_uid)
        record["path"] = relative.as_posix()
        snapshots.append(record)
    return snapshots


def _write_configuration_journal(
    journal_path: Path,
    *,
    instance: str,
    snapshots: list[dict[str, object]],
    trusted_root: Path,
    expected_owner_uid: int,
) -> None:
    payload = json.dumps(
        {"instance": instance, "files": snapshots},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > MAX_CONFIGURE_JOURNAL_BYTES:
        raise OSError("configuration recovery journal is too large")
    _atomic_write(
        journal_path,
        payload,
        0o600,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )


def _read_configuration_journal(
    journal_path: Path,
    *,
    instance: str,
    trusted_root: Path,
    expected_owner_uid: int,
) -> list[dict[str, object]] | None:
    try:
        record = _snapshot_file(
            journal_path,
            expected_owner_uid=expected_owner_uid,
            max_bytes=MAX_CONFIGURE_JOURNAL_BYTES,
        )
    except FileNotFoundError:
        return None
    if record["existed"] is not True:
        return None
    if int(record["mode"]) & 0o077:
        raise OSError("unsafe configuration recovery journal")
    try:
        raw = base64.b64decode(str(record["data"]), validate=True)
        if len(raw) > MAX_CONFIGURE_JOURNAL_BYTES:
            raise ValueError
        payload = json.loads(raw)
    except (ValueError, json.JSONDecodeError, TypeError) as exc:
        raise OSError("invalid configuration recovery journal") from exc
    files = payload.get("files") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"instance", "files"}
        or payload.get("instance") != instance
        or not isinstance(files, list)
        or len(files) > 8
    ):
        raise OSError("invalid configuration recovery journal")
    root = trusted_root.resolve()
    validated: list[dict[str, object]] = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "existed", "mode", "data"}:
            raise OSError("invalid configuration recovery journal")
        relative = Path(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise OSError("invalid configuration recovery path")
        target = root / relative
        if not target.resolve(strict=False).is_relative_to(root):
            raise OSError("invalid configuration recovery path")
        if type(item["existed"]) is not bool or type(item["mode"]) is not int:
            raise OSError("invalid configuration recovery journal")
        if not 0 <= int(item["mode"]) <= 0o777:
            raise OSError("invalid configuration recovery mode")
        try:
            data = base64.b64decode(str(item["data"]), validate=True)
        except ValueError as exc:
            raise OSError("invalid configuration recovery data") from exc
        if len(data) > MAX_CONFIGURE_SNAPSHOT_BYTES:
            raise OSError("configuration recovery data is too large")
        validated.append({**item, "target": target, "decoded": data})
    return validated


def _remove_configuration_journal(
    journal_path: Path,
    *,
    trusted_root: Path,
    expected_owner_uid: int,
) -> None:
    _validate_directory_chain(journal_path.parent, trusted_root, expected_owner_uid)
    journal_path.unlink()
    directory_fd = os.open(
        journal_path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _recover_pending_configuration(
    journal_path: Path,
    *,
    instance: str,
    trusted_root: Path,
    expected_owner_uid: int,
) -> bool:
    snapshots = _read_configuration_journal(
        journal_path,
        instance=instance,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )
    if snapshots is None:
        return False
    for item in snapshots:
        target = item["target"]
        if not isinstance(target, Path):
            raise OSError("invalid configuration recovery target")
        if item["existed"] is True:
            _atomic_write(
                target,
                item["decoded"],
                int(item["mode"]),
                trusted_root=trusted_root,
                expected_owner_uid=expected_owner_uid,
            )
        else:
            try:
                info = target.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != expected_owner_uid
            ):
                raise OSError("unsafe file blocks configuration recovery")
            target.unlink()
    _remove_configuration_journal(
        journal_path,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )
    return True


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(item) for item in values) + "]"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure one Hermes Multica Bridge Isolated instance")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--connection-id", required=True)
    parser.add_argument("--workspace-key", required=True)
    parser.add_argument("--route-policy-fingerprint", required=True)
    parser.add_argument("--hermes-user")
    parser.add_argument("--gateway-unit")
    parser.add_argument("--multica-origin")
    parser.add_argument("--workspace-id")
    parser.add_argument("--autopilot-id")
    parser.add_argument("--trigger-id")
    parser.add_argument("--source-board", action="append", dest="source_boards")
    parser.add_argument("--event", default="hermes.task.dispatched")
    parser.add_argument("--request-timeout-seconds", type=int, default=10)
    parser.add_argument("--max-response-bytes", type=int, default=16_384)
    parser.add_argument("--max-payload-bytes", type=int, default=65_536)
    parser.add_argument("--max-requests-per-window", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=600)
    parser.add_argument("--max-attempts-per-request", type=int, default=2)
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--result-tracking", action="store_true")
    parser.add_argument("--root", default="/", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if root == Path("/") and os.geteuid() != 0:
        print("Run this helper as root for a real installation.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print("A local interactive terminal is required for secret input.", file=sys.stderr)
        return 1

    try:
        hermes_user = _value(args.hermes_user, "Hermes OS user: ")
        if not USER_RE.fullmatch(hermes_user):
            raise BridgeError("configuration_invalid", "The Hermes OS user name is invalid.")
        uid = pwd.getpwnam(hermes_user).pw_uid if root == Path("/") else int(input("Hermes UID for staged config: ").strip())
        if not 1 <= uid <= 2_147_483_647:
            raise BridgeError("configuration_invalid", "The Hermes OS user UID is invalid for the IPC allowlist.")
        gateway_unit = validate_systemd_unit(
            _value(args.gateway_unit, "Trusted Hermes Gateway systemd unit: ")
        )
        origin = _value(args.multica_origin, "Multica HTTPS origin: ")
        workspace_id = _value(args.workspace_id, "Multica Workspace ID: ")
        autopilot_id = _value(args.autopilot_id, "Multica Autopilot ID: ")
        trigger_id = _value(args.trigger_id, "Multica trigger ID: ")
        boards = args.source_boards or [item.strip() for item in input("Allowed Hermes boards (comma-separated): ").split(",") if item.strip()]
        connection = connection_from_mapping(
            {
                "security_mode": "isolated",
                "enabled": bool(args.enable),
                "multica_origin": origin,
                "workspace_id": workspace_id,
                "autopilot_id": autopilot_id,
                "trigger_id": trigger_id,
                "event": args.event,
                "source_boards": boards,
                "request_timeout_seconds": args.request_timeout_seconds,
                "max_response_bytes": args.max_response_bytes,
                "max_payload_bytes": args.max_payload_bytes,
                "max_requests_per_window": args.max_requests_per_window,
                "window_seconds": args.window_seconds,
                "max_attempts_per_request": args.max_attempts_per_request,
                "result_tracking_enabled": bool(args.result_tracking),
                "hmac_enabled": True,
                "isolated_instance_id": args.instance,
            }
        )
        parse_isolated_route_identity(
            {
                "route_id": args.route_id,
                "connection_id": args.connection_id,
                "workspace_key": args.workspace_key,
                "route_policy_fingerprint": args.route_policy_fingerprint,
            },
            isolated_instance_id=connection.isolated_instance_id,
        )
        webhook_url = getpass.getpass("Multica webhook URL (hidden): ").strip()
        hmac_secret = getpass.getpass("HMAC signing secret (hidden): ")
        multica_pat = (
            getpass.getpass("Read-only Multica PAT for result tracking (hidden): ").strip()
            if args.result_tracking
            else ""
        )
        if not hmac_secret or len(hmac_secret.encode("utf-8")) > 4096:
            raise BridgeError("credential_invalid", "The HMAC signing secret is empty or too large.")
        if args.result_tracking and (
            not multica_pat or len(multica_pat.encode("ascii")) > MAX_MULTICA_PAT_BYTES
        ):
            raise BridgeError("credential_invalid", "The Multica PAT is empty or too large.")
        fingerprint = webhook_url_fingerprint(webhook_url, connection.multica_origin)
        bridge_config_from_mapping(
            {
                "default_deny": True,
                "ipc": {
                    "allowed_peer_uids": [uid],
                    "trusted_gateway_unit": gateway_unit,
                },
                "route": {
                    "route_id": args.route_id,
                    "connection_id": args.connection_id,
                    "workspace_key": args.workspace_key,
                    "route_policy_fingerprint": args.route_policy_fingerprint,
                },
                "connection": {
                    "security_mode": "isolated",
                    "enabled": connection.enabled,
                    "multica_origin": connection.multica_origin,
                    "workspace_id": connection.workspace_id,
                    "autopilot_id": connection.autopilot_id,
                    "trigger_id": connection.trigger_id,
                    "event": connection.event,
                    "source_boards": list(connection.source_boards),
                    "request_timeout_seconds": connection.request_timeout_seconds,
                    "max_response_bytes": connection.max_response_bytes,
                    "max_payload_bytes": connection.max_payload_bytes,
                    "max_requests_per_window": connection.max_requests_per_window,
                    "window_seconds": connection.window_seconds,
                    "max_attempts_per_request": connection.max_attempts_per_request,
                    "result_tracking_enabled": connection.result_tracking_enabled,
                    "hmac_enabled": connection.hmac_enabled,
                    "isolated_instance_id": connection.isolated_instance_id,
                },
                "credentials": {
                    "webhook_url_ref": "HMB_WEBHOOK_URL",
                    "webhook_sha256": fingerprint,
                    "hmac_signing_secret_ref": "HMB_HMAC_SIGNING_SECRET",  # nosec B105 - credential name only
                    "multica_pat_ref": "HMB_MULTICA_PAT" if connection.result_tracking_enabled else "",
                },
            }
        )
    except (BridgeError, KeyError, UnicodeError, ValueError) as exc:
        print(f"Configuration rejected: {exc}", file=sys.stderr)
        return 1

    multica_pat_ref = '"HMB_MULTICA_PAT"' if connection.result_tracking_enabled else '""'
    config = f"""default_deny = true

[ipc]
allowed_peer_uids = [{uid}]
trusted_gateway_unit = {_toml_string(gateway_unit)}

[route]
route_id = {_toml_string(args.route_id)}
connection_id = {_toml_string(args.connection_id)}
workspace_key = {_toml_string(args.workspace_key)}
route_policy_fingerprint = {_toml_string(args.route_policy_fingerprint)}

[connection]
security_mode = "isolated"
enabled = {"true" if connection.enabled else "false"}
multica_origin = {_toml_string(connection.multica_origin)}
workspace_id = {_toml_string(connection.workspace_id)}
autopilot_id = {_toml_string(connection.autopilot_id)}
trigger_id = {_toml_string(connection.trigger_id)}
event = {_toml_string(connection.event)}
source_boards = {_toml_list(list(connection.source_boards))}
request_timeout_seconds = {connection.request_timeout_seconds}
max_response_bytes = {connection.max_response_bytes}
max_payload_bytes = {connection.max_payload_bytes}
max_requests_per_window = {connection.max_requests_per_window}
window_seconds = {connection.window_seconds}
max_attempts_per_request = {connection.max_attempts_per_request}
result_tracking_enabled = {"true" if connection.result_tracking_enabled else "false"}
hmac_enabled = true
isolated_instance_id = {_toml_string(connection.isolated_instance_id)}

[credentials]
webhook_url_ref = "HMB_WEBHOOK_URL"
webhook_sha256 = "{fingerprint}"
hmac_signing_secret_ref = "HMB_HMAC_SIGNING_SECRET"
multica_pat_ref = {multica_pat_ref}
"""

    etc = root / "etc"
    operator_uid = os.geteuid()
    config_path = etc / "hermes-multica-bridge" / f"{connection.isolated_instance_id}.toml"
    creds = etc / "hermes-multica-bridge" / "credentials" / connection.isolated_instance_id
    dropin = (
        etc
        / "systemd"
        / "system"
        / f"hermes-multica-bridge@{connection.isolated_instance_id}.socket.d"
        / "10-hermes-user.conf"
    )
    targets = [
        (config_path, config.encode("utf-8"), 0o644),
        (creds / "webhook-url", webhook_url.encode("utf-8"), 0o600),
        (creds / "hmac-signing-secret", hmac_secret.encode("utf-8"), 0o600),
        (creds / "multica-pat", multica_pat.encode("ascii"), 0o600),
        (dropin, f"[Socket]\nSocketUser={hermes_user}\n".encode(), 0o644),
    ]
    try:
        write_options = {"trusted_root": root, "expected_owner_uid": operator_uid}
        _validate_directory_chain(config_path.parent, root, operator_uid)
        os.chmod(config_path.parent, 0o755)  # nosec B103 - DynamicUser must traverse non-secret config.
        for path, _data, _mode in targets:
            _validate_directory_chain(path.parent, root, operator_uid)
        journal_path = _configuration_journal_path(config_path)
        rotation_journal_path = _rotation_journal_path(config_path)
        with _instance_update_lock(config_path, **write_options):
            if _recover_pending_configuration(
                journal_path,
                instance=connection.isolated_instance_id,
                **write_options,
            ):
                print("Recovered a previous interrupted Isolated instance update.")
            if _rotation_journal_pending(rotation_journal_path):
                print(
                    "A pending webhook rotation must be recovered before full instance configuration.",
                    file=sys.stderr,
                )
                return 1
            snapshots = _snapshot_configuration_files(
                [path for path, _data, _mode in targets],
                **write_options,
            )
            _write_configuration_journal(
                journal_path,
                instance=connection.isolated_instance_id,
                snapshots=snapshots,
                **write_options,
            )
            try:
                for path, data, mode in targets:
                    _atomic_write(path, data, mode, **write_options)
            except OSError:
                try:
                    _recover_pending_configuration(
                        journal_path,
                        instance=connection.isolated_instance_id,
                        **write_options,
                    )
                except OSError:
                    print(
                        "Isolated instance update was interrupted; the protected recovery journal was retained.",
                        file=sys.stderr,
                    )
                    return 1
                print(
                    "Could not update the Isolated instance; the previous files were restored.",
                    file=sys.stderr,
                )
                return 1
            try:
                _remove_configuration_journal(journal_path, **write_options)
            except OSError:
                print(
                    "Isolated instance files were written, but the recovery journal could not be cleared.",
                    file=sys.stderr,
                )
                return 1
    except OSError:
        print("Could not write the Isolated instance files safely.", file=sys.stderr)
        return 1

    print(f"Prepared Isolated instance: {connection.isolated_instance_id}")
    print(f"Config: {config_path}")
    print(f"Webhook fingerprint: {fingerprint}")
    print("Secret values were stored with mode 0600 and were not displayed.")
    print("Run systemctl daemon-reload and enable/start the instance socket after reviewing the files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
