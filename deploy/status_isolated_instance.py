#!/usr/bin/env python3
"""Report non-secret readiness for one Isolated bridge instance."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bridge.configuration import INSTANCE_ID_RE
from bridge.errors import BridgeError
from bridge.routes import load_config, read_credential
from bridge.validation import MAX_MULTICA_PAT_BYTES
from bridge.webhook import webhook_url_fingerprint

STAGED_CREDENTIAL_NAMES = frozenset({"webhook-url", "hmac-signing-secret", "multica-pat"})


def _credential_name(*, systemd_directory: bool, configured_ref: str, staged_name: str) -> str:
    """Use LoadCredential IDs at runtime and source filenames for staged operator checks."""
    return configured_ref if systemd_directory else staged_name


def _read_staged_credential(
    credential_dir: str | Path,
    credential_name: str,
    *,
    max_bytes: int = 4096,
    ascii_only: bool = False,
    preserve_whitespace: bool = False,
    expected_owner_uid: int = 0,
) -> str:
    """Read one fixed root-owned staged credential without relaxing systemd credential IDs."""
    if credential_name not in STAGED_CREDENTIAL_NAMES:
        raise BridgeError("configuration_invalid", "The staged credential name is invalid.")
    directory = Path(credential_dir)
    try:
        directory_info = directory.lstat()
    except OSError as exc:
        raise BridgeError("credential_invalid", "A staged credential directory is unavailable.") from exc
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_ISLNK(directory_info.st_mode)
        or directory_info.st_uid != expected_owner_uid
        or directory_info.st_mode & 0o077
    ):
        raise BridgeError("credential_invalid", "A staged credential directory is unsafe or invalid.")

    path = directory / credential_name
    fd: int | None = None
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o077
            or info.st_size > max_bytes
        ):
            raise BridgeError("credential_invalid", "A staged credential is unsafe or invalid.")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw_value = stream.read(max_bytes + 1)
        if len(raw_value) > max_bytes:
            raise BridgeError("credential_invalid", "A staged credential is too large.")
        decoded = raw_value.decode("ascii" if ascii_only else "utf-8")
        value = decoded if preserve_whitespace else decoded.strip()
        if not value:
            raise BridgeError("credential_invalid", "A staged credential is empty.")
        return value
    except BridgeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise BridgeError("credential_invalid", "A staged credential is unavailable.") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _read_status_credential(
    credential_dir: str | Path,
    *,
    systemd_directory: bool,
    configured_ref: str,
    staged_name: str,
    max_bytes: int = 4096,
    ascii_only: bool = False,
    preserve_whitespace: bool = False,
) -> str:
    """Read runtime LoadCredential IDs or the fixed staged source files."""
    if systemd_directory:
        return read_credential(
            credential_dir,
            configured_ref,
            max_bytes=max_bytes,
            ascii_only=ascii_only,
            preserve_whitespace=preserve_whitespace,
        )
    return _read_staged_credential(
        credential_dir,
        staged_name,
        max_bytes=max_bytes,
        ascii_only=ascii_only,
        preserve_whitespace=preserve_whitespace,
    )


def _instance_paths(instance: str, systemd_credential_dir: str | None) -> tuple[Path, Path]:
    """Validate the instance identifier before deriving any root-owned paths."""
    if not isinstance(instance, str) or not INSTANCE_ID_RE.fullmatch(instance):
        raise BridgeError("configuration_invalid", "The Isolated instance identifier is invalid.")
    config_path = Path("/etc/hermes-multica-bridge") / f"{instance}.toml"
    credential_dir = (
        Path(systemd_credential_dir)
        if systemd_credential_dir
        else Path("/etc/hermes-multica-bridge/credentials") / instance
    )
    return config_path, credential_dir


def _webhook_fingerprint_matches(expected: str | None, actual: str) -> bool:
    """Report a match only when a fingerprint is explicitly pinned."""
    return bool(expected) and expected == actual


def _pre_enable_readiness_errors(connection) -> tuple[str, ...]:
    """Report setup readiness while leaving the operator-controlled enable switch off."""
    return tuple(error for error in connection.readiness_errors() if error != "disabled")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check one Isolated bridge instance")
    parser.add_argument("--instance", required=True)
    args = parser.parse_args(argv)
    systemd_credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    systemd_credentials = bool(systemd_credential_dir)
    try:
        config_path, credential_dir = _instance_paths(args.instance, systemd_credential_dir)
        config = load_config(config_path)
        if config.credentials.webhook_url_ref != "HMB_WEBHOOK_URL":
            raise BridgeError("configuration_invalid", "Unexpected webhook credential reference.")
        webhook = _read_status_credential(
            credential_dir,
            systemd_directory=systemd_credentials,
            configured_ref=config.credentials.webhook_url_ref,
            staged_name="webhook-url",
        )
        connection = config.connection
        actual = webhook_url_fingerprint(webhook, connection.multica_origin)
        fingerprint_match = _webhook_fingerprint_matches(config.credentials.webhook_sha256, actual)
        if config.credentials.webhook_sha256 and not fingerprint_match:
            raise BridgeError("credential_mismatch", "Webhook fingerprint mismatch.")
        hmac_ready = connection.hmac_enabled
        if connection.hmac_enabled:
            if config.credentials.hmac_signing_secret_ref != "HMB_HMAC_SIGNING_SECRET":  # nosec B105 - credential name only
                hmac_ready = False
            else:
                _read_status_credential(
                    credential_dir,
                    systemd_directory=systemd_credentials,
                    configured_ref=config.credentials.hmac_signing_secret_ref,
                    staged_name="hmac-signing-secret",
                    max_bytes=4096,
                    preserve_whitespace=True,
                )
        pat_ready = True
        if connection.result_tracking_enabled:
            if config.credentials.multica_pat_ref != "HMB_MULTICA_PAT":
                pat_ready = False
            else:
                _read_status_credential(
                    credential_dir,
                    systemd_directory=systemd_credentials,
                    configured_ref=config.credentials.multica_pat_ref,
                    staged_name="multica-pat",
                    max_bytes=MAX_MULTICA_PAT_BYTES,
                    ascii_only=True,
                )
        socket_path = Path(connection.socket_path)
        try:
            socket_ready = stat.S_ISSOCK(socket_path.lstat().st_mode)
        except OSError:
            socket_ready = False
        result = {
            # This command is run before socket activation; report configuration
            # readiness separately from the socket's current filesystem state.
            "ok": not _pre_enable_readiness_errors(connection) and hmac_ready and pat_ready and fingerprint_match,
            "instance_id": connection.isolated_instance_id or None,
            "enabled": connection.enabled,
            "hmac_credential": hmac_ready,
            "result_credential": pat_ready,
            "webhook_fingerprint_match": fingerprint_match,
            "socket_available": socket_ready,
            "socket_path": str(socket_path),
        }
    except BridgeError as exc:
        result = {"ok": False, "error_code": exc.code, "message": exc.message}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
