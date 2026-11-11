#!/usr/bin/env python3
"""Register approved Multica issues with the isolated watcher."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import selectors
import socket
import stat
import struct
import subprocess  # nosec B404: invoke only the fixed Multica read-only CLI without a shell
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MULTICA_BIN = Path("/usr/local/bin/multica")
SOCKET_PATH = Path("/run/hermes-multica-watcher/ipc.sock")
CONFIG_PATH = Path.home() / ".config/hermes-multica-bridge/watch.json"
STATE_PATH = Path.home() / ".local/state/hermes-multica-bridge/mappings.json"
MAX_IPC_FRAME = 16_384
MAX_CLI_OUTPUT = 2 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 10_000
CLI_TIMEOUT_SECONDS = 45
IPC_TIMEOUT_SECONDS = 3.0
_FRAME = struct.Struct("!I")
_RFC3339 = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_INPUT_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PROFILE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_POSITIVE_DECIMAL = re.compile(r"\A[1-9][0-9]{0,18}\Z")
_CHAT_ID = re.compile(r"\A-?[0-9]{1,20}\Z")
_LIST_FIELDS = "id,identifier,workspace_id,project_id,status,updated_at"


class AppError(Exception):
    def __init__(self, exit_code: int, message: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


class ConfigError(ValueError):
    pass


class MulticaError(RuntimeError):
    pass


class InvalidMulticaResponse(MulticaError):
    """The CLI returned data that does not satisfy the expected response shape."""


class IpcUnavailable(RuntimeError):
    pass


class IpcRejected(RuntimeError):
    pass


class UserArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        raise AppError(4, f"Invalid command arguments: {message}")


@dataclass(frozen=True)
class Route:
    name: str
    route_id: str
    project_id: str


@dataclass(frozen=True)
class WatchConfig:
    watcher_profile: str
    platform: str
    chat_type: str
    multica_profile: str
    multica_server_url: str
    workspace_id: str
    sweep_since: datetime
    user_id: str
    chat_id: str
    thread_id: str | None
    message_id: str
    routes: Mapping[str, Route]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(raw: str | bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_strict_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError("invalid JSON number")
        ),
    )


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{field} must be a UUID.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ConfigError(f"{field} must be a UUID.") from None
    return str(parsed)


def parse_rfc3339(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ConfigError(f"{field} must be an RFC3339 timestamp with a timezone.")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError:
        raise ConfigError(f"{field} must be a valid RFC3339 timestamp.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConfigError(f"{field} must include a timezone.")
    return parsed.astimezone(UTC)


def _https_origin(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ConfigError("multica_server_url is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ConfigError("multica_server_url is invalid.") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ConfigError(
            "multica_server_url must be an HTTPS origin without credentials or path."
        )
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, 443) else f"{host}:{port}"
    return urlunsplit(("https", netloc, "", "", ""))


def parse_config(value: Any) -> WatchConfig:
    required = {
        "watcher_profile",
        "platform",
        "chat_type",
        "message_id",
        "multica_profile",
        "multica_server_url",
        "workspace_id",
        "sweep_since",
        "user_id",
        "chat_id",
        "thread_id",
        "routes",
    }
    optional: set[str] = set()
    if (
        not isinstance(value, dict)
        or required - set(value)
        or set(value) - required - optional
    ):
        raise ConfigError(
            "The private configuration has missing or unsupported fields."
        )

    if not isinstance(value["watcher_profile"], str) or not _PROFILE.fullmatch(value["watcher_profile"]):
        raise ConfigError("watcher_profile is invalid.")
    if not isinstance(value["platform"], str) or value["platform"] not in {"max", "telegram"}:
        raise ConfigError("platform must be max or telegram.")
    if not isinstance(value["chat_type"], str) or value["chat_type"] not in {"dm", "group", "thread"}:
        raise ConfigError("chat_type must be dm, group or thread.")
    if value["platform"] == "max" and value["chat_type"] == "thread":
        raise ConfigError("MAX exact thread delivery is unsupported.")
    profile = value["multica_profile"]
    if not isinstance(profile, str) or not _PROFILE.fullmatch(profile):
        raise ConfigError("multica_profile is invalid.")
    workspace_id = _canonical_uuid(value["workspace_id"], "workspace_id")
    user_id = value["user_id"]
    if not isinstance(user_id, str) or not _POSITIVE_DECIMAL.fullmatch(user_id):
        raise ConfigError("user_id must be a positive decimal identifier.")
    chat_id = value["chat_id"]
    if not isinstance(chat_id, str) or not _CHAT_ID.fullmatch(chat_id):
        raise ConfigError("chat_id must be a decimal chat identifier.")
    thread_id = value["thread_id"]
    anchor_id = value["message_id"]
    if value["chat_type"] == "thread":
        if not isinstance(thread_id, str) or not _POSITIVE_DECIMAL.fullmatch(thread_id):
            raise ConfigError("thread_id must be a positive decimal identifier.")
    elif thread_id is not None:
        raise ConfigError("Non-thread mappings require null thread_id.")
    anchor_pattern = _POSITIVE_DECIMAL if value["platform"] == "telegram" else _INPUT_ID
    if not isinstance(anchor_id, str) or not anchor_pattern.fullmatch(anchor_id):
        raise ConfigError(
            "message_id must be a positive decimal identifier."
        )

    routes_raw = value["routes"]
    if not isinstance(routes_raw, dict) or not 1 <= len(routes_raw) <= 64 or any(not isinstance(name, str) or not _PROFILE.fullmatch(name) for name in routes_raw):
        raise ConfigError("routes must contain 1 to 64 named routes.")
    routes: dict[str, Route] = {}
    for name in routes_raw:
        row = routes_raw[name]
        if not isinstance(row, dict) or set(row) != {"route_id", "project_id"}:
            raise ConfigError(
                f"routes.{name} must contain route_id and project_id only."
            )
        routes[name] = Route(
            name,
            _canonical_uuid(row["route_id"], f"routes.{name}.route_id"),
            _canonical_uuid(row["project_id"], f"routes.{name}.project_id"),
        )
    if (len({r.route_id for r in routes.values()}) != len(routes)
            or len({r.project_id for r in routes.values()}) != len(routes)):
        raise ConfigError("Route identifiers must be distinct.")

    return WatchConfig(
        watcher_profile=value["watcher_profile"],
        platform=value["platform"],
        chat_type=value["chat_type"],
        multica_profile=profile,
        multica_server_url=_https_origin(value["multica_server_url"]),
        workspace_id=workspace_id,
        sweep_since=parse_rfc3339(value["sweep_since"], "sweep_since"),
        user_id=user_id,
        chat_id=chat_id,
        thread_id=thread_id,
        message_id=anchor_id,
        routes=routes,
    )


def _read_private_file(
    path: Path, *, owner_uid: int, max_bytes: int, label: str
) -> bytes:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > max_bytes
        ):
            raise ConfigError(
                f"{label} must be an owner-only regular file with mode 0600."
            )
        result = bytearray()
        while len(result) <= max_bytes:
            chunk = os.read(fd, min(8192, max_bytes + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > max_bytes:
            raise ConfigError(f"{label} exceeds the safe size limit.")
        return bytes(result)
    except OSError as exc:
        raise ConfigError(f"{label} is unavailable or is a symbolic link.") from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_config(path: Path = CONFIG_PATH) -> WatchConfig:
    uid = os.getuid()
    _check_private_directory(path.parent, owner_uid=uid, create=False)
    try:
        raw = _read_private_file(
            path, owner_uid=uid, max_bytes=65_536, label="Private configuration"
        )
        value = _strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise ConfigError(
            "The private configuration is invalid JSON or unreadable."
        ) from None
    return parse_config(value)


def _check_private_directory(path: Path, *, owner_uid: int, create: bool) -> None:
    if create:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError(
                "A private state directory could not be created."
            ) from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConfigError("A private state directory is unavailable.") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != owner_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ConfigError(
            "Private directories must be owned by the current user and have mode 0700."
        )


def _canonical_issue_id(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("issue id is invalid")
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise ValueError("issue id is invalid") from None


def _extract_issue(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("issue"), dict):
        value = value["issue"]
    if not isinstance(value, dict):
        raise InvalidMulticaResponse("Multica returned an invalid issue response.")
    required = {"id", "workspace_id", "project_id", "status", "updated_at"}
    if required - set(value):
        raise InvalidMulticaResponse("Multica returned an incomplete issue response.")
    try:
        value["id"] = _canonical_issue_id(value["id"])
        value["workspace_id"] = _canonical_uuid(value["workspace_id"], "workspace_id")
        value["project_id"] = _canonical_uuid(value["project_id"], "project_id")
    except (ConfigError, TypeError, ValueError):
        raise InvalidMulticaResponse(
            "Multica returned an invalid issue or route identifier."
        ) from None
    return value


def _extract_page(value: Any) -> tuple[list[dict[str, Any]], bool, int]:
    if not isinstance(value, dict) or not isinstance(value.get("issues"), list):
        raise InvalidMulticaResponse("Multica returned an invalid issue-list response.")
    has_more = value.get("has_more")
    offset = value.get("offset")
    if type(has_more) is not bool or type(offset) is not int or offset < 0:
        raise InvalidMulticaResponse("Multica returned incomplete pagination metadata.")
    rows: list[dict[str, Any]] = []
    for item in value["issues"]:
        if not isinstance(item, dict):
            raise InvalidMulticaResponse("Multica returned an invalid issue-list item.")
        rows.append(item)
    return rows, has_more, offset


class MulticaCli:
    def __init__(self, config: WatchConfig, *, executable: Path = MULTICA_BIN):
        self.config = config
        self.executable = executable

    def _json(self, args: Sequence[str]) -> Any:
        command = [
            str(self.executable),
            "--profile",
            self.config.multica_profile,
            "--server-url",
            self.config.multica_server_url,
            "--workspace-id",
            self.config.workspace_id,
            *args,
        ]
        env = os.environ.copy()
        env.pop("MULTICA_DEBUG", None)
        env.pop("MULTICA_SERVER_URL", None)
        env.pop("MULTICA_WORKSPACE_ID", None)
        raw = self._run_bounded(command, env=env)
        try:
            return _strict_json(raw)
        except (UnicodeDecodeError, ValueError):
            raise InvalidMulticaResponse("Multica CLI returned invalid JSON.") from None

    @staticmethod
    def _run_bounded(command: Sequence[str], *, env: Mapping[str, str]) -> bytes:
        try:
            proc = subprocess.Popen(  # nosec B603: fixed binary and argv list; only issue get/list are exposed
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env=dict(env),
                shell=False,
            )
        except OSError as exc:
            raise MulticaError("The Multica CLI could not be started.") from exc
        if proc.stdout is None:
            proc.kill()
            proc.wait(timeout=2)
            raise MulticaError("The Multica CLI output stream is unavailable.")
        output = bytearray()
        deadline = time.monotonic() + CLI_TIMEOUT_SECONDS
        selector = selectors.DefaultSelector()
        try:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MulticaError("The Multica CLI timed out.")
                events = selector.select(min(remaining, 0.5))
                if not events:
                    if proc.poll() is not None:
                        break
                    continue
                chunk = os.read(
                    proc.stdout.fileno(), min(65_536, MAX_CLI_OUTPUT + 1 - len(output))
                )
                if not chunk:
                    selector.unregister(proc.stdout)
                    break
                output.extend(chunk)
                if len(output) > MAX_CLI_OUTPUT:
                    raise MulticaError(
                        "The Multica CLI response exceeds the safe size limit."
                    )
            remaining = max(0.1, deadline - time.monotonic())
            try:
                return_code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise MulticaError("The Multica CLI timed out.") from None
            if return_code != 0:
                raise MulticaError(
                    "The Multica CLI did not complete the read-only request."
                )
            return bytes(output)
        except Exception:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            selector.close()
            proc.stdout.close()

    def get_issue(self, issue_id: str) -> dict[str, Any]:
        return _extract_issue(
            self._json(["issue", "get", issue_id, "--output", "json"])
        )

    def list_page(
        self, route: Route, offset: int
    ) -> tuple[list[dict[str, Any]], bool, int]:
        value = self._json(
            [
                "issue",
                "list",
                "--project",
                route.project_id,
                "--limit",
                str(PAGE_SIZE),
                "--offset",
                str(offset),
                "--fields",
                _LIST_FIELDS,
                "--output",
                "json",
            ]
        )
        return _extract_page(value)


def _frame(payload: Mapping[str, Any]) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not raw or len(raw) > MAX_IPC_FRAME:
        raise IpcRejected("Watcher IPC request exceeds the safe size limit.")
    return _FRAME.pack(len(raw)) + raw


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Watcher IPC exchange timed out.")
    return remaining


def _recv_exact(conn: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        conn.settimeout(_remaining_timeout(deadline))
        chunk = conn.recv(size - len(result))
        if not chunk:
            raise IpcUnavailable(
                "Watcher IPC closed before returning a complete response."
            )
        result.extend(chunk)
    return bytes(result)


class WatcherIpc:
    def __init__(
        self, path: Path = SOCKET_PATH, *, timeout: float = IPC_TIMEOUT_SECONDS
    ):
        self.path = path
        self.timeout = min(max(timeout, 0.1), 10.0)

    def _request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout
        try:
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise IpcUnavailable("Watcher IPC socket is unavailable.")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(_remaining_timeout(deadline))
                conn.connect(str(self.path))
                conn.settimeout(_remaining_timeout(deadline))
                conn.sendall(_frame(payload))
                header = _recv_exact(conn, _FRAME.size, deadline)
                length = _FRAME.unpack(header)[0]
                if not 0 < length <= MAX_IPC_FRAME:
                    raise IpcRejected("Watcher returned an invalid IPC frame.")
                raw = _recv_exact(conn, length, deadline)
        except IpcRejected:
            raise
        except (OSError, TimeoutError) as exc:
            raise IpcUnavailable("Watcher IPC is unavailable.") from exc
        try:
            response = _strict_json(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise IpcRejected("Watcher returned an invalid IPC response.") from None
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise IpcRejected("Watcher returned an invalid IPC response.")
        return response

    def readiness(self) -> dict[str, Any]:
        response = self._request({"operation": "readiness"})
        if response.get("ok") is not True or response.get("ready") is not True:
            raise IpcUnavailable("Watcher did not report ready.")
        return response

    def register(self, mapping: Mapping[str, Any]) -> dict[str, Any]:
        response = self._request(
            {"operation": "register_issue", "mapping": dict(mapping)}
        )
        if response.get("ok") is not True:
            error_code = response.get("error_code")
            safe_code = (
                error_code
                if isinstance(error_code, str)
                and re.fullmatch(r"[a-z0-9_]{1,64}", error_code)
                else "rejected"
            )
            raise IpcRejected(f"Watcher rejected registration ({safe_code}).")
        return response


def _mapping(config: WatchConfig, route: Route, issue_id: str) -> dict[str, Any]:
    return {
        "profile": config.watcher_profile,
        "issue_id": issue_id,
        "route_id": route.route_id,
        "platform": config.platform,
        "user_id": config.user_id,
        "chat_id": config.chat_id,
        "thread_id": config.thread_id,
        "message_id": config.message_id,
        "chat_type": config.chat_type,
    }


def _verify_issue(issue: Mapping[str, Any], config: WatchConfig, route: Route) -> str:
    if (
        issue.get("workspace_id") != config.workspace_id
        or issue.get("project_id") != route.project_id
    ):
        raise AppError(
            1, "The issue does not belong to the selected workspace and project."
        )
    try:
        return _canonical_issue_id(issue.get("id"))
    except (TypeError, ValueError):
        raise AppError(1, "Multica returned an invalid issue identifier.") from None


def _journal_key(mapping: Mapping[str, Any]) -> str:
    return ":".join(
        (str(mapping["profile"]), str(mapping["route_id"]), str(mapping["issue_id"]))
    )


def _empty_journal() -> dict[str, Any]:
    return {"mappings": {}}


def _read_journal(path: Path, *, owner_uid: int) -> dict[str, Any]:
    try:
        path.lstat()
    except FileNotFoundError:
        return _empty_journal()
    except OSError as exc:
        raise ConfigError("The mapping journal is unavailable.") from exc
    raw = _read_private_file(
        path, owner_uid=owner_uid, max_bytes=4 * 1024 * 1024, label="Mapping journal"
    )
    try:
        value = _strict_json(raw)
    except (OSError, UnicodeDecodeError, ValueError):
        raise ConfigError("The mapping journal is corrupt or unreadable.") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"mappings"}
        or not isinstance(value["mappings"], dict)
    ):
        raise ConfigError("The mapping journal has an unsupported structure.")
    for key, entry in value["mappings"].items():
        if (
            not isinstance(key, str)
            or not isinstance(entry, dict)
            or set(entry) != {"mapping"}
            or not isinstance(entry["mapping"], dict)
        ):
            raise ConfigError("The mapping journal contains an invalid record.")
        expected_fields = {
            "profile",
            "issue_id",
            "route_id",
            "platform",
            "user_id",
            "chat_id",
            "thread_id",
            "message_id",
            "chat_type",
        }
        mapping = entry["mapping"]
        if set(mapping) != expected_fields or any(
            (not isinstance(item, str) or not item) and not (key == "thread_id" and item is None) for key, item in mapping.items()
        ):
            raise ConfigError("The mapping journal contains an invalid mapping.")
        if key != _journal_key(entry["mapping"]):
            raise ConfigError("The mapping journal contains an inconsistent record.")
    return value


def _atomic_write_journal(
    path: Path, journal: Mapping[str, Any], *, owner_uid: int
) -> None:
    data = (
        json.dumps(
            journal, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )
    if len(data) > 4 * 1024 * 1024:
        raise ConfigError("The mapping journal exceeds the safe size limit.")
    fd: int | None = None
    temp_path: Path | None = None
    try:
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".mappings-", dir=path.parent)
            temp_path = Path(temp_name)
        except OSError as exc:
            raise ConfigError(
                "A temporary mapping journal file could not be created."
            ) from exc
        os.fchmod(fd, 0o600)
        if os.fstat(fd).st_uid != owner_uid:
            raise ConfigError(
                "The mapping journal temporary file has an unexpected owner."
            )
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(temp_path, path)
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise ConfigError(
                "The mapping journal could not be durably updated."
            ) from exc
    except OSError as exc:
        raise ConfigError("The mapping journal could not be durably updated.") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


@contextmanager
def _locked_journal(
    path: Path, *, owner_uid: int, create: bool
) -> Iterator[dict[str, Any]]:
    if create:
        _check_private_directory(path.parent, owner_uid=owner_uid, create=True)
    else:
        _check_private_directory(path.parent, owner_uid=owner_uid, create=False)
    lock_path = path.with_suffix(path.suffix + ".lock")
    if not create and not lock_path.exists():
        yield _read_journal(path, owner_uid=owner_uid)
        return
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ConfigError("The mapping journal lock is unavailable.") from exc
    try:
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise ConfigError("The mapping journal lock must be owner-only.")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        journal = _read_journal(path, owner_uid=owner_uid)
        yield journal
    finally:
        os.close(lock_fd)


def _save_mapping(
    journal: dict[str, Any], path: Path, mapping: Mapping[str, Any], *, owner_uid: int
) -> None:
    key = _journal_key(mapping)
    journal["mappings"][key] = {"mapping": dict(mapping)}
    _atomic_write_journal(path, journal, owner_uid=owner_uid)


def _journal_state(journal: Mapping[str, Any], mapping: Mapping[str, Any]) -> str:
    prior = journal["mappings"].get(_journal_key(mapping))
    if prior is None:
        return "new"
    if prior.get("mapping") == dict(mapping):
        return "same"
    return "conflict"


def _input_identifier(value: str) -> str:
    if not _INPUT_ID.fullmatch(value):
        raise AppError(4, "Issue identifier has an invalid format.")
    return value


def _display_issue_id(issue: Mapping[str, Any], issue_id: str) -> str:
    candidate = issue.get("identifier")
    if isinstance(candidate, str) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", candidate
    ):
        return candidate
    return issue_id


def _issue_time(issue: Mapping[str, Any]) -> datetime:
    return parse_rfc3339(issue.get("updated_at"), "updated_at")


def _run_single(
    issue_arg: str,
    route_name: str,
    *,
    dry_run: bool,
    config: WatchConfig,
    cli: MulticaCli,
    ipc: WatcherIpc,
    journal_path: Path,
) -> int:
    if route_name not in config.routes:
        raise AppError(4, "Route is not configured.")
    issue_arg = _input_identifier(issue_arg)
    route = config.routes[route_name]
    try:
        issue = cli.get_issue(issue_arg)
    except InvalidMulticaResponse as exc:
        raise AppError(4, "Multica returned an invalid issue response.") from exc
    except MulticaError as exc:
        raise AppError(
            1, "The issue was not found or could not be read from Multica."
        ) from exc
    issue_id = _verify_issue(issue, config, route)
    mapping = _mapping(config, route, issue_id)
    if dry_run:
        print(
            f"would_register route={route_name} issue={_display_issue_id(issue, issue_id)}"
        )
        return 0

    try:
        ipc.readiness()
    except IpcUnavailable as exc:
        raise AppError(2, str(exc)) from exc
    except IpcRejected as exc:
        raise AppError(3, str(exc)) from exc

    uid = os.getuid()
    with _locked_journal(journal_path, owner_uid=uid, create=True) as journal:
        if _journal_state(journal, mapping) == "conflict":
            raise AppError(
                3, "The local journal records a different mapping for this issue."
            )
        try:
            ipc.register(mapping)
        except IpcUnavailable as exc:
            raise AppError(2, str(exc)) from exc
        except IpcRejected as exc:
            raise AppError(3, str(exc)) from exc
        _save_mapping(journal, journal_path, mapping, owner_uid=uid)
    print(f"registered route={route_name} issue={_display_issue_id(issue, issue_id)}")
    return 0


@dataclass
class SweepSummary:
    checked: int = 0
    registered: int = 0
    skipped: int = 0
    errors: int = 0
    would_register: int = 0
    exit_code: int = 0

    def print(self, *, dry_run: bool) -> None:
        suffix = f" dry_run={str(dry_run).lower()}"
        if dry_run:
            suffix += f" would_register={self.would_register}"
        print(
            f"checked={self.checked} registered={self.registered} skipped={self.skipped} "
            f"errors={self.errors}{suffix}"
        )


def _load_project_rows(
    cli: MulticaCli, config: WatchConfig, route: Route, summary: SweepSummary
) -> list[dict[str, Any]]:
    offset = 0
    pages = 0
    seen: dict[str, dict[str, Any]] = {}
    conflicted: set[str] = set()
    while True:
        pages += 1
        if pages > MAX_PAGES:
            raise MulticaError("Multica pagination exceeded the safety limit.")
        rows, has_more, response_offset = cli.list_page(route, offset)
        if response_offset != offset:
            raise MulticaError("Multica returned inconsistent pagination metadata.")
        for raw in rows:
            try:
                issue_id = _canonical_issue_id(raw.get("id"))
                workspace_id = _canonical_uuid(raw.get("workspace_id"), "workspace_id")
                project_id = _canonical_uuid(raw.get("project_id"), "project_id")
            except (ConfigError, TypeError, ValueError):
                summary.errors += 1
                continue
            normalized = dict(raw)
            normalized["id"] = issue_id
            normalized["workspace_id"] = workspace_id
            normalized["project_id"] = project_id
            if issue_id in conflicted:
                continue
            prior = seen.get(issue_id)
            if prior is not None:
                if prior != normalized:
                    summary.errors += 1
                    summary.exit_code = max(summary.exit_code, 4)
                    conflicted.add(issue_id)
                    seen.pop(issue_id, None)
                continue
            seen[issue_id] = normalized
        if not has_more:
            break
        if not rows:
            raise MulticaError("Multica pagination made no progress.")
        offset += len(rows)
    return list(seen.values())


def _sweep_with_journal(
    *,
    dry_run: bool,
    config: WatchConfig,
    cli: MulticaCli,
    ipc: WatcherIpc,
    journal_path: Path,
    journal: dict[str, Any],
    uid: int,
) -> int:
    summary = SweepSummary()
    if not dry_run:
        try:
            ipc.readiness()
        except IpcUnavailable:
            summary.errors += 1
            summary.exit_code = 2
            return _finish_sweep(summary, dry_run=dry_run)
        except IpcRejected:
            summary.errors += 1
            summary.exit_code = 3
            return _finish_sweep(summary, dry_run=dry_run)

    all_rows: dict[str, tuple[dict[str, Any], Route]] = {}
    conflicted_ids: set[str] = set()
    for route in config.routes.values():
        try:
            rows = _load_project_rows(cli, config, route, summary)
        except MulticaError:
            summary.errors += 1
            summary.exit_code = max(summary.exit_code, 4)
            continue
        for issue in rows:
            if (
                issue["workspace_id"] != config.workspace_id
                or issue["project_id"] != route.project_id
            ):
                summary.errors += 1
                summary.exit_code = max(summary.exit_code, 4)
                continue
            existing = all_rows.get(issue["id"])
            if issue["id"] in conflicted_ids:
                continue
            if existing is not None:
                if existing[1].route_id != route.route_id:
                    summary.errors += 1
                    summary.exit_code = max(summary.exit_code, 4)
                    conflicted_ids.add(issue["id"])
                    all_rows.pop(issue["id"], None)
                continue
            all_rows[issue["id"]] = (issue, route)
    summary.checked = len(all_rows) + len(conflicted_ids)
    if summary.errors and summary.exit_code == 0:
        summary.exit_code = 4

    candidates: list[tuple[dict[str, Any], Route, dict[str, Any]]] = []
    for issue, route in all_rows.values():
        try:
            updated_at = _issue_time(issue)
        except ConfigError:
            summary.errors += 1
            summary.exit_code = max(summary.exit_code, 4)
            continue
        status = issue.get("status")
        if not isinstance(status, str) or not status:
            summary.errors += 1
            summary.exit_code = max(summary.exit_code, 4)
            continue
        if updated_at < config.sweep_since or status in {"done", "cancelled"}:
            summary.skipped += 1
            continue
        mapping = _mapping(config, route, issue["id"])
        state = _journal_state(journal, mapping)
        if state == "same":
            summary.skipped += 1
            continue
        if state == "conflict":
            summary.errors += 1
            summary.exit_code = max(summary.exit_code, 3)
            continue
        candidates.append((issue, route, mapping))

    for _issue_row, _route, mapping in candidates:
        if dry_run:
            summary.would_register += 1
            continue
        try:
            ipc.register(mapping)
        except IpcUnavailable:
            summary.errors += 1
            summary.exit_code = 2
            break
        except IpcRejected:
            summary.errors += 1
            summary.exit_code = 3
            break
        try:
            _save_mapping(journal, journal_path, mapping, owner_uid=uid)
        except ConfigError:
            summary.errors += 1
            summary.exit_code = 4
            break
        summary.registered += 1
    return _finish_sweep(summary, dry_run=dry_run)


def _run_sweep(
    *,
    dry_run: bool,
    config: WatchConfig,
    cli: MulticaCli,
    ipc: WatcherIpc,
    journal_path: Path,
) -> int:
    uid = os.getuid()
    try:
        if dry_run:
            if journal_path.parent.exists():
                _check_private_directory(
                    journal_path.parent, owner_uid=uid, create=False
                )
                journal = _read_journal(journal_path, owner_uid=uid)
            else:
                journal = _empty_journal()
            return _sweep_with_journal(
                dry_run=True,
                config=config,
                cli=cli,
                ipc=ipc,
                journal_path=journal_path,
                journal=journal,
                uid=uid,
            )
        with _locked_journal(journal_path, owner_uid=uid, create=True) as journal:
            return _sweep_with_journal(
                dry_run=False,
                config=config,
                cli=cli,
                ipc=ipc,
                journal_path=journal_path,
                journal=journal,
                uid=uid,
            )
    except ConfigError as exc:
        raise AppError(4, str(exc)) from exc


def _finish_sweep(summary: SweepSummary, *, dry_run: bool) -> int:
    summary.print(dry_run=dry_run)
    return summary.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = UserArgumentParser(prog="multica-watch-register")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--sweep",
        action="store_true",
        help="register eligible recent issues in configured routes",
    )
    modes.add_argument(
        "--readiness",
        action="store_true",
        help="show the watcher IPC readiness response",
    )
    parser.add_argument("issue_id", nargs="?", help="Multica issue UUID or identifier")
    parser.add_argument("--route")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    config_path: Path = CONFIG_PATH,
    journal_path: Path = STATE_PATH,
    ipc: WatcherIpc | None = None,
    cli_factory: Any = MulticaCli,
) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except AppError as exc:
        print(exc.message, file=sys.stderr)
        return exc.exit_code
    config_path = args.config or config_path
    journal_path = args.journal or journal_path
    if args.socket is not None and ipc is None:
        ipc = WatcherIpc(args.socket)
    if args.readiness:
        if (
            args.issue_id is not None
            or args.route is not None
            or args.dry_run
            or args.sweep
        ):
            print(
                "--readiness does not accept issue, route, sweep, or dry-run arguments",
                file=sys.stderr,
            )
            return 4
        client = ipc or WatcherIpc()
        try:
            response = client.readiness()
        except IpcUnavailable as exc:
            print(f"ok=false ready=false error={exc}", file=sys.stderr)
            return 2
        except IpcRejected as exc:
            print(f"ok=false ready=false error={exc}", file=sys.stderr)
            return 3
        print(
            f"ok={str(response.get('ok') is True).lower()} ready={str(response.get('ready') is True).lower()}"
        )
        return 0
    if args.sweep:
        if args.issue_id is not None or args.route is not None:
            print("--sweep does not accept an issue or route", file=sys.stderr)
            return 4
    elif args.issue_id is None or args.route is None:
        print("an issue identifier and --route are required", file=sys.stderr)
        return 4

    try:
        config = load_config(config_path)
        client = cli_factory(config)
        ipc_client = ipc or WatcherIpc()
        if args.sweep:
            return _run_sweep(
                dry_run=args.dry_run,
                config=config,
                cli=client,
                ipc=ipc_client,
                journal_path=journal_path,
            )
        return _run_single(
            args.issue_id,
            args.route,
            dry_run=args.dry_run,
            config=config,
            cli=client,
            ipc=ipc_client,
            journal_path=journal_path,
        )
    except AppError as exc:
        print(exc.message, file=sys.stderr)
        return exc.exit_code
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
