"""Private configuration, credentials and append-only TOML updates."""

from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import stat
import tempfile
import tomllib
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class NotifyError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str = "notify_config_invalid") -> None:
    if not condition:
        raise NotifyError(code)


def name(value: Any) -> str:
    require(
        isinstance(value, str)
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value))
    )
    return value


def identifier(value: Any) -> str:
    try:
        require(isinstance(value, str))
        require(str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError):
        raise NotifyError("notify_config_invalid") from None
    return value


def private_dir(path: Path) -> None:
    require(not path.is_symlink(), "notify_permissions_invalid")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(
        info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
        "notify_permissions_invalid",
    )


def private_read(
    path: Path, maximum: int = 1_048_576, *, modes: tuple[int, ...] = (0o600,)
) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid in {0, os.getuid()}
                and stat.S_IMODE(info.st_mode) in modes
                and info.st_size <= maximum,
                "notify_permissions_invalid",
            )
            data = handle.read(maximum + 1)
            require(len(data) <= maximum, "notify_config_invalid")
            return data
    except OSError:
        raise NotifyError("notify_file_unavailable") from None


def atomic_private(path: Path, data: bytes) -> None:
    private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".notify-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def file_lock(path: Path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600,
            "notify_permissions_invalid",
        )
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Config:
    service: dict[str, Any]
    policy: dict[str, Any]
    accounts: dict[str, dict[str, Any]]
    workspaces: dict[str, dict[str, Any]]
    workspace_errors: dict[str, str] = field(default_factory=dict)
    wake: dict[str, Any] = field(default_factory=dict)
    readiness_ipc: dict[str, Any] = field(default_factory=dict)


DEFAULTS = {
    "db_path": "/var/lib/hermes-multica-notify/notify.sqlite3",
    "runtime_dir": "/run/hermes-multica-notify",
    "cli_binary": "/usr/local/bin/multica",
    "poll_seconds": 45,
    "poll_overlap_seconds": 300,
    "request_timeout_seconds": 15,
    "max_attempts": 5,
    "sending_timeout_seconds": 300,
    "retention_events_days": 7,
    "retention_notifications_days": 30,
    "replay_retention_days": 30,
    "full_reconcile_seconds": 300,
    "full_reconcile_jitter_seconds": 30,
    "full_reconcile_parallelism": 2,
    "delivery_workers": 4,
}
POLICY = {
    "final_statuses": ["done", "in_review"],
    "question_prefixes": ["QUESTION:", "ВОПРОС:"],
    "report_prefixes": ["REPORT:", "ОТЧЁТ:"],
    "lookback_minutes": 15,
    "operator_mentions": [],
}
WAKE_DEFAULTS = {
    "enabled": False,
    "base_url": "http://127.0.0.1:8644",
    "secret_credential": "hermes-wake-hmac",
    "webhook_policy_file": "/etc/hermes-multica-notify/webhook-policy.json",
    "request_timeout_seconds": 10,
    "max_attempts": 1,
}
READINESS_IPC_DEFAULTS = {
    "enabled": False,
    "socket_path": "/run/hermes-multica-notify-readiness/readiness.sock",
    "peers": [],
}


def parse_config(raw: Any) -> Config:
    require(
        isinstance(raw, dict)
        and not set(raw) - {"service", "policy", "accounts", "workspaces", "wake", "readiness_ipc"}
    )
    service_raw, policy_raw = raw.get("service", {}), raw.get("policy", {})
    require(isinstance(service_raw, dict) and not set(service_raw) - set(DEFAULTS))
    require(isinstance(policy_raw, dict) and not set(policy_raw) - set(POLICY))
    service, policy = DEFAULTS | service_raw, POLICY | policy_raw
    for key in ("db_path", "runtime_dir", "cli_binary"):
        require(isinstance(service[key], str) and Path(service[key]).is_absolute())
    for key in set(DEFAULTS) - {"db_path", "runtime_dir", "cli_binary"}:
        require(type(service[key]) is int and 1 <= service[key] <= 86400)
    require(
        service["request_timeout_seconds"] <= 30
        and 60 <= service["sending_timeout_seconds"] <= 3600
    )
    require(
        service["max_attempts"] <= 10
        and service["delivery_workers"] <= 32
        and service["full_reconcile_parallelism"] <= 2
        and service["request_timeout_seconds"] < service["sending_timeout_seconds"]
        and service["full_reconcile_jitter_seconds"] < service["full_reconcile_seconds"]
    )
    wake_raw = raw.get("wake", {})
    require(
        isinstance(wake_raw, dict)
        and not set(wake_raw) - set(WAKE_DEFAULTS) - {"routes"},
        "wake_config_invalid",
    )
    wake = WAKE_DEFAULTS | {
        key: value for key, value in wake_raw.items() if key != "routes"
    }
    require(type(wake["enabled"]) is bool, "wake_config_invalid")
    require(
        type(wake["request_timeout_seconds"]) is int
        and 1 <= wake["request_timeout_seconds"] <= 30
        and type(wake["max_attempts"]) is int
        and wake["max_attempts"] == 1,
        "wake_config_invalid",
    )
    require(isinstance(wake["secret_credential"], str), "wake_config_invalid")
    name(wake["secret_credential"])
    require(
        isinstance(wake["webhook_policy_file"], str)
        and Path(wake["webhook_policy_file"]).is_absolute(),
        "wake_config_invalid",
    )
    base_url = wake["base_url"]
    require(
        isinstance(base_url, str)
        and base_url.isascii()
        and len(base_url) <= 128
        and base_url == base_url.strip(),
        "wake_config_invalid",
    )
    try:
        parsed_wake_url = urlsplit(base_url)
        wake_port = parsed_wake_url.port
    except ValueError:
        raise NotifyError("wake_config_invalid") from None
    require(
        parsed_wake_url.scheme == "http"
        and parsed_wake_url.hostname in {"127.0.0.1", "::1"}
        and not parsed_wake_url.username
        and not parsed_wake_url.password
        and not parsed_wake_url.query
        and not parsed_wake_url.fragment
        and parsed_wake_url.path in {"", "/"}
        and wake_port is not None
        and 1 <= wake_port <= 65535,
        "wake_config_invalid",
    )
    host = "[::1]" if parsed_wake_url.hostname == "::1" else "127.0.0.1"
    wake["base_url"] = f"http://{host}:{wake_port}"
    routes_raw = wake_raw.get("routes", {})
    require(isinstance(routes_raw, dict), "wake_config_invalid")
    routes, seen_routes = {}, set()
    for route_key, route_row in routes_raw.items():
        require(
            isinstance(route_key, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", route_key) is not None,
            "wake_config_invalid",
        )
        require(
            isinstance(route_row, dict)
            and not set(route_row) - {"profile", "route", "test"}
            and {"profile", "route"} <= set(route_row),
            "wake_config_invalid",
        )
        profile, route = route_row["profile"], route_row["route"]
        require(
            isinstance(profile, str) and profile in {"default", "om73"},
            "wake_config_invalid",
        )
        require(
            isinstance(route, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", route) is not None,
            "wake_config_invalid",
        )
        require(route not in seen_routes, "wake_config_invalid")
        require(type(route_row.get("test", False)) is bool, "wake_config_invalid")
        seen_routes.add(route)
        routes[route_key] = {
            "profile": profile,
            "route": route,
            "test": route_row.get("test", False),
        }
    require(not wake["enabled"] or bool(routes), "wake_config_invalid")
    wake["routes"] = routes
    ipc_raw = raw.get("readiness_ipc", {})
    require(
        isinstance(ipc_raw, dict)
        and not set(ipc_raw) - set(READINESS_IPC_DEFAULTS),
        "notify_config_invalid",
    )
    readiness_ipc = READINESS_IPC_DEFAULTS | ipc_raw
    require(type(readiness_ipc["enabled"]) is bool, "notify_config_invalid")
    socket_path = readiness_ipc["socket_path"]
    require(
        isinstance(socket_path, str)
        and Path(socket_path).is_absolute()
        and len(socket_path) <= 100
        and str(Path(socket_path).parent) == "/run/hermes-multica-notify-readiness",
        "notify_config_invalid",
    )
    peers = readiness_ipc["peers"]
    require(isinstance(peers, list) and len(peers) <= 64, "notify_config_invalid")
    normalized_peers = []
    seen_uids = set()
    for peer in peers:
        require(
            isinstance(peer, dict)
            and set(peer) == {"uid", "profiles"}
            and type(peer["uid"]) is int
            and 1 <= peer["uid"] <= 2**31 - 1
            and peer["uid"] not in seen_uids
            and isinstance(peer["profiles"], list)
            and 1 <= len(peer["profiles"]) <= 8
            and all(isinstance(p, str) and PROFILE_RE.fullmatch(p) for p in peer["profiles"])
            and len(set(peer["profiles"])) == len(peer["profiles"]),
            "notify_config_invalid",
        )
        seen_uids.add(peer["uid"])
        normalized_peers.append({"uid": peer["uid"], "profiles": tuple(peer["profiles"])})
    readiness_ipc["peers"] = tuple(normalized_peers)
    require(not readiness_ipc["enabled"] or bool(normalized_peers), "notify_config_invalid")
    require(not readiness_ipc["enabled"] or wake["enabled"], "notify_config_invalid")
    require(
        type(policy["lookback_minutes"]) is int
        and 0 <= policy["lookback_minutes"] <= 1440
    )
    for key in set(POLICY) - {"lookback_minutes"}:
        require(
            isinstance(policy[key], list)
            and len(policy[key]) <= 64
            and all(isinstance(v, str) and 0 < len(v) <= 128 for v in policy[key])
        )
        require(bool(policy[key]) or key == "operator_mentions")
    accounts, workspaces = raw.get("accounts", {}), raw.get("workspaces", {})
    require(isinstance(accounts, dict) and isinstance(workspaces, dict))
    pairs = set()
    for key, row in accounts.items():
        name(key)
        require(isinstance(row, dict) and set(row) == {"platform", "token_credential"})
        require(row["platform"] in {"telegram", "max"})
        name(row["token_credential"])
    valid_workspaces, errors = {}, {}
    for key, row in workspaces.items():
        name(key)
        try:
            require(
                isinstance(row, dict)
                and not set(row)
                - {"origin", "workspace_id", "cli_profile", "pat_credential", "enabled"}
            )
            require(
                {"origin", "workspace_id", "cli_profile", "pat_credential"} <= set(row)
            )
            require(
                isinstance(row["origin"], str)
                and row["origin"].isascii()
                and len(row["origin"]) <= 512
                and row["origin"] == row["origin"].strip()
            )
            parsed = urlsplit(row["origin"])
            require(
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and parsed.path in {"", "/"}
                and (parsed.port is None or 1 <= parsed.port <= 65535)
            )
            host = parsed.hostname.lower()
            host = "[" + host + "]" if ":" in host else host
            origin = (
                "https://"
                + host
                + (":" + str(parsed.port) if parsed.port not in (None, 443) else "")
            )
            identifier(row["workspace_id"])
            name(row["cli_profile"])
            name(row["pat_credential"])
            require(type(row.get("enabled", True)) is bool)
        except (NotifyError, ValueError, TypeError, KeyError):
            errors[key] = "notify_config_invalid"
            valid_workspaces[key] = {
                "origin": "https://invalid.example.invalid",
                "workspace_id": "00000000-0000-0000-0000-000000000000",
                "cli_profile": key,
                "pat_credential": "unavailable",
                "enabled": False,
            }
            continue
        pair = (origin, row["workspace_id"])
        require(pair not in pairs)
        pairs.add(pair)
        valid_workspaces[key] = dict(row, origin=origin)
    return Config(service, policy, accounts, valid_workspaces, errors, wake, readiness_ipc)


def load_config(path: Path) -> Config:
    try:
        return parse_config(tomllib.loads(private_read(path).decode("utf-8")))
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise NotifyError("notify_config_invalid") from None


def credential(value: str, directory: Path | None = None) -> str:
    name(value)
    systemd_credentials = "CREDENTIALS_DIRECTORY" in os.environ
    root = directory or Path(
        os.environ.get(
            "CREDENTIALS_DIRECTORY", "/etc/hermes-multica-notify/credentials"
        )
    )
    require(not root.is_symlink(), "notify_permissions_invalid")
    try:
        info = root.stat()
    except OSError:
        raise NotifyError("notify_credential_missing") from None
    require(
        info.st_uid in {0, os.getuid()}
        and stat.S_IMODE(info.st_mode)
        in (
            {0o500, 0o550, 0o700}
            if systemd_credentials
            else {0o700}
        ),
        "notify_permissions_invalid",
    )
    # systemd credential directories can be root-owned/read-only; private file checks still apply.
    try:
        file_modes = (0o400, 0o440, 0o600) if systemd_credentials else (0o400, 0o600)
        result = private_read(root / value, 8192, modes=file_modes).decode().strip()
    except NotifyError:
        raise NotifyError("notify_credential_missing") from None
    require(
        bool(result) and "\n" not in result and "\r" not in result,
        "notify_credential_missing",
    )
    return result


def request_reload(path: Path, config: Config) -> bool:
    pid_path = Path(config.service["runtime_dir"]) / "pid.json"
    if not pid_path.exists():
        return True
    try:
        pid = json.loads(private_read(pid_path))
        require(pid["config"] == str(path.resolve()))
        current = (
            Path(f"/proc/{pid['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19]
        )
        require(current == pid["start"])
        os.kill(pid["pid"], signal.SIGHUP)
        return True
    except (OSError, ValueError, KeyError, NotifyError):
        return False


def append_tables(path: Path, accounts: dict, workspaces: dict) -> bool:
    private_dir(path.parent)
    with file_lock(path.with_suffix(path.suffix + ".lock")):
        original = private_read(path).decode()
        raw = tomllib.loads(original)
        addition = ""
        for category, rows in (("accounts", accounts), ("workspaces", workspaces)):
            for key, row in rows.items():
                name(key)
                require(key not in raw.get(category, {}), "notify_workspace_exists")
                addition += "\n[" + category + "." + json.dumps(key) + "]\n"
                for field, value in row.items():
                    require(field.replace("_", "").isalnum())
                    addition += (
                        field + " = " + json.dumps(value, ensure_ascii=False) + "\n"
                    )
        candidate = original + addition
        config = parse_config(tomllib.loads(candidate))
        require(not config.workspace_errors)
        if addition:
            atomic_private(path, candidate.encode())
    return request_reload(path, config) if addition else True


def append_workspace(path: Path, key: str, row: dict[str, Any]) -> bool:
    return append_tables(path, {}, {key: row})
