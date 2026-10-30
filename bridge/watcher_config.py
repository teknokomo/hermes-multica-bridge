"""Strict configuration and systemd credential access for the isolated watcher."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .configuration import normalize_multica_origin
from .errors import BridgeError

_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CHAT_ID_RE = re.compile(r"\A-?[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PLATFORMS = {"max", "telegram"}
_ROOT_KEYS = {"watcher", "profiles"}
_WATCHER_KEYS = {"socket_path", "socket_gid", "poll_seconds", "request_timeout_seconds", "max_message_chars"}
_PROFILE_KEYS = {
    "state_path", "multica_pat_credential", "max_token_credential",
    "telegram_token_credential", "own_multica_user_id", "allowed_peer_uids", "routes",
}
_ROUTE_KEYS = {
    "route_id", "name", "multica_origin", "workspace_id", "project_id",
    "source_platforms", "allowed_user_ids", "allowed_chat_ids", "allow_groups",
    "allowed_statuses",
}


def _fail(message: str) -> BridgeError:
    return BridgeError("watcher_configuration_invalid", message)


def _clean_id(value: Any, field: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _fail(f"{field} is invalid.")
    return value


def _string_list(
    value: Any,
    field: str,
    *,
    allowed: set[str] | None = None,
    maximum: int = 256,
    pattern: re.Pattern[str] = _ID_RE,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise _fail(f"{field} must be a non-empty bounded list.")
    result = tuple(_clean_id(item, field, pattern) for item in value)
    if len(set(result)) != len(result) or (allowed is not None and set(result) - allowed):
        raise _fail(f"{field} contains duplicates or unsupported values.")
    return result


def _credential_name(value: Any, field: str, *, required: bool) -> str:
    if value in (None, "") and not required:
        return ""
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise _fail(f"{field} must name a systemd credential.")
    return value


@dataclass(frozen=True)
class WatcherRoute:
    route_id: str
    name: str
    multica_origin: str
    workspace_id: str
    project_id: str
    source_platforms: tuple[str, ...]
    allowed_user_ids: tuple[str, ...]
    allowed_chat_ids: tuple[str, ...]
    allow_groups: bool
    allowed_statuses: tuple[str, ...]


@dataclass(frozen=True)
class WatcherProfile:
    name: str
    state_path: Path
    multica_pat_credential: str
    max_token_credential: str
    telegram_token_credential: str
    own_multica_user_id: str
    allowed_peer_uids: tuple[int, ...]
    routes: tuple[WatcherRoute, ...]


@dataclass(frozen=True)
class WatcherConfig:
    socket_path: Path
    socket_gid: int
    poll_seconds: int
    request_timeout_seconds: int
    max_message_chars: int
    profiles: tuple[WatcherProfile, ...]

    def profile(self, name: str) -> WatcherProfile:
        for item in self.profiles:
            if item.name == name:
                return item
        raise BridgeError("watcher_route_denied", "The Hermes profile is not enabled for watcher delivery.")

    def route(self, profile: WatcherProfile, route_id: str) -> WatcherRoute:
        for item in profile.routes:
            if item.route_id == route_id:
                return item
        raise BridgeError("watcher_route_denied", "The Workspace route is not enabled in the watcher.")


def parse_watcher_config(value: Any) -> WatcherConfig:
    if not isinstance(value, dict) or set(value) - _ROOT_KEYS or set(value) != _ROOT_KEYS:
        raise _fail("Watcher configuration must contain only watcher and profiles sections.")
    watcher = value.get("watcher")
    profiles_raw = value.get("profiles")
    if not isinstance(watcher, dict) or set(watcher) - _WATCHER_KEYS:
        raise _fail("The watcher section contains unsupported settings.")
    socket_path = watcher.get("socket_path", "/run/hermes-multica-watcher/ipc.sock")
    if not isinstance(socket_path, str) or not Path(socket_path).is_absolute() or len(socket_path) > 240:
        raise _fail("watcher.socket_path must be an absolute bounded path.")
    socket_gid = watcher.get("socket_gid")
    if type(socket_gid) is not int or socket_gid < 1:
        raise _fail("watcher.socket_gid must be a positive OS group ID.")
    poll = watcher.get("poll_seconds", 45)
    timeout = watcher.get("request_timeout_seconds", 15)
    message_chars = watcher.get("max_message_chars", 3500)
    if type(poll) is not int or not 30 <= poll <= 60:
        raise _fail("watcher.poll_seconds must be between 30 and 60.")
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise _fail("watcher.request_timeout_seconds must be between 1 and 30.")
    if type(message_chars) is not int or not 256 <= message_chars <= 4000:
        raise _fail("watcher.max_message_chars must be between 256 and 4000.")
    if not isinstance(profiles_raw, dict) or not profiles_raw or len(profiles_raw) > 16:
        raise _fail("profiles must be a non-empty bounded table.")

    profiles: list[WatcherProfile] = []
    for profile_name, row in profiles_raw.items():
        if not isinstance(profile_name, str) or not _NAME_RE.fullmatch(profile_name):
            raise _fail("A profile name is invalid.")
        if not isinstance(row, dict) or set(row) - _PROFILE_KEYS:
            raise _fail("A profile contains unsupported settings.")
        state_path = row.get("state_path")
        if not isinstance(state_path, str) or not Path(state_path).is_absolute():
            raise _fail("Each profile requires an absolute state_path.")
        peers = row.get("allowed_peer_uids")
        if (not isinstance(peers, list) or not peers or len(peers) > 8
                or any(type(uid) is not int or uid < 1 for uid in peers) or len(set(peers)) != len(peers)):
            raise _fail("allowed_peer_uids must contain bounded positive UIDs.")
        routes_raw = row.get("routes")
        if not isinstance(routes_raw, list) or not routes_raw or len(routes_raw) > 64:
            raise _fail("Each profile requires a bounded route list.")
        routes: list[WatcherRoute] = []
        for item in routes_raw:
            if not isinstance(item, dict) or set(item) - _ROUTE_KEYS:
                raise _fail("A watcher route contains unsupported settings.")
            route_id = _clean_id(item.get("route_id"), "route_id")
            name = item.get("name")
            if not isinstance(name, str) or not name.strip() or len(name) > 160:
                raise _fail("A watcher route name is invalid.")
            platforms = _string_list(item.get("source_platforms"), "source_platforms", allowed=_PLATFORMS, maximum=2)
            allow_groups = item.get("allow_groups", False)
            if type(allow_groups) is not bool:
                raise _fail("allow_groups must be boolean.")
            route = WatcherRoute(
                route_id=route_id,
                name=name.strip(),
                multica_origin=normalize_multica_origin(item.get("multica_origin", "")),
                workspace_id=_clean_id(item.get("workspace_id"), "workspace_id"),
                project_id=_clean_id(item.get("project_id"), "project_id"),
                source_platforms=platforms,
                allowed_user_ids=_string_list(item.get("allowed_user_ids"), "allowed_user_ids"),
                allowed_chat_ids=_string_list(
                    item.get("allowed_chat_ids"), "allowed_chat_ids", pattern=_CHAT_ID_RE
                ),
                allow_groups=allow_groups,
                allowed_statuses=_string_list(item.get("allowed_statuses"), "allowed_statuses", maximum=64),
            )
            if any(existing.route_id == route.route_id for existing in routes):
                raise _fail("A profile has duplicate route IDs.")
            routes.append(route)
        max_token = _credential_name(row.get("max_token_credential"), "max_token_credential", required=False)
        telegram_token = _credential_name(row.get("telegram_token_credential"), "telegram_token_credential", required=False)
        if "max" in {p for route in routes for p in route.source_platforms} and not max_token:
            raise _fail("A profile with MAX routes requires a MAX systemd credential.")
        if "telegram" in {p for route in routes for p in route.source_platforms} and not telegram_token:
            raise _fail("A profile with Telegram routes requires a Telegram systemd credential.")
        profiles.append(WatcherProfile(
            name=profile_name,
            state_path=Path(state_path),
            multica_pat_credential=_credential_name(row.get("multica_pat_credential"), "multica_pat_credential", required=True),
            max_token_credential=max_token,
            telegram_token_credential=telegram_token,
            own_multica_user_id=_clean_id(row.get("own_multica_user_id"), "own_multica_user_id"),
            allowed_peer_uids=tuple(peers),
            routes=tuple(routes),
        ))
    return WatcherConfig(Path(socket_path), socket_gid, poll, timeout, message_chars, tuple(profiles))


def load_watcher_config(path: str | Path) -> WatcherConfig:
    config_path = Path(path)
    try:
        info = config_path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise _fail("Watcher config must be root-owned and not writable by group or other users.")
        if info.st_size > 262_144:
            raise _fail("Watcher config exceeds the size limit.")
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError as exc:
        raise BridgeError("watcher_configuration_unavailable", "Watcher configuration is unavailable.") from exc
    except tomllib.TOMLDecodeError as exc:
        raise _fail("Watcher configuration is invalid TOML.") from exc
    return parse_watcher_config(raw)


def read_systemd_credential(name: str, *, max_bytes: int = 8192) -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory or not _NAME_RE.fullmatch(name):
        raise BridgeError("watcher_credential_unavailable", "A required systemd credential is unavailable.")
    path = Path(directory) / name
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BridgeError("watcher_credential_unavailable", "A required systemd credential is unavailable.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > max_bytes:
            raise BridgeError("watcher_credential_invalid", "A systemd credential has invalid metadata.")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if not data or len(data) > max_bytes or b"\0" in data:
            raise BridgeError("watcher_credential_invalid", "A systemd credential has invalid content.")
        try:
            return data.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise BridgeError("watcher_credential_invalid", "A systemd credential has invalid encoding.") from exc
    finally:
        os.close(fd)
