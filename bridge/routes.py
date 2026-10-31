"""Load operator-owned Isolated mode policy and systemd credentials."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .configuration import (
    ConnectionConfig,
    connection_from_mapping,
    validate_systemd_unit,
)
from .errors import BridgeError

MAX_CONFIG_BYTES = 65_536
CREDENTIAL_REF_RE = re.compile(r"\A[A-Z][A-Z0-9_]{0,63}\Z")
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
UUID7_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
ROUTE_POLICY_FINGERPRINT_RE = re.compile(r"\Aroute-policy-[0-9a-f]{64}\Z")

TOP_LEVEL_FIELDS = frozenset({"default_deny", "ipc", "route", "connection", "credentials"})
IPC_FIELDS = frozenset({"allowed_peer_uids", "trusted_gateway_unit"})
ROUTE_FIELDS = frozenset({"route_id", "connection_id", "workspace_key", "route_policy_fingerprint"})
CREDENTIAL_FIELDS = frozenset(
    {"webhook_url_ref", "webhook_sha256", "hmac_signing_secret_ref", "multica_pat_ref"}
)


@dataclass(frozen=True)
class IsolatedCredentials:
    webhook_url_ref: str
    webhook_sha256: str | None
    hmac_signing_secret_ref: str | None
    multica_pat_ref: str | None


@dataclass(frozen=True)
class BridgeConfig:
    allowed_peer_uids: frozenset[int]
    trusted_gateway_unit: str
    route_id: str
    connection_id: str
    workspace_key: str
    route_policy_fingerprint: str
    connection: ConnectionConfig
    credentials: IsolatedCredentials

    @property
    def ledger_key(self) -> str:
        """Partition Isolated state by the same immutable Route ID used by Standard mode."""
        return self.route_id


def _lstat_config_path(path: Path) -> tuple[os.stat_result, os.stat_result]:
    try:
        return path.lstat(), path.parent.lstat()
    except OSError as exc:
        raise BridgeError("configuration_unavailable", "The bridge configuration is unavailable.") from exc


def _validate_config_file_metadata(info: os.stat_result, expected_owner_uid: int | None, *, reopened: bool) -> None:
    unsafe = (
        not stat.S_ISREG(info.st_mode)
        or bool(info.st_mode & 0o022)
        or info.st_size > MAX_CONFIG_BYTES
        or (expected_owner_uid is not None and info.st_uid != expected_owner_uid)
    )
    if not unsafe:
        return
    if reopened:
        raise BridgeError("configuration_untrusted", "The bridge configuration changed or has unsafe permissions.")
    if info.st_size > MAX_CONFIG_BYTES:
        raise BridgeError("configuration_invalid", "The bridge configuration is too large.")
    raise BridgeError("configuration_untrusted", "The bridge configuration has unsafe file permissions.")


def _validate_config_parent(parent_info: os.stat_result, expected_owner_uid: int | None) -> None:
    if expected_owner_uid is None:
        return
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != expected_owner_uid
        or bool(parent_info.st_mode & 0o022)
    ):
        raise BridgeError("configuration_untrusted", "The bridge configuration directory is not operator-owned.")


def _read_config(path: Path, *, expected_owner_uid: int | None) -> dict[str, Any]:
    info, parent_info = _lstat_config_path(path)
    _validate_config_file_metadata(info, expected_owner_uid, reopened=False)
    _validate_config_parent(parent_info, expected_owner_uid)
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        _validate_config_file_metadata(os.fstat(fd), expected_owner_uid, reopened=True)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = tomllib.load(stream)
    except BridgeError:
        raise
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BridgeError("configuration_invalid", "The bridge configuration is invalid.") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(raw, dict):
        raise BridgeError("configuration_invalid", "The bridge configuration root must be a mapping.")
    return raw


def _parse_peer_uids(value: Any) -> frozenset[int]:
    if not isinstance(value, list) or not value:
        raise BridgeError("configuration_invalid", "The IPC peer allowlist must contain numeric UIDs.")
    if any(type(uid) is not int or not 1 <= uid <= 2_147_483_647 for uid in value):
        raise BridgeError("configuration_invalid", "The IPC peer allowlist must contain numeric UIDs.")
    if len(set(value)) != len(value) or len(value) > 64:
        raise BridgeError("configuration_invalid", "The IPC peer allowlist is invalid.")
    return frozenset(value)


def _credential_ref(value: Any, field: str, *, optional: bool = False) -> str | None:
    if value in (None, "") and optional:
        return None
    if not isinstance(value, str) or not CREDENTIAL_REF_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", f"{field} is invalid.")
    return value


def _credential_hash(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", "credentials.webhook_sha256 is invalid.")
    return value


def _route_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str) or not UUID7_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", f"{field} must be a canonical UUIDv7.")
    return value


def _route_policy_fingerprint(value: Any) -> str:
    if not isinstance(value, str) or not ROUTE_POLICY_FINGERPRINT_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", "route.route_policy_fingerprint is invalid.")
    return value


def parse_isolated_route_identity(
    value: Any,
    *,
    isolated_instance_id: str,
) -> tuple[str, str, str, str]:
    """Validate immutable registry identity copied into one Isolated instance."""
    if not isinstance(value, dict) or set(value) != ROUTE_FIELDS:
        raise BridgeError("configuration_invalid", "The Route identity has missing or unsupported fields.")
    route_id = _route_uuid(value.get("route_id"), "route.route_id")
    connection_id = _route_uuid(value.get("connection_id"), "route.connection_id")
    workspace_key = _route_uuid(value.get("workspace_key"), "route.workspace_key")
    route_policy_fingerprint = _route_policy_fingerprint(value.get("route_policy_fingerprint"))
    expected_instance = "r-" + route_id.replace("-", "")
    if isolated_instance_id != expected_instance:
        raise BridgeError("configuration_invalid", "The Isolated instance does not match route.route_id.")
    return route_id, connection_id, workspace_key, route_policy_fingerprint


def _parse_config(raw: dict[str, Any]) -> BridgeConfig:
    if set(raw) != TOP_LEVEL_FIELDS or raw.get("default_deny") is not True:
        raise BridgeError("configuration_invalid", "Isolated configuration requires default_deny=true.")
    ipc = raw["ipc"]
    route = raw["route"]
    credentials = raw["credentials"]
    connection_raw = raw["connection"]
    if not isinstance(ipc, dict) or set(ipc) != IPC_FIELDS:
        raise BridgeError("configuration_invalid", "The IPC policy has missing or unsupported fields.")
    if not isinstance(credentials, dict) or set(credentials) != CREDENTIAL_FIELDS:
        raise BridgeError("configuration_invalid", "The credential policy has missing or unsupported fields.")
    if not isinstance(connection_raw, dict):
        raise BridgeError("configuration_invalid", "The connection policy is invalid.")
    connection_map = dict(connection_raw)
    connection_map["security_mode"] = "isolated"
    connection = connection_from_mapping(connection_map)
    if not connection.isolated_instance_id:
        raise BridgeError("configuration_invalid", "The Isolated connection requires isolated_instance_id.")
    route_id, connection_id, workspace_key, route_policy_fingerprint = parse_isolated_route_identity(
        route,
        isolated_instance_id=connection.isolated_instance_id,
    )
    if not connection.hmac_enabled:
        raise BridgeError("configuration_invalid", "HMAC is mandatory for Isolated connections.")
    refs = IsolatedCredentials(
        webhook_url_ref=_credential_ref(credentials.get("webhook_url_ref"), "credentials.webhook_url_ref") or "",
        webhook_sha256=_credential_hash(credentials.get("webhook_sha256")),
        hmac_signing_secret_ref=_credential_ref(
            credentials.get("hmac_signing_secret_ref"), "credentials.hmac_signing_secret_ref", optional=True
        ),
        multica_pat_ref=_credential_ref(
            credentials.get("multica_pat_ref"), "credentials.multica_pat_ref", optional=True
        ),
    )
    if connection.enabled and not refs.hmac_signing_secret_ref:
        raise BridgeError("configuration_invalid", "An enabled Isolated connection requires an HMAC credential reference.")
    if connection.enabled and not refs.webhook_sha256:
        raise BridgeError("configuration_invalid", "An enabled Isolated connection requires a webhook fingerprint.")
    if connection.result_tracking_enabled and not refs.multica_pat_ref:
        raise BridgeError("configuration_invalid", "Result tracking requires a Multica PAT credential reference.")
    return BridgeConfig(
        allowed_peer_uids=_parse_peer_uids(ipc.get("allowed_peer_uids")),
        trusted_gateway_unit=validate_systemd_unit(ipc.get("trusted_gateway_unit")),
        route_id=route_id,
        connection_id=connection_id,
        workspace_key=workspace_key,
        route_policy_fingerprint=route_policy_fingerprint,
        connection=connection,
        credentials=refs,
    )


def bridge_config_from_mapping(value: Any) -> BridgeConfig:
    """Validate a complete in-memory Isolated configuration before persistence."""
    if not isinstance(value, dict):
        raise BridgeError("configuration_invalid", "The bridge configuration root must be a mapping.")
    return _parse_config(value)


def load_config(
    path: str | Path,
    *,
    expected_owner_uid: int | None = 0,
) -> BridgeConfig:
    raw = _read_config(Path(path), expected_owner_uid=expected_owner_uid)
    return bridge_config_from_mapping(raw)


def read_credential(
    credential_dir: str | Path,
    credential_ref: str,
    *,
    max_bytes: int = 4096,
    ascii_only: bool = False,
    preserve_whitespace: bool = False,
) -> str:
    """Read one systemd credential by an allowlisted basename without logging its value."""
    ref = _credential_ref(credential_ref, "credential_ref")
    if ref is None:
        raise BridgeError("credential_unavailable", "The configured credential is unavailable.")
    directory = Path(credential_dir)
    path = directory / ref
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            os.close(fd)
            raise BridgeError("credential_invalid", "A configured credential is invalid.")
        with os.fdopen(fd, "rb") as stream:
            raw_value = stream.read(max_bytes + 1)
        if len(raw_value) > max_bytes:
            raise BridgeError("credential_invalid", "A configured credential is invalid.")
        decoded = raw_value.decode("ascii" if ascii_only else "utf-8")
        value = decoded if preserve_whitespace else decoded.strip()
        if not value:
            raise BridgeError("credential_invalid", "A configured credential is empty.")
        return value
    except BridgeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise BridgeError("credential_invalid", "A configured credential is invalid.") from exc
