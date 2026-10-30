"""Canonical connection configuration shared by Standard and Isolated modes."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .errors import BridgeError

DEFAULT_EVENT = "hermes.task.dispatched"
INSTANCE_SOCKET_ROOT = "/run/hermes-multica-bridge"
DEFAULT_MAX_PAYLOAD_BYTES = 65_536
CONNECTION_CONFIG_FIELDS = frozenset(
    {
        "security_mode",
        "enabled",
        "multica_origin",
        "workspace_id",
        "autopilot_id",
        "trigger_id",
        "event",
        "source_boards",
        "request_timeout_seconds",
        "max_response_bytes",
        "max_payload_bytes",
        "max_requests_per_window",
        "window_seconds",
        "max_attempts_per_request",
        "result_tracking_enabled",
        "hmac_enabled",
        "isolated_instance_id",
    }
)

IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
BOARD_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
INSTANCE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
SYSTEMD_UNIT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.@:-]{0,191}\.service\Z")

@dataclass(frozen=True)
class ConnectionConfig:
    """Validated non-secret settings for one Hermes profile's Multica connection."""

    security_mode: str = "standard"
    enabled: bool = False
    multica_origin: str = ""
    workspace_id: str = ""
    autopilot_id: str = ""
    trigger_id: str = ""
    event: str = DEFAULT_EVENT
    source_boards: tuple[str, ...] = ()
    request_timeout_seconds: int = 10
    max_response_bytes: int = 16_384
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    max_requests_per_window: int = 5
    window_seconds: int = 600
    max_attempts_per_request: int = 2
    result_tracking_enabled: bool = False
    hmac_enabled: bool = True
    isolated_instance_id: str = ""

    @property
    def connection_key(self) -> str:
        """Return a stable non-secret key used only for local ledger partitioning."""
        encoded = "\0".join(  # noqa: FLY002 - explicit separator keeps the hash input unambiguous
            (self.multica_origin, self.workspace_id, self.autopilot_id, self.trigger_id, self.event)
        ).encode("utf-8")
        return "conn-" + hashlib.sha256(encoded).hexdigest()[:24]

    @property
    def policy_fingerprint(self) -> str:
        """Hash non-secret routing/runtime policy for profile-to-sender readiness checks."""
        policy = {
            "security_mode": self.security_mode,
            "multica_origin": self.multica_origin,
            "workspace_id": self.workspace_id,
            "autopilot_id": self.autopilot_id,
            "trigger_id": self.trigger_id,
            "event": self.event,
            "source_boards": list(self.source_boards),
            "request_timeout_seconds": self.request_timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
            "max_payload_bytes": self.max_payload_bytes,
            "max_requests_per_window": self.max_requests_per_window,
            "window_seconds": self.window_seconds,
            "max_attempts_per_request": self.max_attempts_per_request,
            "result_tracking_enabled": self.result_tracking_enabled,
            "hmac_enabled": self.hmac_enabled,
            "isolated_instance_id": self.isolated_instance_id,
        }
        encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "policy-" + hashlib.sha256(encoded).hexdigest()

    @property
    def socket_path(self) -> str:
        if self.security_mode != "isolated":
            raise BridgeError("configuration_invalid", "A Unix socket is available only in Isolated mode.")
        if self.isolated_instance_id:
            return f"{INSTANCE_SOCKET_ROOT}/{self.isolated_instance_id}.sock"
        raise BridgeError("configuration_incomplete", "Isolated mode requires an instance identifier.")

    def readiness_errors(self, *, secret_presence: Mapping[str, bool] | None = None) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.enabled:
            errors.append("disabled")
        if not self.multica_origin:
            errors.append("multica_origin")
        if not self.workspace_id:
            errors.append("workspace_id")
        if not self.autopilot_id:
            errors.append("autopilot_id")
        if not self.trigger_id:
            errors.append("trigger_id")
        if not self.source_boards:
            errors.append("source_boards")
        if self.security_mode == "isolated":
            if not self.isolated_instance_id:
                errors.append("isolated_instance_id")
            if not self.hmac_enabled:
                errors.append("hmac_enabled")
        if secret_presence is not None and self.security_mode == "standard":
            if not secret_presence.get("webhook_url", False):
                errors.append("webhook_url")
            if self.hmac_enabled and not secret_presence.get("hmac_signing_secret", False):
                errors.append("hmac_signing_secret")
            if self.result_tracking_enabled and not secret_presence.get("multica_pat", False):
                errors.append("multica_pat")
        return tuple(errors)


@dataclass(frozen=True)
class StandardSecrets:
    webhook_url: str
    hmac_signing_secret: str | None
    multica_pat: str | None


def _bool(value: Any, field: str, default: bool) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise BridgeError("configuration_invalid", f"{field} must be a boolean.")
    return value


def _bounded_int(value: Any, field: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if type(value) is not int or not minimum <= value <= maximum:
        raise BridgeError(
            "configuration_invalid", f"{field} must be between {minimum} and {maximum}."
        )
    return value


def _identifier(value: Any, field: str, *, required: bool = False) -> str:
    if value in (None, "") and not required:
        return ""
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", f"{field} has an invalid format.")
    return value


def normalize_multica_origin(value: Any) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or len(value) > 512 or not value.isascii():
        raise BridgeError("configuration_invalid", "multica_origin is invalid.")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise BridgeError("configuration_invalid", "multica_origin is invalid.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise BridgeError("configuration_invalid", "multica_origin must be an HTTPS origin.")
    return f"https://{parsed.netloc.lower()}"


def _boards(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return ()
        if stripped.startswith("["):
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise BridgeError("configuration_invalid", "source_boards must be a list of board names.") from exc
        else:
            value = [item.strip() for item in stripped.split(",") if item.strip()]
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise BridgeError("configuration_invalid", "source_boards must contain between 1 and 32 boards.")
    if any(not isinstance(item, str) or not BOARD_RE.fullmatch(item) for item in value):
        raise BridgeError("configuration_invalid", "source_boards contains an invalid board name.")
    if len(set(value)) != len(value):
        raise BridgeError("configuration_invalid", "source_boards contains duplicates.")
    return tuple(value)


def connection_from_mapping(settings: Mapping[str, Any]) -> ConnectionConfig:
    """Validate profile settings or a trusted Isolated configuration mapping."""
    if set(settings) - CONNECTION_CONFIG_FIELDS:
        raise BridgeError("configuration_invalid", "connection contains unsupported fields.")
    mode = settings.get("security_mode", "standard")
    if not isinstance(mode, str) or mode not in {"standard", "isolated"}:
        raise BridgeError("configuration_invalid", "security_mode must be standard or isolated.")
    instance = settings.get("isolated_instance_id") or ""
    if instance and (not isinstance(instance, str) or not INSTANCE_ID_RE.fullmatch(instance)):
        raise BridgeError("configuration_invalid", "isolated_instance_id has an invalid format.")
    event = settings.get("event", DEFAULT_EVENT)
    if not isinstance(event, str) or not IDENTIFIER_RE.fullmatch(event):
        raise BridgeError("configuration_invalid", "event has an invalid format.")
    if mode != "isolated":
        instance = ""

    return ConnectionConfig(
        security_mode=mode,
        enabled=_bool(settings.get("enabled"), "enabled", False),
        multica_origin=normalize_multica_origin(settings.get("multica_origin", "")),
        workspace_id=_identifier(settings.get("workspace_id"), "workspace_id"),
        autopilot_id=_identifier(settings.get("autopilot_id"), "autopilot_id"),
        trigger_id=_identifier(settings.get("trigger_id"), "trigger_id"),
        event=event,
        source_boards=_boards(settings.get("source_boards")),
        request_timeout_seconds=_bounded_int(
            settings.get("request_timeout_seconds"), "request_timeout_seconds", 10, 1, 30
        ),
        max_response_bytes=_bounded_int(
            settings.get("max_response_bytes"), "max_response_bytes", 16_384, 1024, 65_536
        ),
        max_payload_bytes=_bounded_int(
            settings.get("max_payload_bytes"), "max_payload_bytes", DEFAULT_MAX_PAYLOAD_BYTES, 4096, 131_072
        ),
        max_requests_per_window=_bounded_int(
            settings.get("max_requests_per_window"), "max_requests_per_window", 5, 1, 60
        ),
        window_seconds=_bounded_int(settings.get("window_seconds"), "window_seconds", 600, 60, 3600),
        max_attempts_per_request=_bounded_int(
            settings.get("max_attempts_per_request"), "max_attempts_per_request", 2, 1, 5
        ),
        result_tracking_enabled=_bool(
            settings.get("result_tracking_enabled"), "result_tracking_enabled", False
        ),
        hmac_enabled=_bool(settings.get("hmac_enabled"), "hmac_enabled", True),
        isolated_instance_id=instance,
    )


def validate_systemd_unit(value: Any) -> str:
    if not isinstance(value, str) or not SYSTEMD_UNIT_RE.fullmatch(value):
        raise BridgeError("configuration_invalid", "The trusted Gateway systemd unit is invalid.")
    return value
