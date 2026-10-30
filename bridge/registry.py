"""Validated non-secret ConnectionRegistry for one Hermes profile."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .configuration import (
    DEFAULT_EVENT,
    ConnectionConfig,
    StandardSecrets,
    normalize_multica_origin,
)
from .errors import BridgeError
from .identifiers import uuid7

MAX_REGISTRY_BYTES = 131_072
PLUGIN_ID = "hermes-multica-bridge"
UUID7_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CHAT_ID_RE = re.compile(r"\A-?[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
BOARD_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
PROFILE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TASK_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
PLATFORM_RE = re.compile(r"\A(?:max|telegram)\Z")
MIME_RE = re.compile(r"\A[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}\Z")
EXTENSION_RE = re.compile(r"\A\.[a-z0-9]{1,12}\Z")

REGISTRY_FIELDS = frozenset({"connections", "workspaces", "routes", "operator_grants"})
CONNECTION_FIELDS = frozenset(
    {
        "connection_id",
        "name",
        "multica_origin",
        "security_mode",
        "enabled",
        "request_timeout_seconds",
        "max_response_bytes",
        "max_payload_bytes",
        "max_requests_per_window",
        "window_seconds",
        "max_attempts_per_request",
        "hmac_enabled",
    }
)
WORKSPACE_FIELDS = frozenset({"workspace_key", "connection_id", "name", "workspace_id"})
ROUTE_FIELDS = frozenset(
    {
        "route_id",
        "connection_id",
        "workspace_key",
        "name",
        "route_type",
        "project_id",
        "autopilot_id",
        "trigger_id",
        "event",
        "enabled",
        "tombstoned",
        "destination_locked",
        "source_boards",
        "allowed_profiles",
        "allowed_assignees",
        "operator_grant_required",
        "result_tracking_enabled",
        "source_platforms",
        "allowed_user_ids",
        "allowed_chat_ids",
        "allow_groups",
        "allowed_statuses",
        "require_source_attachment",
        "max_attachments",
        "max_attachment_bytes",
        "allowed_mime_types",
        "allowed_extensions",
        "watcher_enabled",
    }
)
GRANT_FIELDS = frozenset({"board", "task_id", "route_id"})


def _fail(message: str) -> BridgeError:
    return BridgeError("configuration_invalid", message)


def _reject_unknown_fields(
    row: Mapping[str, Any], allowed: frozenset[str], field: str
) -> None:
    if set(row) - allowed:
        raise _fail(f"{field} contains unsupported fields.")


def _uuid7(value: Any, field: str) -> str:
    if not isinstance(value, str) or not UUID7_RE.fullmatch(value):
        raise _fail(f"{field} must be a canonical UUIDv7.")
    return value


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 160:
        raise _fail(f"{field} is invalid.")
    return value.strip()


def _identifier(value: Any, field: str, *, required: bool = True) -> str:
    if value in (None, "") and not required:
        return ""
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise _fail(f"{field} is invalid.")
    return value


def _string_list(
    value: Any, field: str, pattern: re.Pattern[str], *, maximum: int = 64
) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list) or len(value) > maximum:
        raise _fail(f"{field} must be a bounded list.")
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        raise _fail(f"{field} contains an invalid value.")
    if len(set(value)) != len(value):
        raise _fail(f"{field} contains duplicates.")
    return tuple(value)


def _bounded_int(value: Any, field: str, default: int, low: int, high: int) -> int:
    if value is None:
        return default
    if type(value) is not int or not low <= value <= high:
        raise _fail(f"{field} must be between {low} and {high}.")
    return value


@dataclass(frozen=True)
class RegistryConnection:
    connection_id: str
    name: str
    multica_origin: str
    security_mode: str
    enabled: bool
    request_timeout_seconds: int = 10
    max_response_bytes: int = 16_384
    max_payload_bytes: int = 65_536
    max_requests_per_window: int = 5
    window_seconds: int = 600
    max_attempts_per_request: int = 2
    hmac_enabled: bool = True


@dataclass(frozen=True)
class RegistryWorkspace:
    workspace_key: str
    connection_id: str
    name: str
    workspace_id: str


@dataclass(frozen=True)
class RegistryRoute:
    route_id: str
    connection_id: str
    workspace_key: str
    name: str
    route_type: str
    project_id: str
    autopilot_id: str
    trigger_id: str
    event: str
    enabled: bool
    tombstoned: bool
    destination_locked: bool
    source_boards: tuple[str, ...]
    allowed_profiles: tuple[str, ...]
    allowed_assignees: tuple[str, ...]
    operator_grant_required: bool
    result_tracking_enabled: bool
    source_platforms: tuple[str, ...]
    allowed_user_ids: tuple[str, ...]
    allowed_chat_ids: tuple[str, ...]
    allow_groups: bool
    allowed_statuses: tuple[str, ...]
    require_source_attachment: bool
    max_attachments: int
    max_attachment_bytes: int
    allowed_mime_types: tuple[str, ...]
    allowed_extensions: tuple[str, ...]
    watcher_enabled: bool

    @property
    def isolated_instance_id(self) -> str:
        return "r-" + self.route_id.replace("-", "")


@dataclass(frozen=True)
class OperatorGrant:
    board: str
    task_id: str
    route_id: str


@dataclass(frozen=True)
class TrustedRouteContext:
    board: str
    task_id: str
    run_id: str
    profile: str
    assignee: str
    state: str


@dataclass(frozen=True)
class ConnectionRegistry:
    connections: tuple[RegistryConnection, ...]
    workspaces: tuple[RegistryWorkspace, ...]
    routes: tuple[RegistryRoute, ...]
    operator_grants: tuple[OperatorGrant, ...]

    def connection(self, connection_id: str) -> RegistryConnection:
        for item in self.connections:
            if item.connection_id == connection_id:
                return item
        raise BridgeError(
            "route_denied", "The selected Multica route has no valid connection."
        )

    def workspace(self, workspace_key: str) -> RegistryWorkspace:
        for item in self.workspaces:
            if item.workspace_key == workspace_key:
                return item
        raise BridgeError(
            "route_denied", "The selected Multica route has no valid workspace."
        )

    def route(self, route_id: str) -> RegistryRoute:
        for item in self.routes:
            if item.route_id == route_id:
                return item
        raise BridgeError(
            "route_denied", "The selected Multica route is not configured."
        )

    def route_config(self, route: RegistryRoute) -> ConnectionConfig:
        connection = self.connection(route.connection_id)
        workspace = self.workspace(route.workspace_key)
        return ConnectionConfig(
            security_mode=connection.security_mode,
            enabled=connection.enabled and route.enabled and not route.tombstoned,
            multica_origin=connection.multica_origin,
            workspace_id=workspace.workspace_id,
            autopilot_id=route.autopilot_id,
            trigger_id=route.trigger_id,
            event=route.event,
            source_boards=route.source_boards,
            request_timeout_seconds=connection.request_timeout_seconds,
            max_response_bytes=connection.max_response_bytes,
            max_payload_bytes=connection.max_payload_bytes,
            max_requests_per_window=connection.max_requests_per_window,
            window_seconds=connection.window_seconds,
            max_attempts_per_request=connection.max_attempts_per_request,
            result_tracking_enabled=route.result_tracking_enabled,
            hmac_enabled=connection.hmac_enabled,
            isolated_instance_id=route.isolated_instance_id
            if connection.security_mode == "isolated"
            else "",
        )

    def _grant_ok(self, route: RegistryRoute, context: TrustedRouteContext) -> bool:
        if not route.operator_grant_required:
            return True
        return any(
            grant.board == context.board
            and grant.task_id == context.task_id
            and grant.route_id == route.route_id
            for grant in self.operator_grants
        )

    def authorized_routes(
        self,
        context: TrustedRouteContext,
        *,
        include_disabled: bool = False,
    ) -> tuple[RegistryRoute, ...]:
        allowed: list[RegistryRoute] = []
        for route in self.routes:
            connection = self.connection(route.connection_id)
            if not route.destination_locked:
                continue
            if not include_disabled and (
                not route.enabled or route.tombstoned or not connection.enabled
            ):
                continue
            if context.state != "running":
                continue
            if context.board not in route.source_boards:
                continue
            if route.allowed_profiles and context.profile not in route.allowed_profiles:
                continue
            if (
                route.allowed_assignees
                and context.assignee not in route.allowed_assignees
            ):
                continue
            if not self._grant_ok(route, context):
                continue
            allowed.append(route)
        return tuple(allowed)

    def authorized_workspace_routes(self, context: Any) -> tuple[RegistryRoute, ...]:
        """Authorize workspace routes using only Hermes supplied message source facts."""
        if not isinstance(context, Mapping):
            return ()
        platform = context.get("platform")
        user_id = context.get("user_id")
        chat_id = context.get("chat_id")
        chat_type = context.get("chat_type")
        if not all(isinstance(value, str) and value for value in (platform, user_id, chat_id)):
            return ()
        if platform not in {"max", "telegram"}:
            return ()
        # A thread may belong to a group; treat it as group-origin unless the
        # exact user and chat are explicitly allowed and group access enabled.
        is_group = chat_type in {"group", "channel", "thread"}
        allowed: list[RegistryRoute] = []
        for route in self.routes:
            if route.route_type != "workspace" or not route.enabled or route.tombstoned:
                continue
            connection = self.connection(route.connection_id)
            workspace = self.workspace(route.workspace_key)
            if not connection.enabled or not workspace.workspace_id or not route.project_id:
                continue
            if platform not in route.source_platforms:
                continue
            if user_id not in route.allowed_user_ids or chat_id not in route.allowed_chat_ids:
                continue
            if is_group and not route.allow_groups:
                continue
            allowed.append(route)
        return tuple(allowed)


def route_policy_fingerprint(registry: ConnectionRegistry, route: RegistryRoute) -> str:
    cfg = registry.route_config(route)
    payload = {
        "route_id": route.route_id,
        "connection_id": route.connection_id,
        "workspace_key": route.workspace_key,
        "policy": cfg.policy_fingerprint,
        "profiles": list(route.allowed_profiles),
        "assignees": list(route.allowed_assignees),
        "grant_required": route.operator_grant_required,
        "route_type": route.route_type,
        "project_id": route.project_id,
        "source_platforms": list(route.source_platforms),
        "allowed_user_ids": list(route.allowed_user_ids),
        "allowed_chat_ids": list(route.allowed_chat_ids),
        "allow_groups": route.allow_groups,
        "allowed_statuses": list(route.allowed_statuses),
        "require_source_attachment": route.require_source_attachment,
        "max_attachments": route.max_attachments,
        "max_attachment_bytes": route.max_attachment_bytes,
        "allowed_mime_types": list(route.allowed_mime_types),
        "allowed_extensions": list(route.allowed_extensions),
        "watcher_enabled": route.watcher_enabled,
    }
    return (
        "route-policy-"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )


def route_secret_env_name(route_id: str, credential_type: str) -> str:
    """Mirror Hermes' public plugin credential resolver for runtime reads."""
    _uuid7(route_id, "route_id")
    if credential_type not in {"webhook", "hmac", "pat"}:
        raise _fail("Unsupported route credential type.")
    digest = (
        hashlib.sha256(f"{PLUGIN_ID}\0{route_id}\0{credential_type}".encode())
        .hexdigest()[:32]
        .upper()
    )
    return f"HERMES_PLUGIN_CRED_{digest}_{credential_type.upper()}"


def standard_route_secrets(
    route: RegistryRoute,
    *,
    get_secret: Any | None = None,
    require_webhook: bool = True,
) -> StandardSecrets:
    """Read only this Route's Standard credentials from the active profile scope."""
    if get_secret is None:
        try:
            from agent.secret_scope import get_secret as scoped_get_secret
        except ImportError as exc:  # pragma: no cover - Hermes supplies this at runtime
            raise BridgeError(
                "credential_unavailable", "Hermes secret scope is unavailable."
            ) from exc
        get_secret = scoped_get_secret

    def read_dynamic(kind: str, *, preserve_whitespace: bool = False) -> str:
        value = get_secret(route_secret_env_name(route.route_id, kind), "")
        if not isinstance(value, str):
            return ""
        return value if preserve_whitespace else value.strip()

    webhook = read_dynamic("webhook")
    hmac = read_dynamic("hmac", preserve_whitespace=True)
    pat = read_dynamic("pat")
    if require_webhook and not webhook:
        raise BridgeError(
            "credential_unavailable",
            "The selected Multica Route has no webhook credential.",
        )
    return StandardSecrets(
        webhook_url=webhook,
        hmac_signing_secret=hmac or None,
        multica_pat=pat or None,
    )


def new_id() -> str:
    return uuid7()


def _parse_connection(row: Any) -> RegistryConnection:
    if not isinstance(row, Mapping):
        raise _fail("registry.connections contains a non-object value.")
    _reject_unknown_fields(row, CONNECTION_FIELDS, "registry.connections item")
    mode = row.get("security_mode", "standard")
    if not isinstance(mode, str) or mode not in {"standard", "isolated"}:
        raise _fail("connection.security_mode must be standard or isolated.")
    if (
        type(row.get("enabled", False)) is not bool
        or type(row.get("hmac_enabled", True)) is not bool
    ):
        raise _fail("connection booleans are invalid.")
    return RegistryConnection(
        connection_id=_uuid7(row.get("connection_id"), "connection_id"),
        name=_name(row.get("name"), "connection.name"),
        multica_origin=normalize_multica_origin(row.get("multica_origin", "")),
        security_mode=mode,
        enabled=row.get("enabled", False),
        request_timeout_seconds=_bounded_int(
            row.get("request_timeout_seconds"), "request_timeout_seconds", 10, 1, 30
        ),
        max_response_bytes=_bounded_int(
            row.get("max_response_bytes"), "max_response_bytes", 16_384, 1024, 65_536
        ),
        max_payload_bytes=_bounded_int(
            row.get("max_payload_bytes"), "max_payload_bytes", 65_536, 4096, 131_072
        ),
        max_requests_per_window=_bounded_int(
            row.get("max_requests_per_window"), "max_requests_per_window", 5, 1, 60
        ),
        window_seconds=_bounded_int(
            row.get("window_seconds"), "window_seconds", 600, 60, 3600
        ),
        max_attempts_per_request=_bounded_int(
            row.get("max_attempts_per_request"), "max_attempts_per_request", 2, 1, 5
        ),
        hmac_enabled=row.get("hmac_enabled", True),
    )


def _parse_workspace(row: Any) -> RegistryWorkspace:
    if not isinstance(row, Mapping):
        raise _fail("registry.workspaces contains a non-object value.")
    _reject_unknown_fields(row, WORKSPACE_FIELDS, "registry.workspaces item")
    return RegistryWorkspace(
        workspace_key=_uuid7(row.get("workspace_key"), "workspace_key"),
        connection_id=_uuid7(row.get("connection_id"), "workspace.connection_id"),
        name=_name(row.get("name"), "workspace.name"),
        workspace_id=_identifier(
            row.get("workspace_id"), "workspace.workspace_id", required=False
        ),
    )


def _parse_route(row: Any) -> RegistryRoute:
    if not isinstance(row, Mapping):
        raise _fail("registry.routes contains a non-object value.")
    _reject_unknown_fields(row, ROUTE_FIELDS, "registry.routes item")
    bool_fields = (
        "enabled",
        "tombstoned",
        "destination_locked",
        "operator_grant_required",
        "result_tracking_enabled",
        "allow_groups",
        "require_source_attachment",
        "watcher_enabled",
    )
    for field in bool_fields:
        if field in row and type(row[field]) is not bool:
            raise _fail(f"route.{field} must be a boolean.")
    event = row.get("event", DEFAULT_EVENT)
    route_type = row.get("route_type")
    if not isinstance(route_type, str) or route_type not in {"autopilot", "workspace"}:
        raise _fail("route.route_type must be autopilot or workspace.")
    project_id = _identifier(row.get("project_id"), "route.project_id", required=False)
    source_platforms = _string_list(
        row.get("source_platforms"), "route.source_platforms", PLATFORM_RE, maximum=2
    )
    allowed_user_ids = _string_list(
        row.get("allowed_user_ids"), "route.allowed_user_ids", IDENTIFIER_RE, maximum=256
    )
    allowed_chat_ids = _string_list(
        row.get("allowed_chat_ids"), "route.allowed_chat_ids", CHAT_ID_RE, maximum=256
    )
    allowed_statuses = _string_list(
        row.get("allowed_statuses"), "route.allowed_statuses", IDENTIFIER_RE, maximum=64
    )
    allowed_mime_types = _string_list(
        row.get("allowed_mime_types"), "route.allowed_mime_types", MIME_RE, maximum=64
    )
    allowed_extensions = _string_list(
        row.get("allowed_extensions"), "route.allowed_extensions", EXTENSION_RE, maximum=64
    )
    max_attachments = _bounded_int(row.get("max_attachments"), "route.max_attachments", 0, 0, 16)
    max_attachment_bytes = _bounded_int(
        row.get("max_attachment_bytes"), "route.max_attachment_bytes", 0, 0, 10_485_760
    )
    if route_type == "autopilot" and any((project_id, source_platforms, allowed_user_ids,
                                         allowed_chat_ids, allowed_statuses, row.get("watcher_enabled", False))):
        raise _fail("Autopilot routes cannot contain workspace routing policy.")
    if route_type == "workspace" and any((row.get("autopilot_id"), row.get("trigger_id"),
                                           row.get("source_boards"), row.get("operator_grant_required", False),
                                           row.get("result_tracking_enabled", False))):
        raise _fail("Workspace routes cannot contain Autopilot routing policy.")
    if route_type == "workspace" and row.get("enabled", False) and (
        not project_id or not source_platforms or not allowed_user_ids or not allowed_chat_ids
        or not allowed_statuses or not allowed_mime_types or not allowed_extensions
        or not 1 <= max_attachments <= 16 or not 1 <= max_attachment_bytes <= 10_485_760
    ):
        raise _fail("An enabled workspace route requires project, source, status, and attachment policy.")
    return RegistryRoute(
        route_id=_uuid7(row.get("route_id"), "route_id"),
        connection_id=_uuid7(row.get("connection_id"), "route.connection_id"),
        workspace_key=_uuid7(row.get("workspace_key"), "route.workspace_key"),
        name=_name(row.get("name"), "route.name"),
        route_type=route_type,
        project_id=project_id,
        autopilot_id=_identifier(
            row.get("autopilot_id"), "route.autopilot_id", required=False
        ),
        trigger_id=_identifier(
            row.get("trigger_id"), "route.trigger_id", required=False
        ),
        event=_identifier(event, "route.event"),
        enabled=row.get("enabled", False),
        tombstoned=row.get("tombstoned", False),
        destination_locked=row.get("destination_locked", False),
        source_boards=_string_list(
            row.get("source_boards"), "route.source_boards", BOARD_RE, maximum=32
        ),
        allowed_profiles=_string_list(
            row.get("allowed_profiles"), "route.allowed_profiles", PROFILE_RE
        ),
        allowed_assignees=_string_list(
            row.get("allowed_assignees"), "route.allowed_assignees", PROFILE_RE
        ),
        operator_grant_required=row.get("operator_grant_required", False),
        result_tracking_enabled=row.get("result_tracking_enabled", False),
        source_platforms=source_platforms,
        allowed_user_ids=allowed_user_ids,
        allowed_chat_ids=allowed_chat_ids,
        allow_groups=row.get("allow_groups", False),
        allowed_statuses=allowed_statuses,
        require_source_attachment=row.get("require_source_attachment", False),
        max_attachments=max_attachments,
        max_attachment_bytes=max_attachment_bytes,
        allowed_mime_types=allowed_mime_types,
        allowed_extensions=allowed_extensions,
        watcher_enabled=row.get("watcher_enabled", False),
    )


def _parse_grant(row: Any) -> OperatorGrant:
    if not isinstance(row, Mapping):
        raise _fail("registry.operator_grants contains a non-object value.")
    _reject_unknown_fields(row, GRANT_FIELDS, "registry.operator_grants item")
    return OperatorGrant(
        board=_identifier(row.get("board"), "grant.board"),
        task_id=_identifier(row.get("task_id"), "grant.task_id"),
        route_id=_uuid7(row.get("route_id"), "grant.route_id"),
    )


def registry_from_mapping(value: Any) -> ConnectionRegistry:
    if not isinstance(value, Mapping):
        raise _fail("ConnectionRegistry must be an object.")
    _reject_unknown_fields(value, REGISTRY_FIELDS, "ConnectionRegistry")
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _fail("ConnectionRegistry is not serializable.") from exc
    if len(encoded) > MAX_REGISTRY_BYTES:
        raise _fail("ConnectionRegistry exceeds the safe serialized size limit.")
    connections = tuple(_parse_connection(row) for row in value.get("connections", ()))
    workspaces = tuple(_parse_workspace(row) for row in value.get("workspaces", ()))
    routes = tuple(_parse_route(row) for row in value.get("routes", ()))
    grants = tuple(_parse_grant(row) for row in value.get("operator_grants", ()))
    for label, identifiers in (
        ("connection_id", [item.connection_id for item in connections]),
        ("workspace_key", [item.workspace_key for item in workspaces]),
        ("route_id", [item.route_id for item in routes]),
    ):
        if len(identifiers) != len(set(identifiers)):
            raise _fail(f"ConnectionRegistry contains duplicate {label} values.")
    connection_ids = {item.connection_id for item in connections}
    workspace_by_key = {item.workspace_key: item for item in workspaces}
    route_ids = {item.route_id for item in routes}
    for workspace in workspaces:
        if workspace.connection_id not in connection_ids:
            raise _fail("A workspace references an unknown connection.")
    for route in routes:
        workspace = workspace_by_key.get(route.workspace_key)
        if route.connection_id not in connection_ids or workspace is None:
            raise _fail("A route references an unknown connection or workspace.")
        if workspace.connection_id != route.connection_id:
            raise _fail("A route workspace belongs to a different connection.")
        connection = next(
            item for item in connections if item.connection_id == route.connection_id
        )
        if route.enabled:
            incomplete = route.tombstoned or not connection.multica_origin or not workspace.workspace_id
            if route.route_type == "autopilot":
                incomplete = incomplete or not route.source_boards or not route.autopilot_id or not route.trigger_id
            else:
                incomplete = (
                    incomplete
                    or connection.security_mode != "standard"
                    or not route.project_id
                    or not route.source_platforms
                    or not route.watcher_enabled
                )
            if incomplete:
                raise _fail("An enabled route must have a complete active destination and source policy.")
    seen_grants: set[tuple[str, str, str]] = set()
    for grant in grants:
        key = (grant.board, grant.task_id, grant.route_id)
        if grant.route_id not in route_ids or key in seen_grants:
            raise _fail("An operator grant is invalid or duplicated.")
        seen_grants.add(key)
    return ConnectionRegistry(connections, workspaces, routes, grants)
