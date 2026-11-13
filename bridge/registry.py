"""Validated non-secret ConnectionRegistry for one Hermes profile."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

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
UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CHAT_ID_RE = re.compile(r"\A-?[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
BOARD_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
PROFILE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TASK_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
PLATFORM_RE = re.compile(r"\A(?:max|telegram)\Z")
MIME_RE = re.compile(r"\A[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}\Z")
EXTENSION_RE = re.compile(r"\A\.[a-z0-9]{1,12}\Z")

REGISTRY_FIELDS = frozenset({"connections", "workspaces", "routes", "operator_grants", "route_grants"})
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
        "require_assignee",
        "default_assignee",
        "test",
        "scope_kind",
        "project_selection",
        "project_ids",
        "default_project_id",
        "squad_id",
        "allowed_thread_ids",
        "wake_mode",
        "credential_route_id",
        "dynamic_status",
        "grant_id",
        "created_by_profile",
    }
)
GRANT_FIELDS = frozenset({"board", "task_id", "route_id"})
ASSIGNEE_FIELDS = frozenset({"id", "type", "label"})
ASSIGNEE_TYPES = frozenset({"member", "agent", "squad"})
ROUTE_GRANT_FIELDS = frozenset({
    "grant_id", "profile", "connection_id", "workspace_key", "workspace_id",
    "allowed_project_ids", "allowed_squad_ids", "allow_all_projects",
    "allowed_source_platforms", "allowed_chat_ids", "allowed_thread_ids",
    "allowed_user_ids", "allowed_assignees", "credential_route_id", "max_routes",
    "auto_approve", "expires_at", "enabled",
})


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
class WorkspaceAssignee:
    id: str
    type: Literal["member", "agent", "squad"]
    label: str = ""


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
    # Autopilot keeps its string-valued Hermes worker allowlist. Workspace
    # assignment policy is represented separately as typed Multica identities.
    allowed_assignees: tuple[str, ...]
    workspace_assignees: tuple[WorkspaceAssignee, ...]
    default_assignee: WorkspaceAssignee | None
    require_assignee: bool
    test: bool
    config_warnings: tuple[str, ...]
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
    scope_kind: str = "project"
    project_selection: str = "allowlist"
    project_ids: tuple[str, ...] = ()
    default_project_id: str = ""
    squad_id: str = ""
    allowed_thread_ids: tuple[str, ...] = ()
    wake_mode: str = "legacy_watcher"
    credential_route_id: str = ""
    dynamic_status: str = ""
    grant_id: str = ""
    created_by_profile: str = ""

    @property
    def isolated_instance_id(self) -> str:
        return "r-" + self.route_id.replace("-", "")


@dataclass(frozen=True)
class OperatorGrant:
    board: str
    task_id: str
    route_id: str


@dataclass(frozen=True)
class RouteGrant:
    grant_id: str
    profile: str
    connection_id: str
    workspace_key: str
    workspace_id: str
    allowed_project_ids: tuple[str, ...]
    allowed_squad_ids: tuple[str, ...]
    allow_all_projects: bool
    allowed_source_platforms: tuple[str, ...]
    allowed_chat_ids: tuple[str, ...]
    allowed_thread_ids: tuple[str, ...]
    allowed_user_ids: tuple[str, ...]
    allowed_assignees: tuple[WorkspaceAssignee, ...]
    credential_route_id: str
    max_routes: int
    auto_approve: bool
    expires_at: str
    enabled: bool

    @property
    def active(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        return self.enabled and expiry.tzinfo is not None and expiry > datetime.now(UTC)


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
    route_grants: tuple[RouteGrant, ...] = ()

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

    def route_grant(self, grant_id: str) -> RouteGrant:
        for item in self.route_grants:
            if item.grant_id == grant_id:
                return item
        raise BridgeError("route_grant_denied", "The operator grant is unavailable.")

    def route_config(self, route: RegistryRoute) -> ConnectionConfig:
        connection = self.connection(route.connection_id)
        workspace = self.workspace(route.workspace_key)
        grant_active = (
            self.route_grant(route.grant_id).active if route.dynamic_status else True
        )
        return ConnectionConfig(
            security_mode=connection.security_mode,
            enabled=connection.enabled and route.enabled and not route.tombstoned and grant_active,
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

    def authorized_workspace_routes(
        self, context: Any, *, include_pending: bool = False
    ) -> tuple[RegistryRoute, ...]:
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
            route_visible_pending = include_pending and route.dynamic_status == "pending"
            if route.route_type != "workspace" or (not route.enabled and not route_visible_pending) or route.tombstoned:
                continue
            connection = self.connection(route.connection_id)
            workspace = self.workspace(route.workspace_key)
            if not connection.enabled or not workspace.workspace_id:
                continue
            if route.dynamic_status and route.dynamic_status != "active" and not route_visible_pending:
                continue
            if platform not in route.source_platforms:
                continue
            if user_id not in route.allowed_user_ids or chat_id not in route.allowed_chat_ids:
                continue
            if is_group and not route.allow_groups:
                continue
            thread_id = context.get("thread_id") or ""
            if route.allowed_thread_ids and thread_id not in route.allowed_thread_ids:
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
    if route.route_type == "workspace":
        payload.update(
            scope_kind=route.scope_kind,
            project_selection=route.project_selection,
            project_ids=list(route.project_ids),
            default_project_id=route.default_project_id,
            squad_id=route.squad_id,
            allowed_thread_ids=list(route.allowed_thread_ids),
            wake_mode=route.wake_mode,
            credential_route_id=route.credential_route_id,
            dynamic_status=route.dynamic_status,
            grant_id=route.grant_id,
            created_by_profile=route.created_by_profile,
            assignees=[
                {"id": item.id, "type": item.type, "label": item.label}
                for item in route.workspace_assignees
            ],
            default_assignee=(
                {"id": route.default_assignee.id, "type": route.default_assignee.type,
                 "label": route.default_assignee.label}
                if route.default_assignee is not None else None
            ),
            require_assignee=route.require_assignee,
            test=route.test,
        )
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
    credential_route_id: str | None = None,
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

    secret_route_id = credential_route_id or route.route_id

    def read_dynamic(kind: str, *, preserve_whitespace: bool = False) -> str:
        value = get_secret(route_secret_env_name(secret_route_id, kind), "")
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
        "require_assignee",
        "test",
    )
    for field in bool_fields:
        if field in row and type(row[field]) is not bool:
            raise _fail(f"route.{field} must be a boolean.")
    event = row.get("event", DEFAULT_EVENT)
    route_type = row.get("route_type")
    if not isinstance(route_type, str) or route_type not in {"autopilot", "workspace"}:
        raise _fail("route.route_type must be autopilot or workspace.")
    project_id = _identifier(row.get("project_id"), "route.project_id", required=False)
    scope_kind = row.get("scope_kind", "project")
    project_selection = row.get("project_selection", "allowlist")
    if not isinstance(scope_kind, str) or scope_kind not in {"project", "squad", "workspace"}:
        raise _fail("route.scope_kind must be project, squad, or workspace.")
    if not isinstance(project_selection, str) or project_selection not in {"allowlist", "all_workspace"}:
        raise _fail("route.project_selection must be allowlist or all_workspace.")
    project_ids = _string_list(
        row.get("project_ids"), "route.project_ids", IDENTIFIER_RE, maximum=256
    )
    default_project_id = _identifier(
        row.get("default_project_id", project_id),
        "route.default_project_id",
        required=False,
    )
    squad_id = _identifier(row.get("squad_id"), "route.squad_id", required=False)
    allowed_thread_ids = _string_list(
        row.get("allowed_thread_ids"), "route.allowed_thread_ids", IDENTIFIER_RE, maximum=256
    )
    wake_mode = row.get("wake_mode", "legacy_watcher")
    dynamic_status = row.get("dynamic_status", "")
    grant_id = row.get("grant_id", "")
    credential_route_id = row.get("credential_route_id", "")
    created_by_profile = row.get("created_by_profile", "")
    if not isinstance(wake_mode, str) or wake_mode not in {"completion", "legacy_watcher"}:
        raise _fail("route.wake_mode must be completion or legacy_watcher.")
    if row.get("watcher_enabled", False) and wake_mode == "completion":
        raise _fail("A completion route cannot enable the legacy watcher.")
    if not isinstance(dynamic_status, str) or dynamic_status not in {"", "pending", "active", "disabled", "revoked"}:
        raise _fail("route.dynamic_status is invalid.")
    if not all(isinstance(value, str) for value in (grant_id, credential_route_id, created_by_profile)):
        raise _fail("Dynamic route metadata must be strings.")
    if (dynamic_status and not (grant_id and credential_route_id and created_by_profile)) or (
        not dynamic_status and any((grant_id, credential_route_id, created_by_profile))
    ):
        raise _fail("Dynamic route metadata is incomplete.")
    if dynamic_status and (wake_mode != "completion" or row.get("watcher_enabled", False)):
        raise _fail("Dynamic routes must use completion wake without the legacy watcher.")
    for value, field_name in (
        (grant_id, "route.grant_id"),
        (credential_route_id, "route.credential_route_id"),
    ):
        if value:
            _uuid7(value, field_name)
    if created_by_profile and (not isinstance(created_by_profile, str) or not PROFILE_RE.fullmatch(created_by_profile)):
        raise _fail("route.created_by_profile is invalid.")
    if route_type == "workspace":
        if not default_project_id:
            default_project_id = project_ids[0] if len(project_ids) == 1 else ""
        if project_selection == "allowlist":
            if not project_ids and project_id:
                project_ids = (project_id,)
            if default_project_id and default_project_id not in project_ids:
                raise _fail("route.default_project_id must be in route.project_ids.")
        elif project_ids:
            raise _fail("all_workspace routes cannot carry a finite project_ids allowlist.")
        if scope_kind == "project" and (
            project_selection != "allowlist" or len(project_ids) != 1 or not default_project_id
        ):
            raise _fail("Project routes require exactly one allowlisted project.")
        if scope_kind == "squad" and not squad_id:
            raise _fail("Squad routes require squad_id.")
        if scope_kind == "squad" and project_selection == "all_workspace":
            raise _fail("Squad routes require an explicit project allowlist.")
        if scope_kind in {"squad", "workspace"} and project_selection == "allowlist" and not project_ids:
            raise _fail("Squad and workspace allowlist routes require project_ids.")
        if scope_kind in {"squad", "workspace"} and not default_project_id:
            raise _fail("Squad and workspace routes require default_project_id.")
        if scope_kind != "squad" and squad_id:
            raise _fail("Only squad routes may include squad_id.")
        if project_selection == "all_workspace" and (
            not dynamic_status or scope_kind != "workspace"
        ):
            raise _fail("all_workspace is available only to dynamic workspace routes.")
    else:
        if any((scope_kind != "project", project_selection != "allowlist", project_ids,
                default_project_id, squad_id, allowed_thread_ids, dynamic_status, grant_id,
                credential_route_id, created_by_profile)):
            raise _fail("Autopilot routes cannot contain Workspace scope policy.")
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
    config_warnings: list[str] = []
    raw_assignees = row.get("allowed_assignees")
    if route_type == "autopilot":
        allowed_assignees = _string_list(
            raw_assignees, "route.allowed_assignees", PROFILE_RE
        )
        workspace_assignees: tuple[WorkspaceAssignee, ...] = ()
        default_assignee = None
        if row.get("default_assignee") is not None:
            raise _fail("Autopilot routes cannot contain default_assignee.")
        if row.get("require_assignee", False):
            raise _fail("Autopilot routes cannot require a Workspace assignee.")
        if row.get("test", False):
            raise _fail("Autopilot routes cannot be marked as test routes.")
        require_assignee = False
    else:
        allowed_assignees = ()
        if raw_assignees in (None, ""):
            raw_assignees = []
        if not isinstance(raw_assignees, list) or len(raw_assignees) > 64:
            raise _fail("route.allowed_assignees must be a bounded list of assignees.")
        parsed_assignees: list[WorkspaceAssignee] = []
        for item in raw_assignees:
            if isinstance(item, str):
                config_warnings.append("legacy_assignee_entry")
                item = {"id": item, "type": "member"}
            parsed_assignees.append(_parse_workspace_assignee(item, "route.allowed_assignees item"))
        pairs = [(item.id, item.type) for item in parsed_assignees]
        if len(pairs) != len(set(pairs)):
            raise _fail("route.allowed_assignees contains duplicate id/type pairs.")
        workspace_assignees = tuple(parsed_assignees)
        require_assignee = row.get("require_assignee", True)
        default_assignee_raw = row.get("default_assignee")
        default_assignee = (
            _parse_workspace_assignee(default_assignee_raw, "route.default_assignee")
            if default_assignee_raw is not None else None
        )
        if default_assignee is not None:
            matched_default = next(
                (item for item in workspace_assignees
                 if (item.id, item.type) == (default_assignee.id, default_assignee.type)),
                None,
            )
            if matched_default is None:
                raise _fail("route.default_assignee must be present in route.allowed_assignees.")
            default_assignee = matched_default
    test_route = row.get("test", False)
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
        not default_project_id or not source_platforms or not allowed_user_ids or not allowed_chat_ids
        or not allowed_statuses or not allowed_mime_types or not allowed_extensions
        or not 1 <= max_attachments <= 16 or not 1 <= max_attachment_bytes <= 10_485_760
    ):
        raise _fail("An enabled workspace route requires project, source, status, and attachment policy.")
    if route_type == "workspace":
        project_id = default_project_id
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
        allowed_assignees=allowed_assignees,
        workspace_assignees=workspace_assignees,
        default_assignee=default_assignee,
        require_assignee=require_assignee,
        test=test_route,
        config_warnings=tuple(dict.fromkeys(config_warnings)),
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
        scope_kind=scope_kind,
        project_selection=project_selection,
        project_ids=project_ids,
        default_project_id=default_project_id,
        squad_id=squad_id,
        allowed_thread_ids=allowed_thread_ids,
        wake_mode=wake_mode,
        credential_route_id=credential_route_id,
        dynamic_status=dynamic_status,
        grant_id=grant_id,
        created_by_profile=created_by_profile,
    )


def _parse_workspace_assignee(value: Any, field: str) -> WorkspaceAssignee:
    if not isinstance(value, Mapping):
        raise _fail(f"{field} must be an assignee object.")
    _reject_unknown_fields(value, ASSIGNEE_FIELDS, field)
    assignee_id = value.get("id")
    assignee_type = value.get("type")
    label = value.get("label", "")
    if not isinstance(assignee_id, str) or not UUID_RE.fullmatch(assignee_id):
        raise _fail(f"{field}.id must be a canonical UUID.")
    if not isinstance(assignee_type, str) or assignee_type not in ASSIGNEE_TYPES:
        raise _fail(f"{field}.type must be member, agent, or squad.")
    if not isinstance(label, str) or len(label) > 128:
        raise _fail(f"{field}.label must be a string of at most 128 characters.")
    return WorkspaceAssignee(assignee_id, assignee_type, label.strip())


def _parse_grant(row: Any) -> OperatorGrant:
    if not isinstance(row, Mapping):
        raise _fail("registry.operator_grants contains a non-object value.")
    _reject_unknown_fields(row, GRANT_FIELDS, "registry.operator_grants item")
    return OperatorGrant(
        board=_identifier(row.get("board"), "grant.board"),
        task_id=_identifier(row.get("task_id"), "grant.task_id"),
        route_id=_uuid7(row.get("route_id"), "grant.route_id"),
    )


def _parse_route_grant(row: Any) -> RouteGrant:
    if not isinstance(row, Mapping):
        raise _fail("registry.route_grants contains a non-object value.")
    _reject_unknown_fields(row, ROUTE_GRANT_FIELDS, "registry.route_grants item")
    bool_fields = ("allow_all_projects", "auto_approve", "enabled")
    if any(type(row.get(key, False)) is not bool for key in bool_fields):
        raise _fail("route grant booleans are invalid.")
    profile = row.get("profile")
    if not isinstance(profile, str) or not PROFILE_RE.fullmatch(profile):
        raise _fail("route grant profile is invalid.")
    expires_at = row.get("expires_at")
    if not isinstance(expires_at, str) or len(expires_at) > 64:
        raise _fail("route grant expiry is invalid.")
    # Validate expiry shape here; active/expired is a runtime policy decision.
    try:
        parsed_expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        raise _fail("route grant expiry must be an ISO-8601 timestamp.") from None
    if parsed_expiry.tzinfo is None:
        raise _fail("route grant expiry must include a timezone.")
    raw_assignees = row.get("allowed_assignees", [])
    if not isinstance(raw_assignees, list) or len(raw_assignees) > 64:
        raise _fail("route_grant.allowed_assignees must be a bounded list.")
    assignees = tuple(
        _parse_workspace_assignee(item, "route_grant.allowed_assignees item")
        for item in raw_assignees
    )
    if len({(item.id, item.type) for item in assignees}) != len(assignees):
        raise _fail("route_grant.allowed_assignees contains duplicate identities.")
    return RouteGrant(
        grant_id=_uuid7(row.get("grant_id"), "route_grant.grant_id"),
        profile=profile,
        connection_id=_uuid7(row.get("connection_id"), "route_grant.connection_id"),
        workspace_key=_uuid7(row.get("workspace_key"), "route_grant.workspace_key"),
        workspace_id=_identifier(row.get("workspace_id"), "route_grant.workspace_id"),
        allowed_project_ids=_string_list(row.get("allowed_project_ids"), "route_grant.allowed_project_ids", IDENTIFIER_RE, maximum=256),
        allowed_squad_ids=_string_list(row.get("allowed_squad_ids"), "route_grant.allowed_squad_ids", UUID_RE, maximum=128),
        allow_all_projects=row.get("allow_all_projects", False),
        allowed_source_platforms=_string_list(row.get("allowed_source_platforms"), "route_grant.allowed_source_platforms", PLATFORM_RE, maximum=2),
        allowed_chat_ids=_string_list(row.get("allowed_chat_ids"), "route_grant.allowed_chat_ids", CHAT_ID_RE, maximum=256),
        allowed_thread_ids=_string_list(row.get("allowed_thread_ids"), "route_grant.allowed_thread_ids", IDENTIFIER_RE, maximum=256),
        allowed_user_ids=_string_list(row.get("allowed_user_ids"), "route_grant.allowed_user_ids", IDENTIFIER_RE, maximum=256),
        allowed_assignees=assignees,
        credential_route_id=_uuid7(row.get("credential_route_id"), "route_grant.credential_route_id"),
        max_routes=_bounded_int(row.get("max_routes"), "route_grant.max_routes", 1, 1, 1000),
        auto_approve=row.get("auto_approve", False),
        expires_at=expires_at,
        enabled=row.get("enabled", False),
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
    route_grants = tuple(_parse_route_grant(row) for row in value.get("route_grants", ()))
    for label, identifiers in (
        ("connection_id", [item.connection_id for item in connections]),
        ("workspace_key", [item.workspace_key for item in workspaces]),
        ("route_id", [item.route_id for item in routes]),
        ("route_grant_id", [item.grant_id for item in route_grants]),
    ):
        if len(identifiers) != len(set(identifiers)):
            raise _fail(f"ConnectionRegistry contains duplicate {label} values.")
    connection_ids = {item.connection_id for item in connections}
    workspace_by_key = {item.workspace_key: item for item in workspaces}
    route_ids = {item.route_id for item in routes}
    route_by_id = {item.route_id: item for item in routes}
    route_grant_ids = {item.grant_id for item in route_grants}
    if len(route_grant_ids) != len(route_grants):
        raise _fail("ConnectionRegistry contains duplicate route_grant_id values.")
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
                    or not route.source_platforms
                    or not route.default_project_id
                    or (route.wake_mode == "legacy_watcher" and not route.watcher_enabled)
                )
            if incomplete:
                raise _fail("An enabled route must have a complete active destination and source policy.")
    seen_grants: set[tuple[str, str, str]] = set()
    for grant in grants:
        key = (grant.board, grant.task_id, grant.route_id)
        if grant.route_id not in route_ids or key in seen_grants:
            raise _fail("An operator grant is invalid or duplicated.")
        seen_grants.add(key)
    for grant in route_grants:
        connection = next((item for item in connections if item.connection_id == grant.connection_id), None)
        workspace = workspace_by_key.get(grant.workspace_key)
        anchor = route_by_id.get(grant.credential_route_id)
        if (connection is None or workspace is None
                or workspace.connection_id != grant.connection_id
                or workspace.workspace_id != grant.workspace_id
                or anchor is None or anchor.route_type != "workspace"
                or anchor.connection_id != grant.connection_id
                or anchor.workspace_key != grant.workspace_key
                or anchor.dynamic_status):
            raise _fail("A route grant has an invalid connection, workspace, or static credential anchor.")
    grant_by_id = {item.grant_id: item for item in route_grants}
    for route in routes:
        if route.dynamic_status:
            grant = grant_by_id.get(route.grant_id)
            if grant is None:
                raise _fail("A dynamic route references an unknown operator grant.")
            if (route.connection_id != grant.connection_id or route.workspace_key != grant.workspace_key
                    or route.created_by_profile != grant.profile or route.credential_route_id != grant.credential_route_id):
                raise _fail("A dynamic route does not match its operator grant.")
            if route.project_selection == "all_workspace" and (route.dynamic_status not in {"pending", "active", "disabled", "revoked"} or not grant.allow_all_projects):
                raise _fail("all_workspace requires an explicit allow_all_projects grant.")
            if (not set(route.source_platforms) <= set(grant.allowed_source_platforms)
                    or not set(route.allowed_user_ids) <= set(grant.allowed_user_ids)
                    or not set(route.allowed_chat_ids) <= set(grant.allowed_chat_ids)
                    or grant.allowed_thread_ids and (
                        not route.allowed_thread_ids
                        or not set(route.allowed_thread_ids) <= set(grant.allowed_thread_ids)
                    )
                    or any((item.id, item.type) not in {(a.id, a.type) for a in grant.allowed_assignees}
                           for item in route.workspace_assignees)
                    or route.squad_id and route.squad_id not in grant.allowed_squad_ids):
                raise _fail("A dynamic route exceeds its operator grant.")
            if (route.project_selection == "allowlist" and not grant.allow_all_projects
                    and not set(route.project_ids) <= set(grant.allowed_project_ids)):
                raise _fail("A dynamic route exceeds its project grant.")
            if route.default_assignee is not None and (
                route.default_assignee.id, route.default_assignee.type
            ) not in {(item.id, item.type) for item in grant.allowed_assignees}:
                raise _fail("A dynamic route default assignee exceeds its operator grant.")
    return ConnectionRegistry(connections, workspaces, routes, grants, route_grants)
