"""Profile-aware dashboard API for Hermes Multica Bridge ConnectionRegistry."""

from __future__ import annotations

import stat
import sys
import threading
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from bridge.errors import BridgeError
from bridge.protocol import BridgeIpcClient
from bridge.registry import (
    ConnectionRegistry,
    RegistryRoute,
    new_id,
    registry_from_mapping,
    route_policy_fingerprint,
    standard_route_secrets,
)
from bridge.state import DeliveryStore

PLUGIN_ID = "hermes-multica-bridge"
router = APIRouter()
_REGISTRY_UPDATE_LOCK = threading.Lock()


def _settings_module():
    # T38-DEBT-2: dashboard settings use private plugins_settings.
    # Dashboard routes have no PluginContext; migrate when Hermes exposes a public settings API here.
    try:
        from hermes_cli import plugins_settings
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Hermes plugin settings API is unavailable.") from exc
    return plugins_settings


def _storage_path() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Hermes plugin storage is unavailable.") from exc
    return plugin_data_dir(PLUGIN_ID) / "deliveries.sqlite3"


def _fields() -> list[dict[str, Any]]:
    return _settings_module().plugin_settings_fields(PLUGIN_ID, PLUGIN_ROOT)


def _declared_registry(fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    for field in fields:
        if field.get("key") == "registry" and field.get("type") != "secret":
            value = field.get("value", field.get("default"))
            return value if isinstance(value, dict) else None
    return None


def _effective_registry(fields: list[dict[str, Any]]) -> dict[str, Any]:
    raw = _declared_registry(fields)
    if isinstance(raw, dict):
        registry_from_mapping(raw)
        return raw
    empty = {
        "connections": [],
        "workspaces": [],
        "routes": [],
        "operator_grants": [],
    }
    registry_from_mapping(empty)
    return empty


def _socket_available(path: str) -> bool:
    try:
        info = Path(path).lstat()
    except OSError:
        return False
    return stat.S_ISSOCK(info.st_mode)


def _isolated_sender_status(
    connection,
    expected_route_policy_fingerprint: str,
) -> dict[str, Any]:
    """Probe one route-specific Isolated sender without contacting Multica."""
    try:
        socket_ready = _socket_available(connection.socket_path)
    except BridgeError:
        socket_ready = False
    result: dict[str, Any] = {"socket_available": socket_ready, "sender_ready": False, "error_code": None}
    if not socket_ready:
        result["error_code"] = "isolated_socket"
        return result
    try:
        response = BridgeIpcClient(
            connection.socket_path,
            timeout=min(float(connection.request_timeout_seconds), 5.0),
        ).readiness()
    except BridgeError as exc:
        result["error_code"] = exc.code
        return result
    if not response.get("ok") or response.get("ready") is not True:
        result["error_code"] = str(response.get("error_code") or "isolated_sender")
        return result
    if (
        response.get("policy_fingerprint") != connection.policy_fingerprint
        or response.get("route_policy_fingerprint") != expected_route_policy_fingerprint
    ):
        result["error_code"] = "isolated_policy"
        return result
    result["sender_ready"] = True
    return result


def _enable_readiness(
    connection,
    secrets: dict[str, bool],
    *,
    isolated_status: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return fail-closed readiness errors while ignoring disabled pre-activation state."""
    readiness = [
        error
        for error in connection.readiness_errors(
            secret_presence=secrets if connection.security_mode == "standard" else None
        )
        if error != "disabled"
    ]
    if connection.security_mode == "isolated":
        if not connection.hmac_enabled:
            readiness.append("hmac_enabled")
        if isolated_status is None:
            readiness.append("isolated_policy")
        elif not isolated_status["socket_available"]:
            readiness.append("isolated_socket")
        elif not isolated_status["sender_ready"]:
            readiness.append(str(isolated_status["error_code"] or "isolated_sender"))
    return tuple(dict.fromkeys(readiness))


def _route_secret_presence(route: RegistryRoute) -> dict[str, bool]:
    try:
        secrets = standard_route_secrets(route, require_webhook=False)
    except BridgeError:
        # Boolean presence flags only; this response never contains credential values.
        return {"webhook_url": False, "hmac_signing_secret": False, "multica_pat": False}  # nosec B105
    return {
        "webhook_url": bool(secrets.webhook_url),
        "hmac_signing_secret": bool(secrets.hmac_signing_secret),
        "multica_pat": bool(secrets.multica_pat),
    }


def _latest_delivery(route_id: str) -> dict[str, Any] | None:
    try:
        record = DeliveryStore(_storage_path()).latest_delivery(connection_key=route_id)
    except (BridgeError, HTTPException):
        return None
    if record is None:
        return None
    return {
        "request_id": record.request_id,
        "delivery_status": record.delivery_status,
        "execution_status": record.execution_status,
        "delivery_id": record.delivery_id,
        "run_id": record.run_id,
        "issue_id": record.target_issue_id,
        "task_id": record.target_task_id,
        "result_status": record.result_status,
    }


def _route_status(registry: ConnectionRegistry, route: RegistryRoute) -> dict[str, Any]:
    effective_config = registry.route_config(route)
    secrets: dict[str, bool] = {}
    isolated_status = None
    if route.route_type == "workspace":
        secrets = _route_secret_presence(route)
        readiness: list[str] = []
        workspace = registry.workspace(route.workspace_key)
        if not effective_config.enabled:
            readiness.append("connection_disabled")
        if not route.enabled:
            readiness.append("disabled")
        if route.tombstoned:
            readiness.append("tombstoned")
        if not effective_config.multica_origin:
            readiness.append("multica_origin")
        if not workspace.workspace_id:
            readiness.append("workspace_id")
        if not route.project_id:
            readiness.append("project_id")
        if not route.source_platforms or not route.allowed_user_ids or not route.allowed_chat_ids:
            readiness.append("source_policy")
        if not route.allowed_statuses:
            readiness.append("allowed_statuses")
        if not route.watcher_enabled:
            readiness.append("watcher_disabled")
        if not secrets["multica_pat"]:
            readiness.append("multica_pat")
        watcher_ready = False
        if route.watcher_enabled:
            try:
                from bridge.watcher_ipc import WatcherIpcClient
                watcher_ready = WatcherIpcClient().readiness().get("ready") is True
            except BridgeError:
                watcher_ready = False
            if not watcher_ready:
                readiness.append("watcher_unavailable")
        return {
            "route_id": route.route_id,
            "route_type": route.route_type,
            "purpose": "Workspace issue, comment, attachment and status exchange",
            "configured": not readiness,
            "enabled": effective_config.enabled,
            "tombstoned": route.tombstoned,
            "security_mode": effective_config.security_mode,
            "project_id": route.project_id,
            "watcher_ready": watcher_ready,
            "readiness_errors": readiness,
            "secrets": secrets,
            "isolated_socket_path": None,
            "isolated_socket_available": None,
            "isolated_sender_ready": None,
            "isolated_sender_error_code": None,
            "latest_delivery": None,
        }
    if effective_config.security_mode == "standard":
        secrets = _route_secret_presence(route)
    else:
        isolated_status = _isolated_sender_status(
            effective_config,
            route_policy_fingerprint(registry, route),
        )
    readiness = list(_enable_readiness(effective_config, secrets, isolated_status=isolated_status))
    return {
        "route_id": route.route_id,
        "route_type": route.route_type,
        "purpose": "Autopilot task dispatch and result tracking",
        "configured": not readiness,
        "enabled": effective_config.enabled,
        "tombstoned": route.tombstoned,
        "security_mode": effective_config.security_mode,
        "readiness_errors": readiness,
        "secrets": secrets,
        "isolated_socket_path": effective_config.socket_path if effective_config.security_mode == "isolated" else None,
        "isolated_socket_available": isolated_status["socket_available"] if isolated_status else None,
        "isolated_sender_ready": isolated_status["sender_ready"] if isolated_status else None,
        "isolated_sender_error_code": isolated_status["error_code"] if isolated_status else None,
        "latest_delivery": _latest_delivery(route.route_id) if effective_config.security_mode == "standard" else None,
    }


def _destination(registry: ConnectionRegistry, route: RegistryRoute) -> tuple[str, ...]:
    connection = registry.connection(route.connection_id)
    workspace = registry.workspace(route.workspace_key)
    return (
        route.connection_id,
        connection.multica_origin,
        connection.security_mode,
        route.workspace_key,
        workspace.workspace_id,
        route.autopilot_id,
        route.trigger_id,
        route.event,
        route.route_type,
        route.project_id,
    )


def _used_route_ids() -> frozenset[str]:
    return DeliveryStore(_storage_path()).route_ids_with_deliveries()


def _guard_registry_update(
    old: ConnectionRegistry,
    new: ConnectionRegistry,
    *,
    used_route_ids: frozenset[str] | None = None,
) -> frozenset[str]:
    old_routes = {route.route_id: route for route in old.routes}
    new_routes = {route.route_id: route for route in new.routes}
    used = _used_route_ids() if used_route_ids is None else used_route_ids
    reused_used_route_ids = (new_routes.keys() - old_routes.keys()) & used
    if reused_used_route_ids:
        raise BridgeError(
            "route_immutable",
            "A Route ID with delivery history cannot be reused after deletion; create a new Route instead.",
        )
    locked_route_ids = frozenset(
        route.route_id
        for route in old.routes
        if route.destination_locked or route.enabled or route.route_id in used
    )
    for route_id, old_route in old_routes.items():
        locked = route_id in locked_route_ids
        replacement = new_routes.get(route_id)
        if locked and replacement is None:
            raise BridgeError(
                "route_immutable",
                "An enabled or previously used Route must be retained and tombstoned instead of deleted.",
            )
        if replacement is None:
            continue
        if old_route.tombstoned and not replacement.tombstoned:
            raise BridgeError("route_immutable", "A tombstoned Route cannot be reactivated.")
        if locked and _destination(old, old_route) != _destination(new, replacement):
            raise BridgeError(
                "route_immutable",
                "The destination of an enabled or previously used Route is immutable; create a new Route instead.",
            )
    return locked_route_ids


@router.get("/status")
def status() -> dict[str, Any]:
    try:
        raw = _effective_registry(_fields())
        registry = registry_from_mapping(raw)
    except BridgeError as exc:
        return {"ok": False, "configured": False, "error_code": exc.code, "message": exc.message}
    routes = [_route_status(registry, route) for route in registry.routes]
    enabled_rows = [row for row in routes if row["enabled"]]
    return {
        "ok": True,
        "configured": bool(enabled_rows) and all(row["configured"] for row in enabled_rows),
        "registry": raw,
        "routes": routes,
        "counts": {
            "connections": len(registry.connections),
            "workspaces": len(registry.workspaces),
            "routes": len(registry.routes),
        },
    }


@router.get("/new-id")
def allocate_id() -> dict[str, str]:
    return {"id": new_id()}


@router.put("/registry")
def update_registry(payload: Annotated[dict[str, Any], Body(...)]) -> dict[str, Any]:
    raw = payload.get("registry") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="registry must be an object.")
    try:
        new_registry = registry_from_mapping(raw)
        # Keep read/guard/readiness/persist in one critical section. Hermes
        # serializes the config write itself, but without this wider lock two
        # concurrent requests could both validate against the same old
        # registry and let a stale save undo a tombstone or destination lock.
        with _REGISTRY_UPDATE_LOCK:
            current_raw = _effective_registry(_fields())
            old_registry = registry_from_mapping(current_raw)
            used_route_ids = _used_route_ids()
            locked_route_ids = _guard_registry_update(
                old_registry,
                new_registry,
                used_route_ids=used_route_ids,
            )

            normalized = dict(raw)
            normalized["routes"] = [dict(row) for row in raw.get("routes", [])]
            for row in normalized["routes"]:
                if row.get("route_id") in locked_route_ids or row.get("enabled"):
                    row["destination_locked"] = True
            new_registry = registry_from_mapping(normalized)

            for route in new_registry.routes:
                if not route.enabled or route.tombstoned:
                    continue
                connection = new_registry.route_config(route)
                secrets = _route_secret_presence(route) if connection.security_mode == "standard" else {}
                isolated_status = (
                    _isolated_sender_status(
                        connection,
                        route_policy_fingerprint(new_registry, route),
                    )
                    if connection.security_mode == "isolated"
                    else None
                )
                readiness = _enable_readiness(connection, secrets, isolated_status=isolated_status)
                if readiness:
                    raise BridgeError(
                        "configuration_incomplete",
                        "Route cannot be enabled until these checks pass: " + ", ".join(readiness) + ".",
                    )
            written = _settings_module().save_plugin_settings(
                PLUGIN_ID,
                PLUGIN_ROOT,
                {"registry": normalized},
            )
    except (BridgeError, ValueError, PermissionError) as exc:
        detail = exc.message if isinstance(exc, BridgeError) else str(exc)
        raise HTTPException(status_code=400, detail=detail) from exc
    return {"ok": True, "written": written, "registry": normalized}


@router.get("/isolated-instructions")
def isolated_instructions(route_id: str) -> dict[str, Any]:
    try:
        raw = _effective_registry(_fields())
        registry = registry_from_mapping(raw)
        route = registry.route(route_id)
        connection = registry.route_config(route)
    except BridgeError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    if connection.security_mode != "isolated":
        raise HTTPException(status_code=400, detail="The selected Route is not in Isolated mode.")
    instance = connection.isolated_instance_id
    policy_fingerprint = route_policy_fingerprint(registry, route)
    return {
        "ok": True,
        "route_id": route.route_id,
        "instance_id": instance,
        "config_path": f"/etc/hermes-multica-bridge/{instance}.toml",
        "socket_path": connection.socket_path,
        "service_unit": f"hermes-multica-bridge@{instance}.service",
        "socket_unit": f"hermes-multica-bridge@{instance}.socket",
        "requires_root": True,
        "setup_command": (
            "python3 /opt/hermes-multica-bridge/deploy/configure_isolated_instance.py "
            f"--instance {instance} --route-id {route.route_id} "
            f"--connection-id {route.connection_id} --workspace-key {route.workspace_key} "
            f"--route-policy-fingerprint {policy_fingerprint} --event {connection.event} "
            f"--request-timeout-seconds {connection.request_timeout_seconds} "
            f"--max-response-bytes {connection.max_response_bytes} "
            f"--max-payload-bytes {connection.max_payload_bytes} "
            f"--max-requests-per-window {connection.max_requests_per_window} "
            f"--window-seconds {connection.window_seconds} "
            f"--max-attempts-per-request {connection.max_attempts_per_request}"
            + (" --result-tracking" if connection.result_tracking_enabled else "")
        ),
        "verify_command": (
            "python3 /opt/hermes-multica-bridge/deploy/status_isolated_instance.py "
            f"--instance {instance}"
        ),
        "systemd_status_command": (
            f"systemctl status hermes-multica-bridge@{instance}.socket "
            f"hermes-multica-bridge@{instance}.service"
        ),
    }
