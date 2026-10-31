"""Hermes tools for sending the current Kanban task to Multica and reading its result."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .hermes import add_current_task_comment, read_current_task_with_context
from .protocol import BridgeIpcClient
from .registry import (
    ConnectionRegistry,
    RegistryRoute,
    registry_from_mapping,
    route_policy_fingerprint,
    standard_route_secrets,
)
from .service import BridgeService, ServiceCredentials
from .state import DeliverySnapshot, DeliveryStore
from .validation import request_fingerprint
from .workspace_tools import register_workspace_tools, trusted_source

PLUGIN_ID = "hermes-multica-bridge"
TOOLSET = "hermes_multica_bridge"

SEND_TOOL_SCHEMA = {
    "name": "multica_send_task",
    "description": (
        "Send the current pinned Hermes Kanban task through an authorized operator-configured Multica Route. "
        "The only optional argument is route_id. The bridge reads title/body from Hermes Kanban state and never accepts "
        "a model-supplied destination, URL, workspace, Autopilot, trigger, credential, or task body. "
        "An accepted delivery starts result tracking but does not prove that Multica completed the task."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "route_id": {
                "type": "string",
                "description": "Optional Route id returned by multica_list_routes when more than one Route is authorized.",
            }
        },
        "required": [],
        "additionalProperties": False,
    },
}

RESULT_TOOL_SCHEMA = {
    "name": "multica_check_task_result",
    "description": (
        "Read the Multica result for the current pinned Hermes Kanban task. The only optional argument is route_id. "
        "The bridge uses only the recorded run from the original delivery and writes each new "
        "result state back to this same Hermes task as a durable deduplicated comment."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "route_id": {
                "type": "string",
                "description": "Optional Route id when the task has deliveries to more than one Route.",
            }
        },
        "required": [],
        "additionalProperties": False,
    },
}

LIST_ROUTES_TOOL_SCHEMA = {
    "name": "multica_list_routes",
    "description": (
        "List only Multica Routes authorized for the current pinned Hermes Kanban worker. "
        "Takes no arguments and never returns credentials or destination secrets."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
}


def _profile_state_path() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
    except ImportError as exc:  # pragma: no cover - Hermes runtime supplies this helper
        raise BridgeError("hermes_unavailable", "Hermes plugin storage is unavailable.") from exc
    return plugin_data_dir(PLUGIN_ID) / "deliveries.sqlite3"


def _error_json(exc: BridgeError) -> str:
    result: dict[str, Any] = {"ok": False, "error_code": exc.code, "message": exc.message}
    if exc.retryable:
        result["retryable"] = True
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


def _json_result(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class PluginRuntime:
    """Profile-scoped runtime captured when Hermes loads this plugin."""

    def __init__(self, ctx: Any):
        self.ctx = ctx

    def _registry(self) -> ConnectionRegistry:
        raw = self.ctx.get_config("registry", None)
        if isinstance(raw, dict):
            return registry_from_mapping(raw)
        return registry_from_mapping(
            {
                "connections": [],
                "workspaces": [],
                "routes": [],
                "operator_grants": [],
            }
        )

    @staticmethod
    def _route_arg(args: dict[str, Any]) -> str | None:
        if not isinstance(args, dict) or set(args) - {"route_id"}:
            raise BridgeError("invalid_arguments", "Only the optional route_id argument is accepted.")
        route_id = args.get("route_id")
        if route_id is None:
            return None
        if not isinstance(route_id, str) or not route_id:
            raise BridgeError("invalid_arguments", "route_id must be a non-empty string.")
        return route_id

    @staticmethod
    def _select_route(
        registry: ConnectionRegistry,
        trusted: Any,
        requested: str | None,
        *,
        include_disabled: bool = False,
    ) -> RegistryRoute:
        allowed = registry.authorized_routes(trusted, include_disabled=include_disabled)
        if requested is not None:
            for route in allowed:
                if route.route_id == requested:
                    return route
            raise BridgeError("route_denied", "The requested Multica Route is not authorized for this worker.")
        if not allowed:
            raise BridgeError("route_denied", "No Multica Route is authorized for this worker.")
        if len(allowed) != 1:
            raise BridgeError("route_required", "More than one Multica Route is available; choose a route_id from multica_list_routes.")
        return allowed[0]

    @staticmethod
    def _snapshot(registry: ConnectionRegistry, route: RegistryRoute) -> DeliverySnapshot:
        connection = registry.connection(route.connection_id)
        workspace = registry.workspace(route.workspace_key)
        return DeliverySnapshot(
            route_id=route.route_id,
            connection_id=route.connection_id,
            workspace_key=route.workspace_key,
            workspace_id=workspace.workspace_id,
            multica_origin=connection.multica_origin,
            autopilot_id=route.autopilot_id,
            trigger_id=route.trigger_id,
            security_mode=connection.security_mode,
            route_policy_fingerprint=route_policy_fingerprint(registry, route),
        )

    def _standard_service(
        self,
        registry: ConnectionRegistry,
        route: RegistryRoute,
        *,
        require_webhook: bool,
    ) -> BridgeService:
        connection = registry.route_config(route)
        secrets = standard_route_secrets(route, require_webhook=require_webhook)
        store = DeliveryStore(_profile_state_path())
        return BridgeService(
            connection,
            ServiceCredentials(
                webhook_url=secrets.webhook_url,
                hmac_signing_secret=secrets.hmac_signing_secret,
                multica_pat=secrets.multica_pat,
            ),
            store,
            ledger_key=route.route_id,
            delivery_snapshot=self._snapshot(registry, route),
        )

    @staticmethod
    def _isolated_client(connection) -> BridgeIpcClient:
        return BridgeIpcClient(
            connection.socket_path,
            timeout=float(connection.request_timeout_seconds + 10),
        )

    def _send(self, registry: ConnectionRegistry, route: RegistryRoute, request: dict[str, Any]) -> dict[str, Any]:
        connection = registry.route_config(route)
        DeliveryStore(_profile_state_path()).reserve_connection_request(
            connection_id=route.connection_id,
            max_requests=connection.max_requests_per_window,
            window_seconds=connection.window_seconds,
        )
        if connection.security_mode == "standard":
            return self._standard_service(registry, route, require_webhook=True).send(request)
        return self._isolated_client(connection).send(request)

    def _check(
        self,
        registry: ConnectionRegistry,
        route: RegistryRoute,
        request: dict[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        connection = registry.route_config(route)
        if connection.security_mode == "standard":
            service = self._standard_service(registry, route, require_webhook=False)
            return service.check_result(request), service
        client = self._isolated_client(connection)
        return client.check_result(request), client

    def _delivered_routes(
        self,
        registry: ConnectionRegistry,
        allowed: list[RegistryRoute],
        request: dict[str, Any],
        trusted: Any,
    ) -> list[RegistryRoute]:
        recorded = set(
            DeliveryStore(_profile_state_path()).routes_for_task(
                source_board=trusted.board,
                source_task_id=trusted.task_id,
            )
        )
        for route in allowed:
            connection = registry.route_config(route)
            if connection.security_mode != "isolated":
                continue
            if not connection.enabled:
                continue
            response = self._isolated_client(connection).has_delivery(request)
            if response.get("ok") is not True:
                raise BridgeError(
                    str(response.get("error_code") or "bridge_unavailable"),
                    str(response.get("message") or "The trusted sender could not inspect delivery history."),
                    retryable=bool(response.get("retryable")),
                )
            if type(response.get("has_delivery")) is not bool:
                raise BridgeError("invalid_bridge_response", "The trusted sender returned invalid delivery history.")
            if response["has_delivery"]:
                recorded.add(route.route_id)
        return [route for route in allowed if route.route_id in recorded]

    @staticmethod
    def _validate_comment_response(response: dict[str, Any]) -> tuple[str, str, str, str]:
        request_id = response.get("request_id")
        fingerprint = response.get("comment_fingerprint")
        marker = response.get("comment_marker")
        text = response.get("comment_text")
        if (
            not isinstance(request_id, str)
            or not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or not isinstance(marker, str)
            or marker != f"<!-- hmb-result:{request_id}:{fingerprint} -->"
            or not isinstance(text, str)
            or marker not in text
            or len(text) > 8_192
        ):
            raise BridgeError("invalid_bridge_response", "The bridge returned an invalid result comment.")
        return request_id, fingerprint, marker, text

    @staticmethod
    def _ack_comment(
        transport: Any,
        request: dict[str, Any],
        request_id: str,
        fingerprint: str,
        *,
        published: bool,
    ) -> None:
        if isinstance(transport, BridgeService):
            transport.finish_result_comment_for_request(
                request,
                request_id,
                fingerprint,
                published=published,
            )
            return
        response = transport.finish_result_comment(
            request,
            request_id,
            fingerprint,
            published=published,
        )
        if not response.get("ok"):
            raise BridgeError(
                str(response.get("error_code") or "bridge_unavailable"),
                str(response.get("message") or "The trusted sender could not acknowledge the result comment."),
                retryable=bool(response.get("retryable")),
            )

    def handle_send(self, args: dict[str, Any], **_kwargs: Any) -> str:
        try:
            requested = self._route_arg(args)
            current = read_current_task_with_context(dispatch_tool=self.ctx.dispatch_tool)
            registry = self._registry()
            route = self._select_route(registry, current.trusted, requested)
            # Re-resolve immediately before delivery so a concurrent settings
            # change cannot widen a route chosen from an earlier snapshot.
            registry = self._registry()
            route = self._select_route(registry, current.trusted, route.route_id)
            response = self._send(registry, route, current.request)
            response["route_id"] = route.route_id
            return _json_result(response)
        except BridgeError as exc:
            return _error_json(exc)
        except Exception:  # noqa: BLE001
            return _json_result(
                {
                    "ok": False,
                    "error_code": "internal_error",
                    "message": "The bridge tool could not complete the request.",
                }
            )

    def handle_check_result(self, args: dict[str, Any], **_kwargs: Any) -> str:
        try:
            requested = self._route_arg(args)
            current = read_current_task_with_context(dispatch_tool=self.ctx.dispatch_tool)
            registry = self._registry()
            if requested is None:
                allowed = registry.authorized_routes(current.trusted, include_disabled=True)
                if len(allowed) == 1:
                    route = allowed[0]
                else:
                    delivered_allowed = self._delivered_routes(
                        registry,
                        allowed,
                        current.request,
                        current.trusted,
                    )
                    if len(delivered_allowed) == 1:
                        route = delivered_allowed[0]
                    elif len(delivered_allowed) > 1:
                        raise BridgeError(
                            "route_required",
                            "This task has deliveries to more than one Multica Route; choose route_id.",
                        )
                    else:
                        route = self._select_route(registry, current.trusted, None, include_disabled=True)
            else:
                route = self._select_route(registry, current.trusted, requested, include_disabled=True)
            response, transport = self._check(registry, route, current.request)
            if not response.get("ok"):
                return _json_result(response)
            comment_written = False
            if response.get("comment_required") is True:
                request_id, fingerprint, marker, text = self._validate_comment_response(response)
                try:
                    comment_written = add_current_task_comment(
                        text,
                        dispatch_tool=self.ctx.dispatch_tool,
                        dedupe_marker=marker,
                        expected_request_sha256=request_fingerprint(current.request),
                    )
                except BridgeError:
                    try:
                        self._ack_comment(
                            transport,
                            current.request,
                            request_id,
                            fingerprint,
                            published=False,
                        )
                    except BridgeError:
                        pass
                    raise
                self._ack_comment(
                    transport,
                    current.request,
                    request_id,
                    fingerprint,
                    published=True,
                )

            public = {
                key: value
                for key, value in response.items()
                if key not in {
                    "comment_required",
                    "comment_fingerprint",
                    "comment_marker",
                    "comment_text",
                }
            }
            public["comment_written"] = comment_written
            public["route_id"] = route.route_id
            return _json_result(public)
        except BridgeError as exc:
            return _error_json(exc)
        except Exception:  # noqa: BLE001
            return _json_result(
                {
                    "ok": False,
                    "error_code": "internal_error",
                    "message": "The bridge result tool could not complete the request.",
                }
            )

    def handle_list_routes(self, args: dict[str, Any], *, tool_context: Any = None, **_kwargs: Any) -> str:
        try:
            if not isinstance(args, dict) or args:
                raise BridgeError("invalid_arguments", "This tool takes no model-supplied arguments.")
            registry = self._registry()
            rows = []
            try:
                source = trusted_source(tool_context)
            except BridgeError:
                source = None
            if source is not None:
                for route in registry.authorized_workspace_routes(source):
                    connection = registry.connection(route.connection_id)
                    workspace = registry.workspace(route.workspace_key)
                    rows.append({
                        "route_id": route.route_id,
                        "type": "workspace",
                        "name": route.name,
                        "purpose": "Create and track issues in the configured project.",
                        "workspace": workspace.name,
                        "project_id": route.project_id,
                        "platforms": list(route.source_platforms),
                        "watcher_enabled": route.watcher_enabled,
                        "security_mode": connection.security_mode,
                    })
            try:
                current = read_current_task_with_context(dispatch_tool=self.ctx.dispatch_tool)
            except BridgeError:
                current = None
            if current is not None:
                for route in registry.authorized_routes(current.trusted):
                    connection = registry.connection(route.connection_id)
                    workspace = registry.workspace(route.workspace_key)
                    rows.append({
                        "route_id": route.route_id,
                        "type": "autopilot",
                        "name": route.name,
                        "purpose": "Send a Hermes Kanban task to Multica Autopilot.",
                        "connection": connection.name,
                        "workspace": workspace.name,
                        "security_mode": connection.security_mode,
                        "result_tracking_enabled": route.result_tracking_enabled,
                    })
            return _json_result({"ok": True, "routes": rows})
        except BridgeError as exc:
            return _error_json(exc)
        except Exception:  # noqa: BLE001
            return _json_result(
                {"ok": False, "error_code": "internal_error", "message": "The bridge could not list Multica Routes."}
            )


def register(ctx: Any) -> None:
    runtime = PluginRuntime(ctx)
    ctx.register_tool(
        name="multica_list_routes",
        toolset=TOOLSET,
        schema=LIST_ROUTES_TOOL_SCHEMA,
        handler=runtime.handle_list_routes,
    )
    ctx.register_tool(
        name="multica_send_task",
        toolset=TOOLSET,
        schema=SEND_TOOL_SCHEMA,
        handler=runtime.handle_send,
    )
    ctx.register_tool(
        name="multica_check_task_result",
        toolset=TOOLSET,
        schema=RESULT_TOOL_SCHEMA,
        handler=runtime.handle_check_result,
    )
    register_workspace_tools(ctx)
