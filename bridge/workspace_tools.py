"""Hermes Workspace tools backed by trusted, per-message source context."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .registry import (
    ConnectionRegistry,
    RegistryRoute,
    WorkspaceAssignee,
    registry_from_mapping,
    standard_route_secrets,
)
from .validation import _valid_telegram_thread_id
from .workspace_api import WorkspaceApiClient, WorkspaceApiFailure
from .workspace_state import WorkspaceState

_FILENAME_RE = re.compile(r"[^A-Za-z0-9._ -]+")
_MIME_RE = re.compile(r"\A[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")
_ISSUE_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_WORKSPACE_ASSIGNEE_TYPES = frozenset({"member", "agent", "squad"})
_WORKSPACE_STATES: dict[Path, WorkspaceState] = {}
_WORKSPACE_STATES_LOCK = threading.Lock()

_SOURCE_ENV = {
    "platform": "HERMES_SESSION_PLATFORM",
    "user_id": "HERMES_SESSION_USER_ID",
    "chat_id": "HERMES_SESSION_CHAT_ID",
    "thread_id": "HERMES_SESSION_THREAD_ID",
    "message_id": "HERMES_SESSION_MESSAGE_ID",
    "chat_type": "HERMES_SESSION_CHAT_TYPE",
}


@dataclass(frozen=True)
class _HermesMessageContext:
    source: dict[str, Any]
    attachments: tuple[Mapping[str, Any], ...] = ()


def _workspace_state(path: Path) -> WorkspaceState:
    with _WORKSPACE_STATES_LOCK:
        state = _WORKSPACE_STATES.get(path)
        if state is None:
            state = WorkspaceState(path)
            _WORKSPACE_STATES[path] = state
        return state


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _error(exc: BridgeError) -> str:
    value: dict[str, Any] = {"ok": False, "error_code": exc.code, "message": exc.message}
    if exc.retryable:
        value["retryable"] = True
    return _json(value)


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _load_hermes_context(*, include_attachments: bool = False) -> _HermesMessageContext:
    """Read the active Gateway turn context without trusting process-environment fallbacks."""
    try:
        from gateway import session_context

        get_bound = session_context.get_bound_session_env
        get_env = session_context.get_session_env
    except (ImportError, AttributeError) as exc:  # T38-DEBT-3: Hermes has no plugin tool_context here.
        raise BridgeError("source_unavailable", "Hermes did not expose a bound message source.") from exc

    try:
        bound = {key: get_bound(name, "") for key, name in _SOURCE_ENV.items()}
        values = {key: get_env(name, "") for key, name in _SOURCE_ENV.items()}
    except Exception as exc:
        raise BridgeError("source_unavailable", "Hermes could not provide the current message source.") from exc
    if (any(not isinstance(value, str) for value in (*bound.values(), *values.values()))
            or bound != values):
        raise BridgeError("source_unavailable", "Hermes did not provide a consistent bound message source.")

    source = dict(bound)
    source["thread_id"] = source["thread_id"] or None
    attachments: tuple[Mapping[str, Any], ...] = ()
    if include_attachments:
        try:
            raw_attachments = session_context.get_current_attachments()
        except Exception as exc:
            raise BridgeError("attachment_invalid", "Hermes could not provide current-message attachments.") from exc
        if not isinstance(raw_attachments, (tuple, list)) or any(
            not isinstance(item, Mapping) for item in raw_attachments
        ):
            raise BridgeError("attachment_invalid", "Hermes returned invalid current-message attachments.")
        attachments = tuple(dict(item) for item in raw_attachments)
    return _HermesMessageContext(source=source, attachments=attachments)


def trusted_source(context: Any = None) -> dict[str, Any]:
    """Validate Hermes source facts; no source field comes from model arguments."""
    if context is None:
        context = _load_hermes_context()
    if isinstance(context, _HermesMessageContext):
        context = context.source
    fields = {
        "platform": _get(context, "platform"),
        "user_id": _get(context, "user_id"),
        "chat_id": _get(context, "chat_id"),
        "thread_id": _get(context, "thread_id"),
        "message_id": _get(context, "message_id"),
        "chat_type": _get(context, "chat_type"),
    }
    if (fields["platform"] not in {"max", "telegram"}
            or not all(isinstance(fields[key], str) and fields[key] for key in ("user_id", "chat_id", "message_id"))
            or fields["chat_type"] not in {"dm", "group", "channel", "thread"}
            or (fields["thread_id"] is not None
                and (not isinstance(fields["thread_id"], str) or not fields["thread_id"]))
            or (fields["platform"] == "telegram" and fields["chat_type"] == "thread"
                and not _valid_telegram_thread_id(fields["thread_id"]))):
        raise BridgeError("source_unavailable", "This tool requires a complete trusted MAX or Telegram message source.")
    return fields


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_hermes_attachment(path: str, *, max_bytes: int) -> bytes:
    """Read one Gateway-provided path without following symlinks or accepting file races."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if (not isinstance(path, str) or nofollow is None or directory_flag is None
            or not Path(path).is_absolute() or "\x00" in path):
        raise BridgeError("attachment_invalid", "Hermes provided an unsafe attachment reference.")
    parts = Path(path).parts
    if len(parts) < 2 or any(part == ".." for part in parts):
        raise BridgeError("attachment_invalid", "Hermes provided an unsafe attachment reference.")
    directory_flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(os.sep, directory_flags)
        for part in parts[1:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        filename = parts[-1]
        before = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > max_bytes:
            raise BridgeError("attachment_invalid", "An attachment is not a regular file within the route size limit.")
        descriptor = os.open(filename, file_flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
            raise BridgeError("attachment_invalid", "An attachment changed while it was being opened.")
        if opened.st_size > max_bytes:
            raise BridgeError("attachment_invalid", "An attachment exceeds the route size limit.")

        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if (len(data) == 0 or len(data) > max_bytes or len(data) != opened.st_size
                or _file_identity(after) != _file_identity(opened)
                or _file_identity(path_after) != _file_identity(opened)):
            raise BridgeError("attachment_invalid", "An attachment changed or exceeded its allowed size while being read.")
        return bytes(data)
    except BridgeError:
        raise
    except OSError as exc:
        raise BridgeError("attachment_invalid", "Hermes could not safely open or read a current-message attachment.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


class WorkspaceRuntime:
    def __init__(self, ctx: Any):
        self.ctx = ctx
        self._watcher_mapping_registered: set[tuple[str, str]] = set()
        self._watcher_mapping_retry_after: dict[tuple[str, str], float] = {}
        self._watcher_mapping_lock = threading.Lock()

    def _registry(self) -> ConnectionRegistry:
        raw = self.ctx.get_config("registry", None)
        if not isinstance(raw, dict):
            raise BridgeError("route_denied", "No Workspace routes are configured for this Hermes profile.")
        return registry_from_mapping(raw)

    def _profile(self) -> str:
        value = getattr(self.ctx, "profile_name", None)
        return value if isinstance(value, str) and value else "default"

    def _state(self) -> WorkspaceState:
        try:
            from plugins.plugin_storage import plugin_data_dir
        except ImportError as exc:  # pragma: no cover - Hermes runtime supplies this API
            raise BridgeError("hermes_unavailable", "Hermes profile storage is unavailable.") from exc
        return _workspace_state(plugin_data_dir("hermes-multica-bridge") / "workspace.sqlite3")

    def _route(self, registry: ConnectionRegistry, context: Any, requested: Any) -> RegistryRoute:
        source = trusted_source(context)
        routes = registry.authorized_workspace_routes(source)
        if requested is not None:
            if not isinstance(requested, str) or not requested:
                raise BridgeError("invalid_arguments", "route_id must be a configured route identifier.")
            routes = tuple(route for route in routes if route.route_id == requested)
            if not routes:
                raise BridgeError("route_denied", "The requested Workspace route is not authorized for this message.")
        if not routes:
            raise BridgeError("route_denied", "No Workspace route is authorized for this message source.")
        if len(routes) != 1:
            raise BridgeError("route_required", "Choose a route_id from multica_list_routes.")
        return routes[0]

    def _api(self, registry: ConnectionRegistry, route: RegistryRoute) -> WorkspaceApiClient:
        connection = registry.connection(route.connection_id)
        if connection.security_mode != "standard":
            raise BridgeError("configuration_invalid", "Workspace routes require profile-scoped Multica credentials.")
        secrets = standard_route_secrets(route, require_webhook=False)
        if not secrets.multica_pat:
            raise BridgeError("credential_unavailable", "The Workspace route has no Multica API credential.")
        workspace = registry.workspace(route.workspace_key)
        return WorkspaceApiClient(connection.multica_origin, secrets.multica_pat, workspace.workspace_id,
                                  timeout=connection.request_timeout_seconds)

    @staticmethod
    def _issue_in_route(issue: dict[str, Any], registry: ConnectionRegistry, route: RegistryRoute) -> None:
        workspace = registry.workspace(route.workspace_key)
        if issue.get("workspace_id") != workspace.workspace_id or issue.get("project_id") != route.project_id:
            raise BridgeError("route_denied", "The issue does not belong to this Workspace route.")

    @staticmethod
    def _safe_issue(issue: dict[str, Any]) -> dict[str, Any]:
        fields = ("id", "identifier", "title", "description", "status", "priority", "project_id", "workspace_id",
                  "parent_issue_id", "assignee_id", "assignee_type", "revision")
        return {field: issue[field] for field in fields if field in issue and isinstance(issue[field], (str, int, type(None)))}

    @staticmethod
    def _route_arg(args: Any, allowed: set[str]) -> str | None:
        if not isinstance(args, dict) or set(args) - allowed:
            raise BridgeError("invalid_arguments", "The request contains unsupported arguments.")
        route_id = args.get("route_id")
        if route_id is not None and (not isinstance(route_id, str) or not route_id):
            raise BridgeError("invalid_arguments", "route_id is invalid.")
        return route_id

    @staticmethod
    def _resolve_create_assignee(route: RegistryRoute, args: dict[str, Any]) -> WorkspaceAssignee | None:
        assignee_id = args.get("assignee_id")
        assignee_type = args.get("assignee_type")
        allow_unassigned = args.get("allow_unassigned", False)
        if type(allow_unassigned) is not bool:
            raise BridgeError("invalid_arguments", "allow_unassigned must be a boolean.")
        if assignee_type is not None and assignee_id is None:
            raise BridgeError("invalid_arguments", "assignee_type requires assignee_id.")
        if assignee_id is not None:
            if not isinstance(assignee_id, str) or not assignee_id:
                raise BridgeError("invalid_arguments", "assignee_id must be a non-empty string.")
            matches = [item for item in route.workspace_assignees if item.id == assignee_id]
            if assignee_type is None:
                if not matches:
                    raise BridgeError("assignee_not_allowed", "The requested assignee is not allowed by this route.")
                if len(matches) > 1:
                    raise BridgeError("assignee_type_required", "This assignee ID has multiple allowed types; provide assignee_type.")
                return matches[0]
            if not isinstance(assignee_type, str):
                raise BridgeError("invalid_arguments", "assignee_type must be member, agent, or squad.")
            if assignee_type not in _WORKSPACE_ASSIGNEE_TYPES:
                raise BridgeError("invalid_arguments", "assignee_type must be member, agent, or squad.")
            exact = next((item for item in matches if item.type == assignee_type), None)
            if exact is None:
                raise BridgeError("assignee_not_allowed", "The requested assignee and type are not allowed by this route.")
            return exact
        if route.default_assignee is not None:
            return route.default_assignee
        if allow_unassigned:
            return None
        raise BridgeError("assignee_required", "Choose an allowed assignee or explicitly set allow_unassigned=true.")

    @staticmethod
    def _resolve_update_assignee(
        route: RegistryRoute, args: dict[str, Any], issue: dict[str, Any],
    ) -> tuple[bool, WorkspaceAssignee | None]:
        has_id = "assignee_id" in args
        has_type = "assignee_type" in args
        if not has_id and not has_type:
            return False, None
        if has_type and not has_id and args.get("assignee_type") is None:
            raise BridgeError("invalid_arguments", "assignee_type requires an assignee_id.")
        assignee_id = args.get("assignee_id") if has_id else issue.get("assignee_id")
        assignee_type = args.get("assignee_type")
        if assignee_id is None:
            if assignee_type is not None:
                raise BridgeError("invalid_arguments", "assignee_type cannot be set without an assignee_id.")
            if route.require_assignee:
                raise BridgeError("assignee_required", "This route does not allow removing the assignee.")
            return True, None
        if not isinstance(assignee_id, str) or not assignee_id:
            raise BridgeError("invalid_arguments", "assignee_id must be a non-empty string.")
        matches = [item for item in route.workspace_assignees if item.id == assignee_id]
        if assignee_type is None:
            if not matches:
                raise BridgeError("assignee_not_allowed", "The requested assignee is not allowed by this route.")
            if len(matches) > 1:
                raise BridgeError("assignee_type_required", "This assignee ID has multiple allowed types; provide assignee_type.")
            return True, matches[0]
        if not isinstance(assignee_type, str):
            raise BridgeError("invalid_arguments", "assignee_type must be member, agent, or squad.")
        if assignee_type not in _WORKSPACE_ASSIGNEE_TYPES:
            raise BridgeError("invalid_arguments", "assignee_type must be member, agent, or squad.")
        exact = next((item for item in matches if item.type == assignee_type), None)
        if exact is None:
            raise BridgeError("assignee_not_allowed", "The requested assignee and type are not allowed by this route.")
        return True, exact

    @staticmethod
    def _related_issue_ids(value: Any) -> tuple[list[str], str | None]:
        if value is None:
            return [], None
        if not isinstance(value, list) or len(value) > 16:
            raise BridgeError("invalid_arguments", "related_issue_ids must be a list of at most 16 issue identifiers.")
        if any(not isinstance(item, str) or not _ISSUE_IDENTIFIER_RE.fullmatch(item) for item in value):
            raise BridgeError("invalid_arguments", "related_issue_ids contains an invalid issue identifier.")
        if len(set(value)) != len(value):
            raise BridgeError("invalid_arguments", "related_issue_ids must not contain duplicates.")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded) > 1024:
            raise BridgeError("invalid_arguments", "related_issue_ids exceeds the metadata value limit.")
        return list(value), encoded if value else None

    @staticmethod
    def _verify_readback(
        api: WorkspaceApiClient,
        registry: ConnectionRegistry,
        route: RegistryRoute,
        issue_id: str,
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        issue = api.get_issue(issue_id)
        WorkspaceRuntime._issue_in_route(issue, registry, route)
        if any(issue.get(key) != value for key, value in expected.items()):
            raise BridgeError("assignee_verification_failed", "Multica readback does not match the requested issue state.")
        return issue

    def _write_metadata(
        self,
        *,
        state: WorkspaceState, route: RegistryRoute, context: Any, api: WorkspaceApiClient,
        issue_id: str, values: dict[str, Any],
    ) -> list[str]:
        warnings: list[str] = []
        for key, value in values.items():
            try:
                self._operation(
                    state, route, context, f"metadata:set:{key}",
                    {"issue_id": issue_id, "key": key, "value": value},
                    lambda key=key, value=value: api.set_issue_metadata(issue_id, key, value),
                )
            except BridgeError:
                if "metadata_incomplete" not in warnings:
                    warnings.append("metadata_incomplete")
        return warnings

    @staticmethod
    def _metadata_pseudonym_key(route: RegistryRoute) -> bytes:
        secrets = standard_route_secrets(route, require_webhook=False)
        if not secrets.multica_pat:
            raise BridgeError("credential_unavailable", "The Workspace route has no Multica API credential.")
        return hmac.new(
            secrets.multica_pat.encode("utf-8"),
            b"hermes-multica-bridge|workspace-metadata-pseudonym|v1",
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _metadata_for_source(
        route: RegistryRoute, source: dict[str, Any], related_ids_json: str | None,
        pseudonym_key: bytes,
    ) -> dict[str, Any]:
        requester = hmac.new(
            pseudonym_key,
            _json({"platform": source["platform"], "user_id": source["user_id"], "route_id": route.route_id}).encode(),
            hashlib.sha256,
        ).hexdigest()
        source_message = hmac.new(
            pseudonym_key,
            _json({key: source[key] for key in (
                "platform", "user_id", "chat_id", "thread_id", "message_id", "chat_type",
            )}).encode(),
            hashlib.sha256,
        ).hexdigest()
        result: dict[str, Any] = {
            "requester": requester,
            "origin": source["platform"],
            "origin_route": route.route_id,
            "source_message_id": source_message,
            "created_by": "hermes-multica-bridge",
        }
        if route.test:
            result["origin_test"] = True
        if related_ids_json is not None:
            result["related_issue_ids"] = related_ids_json
        return result

    @staticmethod
    def _post_message_result(result: Any) -> str:
        if _get(result, "ok") is True and _get(result, "pending", False) is not True and _get(result, "message_id"):
            return "delivered"
        error = _get(result, "error") or _get(result, "error_code")
        if isinstance(error, str) and error in {
            "no_conversation", "gateway_unavailable", "adapter_unavailable", "on_event_loop",
        }:
            return "not_sent"
        return "delivery_unknown"

    def _notify_unassigned(self, state: WorkspaceState, route: RegistryRoute, issue: dict[str, Any]) -> str:
        issue_id = issue["id"]
        source = {"issue_id": issue_id}
        operation = "unassigned_notification"
        key = state.operation_key(self._profile(), route.route_id, source, operation)
        payload = {
            "issue_id": issue_id,
            "text": f"Задача {issue.get('identifier') or issue_id} создана, но отдел не назначен; работа не началась.",
        }
        existing = state.begin(
            key=key, route_id=route.route_id, operation=operation, request_hash=state.payload_hash(payload),
        )
        if existing.status == "accepted":
            return str((existing.result or {}).get("delivery_status", "delivery_unknown"))
        if existing.status != "ready":
            return "delivery_unknown"
        try:
            result = self.ctx.post_message(payload["text"])
            delivery_status = self._post_message_result(result)
        except Exception:  # noqa: BLE001 - the message may have reached the chat before an error
            delivery_status = "delivery_unknown"
        state.finish(key, status="accepted", result={"delivery_status": delivery_status})
        return delivery_status

    def _operation(self, state: WorkspaceState, route: RegistryRoute, context: Any, operation: str,
                   payload: Any, write: Any) -> dict[str, Any]:
        source = trusted_source(context)
        key = state.operation_key(self._profile(), route.route_id, source, operation)
        existing = state.begin(
            key=key, route_id=route.route_id, operation=operation,
            request_hash=state.payload_hash(payload),
        )
        if existing.status == "accepted" and existing.result is not None:
            return existing.result
        if existing.status != "ready":
            raise BridgeError(
                "operation_unknown",
                "A previous write may have been accepted. Do not repeat it; inspect Multica for "
                f"route {route.route_id}, source chat {source['chat_id']}, message {source['message_id']}.",
            )
        try:
            result = write()
        except WorkspaceApiFailure as exc:
            state.finish(key, status="not_sent" if exc.outcome == "not_sent" else "operation_unknown", detail=exc.code)
            raise
        except BridgeError as exc:
            state.finish(key, status="not_sent", detail=exc.code)
            raise
        except Exception:  # noqa: BLE001 - an unexpected write failure may follow server acceptance
            state.finish(key, status="operation_unknown", detail="unexpected_write_error")
            raise BridgeError("operation_unknown", "The write result is uncertain; inspect Multica before retrying.") from None
        state.finish(key, status="accepted", result=result)
        return result

    def _retry_watcher_mapping(self, state: WorkspaceState, route: RegistryRoute, issue_id: str) -> bool:
        if not route.watcher_enabled:
            return False
        stored = state.issue_mapping(issue_id)
        if stored is None or stored["route_id"] != route.route_id:
            return False

        key = (route.route_id, issue_id)
        now = time.monotonic()
        with self._watcher_mapping_lock:
            if key in self._watcher_mapping_registered:
                return True
            if self._watcher_mapping_retry_after.get(key, 0.0) > now:
                return False
            self._watcher_mapping_retry_after[key] = now + 30.0

        watcher_mapping = {
            "profile": self._profile(),
            "issue_id": issue_id,
            "route_id": stored["route_id"],
            **{
                field: stored[field]
                for field in ("platform", "user_id", "chat_id", "thread_id", "message_id", "chat_type")
            },
        }
        try:
            from .watcher_ipc import WatcherIpcClient

            WatcherIpcClient().register_issue(watcher_mapping)
        except BridgeError:
            return False

        with self._watcher_mapping_lock:
            self._watcher_mapping_registered.add(key)
            self._watcher_mapping_retry_after.pop(key, None)
        return True

    def _attachments(self, context: Any, route: RegistryRoute) -> list[tuple[str, str, str, bytes]]:
        if isinstance(context, _HermesMessageContext):
            descriptors = context.attachments
        elif context is None:
            descriptors = _load_hermes_context(include_attachments=True).attachments
        else:
            descriptors = _get(context, "attachments", ())
        if descriptors is None:
            descriptors = ()
        if not isinstance(descriptors, (tuple, list)):
            raise BridgeError("attachment_invalid", "Hermes returned invalid current-message attachments.")
        source = trusted_source(context)
        if len(descriptors) > route.max_attachments:
            raise BridgeError("attachment_invalid", "The message has more attachments than this route allows.")
        if not descriptors and route.require_source_attachment:
            raise BridgeError("attachment_required", "This route requires an attachment from the current message.")
        if not descriptors:
            return []
        result: list[tuple[str, str, str, bytes]] = []
        total = 0
        for descriptor in descriptors:
            path = _get(descriptor, "path")
            content_type = _get(descriptor, "media_type")
            if (not isinstance(path, str) or not path or len(path) > 4096
                    or _get(descriptor, "message_id") != source["message_id"]
                    or _get(descriptor, "platform") != source["platform"]
                    or _get(descriptor, "chat_type") != source["chat_type"]
                    or _get(descriptor, "chat_id") != source["chat_id"]
                    or _get(descriptor, "actor") != source["user_id"]
                    or not isinstance(content_type, str) or not _MIME_RE.fullmatch(content_type.lower())):
                raise BridgeError("attachment_invalid", "An attachment does not belong to the current message.")
            filename = Path(path).name
            if not filename or filename in {".", ".."} or len(filename) > 240:
                raise BridgeError("attachment_invalid", "Hermes returned an invalid attachment name.")
            extension = Path(filename).suffix.lower()
            if content_type.lower() not in route.allowed_mime_types or extension not in route.allowed_extensions:
                raise BridgeError("attachment_invalid", "An attachment type is not allowed by this route.")
            remaining = route.max_attachment_bytes - total
            if remaining <= 0:
                raise BridgeError("attachment_invalid", "Attachments exceed the route size limit.")
            try:
                data = _read_hermes_attachment(path, max_bytes=remaining)
            except BridgeError:
                raise
            except Exception as exc:
                raise BridgeError("attachment_invalid", "Hermes could not read a current-message attachment.") from exc
            total += len(data)
            clean_name = _FILENAME_RE.sub("_", filename)[:180]
            result.append((clean_name, content_type.lower(), hashlib.sha256(data).hexdigest(), data))
        return result

    def _upload_attachments(self, *, state: WorkspaceState, api: WorkspaceApiClient, route: RegistryRoute,
                            context: Any, issue_id: str, attachments: list[tuple[str, str, str, bytes]]) -> list[dict[str, Any]]:
        output = []
        for index, (filename, content_type, content_hash, data) in enumerate(attachments):
            attachment_identity = hashlib.sha256(
                f"{index}\0{filename}\0{content_type}\0{content_hash}".encode()
            ).hexdigest()
            payload = {"issue_id": issue_id, "attachment_identity": attachment_identity,
                       "content_sha256": content_hash}
            try:
                uploaded = self._operation(
                    state, route, context, "attachment:" + attachment_identity, payload,
                    lambda filename=filename, content_type=content_type, data=data:
                        api.upload_issue_attachment(issue_id, filename, content_type, data),
                )
                output.append({"status": "attached", "attachment_id": uploaded["id"]})
            except BridgeError as exc:
                output.append({"status": "operation_unknown" if exc.code == "operation_unknown" else "not_attached",
                               "message": exc.message})
                if exc.code == "operation_unknown":
                    break
        return output

    def send(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if tool_context is None:
                tool_context = _load_hermes_context(include_attachments=True)
            route_id = self._route_arg(args, {
                "route_id", "title", "description", "status", "parent_issue_id", "assignee_id",
                "assignee_type", "allow_unassigned", "related_issue_ids",
            })
            registry = self._registry()
            route = self._route(registry, tool_context, route_id)
            title = args.get("title")
            description = args.get("description", "")
            status = args.get("status") or ("todo" if "todo" in route.allowed_statuses else route.allowed_statuses[0])
            if status not in route.allowed_statuses:
                raise BridgeError("route_denied", "The requested status is not allowed by this Workspace route.")
            assignment = self._resolve_create_assignee(route, args)
            related_ids, related_ids_json = self._related_issue_ids(args.get("related_issue_ids"))
            if assignment is None and not callable(getattr(self.ctx, "post_message", None)):
                raise BridgeError("notification_unavailable", "Hermes cannot post an unassigned-task notice to this conversation.")
            if not isinstance(title, str) or not title.strip() or len(title) > 4096:
                raise BridgeError("invalid_arguments", "Issue title is empty or too long.")
            if not isinstance(description, str) or len(description) > 65536:
                raise BridgeError("invalid_arguments", "Issue description is too long.")
            parent_id = args.get("parent_issue_id")
            api = self._api(registry, route)
            pseudonym_key = self._metadata_pseudonym_key(route)
            if parent_id is not None:
                parent = api.get_issue(parent_id)
                self._issue_in_route(parent, registry, route)
            assignee_id = assignment.id if assignment else None
            assignee_type = assignment.type if assignment else None
            attachments = self._attachments(tool_context, route)
            state = self._state()
            payload = {"title": title, "description": description, "status": status,
                       "parent_issue_id": parent_id, "assignee_id": assignee_id,
                       "assignee_type": assignee_type, "allow_unassigned": args.get("allow_unassigned", False),
                       "related_issue_ids": related_ids,
                       "attachment_hashes": [item[2] for item in attachments]}
            issue = self._operation(
                state, route, tool_context, "create_issue", payload,
                lambda: api.create_issue(title=title, description=description, project_id=route.project_id,
                                         status=status, parent_issue_id=parent_id, assignee_id=assignee_id,
                                         assignee_type=assignee_type),
            )
            self._issue_in_route(issue, registry, route)
            issue_id = issue["id"]
            expected = {"title": title.strip(), "description": description, "status": status,
                        "assignee_id": assignee_id, "assignee_type": assignee_type}
            if parent_id is not None:
                expected["parent_issue_id"] = parent_id
            readback_issue = issue
            verification_error: BridgeError | None = None
            try:
                readback_issue = self._verify_readback(api, registry, route, issue_id, expected)
            except BridgeError as exc:
                if exc.code == "route_denied":
                    return _json({
                        "ok": False,
                        "error_code": "route_denied",
                        "message": exc.message,
                        "issue_id": issue_id,
                        "issue": self._safe_issue(issue),
                    })
                verification_error = BridgeError(
                    "assignee_verification_failed",
                    "The issue was created, but Multica could not confirm its requested state.",
                )
            except Exception:  # noqa: BLE001 - the accepted POST must never be repeated on readback failure
                verification_error = BridgeError(
                    "assignee_verification_failed",
                    "The issue was created, but Multica readback is unavailable.",
                )
            source = trusted_source(tool_context)
            if not state.register_issue(issue_id, route.route_id, source):
                raise BridgeError("mapping_conflict", "This Multica issue is already mapped to a different source message.")
            mapping_status = "pending"
            if route.watcher_enabled and self._retry_watcher_mapping(state, route, issue_id):
                mapping_status = "registered"
            metadata_warnings = self._write_metadata(
                state=state, route=route, context=tool_context, api=api, issue_id=issue_id,
                values=self._metadata_for_source(route, source, related_ids_json, pseudonym_key),
            )
            files = self._upload_attachments(state=state, api=api, route=route, context=tool_context,
                                             issue_id=issue_id, attachments=attachments)
            notification_status = self._notify_unassigned(state, route, readback_issue) if assignment is None else None
            result = {"issue": self._safe_issue(readback_issue), "issue_id": issue_id,
                      "attachments": files, "watcher_mapping": mapping_status, "warnings": metadata_warnings}
            if verification_error is not None:
                return _json({"ok": False, "error_code": verification_error.code,
                              "message": verification_error.message, **result})
            if assignment is None:
                return _json({"ok": False, "error_code": "assignee_required",
                              "message": "The issue was created without an assignee; work has not started.",
                              "notification_status": notification_status, **result})
            return _json({"ok": True, **result})
        except BridgeError as exc:
            return _error(exc)
        except Exception:  # noqa: BLE001 - keep unexpected tool internals out of model-visible output
            return _json({"ok": False, "error_code": "internal_error", "message": "Workspace issue creation failed."})

    def get(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if tool_context is None:
                tool_context = _load_hermes_context()
            route_id = self._route_arg(args, {"route_id", "issue_id"})
            registry = self._registry()
            route = self._route(registry, tool_context, route_id)
            issue = self._api(registry, route).get_issue(args.get("issue_id"))
            self._issue_in_route(issue, registry, route)
            self._retry_watcher_mapping(self._state(), route, args["issue_id"])
            comments = self._api(registry, route).list_comments(args.get("issue_id"))
            safe_comments = [
                {key: item[key] for key in ("id", "author_type", "author_id", "content", "type", "created_at")
                 if key in item and isinstance(item[key], (str, int, type(None)))}
                for item in comments[-100:]
            ]
            return _json({"ok": True, "issue": self._safe_issue(issue), "comments": safe_comments})
        except BridgeError as exc:
            return _error(exc)
        except Exception:  # noqa: BLE001 - keep unexpected tool internals out of model-visible output
            return _json({"ok": False, "error_code": "internal_error", "message": "Workspace issue lookup failed."})

    def comment(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if tool_context is None:
                tool_context = _load_hermes_context()
            route_id = self._route_arg(args, {"route_id", "issue_id", "content"})
            registry = self._registry()
            route = self._route(registry, tool_context, route_id)
            api = self._api(registry, route)
            issue_id = args.get("issue_id")
            issue = api.get_issue(issue_id)
            self._issue_in_route(issue, registry, route)
            state = self._state()
            self._retry_watcher_mapping(state, route, issue_id)
            result = self._operation(state, route, tool_context, "create_comment",
                                     {"issue_id": issue_id, "content": args.get("content")},
                                     lambda: api.create_comment(issue_id, args.get("content")))
            return _json({"ok": True, "comment": {key: result[key] for key in ("id", "content", "created_at") if key in result}})
        except BridgeError as exc:
            return _error(exc)
        except Exception:  # noqa: BLE001 - keep unexpected tool internals out of model-visible output
            return _json({"ok": False, "error_code": "internal_error", "message": "Workspace comment creation failed."})

    def update(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if tool_context is None:
                tool_context = _load_hermes_context()
            route_id = self._route_arg(args, {
                "route_id", "issue_id", "title", "description", "status", "assignee_id",
                "assignee_type", "related_issue_ids",
            })
            registry = self._registry()
            route = self._route(registry, tool_context, route_id)
            issue_id = args.get("issue_id")
            api = self._api(registry, route)
            issue = api.get_issue(issue_id)
            self._issue_in_route(issue, registry, route)
            state = self._state()
            self._retry_watcher_mapping(state, route, issue_id)
            related_requested = "related_issue_ids" in args
            related_ids: list[str] = []
            related_ids_json = None
            if related_requested:
                related_ids, related_ids_json = self._related_issue_ids(args["related_issue_ids"])
            updates = {key: args[key] for key in ("title", "description", "status") if key in args}
            assignment_requested, assignment = self._resolve_update_assignee(route, args, issue)
            if assignment_requested:
                updates["assignee_id"] = assignment.id if assignment else None
                updates["assignee_type"] = assignment.type if assignment else None
            if not updates and not related_requested:
                raise BridgeError("invalid_arguments", "At least one supported issue field must be updated.")
            if "status" in updates and updates["status"] not in route.allowed_statuses:
                raise BridgeError("route_denied", "The requested status is not allowed by this Workspace route.")
            verification_error: BridgeError | None = None
            changed = issue
            if updates:
                changed = self._operation(
                    state, route, tool_context, "update_issue",
                    {"issue_id": issue_id, "updates": updates, "related_issue_ids": related_ids if related_requested else None},
                    lambda: api.update_issue(issue_id, updates),
                )
                expected_updates = dict(updates)
                if isinstance(expected_updates.get("title"), str):
                    expected_updates["title"] = expected_updates["title"].strip()
                try:
                    changed = self._verify_readback(api, registry, route, issue_id, expected_updates)
                except BridgeError as exc:
                    verification_error = BridgeError(
                        "route_denied" if exc.code == "route_denied" else "assignee_verification_failed",
                        "The update was accepted, but Multica could not confirm the requested state.",
                    )
                except Exception:  # noqa: BLE001 - the accepted PUT must never be repeated on readback failure
                    verification_error = BridgeError(
                        "assignee_verification_failed",
                        "The update was accepted, but Multica readback is unavailable.",
                    )
            metadata_warnings: list[str] = []
            if related_requested and not (
                verification_error is not None and verification_error.code == "route_denied"
            ):
                try:
                    if related_ids_json is None:
                        operation = "metadata:delete:related_issue_ids"
                        payload = {"issue_id": issue_id, "key": "related_issue_ids"}
                        writer = lambda: api.delete_issue_metadata(issue_id, "related_issue_ids")
                    else:
                        operation = "metadata:set:related_issue_ids"
                        payload = {"issue_id": issue_id, "key": "related_issue_ids", "value": related_ids_json}
                        writer = lambda: api.set_issue_metadata(issue_id, "related_issue_ids", related_ids_json)
                    self._operation(state, route, tool_context, operation, payload, writer)
                except BridgeError:
                    metadata_warnings.append("metadata_incomplete")
            result = {"issue": self._safe_issue(changed), "issue_id": issue_id, "warnings": metadata_warnings}
            if verification_error is not None:
                return _json({"ok": False, "error_code": verification_error.code,
                              "message": verification_error.message, **result})
            return _json({"ok": True, **result})
        except BridgeError as exc:
            return _error(exc)
        except Exception:  # noqa: BLE001 - keep unexpected tool internals out of model-visible output
            return _json({"ok": False, "error_code": "internal_error", "message": "Workspace issue update failed."})


def _schema(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required,
                           "additionalProperties": False}}


ROUTE_PROPERTY = {"route_id": {"type": "string", "description": "Authorized route from multica_list_routes."}}
WORKSPACE_TOOLS = (
    ("multica_workspace_send", "Create an issue in the configured Multica project, using an allowed member, agent, or squad assignment. Current-message attachments are included automatically.",
     {**ROUTE_PROPERTY, "title": {"type": "string"}, "description": {"type": "string"},
      "status": {"type": "string"}, "parent_issue_id": {"type": "string"},
      "assignee_id": {"type": "string"}, "assignee_type": {"type": "string", "enum": ["member", "agent", "squad"]},
      "allow_unassigned": {"type": "boolean"},
      "related_issue_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 16, "uniqueItems": True}},
     ["title"], "send"),
    ("multica_workspace_get", "Read an issue only when it belongs to the selected Workspace route.",
     {**ROUTE_PROPERTY, "issue_id": {"type": "string"}}, ["issue_id"], "get"),
    ("multica_workspace_comment", "Add a comment to an issue belonging to the selected Workspace route.",
     {**ROUTE_PROPERTY, "issue_id": {"type": "string"}, "content": {"type": "string"}},
     ["issue_id", "content"], "comment"),
    ("multica_workspace_update", "Update allowlisted issue fields, typed assignee, or related issue identifiers on the selected Workspace route.",
     {**ROUTE_PROPERTY, "issue_id": {"type": "string"}, "title": {"type": "string"},
      "description": {"type": "string"}, "status": {"type": "string"},
      "assignee_id": {"type": ["string", "null"]},
      "assignee_type": {"type": ["string", "null"], "enum": ["member", "agent", "squad", None]},
      "related_issue_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 16, "uniqueItems": True}},
     ["issue_id"], "update"),
)


def register_workspace_tools(ctx: Any) -> None:
    runtime = WorkspaceRuntime(ctx)
    for name, description, properties, required, method_name in WORKSPACE_TOOLS:
        ctx.register_tool(
            name=name, toolset="hermes_multica_bridge",
            schema=_schema(name, description, properties, required),
            handler=getattr(runtime, method_name),
        )
