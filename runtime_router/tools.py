"""Hermes tool boundary for the local runtime router."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from collections.abc import Mapping
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from typing import Any

from bridge.condition_wake import parse_condition_wake
from bridge.errors import BridgeError
from bridge.registry import new_id, route_policy_fingerprint
from bridge.workspace_tools import (
    WorkspaceRuntime,
    _load_hermes_context,
    trusted_source,
)

from .adapter import MulticaCliAdapter, MulticaCliError
from .config import RouterConfig, RouterConfigError, service_cli_home
from .policy import ResolutionError, resolve_runtime, route_request_policy_hash
from .spool import AttachmentSpool
from .state import RouterStore

_LIMIT = 131072
_PROFILE_STATE_POINTER = "runtime-router-state-path.json"
_PROFILE_STATE_POINTER_LIMIT = 4096
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PRIORITY_RANK = {"urgent": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
_SAFE_FAILURES = (
    OSError,
    ValueError,
    TypeError,
    KeyError,
    sqlite3.Error,
    AttributeError,
)


def _reply(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _error(
    code: str, message: str = "Runtime router could not complete this request."
) -> str:
    return _reply({"ok": False, "error_code": code, "message": message})


def _aware_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _store(config: RouterConfig) -> RouterStore:
    return RouterStore(config.state_path)


def _plugin_data_dir() -> Path:
    """Return the profile-scoped public Hermes data directory for this plugin."""
    try:
        from plugins.plugin_storage import plugin_data_dir
    except ImportError as exc:  # pragma: no cover - Hermes runtime supplies this helper
        raise RouterConfigError("plugin_storage_unavailable") from exc
    root = Path(plugin_data_dir("hermes-multica-bridge"))
    try:
        info = root.lstat()
    except OSError as exc:
        raise RouterConfigError("plugin_storage_unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise RouterConfigError("plugin_storage_permissions_unsafe")
    return root


def _profile_state_pointer(profile: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", profile):
        raise RouterConfigError("profile_unavailable")
    return _plugin_data_dir() / _PROFILE_STATE_POINTER


def _write_profile_state_pointer(config: RouterConfig, profile: str) -> None:
    path = _profile_state_pointer(profile)
    payload = json.dumps(
        {"profile": profile, "state_path": str(config.state_path)},
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > _PROFILE_STATE_POINTER_LIMIT:
        raise RouterConfigError("router_state_path_invalid")
    fd, name = tempfile.mkstemp(prefix=".runtime-router-path-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError as exc:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise RouterConfigError("plugin_storage_unavailable") from exc


def _read_profile_state_pointer(profile: str) -> Path | None:
    path = _profile_state_pointer(profile)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RouterConfigError("plugin_storage_permissions_unsafe") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _PROFILE_STATE_POINTER_LIMIT
        ):
            raise RouterConfigError("plugin_storage_permissions_unsafe")
        raw = bytearray()
        while len(raw) <= _PROFILE_STATE_POINTER_LIMIT:
            chunk = os.read(fd, _PROFILE_STATE_POINTER_LIMIT + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > _PROFILE_STATE_POINTER_LIMIT:
            raise RouterConfigError("router_state_path_invalid")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RouterConfigError("router_state_path_invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"profile", "state_path"}
        or value.get("profile") != profile
        or not isinstance(value.get("state_path"), str)
    ):
        raise RouterConfigError("router_state_path_invalid")
    config = RouterConfig.parse(
        {"enabled": False, "state_path": value["state_path"]}
    )
    return config.state_path


def _write_profile_snapshot_file(root: Path, profile: str, payload: bytes) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RouterConfigError("router_config_permissions_unsafe")
    fd, name = tempfile.mkstemp(prefix=".profile-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, root / f"{profile}.json")
        dirfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def _get_runtime_config(ctx: Any) -> RouterConfig:
    raw = ctx.get_config("runtime_router", {})
    return RouterConfig.parse(raw)


class RuntimeRouterTools:
    def __init__(self, ctx: Any):
        self.ctx = ctx

    def _context(
        self, tool_context: Any = None
    ) -> tuple[dict[str, Any], str, RouterConfig, RouterStore]:
        config = _get_runtime_config(self.ctx)
        profile = getattr(self.ctx, "profile_name", None) or "default"
        if not isinstance(profile, str) or not profile:
            raise RouterConfigError("profile_unavailable")
        # Keep the worker's profile projection current even when the flag was disabled.
        self._snapshot_profile(config, profile)
        source = trusted_source(tool_context)
        for key in ("user_id", "chat_id", "thread_id", "message_id"):
            value = source.get(key)
            if value is not None and (
                len(value) > 512 or any(ord(char) < 32 for char in value)
            ):
                raise RouterConfigError("source_unavailable")
        store = _store(config)
        for connector in config.connectors:
            store.upsert_connector(
                connector.connector_id,
                connector.profile,
                connector.platform,
                connector.label,
                connector.enabled,
            )
        return source, profile, config, store

    def _snapshot_profile(
        self,
        config: RouterConfig,
        profile: str,
        *,
        runtime_config_snapshot: Mapping[str, Any] | None = None,
        registry_snapshot: Mapping[str, Any] | None = None,
    ) -> None:
        registry = (
            registry_snapshot
            if registry_snapshot is not None
            else self.ctx.get_config("registry", {})
        )
        if not isinstance(registry, Mapping):
            raise RouterConfigError("registry_unavailable")
        envelope = {
            "profile": profile,
            "runtime_router": (
                runtime_config_snapshot
                if runtime_config_snapshot is not None
                else self.ctx.get_config("runtime_router", {})
            ),
            "registry": registry,
            "updated_at": int(time.time()),
        }
        payload = json.dumps(
            envelope, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(payload) > 524288:
            raise RouterConfigError("router_config_too_large")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", profile):
            raise RouterConfigError("profile_unavailable")
        previous_state_path = _read_profile_state_pointer(profile)
        if previous_state_path is not None and previous_state_path != config.state_path:
            invalid_payload = json.dumps(
                {
                    "profile": profile,
                    "runtime_router": {"__invalid_configuration__": True},
                    "registry": {
                        "connections": [],
                        "workspaces": [],
                        "routes": [],
                        "operator_grants": [],
                        "route_grants": [],
                    },
                    "updated_at": int(time.time()),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            _write_profile_snapshot_file(
                previous_state_path.parent / "profiles", profile, invalid_payload
            )
        # Remember the last validated shared state path in Hermes-owned profile
        # storage. If the config later disappears or becomes invalid, registration
        # can still replace the worker snapshot at its previous location.
        _write_profile_state_pointer(config, profile)
        _write_profile_snapshot_file(
            config.state_path.parent / "profiles", profile, payload
        )

    def create(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            source, profile, config, store = self._context(tool_context)
            if not config.enabled:
                raise RouterConfigError("runtime_router_disabled")
            allowed = {
                "route_id",
                "title",
                "description",
                "project_id",
                "priority",
                "explicit_runtime_id",
                "explicit_model",
                "task_class",
                "parent_issue_id",
                "related_issue_ids",
                "condition_wake",
            }
            if not isinstance(args, dict) or set(args) - allowed:
                raise RouterConfigError("invalid_arguments")
            route_id = args.get("route_id")
            if (
                not isinstance(route_id, str)
                or not isinstance(args.get("title"), str)
                or not args["title"].strip()
            ):
                raise RouterConfigError("invalid_arguments")
            if len(args["title"]) > 512 or not isinstance(
                args.get("description", ""), str
            ):
                raise RouterConfigError("invalid_arguments")
            if len(args.get("description", "").encode("utf-8")) > _LIMIT:
                raise RouterConfigError("payload_too_large")
            priority = args.get("priority", "medium")
            if not isinstance(priority, str) or priority not in _PRIORITY_RANK:
                raise RouterConfigError("invalid_arguments")
            explicit_runtime = args.get("explicit_runtime_id")
            if explicit_runtime is not None and (
                not isinstance(explicit_runtime, str) or not explicit_runtime
            ):
                raise RouterConfigError("invalid_arguments")
            explicit_model = args.get("explicit_model")
            if explicit_model is not None and (
                not isinstance(explicit_model, str)
                or not explicit_model
                or explicit_model != explicit_model.strip()
                or len(explicit_model) > 128
            ):
                raise RouterConfigError("invalid_arguments")
            task_class = args.get("task_class")
            if task_class is not None and (
                not isinstance(task_class, str)
                or not task_class
                or task_class != task_class.strip()
                or len(task_class) > 128
                or any(ord(char) < 32 for char in task_class)
            ):
                raise RouterConfigError("invalid_arguments")
            parent_id = args.get("parent_issue_id")
            if parent_id is not None and (
                not isinstance(parent_id, str) or not _IDENTIFIER.fullmatch(parent_id)
            ):
                raise RouterConfigError("invalid_arguments")
            condition_spec = parse_condition_wake(args["condition_wake"]) if "condition_wake" in args else None
            if condition_spec is not None and parent_id is not None:
                raise RouterConfigError("condition_wake_invalid")
            related = args.get("related_issue_ids", [])
            if (
                not isinstance(related, list)
                or len(related) > 16
                or any(
                    not isinstance(item, str) or not _IDENTIFIER.fullmatch(item)
                    for item in related
                )
                or len(set(related)) != len(related)
            ):
                raise RouterConfigError("invalid_arguments")
            registry = WorkspaceRuntime(self.ctx)._registry()
            route = WorkspaceRuntime(self.ctx)._route(registry, tool_context, route_id)
            if not route.runtime_router_enabled:
                raise RouterConfigError("runtime_router_route_disabled")
            agent = config.agent(route.runtime_router_agent_ref)
            if agent.instance_id != route.instance_id:
                raise RouterConfigError("route_instance_mismatch")
            instance = config.instance(agent.instance_id)
            workspace = registry.workspace(route.workspace_key)
            if workspace.workspace_id != instance.workspace_id:
                raise RouterConfigError("route_instance_mismatch")
            project_id = args.get("project_id")
            if route.project_selection == "all_workspace" and not project_id:
                raise RouterConfigError("project_required")
            project_id = project_id or route.default_project_id or route.project_id
            if not isinstance(project_id, str) or not _IDENTIFIER.fullmatch(project_id):
                raise RouterConfigError("route_project_not_allowed")
            if route.project_selection == "allowlist" and project_id not in set(
                route.project_ids
            ):
                raise RouterConfigError("route_project_not_allowed")

            connector = config.connector_for(profile, source["platform"])
            identity = store.identity(connector.connector_id, source["user_id"])
            if identity is None:
                raise RouterConfigError("principal_unresolved")
            if identity["principal_id"] not in agent.allowed_principal_ids:
                raise RouterConfigError("runtime_not_allowed")
            cli = MulticaCliAdapter(
                binary=config.cli_binary,
                home=str(service_cli_home(config)),
                timeout=config.cli_timeout_seconds,
                spool_root=config.state_path.parent / "runtime-router-spool",
            )
            binding = store.binding(identity["principal_id"], agent.instance_id)
            if binding is None:
                if config.unbound_policy != "keep_current":
                    raise RouterConfigError("runtime_unbound")
                current_agent = cli.agent_get(instance, agent.agent_id)
                binding = {
                    "principal_id": identity["principal_id"],
                    "instance_id": agent.instance_id,
                    "default_runtime_id": current_agent["runtime_id"],
                    "mode": "strict",
                    "strict_until": None,
                }
            if route.project_selection not in {"allowlist", "all_workspace"}:
                raise RouterConfigError("route_project_not_allowed")
            project = cli.project_get(instance, project_id)
            if project.get("workspace_id") != workspace.workspace_id:
                raise RouterConfigError("route_project_not_allowed")
            if condition_spec is not None:
                WorkspaceRuntime(self.ctx)._condition_wake_preflight(registry, route, project_id)
            if parent_id:
                parent = cli.issue_get(instance, parent_id)
                if (
                    parent.get("workspace_id") != workspace.workspace_id
                    or parent.get("project_id") != project_id
                ):
                    raise RouterConfigError("parent_issue_scope_invalid")
            catalog = cli.runtime_list(instance)
            runtime_catalog = {
                row["id"]: {**row, "instance_id": agent.instance_id}
                for row in catalog
                if isinstance(row.get("id"), str)
            }
            binding_id = binding.get("binding_id")
            rules = (
                store.exceptions(binding_id)
                if isinstance(binding_id, str) and binding_id
                else []
            )
            resolution = resolve_runtime(
                identity=identity,
                binding=binding,
                exceptions=rules,
                context={
                    **source,
                    "agent_id": agent.agent_id,
                    "workspace_id": workspace.workspace_id,
                    "project_id": project_id,
                    "instance_id": agent.instance_id,
                    "squad_id": route.squad_id,
                    "task_class": task_class,
                },
                allowed_runtime_ids=set(agent.allowed_runtime_ids),
                runtime_catalog=runtime_catalog,
                model_by_runtime=agent.model_by_runtime,
                model_policy=config.model_policy,
                allowed_models_by_runtime=agent.allowed_models_by_runtime,
                explicit_model=explicit_model,
                explicit_runtime_id=explicit_runtime,
            )

            attachments: list[dict[str, Any]] = []
            validated_attachments: list[tuple[str, str, str, bytes]] = []
            spool: AttachmentSpool | None = None
            ctx_message = _load_hermes_context(include_attachments=True)
            if trusted_source(ctx_message.source) != source:
                raise BridgeError(
                    "source_unavailable",
                    "The attachment context is not bound to this message.",
                )
            if ctx_message.attachments or route.require_source_attachment:
                workspace_runtime = WorkspaceRuntime(self.ctx)
                validated = workspace_runtime._attachments(ctx_message, route)
                if validated:
                    spool = AttachmentSpool(
                        config.state_path.parent / "runtime-router-spool"
                    )
                validated_attachments = validated
            source_key = "\0".join(
                str(source.get(key) or "")
                for key in ("platform", "user_id", "chat_id", "thread_id", "message_id")
            )
            idem = hashlib.sha256(
                (
                    profile
                    + "\0"
                    + route.route_id
                    + "\0"
                    + agent.instance_id
                    + "\0"
                    + source_key
                ).encode()
            ).hexdigest()
            with spool.locked() if spool else nullcontext():
                if spool and validated_attachments:
                    attachments = spool.store_locked(
                        validated_attachments,
                        maximum_total=route.max_attachment_bytes,
                    )
                payload = {
                    "title": args["title"].strip(),
                    "description": args.get("description", ""),
                    "priority": priority,
                    "parent_issue_id": parent_id,
                    "related_issue_ids": related,
                    "condition_wake": condition_spec.canonical() if condition_spec else None,
                    "attachments": attachments,
                    "explicit_runtime_id": explicit_runtime,
                    "explicit_model": explicit_model,
                    "task_class": task_class,
                    "source": {"profile": profile, **source},
                    "route_policy_hash": route_request_policy_hash(
                        route_policy_fingerprint(registry, route), project_id
                    ),
                }
                try:
                    request, created = store.enqueue(
                        request_id=new_id(),
                        key=idem,
                        principal_id=identity["principal_id"],
                        connector_id=connector.connector_id,
                        instance_id=agent.instance_id,
                        agent_id=agent.agent_id,
                        agent_ref=agent.agent_ref,
                        route_id=route.route_id,
                        project_id=project_id,
                        payload=payload,
                        priority=_PRIORITY_RANK[priority],
                        runtime_id=resolution.runtime_id,
                        model=resolution.model,
                        model_rule_id=resolution.model_rule_id,
                        model_source=resolution.model_source,
                        model_reason=resolution.model_reason,
                        resolution={
                            "rule_id": resolution.rule_id,
                            "reason": resolution.reason,
                            "source": resolution.source,
                            "runtime_id": resolution.runtime_id,
                            "model": resolution.model,
                            "model_rule_id": resolution.model_rule_id,
                            "model_source": resolution.model_source,
                            "model_reason": resolution.model_reason,
                            "capability_source": resolution.capability_source,
                        },
                    )
                except _SAFE_FAILURES:
                    self._cleanup_unreferenced_attachments_locked(
                        store, spool, attachments
                    )
                    raise
                if not created:
                    self._cleanup_unreferenced_attachments_locked(
                        store, spool, attachments
                    )
            if created:
                store.record_event(
                    request["request_id"],
                    "resolved",
                    actor=identity["principal_id"],
                    runtime_id=resolution.runtime_id,
                    rule_id=resolution.rule_id,
                )
                if resolution.reason == "strict_expired_fallback":
                    store.record_event(
                        request["request_id"],
                        "strict_expired",
                        actor=identity["principal_id"],
                        runtime_id=resolution.runtime_id,
                    )
                store.record_event(
                    request["request_id"],
                    "queued",
                    actor=identity["principal_id"],
                    runtime_id=resolution.runtime_id,
                    rule_id=resolution.rule_id,
                )
            return _reply(
                {
                    "ok": True,
                    "request_id": request["request_id"],
                    "state": request["state"],
                    "queue_position": self._queue_position(
                        store, request["request_id"]
                    ),
                    "resolved_runtime_id": request["target_runtime_id"],
                    "resolved_model": request.get("target_model"),
                    "principal_id": identity["principal_id"],
                    "duplicate": not created,
                }
            )
        except RouterConfigError as exc:
            return _error(str(exc))
        except ResolutionError as exc:
            return _error(exc.code)
        except MulticaCliError as exc:
            return _error(exc.code)
        except BridgeError as exc:
            return _error(exc.code, exc.message)
        except _SAFE_FAILURES:
            return _error("internal_error")

    @staticmethod
    def _cleanup_unreferenced_attachments(
        store: RouterStore,
        spool: AttachmentSpool | None,
        attachments: list[dict[str, Any]],
    ) -> None:
        if spool is None or not attachments:
            return
        with spool.locked():
            RuntimeRouterTools._cleanup_unreferenced_attachments_locked(
                store, spool, attachments
            )

    @staticmethod
    def _cleanup_unreferenced_attachments_locked(
        store: RouterStore,
        spool: AttachmentSpool | None,
        attachments: list[dict[str, Any]],
    ) -> None:
        if spool is None or not attachments:
            return
        try:
            referenced = store.active_attachment_paths()
        except (OSError, ValueError, TypeError, sqlite3.Error):
            return
        spool.cleanup_locked(
            [item for item in attachments if item.get("path") not in referenced]
        )

    @staticmethod
    def _queue_position(store: RouterStore, request_id: str) -> int:
        return store.queue_position(request_id)

    def status(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            source, profile, config, store = self._context(tool_context)
            if not isinstance(args, dict) or set(args) - {"request_id"}:
                raise RouterConfigError("invalid_arguments")
            connector = config.connector_for(profile, source["platform"])
            operator = config.is_operator(connector.connector_id, source["user_id"])
            identity = store.identity(connector.connector_id, source["user_id"])
            if identity is None and not operator:
                raise RouterConfigError("principal_unresolved")
            request_id = args.get("request_id")
            if request_id is not None and (
                not isinstance(request_id, str) or not request_id
            ):
                raise RouterConfigError("invalid_arguments")
            row = store.get(request_id) if request_id else None
            if request_id and (
                row is None
                or not operator
                and row["principal_id"] != identity["principal_id"]
            ):
                raise RouterConfigError("route_denied")
            metrics = store.runtime_metrics(
                None if operator else identity["principal_id"]
            )
            result: dict[str, Any] = {
                "ok": True,
                "queue_depth": metrics["queue_depth"],
                "active": metrics["active"],
                "worker_heartbeat_at": metrics["worker_heartbeat_at"],
                "worker_state": (metrics["worker"] or {}).get("state"),
                "worker_stale": self._worker_stale(
                    metrics["worker"], config.tick_seconds
                ),
            }
            if row:
                result["request"] = {
                    key: row[key]
                    for key in (
                        "request_id",
                        "state",
                        "issue_id",
                        "target_runtime_id",
                        "last_error_code",
                        "created_at",
                        "updated_at",
                    )
                }
                try:
                    agent = config.agent(row["agent_ref"])
                    instance = config.instance(row["instance_id"])
                    current = MulticaCliAdapter(
                        binary=config.cli_binary,
                        home=str(service_cli_home(config)),
                        timeout=config.cli_timeout_seconds,
                    ).agent_get(instance, agent.agent_id)
                    result["request"]["current_runtime_id"] = current["runtime_id"]
                    result["request"]["current_model"] = current.get("model")
                except (RouterConfigError, MulticaCliError, KeyError, TypeError):
                    result["request"]["current_runtime_status"] = "unavailable"
            elif not operator:
                result["requests"] = store.list_requests_for_principal(
                    identity["principal_id"]
                )
            if operator:
                result["states"] = metrics["states"]
            return _reply(result)
        except RouterConfigError as exc:
            return _error(str(exc))
        except _SAFE_FAILURES:
            return _error("internal_error")

    @staticmethod
    def _worker_stale(worker: dict[str, Any] | None, tick_seconds: int) -> bool:
        if not worker or worker.get("state") == "error":
            return True
        heartbeat = worker.get("heartbeat_at")
        return type(heartbeat) is not int or time.time() - heartbeat > max(
            90, tick_seconds * 3
        )

    def cancel(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            source, profile, config, store = self._context(tool_context)
            if not isinstance(args, dict) or set(args) != {"request_id"}:
                raise RouterConfigError("invalid_arguments")
            request_id = args.get("request_id")
            if not isinstance(request_id, str) or not request_id:
                raise RouterConfigError("invalid_arguments")
            connector = config.connector_for(profile, source["platform"])
            identity = store.identity(connector.connector_id, source["user_id"])
            operator = config.is_operator(connector.connector_id, source["user_id"])
            row = store.get(request_id)
            if (
                row is None
                or identity is None
                and not operator
                or not operator
                and row["principal_id"] != identity["principal_id"]
            ):
                raise RouterConfigError("route_denied")
            state = store.cancel(request_id)
            if state == "cancelled":
                try:
                    payload = json.loads(row["payload_json"])
                    self._cleanup_unreferenced_attachments(
                        store,
                        AttachmentSpool(
                            config.state_path.parent / "runtime-router-spool"
                        ),
                        payload.get("attachments", []),
                    )
                except (ValueError, TypeError, OSError, RouterConfigError):
                    pass
            return _reply({"ok": True, "request_id": request_id, "state": state})
        except RouterConfigError as exc:
            return _error(str(exc))
        except _SAFE_FAILURES:
            return _error("internal_error")

    def bindings(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if not isinstance(args, dict) or args:
                raise RouterConfigError("invalid_arguments")
            source, profile, config, store = self._context(tool_context)
            connector = config.connector_for(profile, source["platform"])
            identity = store.identity(connector.connector_id, source["user_id"])
            if identity is None:
                raise RouterConfigError("principal_unresolved")
            with store.connect() as db:
                rows = [
                    dict(r)
                    for r in db.execute(
                        "SELECT binding_id,instance_id,default_runtime_id,mode,strict_until,updated_at FROM runtime_bindings WHERE principal_id=? ORDER BY instance_id",
                        (identity["principal_id"],),
                    )
                ]
            return _reply({"ok": True, "bindings": rows})
        except RouterConfigError as exc:
            return _error(str(exc))
        except _SAFE_FAILURES:
            return _error("internal_error")

    def binding_set(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            source, profile, config, store = self._context(tool_context)
            if not isinstance(args, dict):
                raise RouterConfigError("invalid_arguments")
            if set(args) - {"instance_id", "runtime_id", "mode", "strict_until"}:
                raise RouterConfigError("invalid_arguments")
            connector = config.connector_for(profile, source["platform"])
            identity = store.identity(connector.connector_id, source["user_id"])
            if identity is None:
                raise RouterConfigError("principal_unresolved")
            instance_id, runtime_id, mode = (
                args.get("instance_id"),
                args.get("runtime_id"),
                args.get("mode"),
            )
            if (
                not isinstance(instance_id, str)
                or not isinstance(runtime_id, str)
                or mode not in {"strict", "exceptions"}
            ):
                raise RouterConfigError("invalid_arguments")
            if not any(
                runtime_id in a.allowed_runtime_ids
                and a.instance_id == instance_id
                and identity["principal_id"] in a.allowed_principal_ids
                for a in config.agents
            ):
                raise RouterConfigError("runtime_not_allowed")
            strict_until = args.get("strict_until")
            if strict_until is not None and not _aware_timestamp(strict_until):
                raise RouterConfigError("invalid_arguments")
            instance = config.instance(instance_id)
            runtime_rows = MulticaCliAdapter(
                binary=config.cli_binary,
                home=str(service_cli_home(config)),
                timeout=config.cli_timeout_seconds,
            ).runtime_list(instance)
            selected = next(
                (row for row in runtime_rows if row["id"] == runtime_id), None
            )
            if selected is None:
                raise RouterConfigError("runtime_not_available_in_instance")
            if selected.get("accessible") is not True:
                raise RouterConfigError("runtime_not_accessible")
            if selected.get("status") != "online":
                raise RouterConfigError("runtime_offline")
            binding = store.binding(identity["principal_id"], instance_id)
            store.set_binding(
                binding["binding_id"] if binding else new_id(),
                identity["principal_id"],
                instance_id,
                runtime_id,
                mode,
                strict_until,
                identity["principal_id"],
            )
            return _reply(
                {
                    "ok": True,
                    "instance_id": instance_id,
                    "runtime_id": runtime_id,
                    "mode": mode,
                }
            )
        except RouterConfigError as exc:
            return _error(str(exc))
        except MulticaCliError as exc:
            return _error(exc.code)
        except _SAFE_FAILURES:
            return _error("internal_error")

    def queue(self, args: dict[str, Any], *, tool_context: Any = None) -> str:
        try:
            if not isinstance(args, dict) or set(args) - {"limit"}:
                raise RouterConfigError("invalid_arguments")
            source, profile, config, store = self._context(tool_context)
            connector = config.connector_for(profile, source["platform"])
            if not config.is_operator(connector.connector_id, source["user_id"]):
                raise RouterConfigError("operator_required")
            limit = args.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 500:
                raise RouterConfigError("invalid_arguments")
            return _reply({"ok": True, "requests": store.list_queue(limit)})
        except RouterConfigError as exc:
            return _error(str(exc))
        except _SAFE_FAILURES:
            return _error("internal_error")


def register_tools(ctx: Any) -> None:
    runtime = RuntimeRouterTools(ctx)
    raw_router = ctx.get_config("runtime_router", None)
    profile = getattr(ctx, "profile_name", None) or "default"
    try:
        if raw_router is None:
            _disable_profile_snapshot(runtime, profile, raw_router)
        else:
            config = RouterConfig.parse(raw_router)
            runtime._snapshot_profile(config, profile)
    except (RouterConfigError, OSError, ValueError, TypeError, AttributeError):
        # Replace any previous usable snapshot with an invalid, disabled marker.
        # The worker deliberately skips this profile instead of reusing stale policy.
        _disable_profile_snapshot(runtime, profile, raw_router)
    specs = [
        (
            "multica_runtime_task_create",
            "Queue a task for the configured canonical agent and its resolved runtime.",
            {
                "route_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "project_id": {"type": "string"},
                "priority": {"type": "string", "enum": list(_PRIORITY_RANK)},
                "explicit_runtime_id": {"type": "string"},
                "explicit_model": {"type": "string"},
                "task_class": {"type": "string"},
                "parent_issue_id": {"type": "string"},
                "related_issue_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 16,
                },
                "condition_wake": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "mode": {"type": "string", "enum": ["children_done"]},
                        "instruction": {"type": "string", "maxLength": 2000},
                        "stage": {"type": "integer", "minimum": 1},
                        "expected_stage_count": {"type": "integer", "minimum": 1},
                        "expires_in": {"type": "string", "pattern": "^[1-9][0-9]{0,5}(s|m|h|d)$"},
                        "expires_at": {"type": ["string", "integer"]},
                        "on_timeout": {"type": "string", "enum": ["wake", "end"]},
                    },
                    "required": ["enabled", "instruction"],
                    "additionalProperties": False,
                },
            },
            ["route_id", "title"],
            runtime.create,
        ),
        (
            "multica_runtime_cancel",
            "Cancel a queued request or request cancellation of active work. The agent stays locked until terminal confirmation.",
            {"request_id": {"type": "string"}},
            ["request_id"],
            runtime.cancel,
        ),
        (
            "multica_runtime_status",
            "Read your requests, queue depth, active work, and worker heartbeat; operators can inspect the full queue.",
            {"request_id": {"type": "string"}},
            [],
            runtime.status,
        ),
        (
            "multica_runtime_bindings_list",
            "List your runtime bindings.",
            {},
            [],
            runtime.bindings,
        ),
        (
            "multica_runtime_binding_set",
            "Set your own default runtime and routing mode within the operator-approved runtime allowlist.",
            {
                "instance_id": {"type": "string"},
                "runtime_id": {"type": "string"},
                "mode": {"type": "string", "enum": ["strict", "exceptions"]},
                "strict_until": {"type": "string"},
            },
            ["instance_id", "runtime_id", "mode"],
            runtime.binding_set,
        ),
        (
            "multica_runtime_queue_list",
            "Operator-only queue summary.",
            {"limit": {"type": "integer", "minimum": 1, "maximum": 500}},
            [],
            runtime.queue,
        ),
    ]
    for name, description, properties, required, handler in specs:
        ctx.register_tool(
            name=name,
            toolset="hermes_multica_bridge",
            schema={
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
            },
            handler=handler,
        )


def _disable_profile_snapshot(
    runtime: RuntimeRouterTools, profile: str, raw_router: Any
) -> None:
    """Fail closed at the last validated snapshot location after bad config."""
    try:
        state_path = _read_profile_state_pointer(profile)
    except RouterConfigError as exc:
        # Lightweight plugin validators and unit-test contexts may register this
        # feature-off plugin without Hermes storage APIs. With no configured path,
        # there is no known prior snapshot to invalidate in those environments.
        if raw_router is None and str(exc) == "plugin_storage_unavailable":
            return
        raise
    if state_path is None and isinstance(raw_router, Mapping):
        candidate = raw_router.get("state_path")
        if isinstance(candidate, str):
            try:
                state_path = RouterConfig.parse(
                    {"enabled": False, "state_path": candidate}
                ).state_path
            except RouterConfigError:
                state_path = None
    if state_path is None:
        return
    config = RouterConfig.parse(
        {"enabled": False, "state_path": str(state_path)}
    )
    runtime._snapshot_profile(
        config,
        profile,
        runtime_config_snapshot={"__invalid_configuration__": True},
        registry_snapshot={
            "connections": [],
            "workspaces": [],
            "routes": [],
            "operator_grants": [],
            "route_grants": [],
        },
    )
