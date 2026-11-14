"""One bounded worker tick; the timer, not the Gateway, owns scheduling."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from bridge.errors import BridgeError
from bridge.registry import registry_from_mapping

from .adapter import MulticaCliAdapter, MulticaCliError
from .config import Connector, RouterConfig, RouterConfigError, service_cli_home
from .policy import ResolutionError, resolve_runtime, route_request_policy_hash
from .spool import AttachmentSpool
from .state import RouterStore

_SNAPSHOT_MAX = 524_288


class RouterWorker:
    """Process at most one queued request and reconcile already active rows."""

    def __init__(
        self,
        config: RouterConfig,
        *,
        adapter: MulticaCliAdapter | None = None,
        owner: str | None = None,
    ):
        self.config = config
        self.store = RouterStore(config.state_path)
        self.adapter = adapter or MulticaCliAdapter(
            binary=config.cli_binary,
            home=str(service_cli_home(config)),
            timeout=config.cli_timeout_seconds,
            spool_root=config.state_path.parent / "runtime-router-spool",
        )
        self.owner = owner or f"{os.getpid()}"
        self.profile_dir = config.state_path.parent / "profiles"

    def _read_snapshot(self, path: Path) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError:
            raise RouterConfigError("router_profile_snapshot_unavailable") from None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > _SNAPSHOT_MAX
            ):
                raise RouterConfigError("router_profile_snapshot_unsafe")
            chunks = bytearray()
            while len(chunks) <= _SNAPSHOT_MAX:
                block = os.read(fd, min(65536, _SNAPSHOT_MAX + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > _SNAPSHOT_MAX:
                raise RouterConfigError("router_profile_snapshot_too_large")
        finally:
            os.close(fd)
        try:
            value = json.loads(chunks)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise RouterConfigError("router_profile_snapshot_invalid") from None
        if not isinstance(value, dict):
            raise RouterConfigError("router_profile_snapshot_invalid")
        return value

    def _profile_snapshots(
        self,
    ) -> tuple[RouterConfig, dict[str, dict[str, Any]], set[str]]:
        try:
            info = self.profile_dir.lstat()
        except FileNotFoundError:
            raise RouterConfigError("router_profile_snapshots_unavailable") from None
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RouterConfigError("router_profile_snapshot_directory_unsafe")
        snapshots: dict[str, dict[str, Any]] = {}
        configs: list[RouterConfig] = []
        for path in sorted(self.profile_dir.glob("*.json")):
            try:
                snapshot = self._read_snapshot(path)
                profile = snapshot.get("profile")
                if (
                    not isinstance(profile, str)
                    or path.name != f"{profile}.json"
                    or not isinstance(snapshot.get("registry"), dict)
                    or type(snapshot.get("updated_at")) is not int
                    or snapshot["updated_at"] > int(time.time()) + 60
                ):
                    continue
                registry_from_mapping(snapshot["registry"])
                router_config = RouterConfig.parse(snapshot.get("runtime_router"))
                if router_config.state_path != self.config.state_path:
                    continue
            except (RouterConfigError, BridgeError, OSError, ValueError, TypeError):
                # A broken profile is disabled without preventing another profile from draining.
                continue
            snapshots[profile] = snapshot
            configs.append(router_config)
        if not configs:
            raise RouterConfigError("router_profile_snapshots_unavailable")
        base = configs[0]
        for item in configs[1:]:
            if (
                item.tick_seconds != base.tick_seconds
                or item.lease_seconds != base.lease_seconds
                or item.cli_binary != base.cli_binary
                or item.cli_timeout_seconds != base.cli_timeout_seconds
                or item.worker_profile != base.worker_profile
                or item.unbound_policy != base.unbound_policy
                or item.kanban_mirror != base.kanban_mirror
            ):
                raise RouterConfigError("profile_router_configuration_inconsistent")
        instances_by_id: dict[str, Any] = {}
        agents_by_ref: dict[str, Any] = {}
        canonical_agents: set[tuple[str, str]] = set()
        for item in configs:
            for instance in item.instances:
                previous = instances_by_id.get(instance.instance_id)
                if previous is not None and previous != instance:
                    raise RouterConfigError(
                        "profile_instance_configuration_inconsistent"
                    )
                instances_by_id[instance.instance_id] = instance
            for agent in item.agents:
                previous = agents_by_ref.get(agent.agent_ref)
                if previous is not None and previous != agent:
                    raise RouterConfigError("profile_agent_configuration_inconsistent")
                identity = (agent.instance_id, agent.agent_id)
                if identity in canonical_agents and previous is None:
                    raise RouterConfigError("canonical_agent_duplicate")
                canonical_agents.add(identity)
                agents_by_ref[agent.agent_ref] = agent
        connectors_by_id: dict[str, Connector] = {}
        connector_slots: set[tuple[str, str]] = set()
        operators: set[tuple[str, str]] = set()
        for item in configs:
            for connector in item.connectors:
                previous = connectors_by_id.get(connector.connector_id)
                if previous and previous != connector:
                    raise RouterConfigError(
                        "profile_connector_configuration_inconsistent"
                    )
                slot = (connector.profile, connector.platform)
                if (
                    slot in connector_slots
                    and connector.connector_id not in connectors_by_id
                ):
                    raise RouterConfigError("connector_ambiguous")
                connector_slots.add(slot)
                connectors_by_id[connector.connector_id] = connector
            operators.update(item.operator_identities)
        enabled_profiles = {
            profile
            for profile, snapshot in snapshots.items()
            if RouterConfig.parse(snapshot["runtime_router"]).enabled
        }
        merged = replace(
            base,
            connectors=tuple(connectors_by_id.values()),
            instances=tuple(instances_by_id.values()),
            agents=tuple(agents_by_ref.values()),
            operator_identities=tuple(sorted(operators)),
            enabled=bool(enabled_profiles),
        )
        return merged, snapshots, enabled_profiles

    @staticmethod
    def _route(
        snapshot: dict[str, Any], route_id: str, source: dict[str, Any]
    ) -> tuple[Any, Any]:
        registry = registry_from_mapping(snapshot.get("registry"))
        route = registry.route(route_id)
        if (
            route not in registry.authorized_workspace_routes(source)
            or not route.runtime_router_enabled
        ):
            raise RouterConfigError("route_denied")
        return registry, route

    @staticmethod
    def _policy_hash(registry: Any, route: Any, project_id: str) -> str:
        from bridge.registry import route_policy_fingerprint

        return route_request_policy_hash(
            route_policy_fingerprint(registry, route), project_id
        )

    def _resolution(
        self,
        config: RouterConfig,
        request: dict[str, Any],
        route: Any,
        payload: dict[str, Any],
        registry: Any,
    ) -> Any:
        source = payload.get("source")
        if not isinstance(source, dict):
            raise RouterConfigError("request_context_invalid")
        profile = source.get("profile")
        platform = source.get("platform")
        user_id = source.get("user_id")
        if not all(
            isinstance(value, str) and value for value in (profile, platform, user_id)
        ):
            raise RouterConfigError("request_context_invalid")
        connector = config.connector_for(profile, platform)
        if connector.connector_id != request["connector_id"]:
            raise RouterConfigError("connector_unresolved")
        identity = self.store.identity(connector.connector_id, user_id)
        if identity is None or identity["principal_id"] != request["principal_id"]:
            raise RouterConfigError("principal_unresolved")
        agent = config.agent(request["agent_ref"])
        if (
            identity["principal_id"] not in agent.allowed_principal_ids
            or agent.agent_id != request["agent_id"]
        ):
            raise RouterConfigError("runtime_not_allowed")
        instance = config.instance(request["instance_id"])
        workspace = registry.workspace(route.workspace_key)
        if (
            route.instance_id != agent.instance_id
            or route.runtime_router_agent_ref != agent.agent_ref
            or workspace.workspace_id != instance.workspace_id
        ):
            raise RouterConfigError("route_instance_mismatch")
        project_id = request["project_id"]
        if not isinstance(project_id, str) or not project_id:
            raise RouterConfigError("route_project_not_allowed")
        if route.project_selection == "allowlist":
            if project_id not in set(route.project_ids):
                raise RouterConfigError("route_project_not_allowed")
        elif route.project_selection != "all_workspace":
            raise RouterConfigError("route_project_not_allowed")
        project = self.adapter.project_get(instance, project_id)
        if project.get("workspace_id") != workspace.workspace_id:
            raise RouterConfigError("route_project_not_allowed")
        expected_hash = self._policy_hash(registry, route, project_id)
        if expected_hash != payload.get("route_policy_hash"):
            raise RouterConfigError("route_policy_changed")
        binding = self.store.binding(identity["principal_id"], agent.instance_id)
        if binding is None:
            if config.unbound_policy != "keep_current" or not request.get(
                "target_runtime_id"
            ):
                raise RouterConfigError("runtime_unbound")
            binding = {
                "principal_id": identity["principal_id"],
                "instance_id": agent.instance_id,
                "default_runtime_id": request["target_runtime_id"],
                "mode": "strict",
                "strict_until": None,
            }
        catalog_rows = self.adapter.runtime_list(instance)
        # Operator-owned allowed_runtime_ids are the explicit record of runtime sharing approval.
        catalog = {
            row["id"]: {
                **row,
                "instance_id": agent.instance_id,
                "accessible": row["id"] in agent.allowed_runtime_ids,
            }
            for row in catalog_rows
        }
        binding_id = binding.get("binding_id")
        exceptions = (
            self.store.exceptions(binding_id)
            if isinstance(binding_id, str) and binding_id
            else []
        )
        resolution = resolve_runtime(
            identity=identity,
            binding=binding,
            exceptions=exceptions,
            context={
                **source,
                "agent_id": agent.agent_id,
                "workspace_id": workspace.workspace_id,
                "project_id": project_id,
                "instance_id": agent.instance_id,
                "squad_id": route.squad_id,
            },
            allowed_runtime_ids=set(agent.allowed_runtime_ids),
            runtime_catalog=catalog,
            model_by_runtime=agent.model_by_runtime,
            explicit_runtime_id=payload.get("explicit_runtime_id"),
        )
        if (
            resolution.runtime_id != request["target_runtime_id"]
            or resolution.model != request["target_model"]
        ):
            raise RouterConfigError("request_resolution_changed")
        return resolution

    @staticmethod
    def _validate_issue(
        issue: dict[str, Any], request: dict[str, Any], agent: Any, instance: Any
    ) -> None:
        marker = f"<!-- router-request:{request['request_id']} -->"
        if (
            issue.get("project_id") != request["project_id"]
            or issue.get("workspace_id") != instance.workspace_id
            or issue.get("assignee_id") != agent.agent_id
            or marker not in str(issue.get("description", ""))
        ):
            raise MulticaCliError("issue_readback_mismatch", uncertain=True)

    def _event(
        self,
        request_id: str,
        event: str,
        *,
        error: str | None = None,
        issue_id: str | None = None,
        agent_id: str | None = None,
        runtime_id: str | None = None,
    ) -> None:
        self.store.record_event(
            request_id,
            event,
            error=error,
            issue_id=issue_id,
            agent_id=agent_id,
            runtime_id=runtime_id,
        )

    def _cleanup_terminal_attachments(self, request: dict[str, Any]) -> None:
        try:
            payload = json.loads(request["payload_json"])
            attachments = payload.get("attachments", [])
            spool = AttachmentSpool(
                self.config.state_path.parent / "runtime-router-spool"
            )
            with spool.locked():
                referenced = self.store.active_attachment_paths()
                unreferenced = [
                    item
                    for item in attachments
                    if item.get("path") not in referenced
                ]
                spool.cleanup_locked(unreferenced)
        except (KeyError, TypeError, ValueError, RouterConfigError, sqlite3.Error):
            return

    def _terminal_sweep(
        self,
        config: RouterConfig,
        snapshots: dict[str, dict[str, Any]],
        enabled_profiles: set[str],
    ) -> int:
        changed = 0
        for request in self.store.active(limit=100):
            if request["state"] not in {"waiting", "reconciling", "cancelling"}:
                continue
            try:
                current_config, current_snapshots, _enabled = self._profile_snapshots()
                payload = json.loads(request["payload_json"])
                source = payload["source"]
                if source.get("profile") not in enabled_profiles:
                    continue
                snapshot = current_snapshots.get(source["profile"])
                if snapshot is None:
                    continue
                agent = current_config.agent(request["agent_ref"])
                instance = current_config.instance(request["instance_id"])
                if (
                    agent.agent_id != request["agent_id"]
                    or agent.instance_id != request["instance_id"]
                ):
                    continue
                state = request["state"]
                issue_id = request.get("issue_id")
                cancel_source = request.get("cancel_source_state")
                if (
                    cancel_source is None
                    and request.get("last_error_code") == "cancel_requested"
                ):
                    # Conservative handling for a pre-v3 database row.
                    cancel_source = "reconciling"
                if state == "waiting":
                    if not issue_id:
                        self.store.transition(
                            request["request_id"],
                            "reconciling",
                            expected={"waiting"},
                            error="issue_id_missing",
                        )
                        continue
                    issue = self.adapter.issue_get(instance, issue_id)
                    self._validate_issue(issue, request, agent, instance)
                    status = str(issue.get("status", "")).lower()
                    if status == "canceled":
                        status = "cancelled"
                    if status not in {"done", "cancelled", "failed"}:
                        continue
                    if self.adapter.active_runs(
                        self.adapter.agent_runs(instance, agent.agent_id)
                    ):
                        continue
                    if self.store.transition(
                        request["request_id"],
                        status,
                        expected={"waiting"},
                        issue=issue,
                        error=None,
                    ):
                        self._event(
                            request["request_id"],
                            status,
                            issue_id=issue_id,
                            agent_id=agent.agent_id,
                        )
                        self._cleanup_terminal_attachments(request)
                        changed += 1
                elif state == "reconciling":
                    marker = f"<!-- router-request:{request['request_id']} -->"
                    issue = self.adapter.find_request_issue(
                        instance, marker, request["project_id"]
                    )
                    if issue and isinstance(issue.get("id"), str):
                        readback = self.adapter.issue_get(instance, issue["id"])
                        self._validate_issue(readback, request, agent, instance)
                        status = str(readback.get("status", "")).lower()
                        if status == "canceled":
                            status = "cancelled"
                        if status in {"done", "cancelled", "failed"}:
                            if self.adapter.active_runs(
                                self.adapter.agent_runs(instance, agent.agent_id)
                            ):
                                continue
                            if self.store.transition(
                                request["request_id"],
                                status,
                                expected={"reconciling"},
                                issue=readback,
                                error=None,
                            ):
                                self._event(
                                    request["request_id"],
                                    status,
                                    issue_id=issue["id"],
                                    agent_id=agent.agent_id,
                                )
                                self._cleanup_terminal_attachments(request)
                                changed += 1
                        elif cancel_source:
                            if self.store.transition(
                                request["request_id"],
                                "cancelling",
                                expected={"reconciling"},
                                issue=readback,
                                error=None,
                            ):
                                changed += 1
                        elif self.store.transition(
                            request["request_id"],
                            "waiting",
                            expected={"reconciling"},
                            issue=readback,
                            error=None,
                        ):
                            self._event(
                                request["request_id"],
                                "wait_started",
                                issue_id=issue["id"],
                                agent_id=agent.agent_id,
                            )
                            changed += 1
                    elif cancel_source == "switching":
                        runs = self.adapter.active_runs(
                            self.adapter.agent_runs(instance, agent.agent_id)
                        )
                        if not runs and self.store.transition(
                            request["request_id"],
                            "cancelled",
                            expected={"reconciling"},
                            error=None,
                        ):
                            self._event(
                                request["request_id"],
                                "cancelled",
                                agent_id=agent.agent_id,
                            )
                            self._cleanup_terminal_attachments(request)
                            changed += 1
                    elif not cancel_source and (
                        request.get("reconcile_source_state") == "switching"
                        or request.get("last_error_code") == "lease_expired:switching"
                    ):
                        # A switch may have succeeded even when its response was
                        # lost. No issue POST happens in `switching`, so after a
                        # complete marker search and run check it is safe to
                        # requeue and re-verify the canonical agent state.
                        runs = self.adapter.active_runs(
                            self.adapter.agent_runs(instance, agent.agent_id)
                        )
                        if not runs:
                            current_agent = self.adapter.agent_get(
                                instance, agent.agent_id
                            )
                            if (
                                current_agent.get("max_concurrent_tasks") == 1
                                and current_agent.get("runtime_id")
                                in agent.allowed_runtime_ids
                                and self.store.transition(
                                    request["request_id"],
                                    "queued",
                                    expected={"reconciling"},
                                    error=None,
                                )
                            ):
                                changed += 1
                else:  # cancelling
                    if issue_id:
                        issue = self.adapter.issue_get(instance, issue_id)
                        self._validate_issue(issue, request, agent, instance)
                        status = str(issue.get("status", "")).lower()
                        if status == "canceled":
                            status = "cancelled"
                        if status not in {"done", "cancelled", "failed"}:
                            issue = self.adapter.cancel_issue(instance, issue_id)
                            status = str(issue.get("status", "")).lower()
                            if status == "canceled":
                                status = "cancelled"
                            self._validate_issue(issue, request, agent, instance)
                        if (
                            status in {"done", "cancelled", "failed"}
                            and not self.adapter.active_runs(
                                self.adapter.agent_runs(instance, agent.agent_id)
                            )
                            and self.store.transition(
                                request["request_id"],
                                status,
                                expected={"cancelling"},
                                issue=issue,
                                error=None,
                            )
                        ):
                            self._event(
                                request["request_id"],
                                status,
                                issue_id=issue_id,
                                agent_id=agent.agent_id,
                            )
                            self._cleanup_terminal_attachments(request)
                            changed += 1
                    else:
                        marker = f"<!-- router-request:{request['request_id']} -->"
                        issue = self.adapter.find_request_issue(
                            instance, marker, request["project_id"]
                        )
                        if issue and isinstance(issue.get("id"), str):
                            readback = self.adapter.issue_get(instance, issue["id"])
                            self._validate_issue(readback, request, agent, instance)
                            status = str(readback.get("status", "")).lower()
                            if status == "canceled":
                                status = "cancelled"
                            if status not in {"done", "cancelled", "failed"}:
                                readback = self.adapter.cancel_issue(
                                    instance, issue["id"]
                                )
                                self._validate_issue(readback, request, agent, instance)
                                status = str(readback.get("status", "")).lower()
                                if status == "canceled":
                                    status = "cancelled"
                            if (
                                status in {"done", "cancelled", "failed"}
                                and not self.adapter.active_runs(
                                    self.adapter.agent_runs(instance, agent.agent_id)
                                )
                                and self.store.transition(
                                    request["request_id"],
                                    status,
                                    expected={"cancelling"},
                                    issue=readback,
                                    error=None,
                                )
                            ):
                                self._event(
                                    request["request_id"],
                                    status,
                                    issue_id=issue["id"],
                                    agent_id=agent.agent_id,
                                )
                                self._cleanup_terminal_attachments(request)
                                changed += 1
                    if not issue_id and not issue and cancel_source == "switching":
                        runs = self.adapter.active_runs(
                            self.adapter.agent_runs(instance, agent.agent_id)
                        )
                        if not runs and self.store.transition(
                            request["request_id"],
                            "cancelled",
                            expected={"cancelling"},
                            error=None,
                        ):
                            self._event(
                                request["request_id"],
                                "cancelled",
                                agent_id=agent.agent_id,
                            )
                            self._cleanup_terminal_attachments(request)
                            changed += 1
            except (
                RouterConfigError,
                MulticaCliError,
                ResolutionError,
                KeyError,
                TypeError,
                ValueError,
                sqlite3.Error,
                OSError,
            ):
                # Unknown state or revoked scope remains locked for an operator.
                continue
        return changed

    def _open_lock(self) -> Any:
        path = self.config.state_path.parent / "runtime-router.lock"
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(path, flags, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(fd)
            raise RouterConfigError("router_lock_permissions_unsafe")
        return os.fdopen(fd, "r+")

    def tick(self) -> dict[str, Any]:
        with self._open_lock() as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"ok": True, "busy": True, "processed": 0}
            self.store.record_worker_heartbeat(self.owner, "running")
            try:
                result = self._tick_locked()
            except Exception:
                # Preserve the terminal worker heartbeat on unexpected failures.
                self.store.record_worker_heartbeat(
                    self.owner, "error", error="router_worker_error"
                )
                raise
            self.store.record_worker_heartbeat(self.owner, "idle")
            return result

    def _tick_locked(self) -> dict[str, Any]:
        config, snapshots, enabled_profiles = self._profile_snapshots()
        if not enabled_profiles:
            return {
                "ok": True,
                "enabled": False,
                "processed": 0,
                "queue_depth": self.store.runtime_metrics()["queue_depth"],
            }
        terminal_count = self._terminal_sweep(config, snapshots, enabled_profiles)
        request = self.store.claim_next(
            self.owner, config.lease_seconds, enabled_profiles
        )
        if request is None:
            return {"ok": True, "processed": terminal_count}
        request_id = request["request_id"]
        token = request["lease_token"]
        try:
            payload = json.loads(request["payload_json"])
            source = payload["source"]
            profile = source["profile"]
            latest_config, latest_snapshots, latest_enabled = self._profile_snapshots()
            snapshot = latest_snapshots.get(profile)
            if snapshot is None or profile not in latest_enabled:
                self.store.transition(
                    request_id,
                    "queued",
                    token=token,
                    expected={"switching"},
                    error="runtime_router_disabled",
                )
                return {"ok": True, "processed": terminal_count, "queued": True}
            registry, route = self._route(snapshot, request["route_id"], source)
            if self._policy_hash(registry, route, request["project_id"]) != payload.get(
                "route_policy_hash"
            ):
                raise RouterConfigError("route_policy_changed")
            resolution = self._resolution(
                latest_config, request, route, payload, registry
            )
            agent = latest_config.agent(request["agent_ref"])
            instance = latest_config.instance(request["instance_id"])
            if (
                agent.agent_id != request["agent_id"]
                or agent.instance_id != request["instance_id"]
            ):
                raise RouterConfigError("route_instance_mismatch")
            if self.adapter.active_runs(
                self.adapter.agent_runs(instance, agent.agent_id)
            ):
                self.store.transition(
                    request_id,
                    "queued",
                    token=token,
                    expected={"switching"},
                    error="agent_busy",
                )
                return {
                    "ok": True,
                    "processed": terminal_count,
                    "queued": True,
                    "reason": "agent_busy",
                }
            agent_state = self.adapter.agent_get(instance, agent.agent_id)
            if (
                type(agent_state.get("max_concurrent_tasks")) is not int
                or agent_state["max_concurrent_tasks"] != 1
            ):
                raise RouterConfigError("agent_concurrency_invalid")
            if agent_state.get("runtime_id") != resolution.runtime_id:
                self._event(
                    request_id,
                    "switch_started",
                    agent_id=agent.agent_id,
                    runtime_id=resolution.runtime_id,
                )
                self.adapter.switch_runtime(
                    instance, agent.agent_id, resolution.runtime_id, resolution.model
                )
            else:
                self.adapter.verify_agent_runtime(
                    instance, agent.agent_id, resolution.runtime_id, resolution.model
                )
            self._event(
                request_id,
                "switch_verified",
                agent_id=agent.agent_id,
                runtime_id=resolution.runtime_id,
            )
            if not self.store.transition(
                request_id,
                "creating",
                token=token,
                expected={"switching"},
                runtime_id=resolution.runtime_id,
                model=resolution.model,
                resolution={
                    "runtime_id": resolution.runtime_id,
                    "model": resolution.model,
                    "rule_id": resolution.rule_id,
                    "reason": resolution.reason,
                    "source": resolution.source,
                },
                lease_seconds=latest_config.lease_seconds,
            ):
                return {"ok": True, "processed": terminal_count, "state_changed": True}

            # Revalidate route, principal, binding, runtime, and project immediately before POST.
            latest_config, latest_snapshots, latest_enabled = self._profile_snapshots()
            latest_snapshot = latest_snapshots.get(profile)
            if latest_snapshot is None or profile not in latest_enabled:
                raise RouterConfigError("runtime_router_disabled")
            latest_registry, latest_route = self._route(
                latest_snapshot, request["route_id"], source
            )
            self._resolution(
                latest_config, request, latest_route, payload, latest_registry
            )
            latest_agent = latest_config.agent(request["agent_ref"])
            latest_instance = latest_config.instance(request["instance_id"])
            if self.adapter.active_runs(
                self.adapter.agent_runs(latest_instance, latest_agent.agent_id)
            ):
                self.store.transition(
                    request_id,
                    "queued",
                    token=token,
                    expected={"creating"},
                    error="agent_busy",
                )
                return {
                    "ok": True,
                    "processed": terminal_count,
                    "queued": True,
                    "reason": "agent_busy",
                }
            self.adapter.verify_agent_runtime(
                latest_instance,
                latest_agent.agent_id,
                resolution.runtime_id,
                resolution.model,
            )
            parent_id = payload.get("parent_issue_id")
            if parent_id:
                parent = self.adapter.issue_get(latest_instance, parent_id)
                if (
                    parent.get("workspace_id") != latest_instance.workspace_id
                    or parent.get("project_id") != request["project_id"]
                ):
                    raise RouterConfigError("parent_issue_scope_invalid")
            issue = self.adapter.create_issue(
                latest_instance,
                request_id=request_id,
                agent_id=latest_agent.agent_id,
                project_id=request["project_id"],
                title=payload["title"],
                description=payload["description"],
                priority=payload.get("priority", "medium"),
                parent_id=parent_id,
                attachments=payload.get("attachments", []),
                related_issue_ids=payload.get("related_issue_ids", []),
            )
            if not isinstance(issue.get("id"), str):
                raise MulticaCliError("issue_create_unknown", uncertain=True)
            try:
                readback = self.adapter.issue_get(latest_instance, issue["id"])
            except MulticaCliError as exc:
                self.store.transition(
                    request_id,
                    "reconciling",
                    token=token,
                    expected={"creating", "cancelling"},
                    issue=issue,
                    error=exc.code,
                    lease_seconds=latest_config.lease_seconds,
                )
                return {
                    "ok": False,
                    "request_id": request_id,
                    "state": "reconciling",
                    "error_code": exc.code,
                }
            self._validate_issue(readback, request, latest_agent, latest_instance)
            current = self.store.get(request_id)
            target = (
                "cancelling"
                if current and current["state"] == "cancelling"
                else "waiting"
            )
            if self.store.transition(
                request_id,
                target,
                token=token,
                expected={"creating", "cancelling"},
                issue=readback,
                lease_seconds=latest_config.lease_seconds,
            ):
                self._event(
                    request_id,
                    "issue_created",
                    issue_id=readback["id"],
                    agent_id=latest_agent.agent_id,
                    runtime_id=resolution.runtime_id,
                )
                if target == "waiting":
                    self._event(
                        request_id,
                        "wait_started",
                        issue_id=readback["id"],
                        agent_id=latest_agent.agent_id,
                    )
                return {
                    "ok": True,
                    "request_id": request_id,
                    "state": target,
                    "issue_id": readback["id"],
                    "processed": terminal_count + 1,
                }
            return {
                "ok": True,
                "request_id": request_id,
                "state_changed": True,
                "processed": terminal_count,
            }
        except (RouterConfigError, ResolutionError) as exc:
            code = exc.code if isinstance(exc, ResolutionError) else str(exc)
            current = self.store.get(request_id)
            state = current["state"] if current else ""
            if state == "cancelling":
                self.store.transition(
                    request_id,
                    "reconciling",
                    token=token,
                    expected={"cancelling"},
                    error=code,
                    lease_seconds=self.config.lease_seconds,
                )
            elif state in {"switching", "creating"}:
                self.store.transition(
                    request_id, "blocked", token=token, expected={state}, error=code
                )
            return {
                "ok": False,
                "request_id": request_id,
                "state": "blocked",
                "error_code": code,
            }
        except MulticaCliError as exc:
            current = self.store.get(request_id)
            state = current["state"] if current else ""
            next_state = (
                "reconciling" if exc.uncertain or state == "cancelling" else "failed"
            )
            if state in {"switching", "creating", "cancelling"}:
                self.store.transition(
                    request_id,
                    next_state,
                    token=token,
                    expected={state},
                    error=exc.code,
                    lease_seconds=self.config.lease_seconds,
                )
            return {
                "ok": False,
                "request_id": request_id,
                "state": next_state,
                "error_code": exc.code,
            }
        except (KeyError, TypeError, ValueError, OSError):
            current = self.store.get(request_id)
            state = current["state"] if current else ""
            if state in {"switching", "creating", "cancelling"}:
                next_state = "reconciling" if state == "cancelling" else "blocked"
                self.store.transition(
                    request_id,
                    next_state,
                    token=token,
                    expected={state},
                    error="router_internal_error",
                    lease_seconds=self.config.lease_seconds,
                )
            return {
                "ok": False,
                "request_id": request_id,
                "state": "blocked",
                "error_code": "router_internal_error",
            }
