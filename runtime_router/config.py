"""Strict parsing for the operator-owned runtime router configuration."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_UUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PLATFORM = {"telegram", "max"}
_CONFIG_FIELDS = {
    "enabled",
    "state_path",
    "operator_config_path",
    "worker_profile",
    "tick_seconds",
    "lease_seconds",
    "unbound_policy",
    "kanban_mirror",
    "connectors",
    "instances",
    "agents",
    "operators",
    "model_policy",
    "cli_binary",
    "cli_timeout_seconds",
}
_INSTANCE_FIELDS = {"cli_profile", "workspace_id", "base_url", "enabled"}
_AGENT_FIELDS = {
    "instance_id",
    "agent_id",
    "model_by_runtime",
    "allowed_runtime_ids",
    "allowed_principal_ids",
    "allowed_models_by_runtime",
}
_OVERLAY_LIMIT = 262_144


class RouterConfigError(ValueError):
    """A configuration value is unsafe or inconsistent."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RouterConfigError(f"{label} must be an object")
    return value


def _fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    if set(value) - allowed:
        raise RouterConfigError(f"{label} contains unsupported fields")


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise RouterConfigError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RouterConfigError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise RouterConfigError(f"{label} must be an absolute normalized path")
    return path


def read_private_json(
    path: Path, *, maximum: int = _OVERLAY_LIMIT
) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise RouterConfigError("operator_config_unavailable") from exc
    except OSError as exc:
        raise RouterConfigError("operator_config_unreadable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > maximum
        ):
            raise RouterConfigError("operator_config_permissions_unsafe")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise RouterConfigError("operator_config_too_large")
    finally:
        os.close(fd)
    try:
        decoded = json.loads(chunks)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise RouterConfigError("operator_config_invalid") from None
    return _mapping(decoded, "operator_config")


@dataclass(frozen=True)
class Connector:
    connector_id: str
    profile: str
    platform: str
    label: str
    enabled: bool = True


@dataclass(frozen=True)
class Instance:
    instance_id: str
    cli_profile: str
    workspace_id: str
    base_url: str
    enabled: bool = True


@dataclass(frozen=True)
class CanonicalAgent:
    agent_ref: str
    instance_id: str
    agent_id: str
    model_by_runtime: Mapping[str, str]
    allowed_runtime_ids: tuple[str, ...]
    allowed_principal_ids: tuple[str, ...]
    allowed_models_by_runtime: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class ModelRule:
    rule_id: str
    priority: int
    match: Mapping[str, tuple[str, ...]]
    model: str
    runtime_ids: tuple[str, ...]
    fallback_models: tuple[str, ...]


@dataclass(frozen=True)
class ModelPolicy:
    enabled: bool = False
    allow_explicit_model: bool = False
    capability_source: str = "none"
    rules: tuple[ModelRule, ...] = ()
    catalog_version: str | None = None
    catalog_checked_at: datetime | None = None
    catalog_ttl_seconds: int | None = None
    catalog_entries: Mapping[tuple[str, str], str] | None = None


@dataclass(frozen=True)
class RouterConfig:
    enabled: bool
    state_path: Path
    operator_config_path: Path | None
    cli_binary: str
    cli_timeout_seconds: int
    worker_profile: str
    tick_seconds: int
    lease_seconds: int
    unbound_policy: str
    kanban_mirror: bool
    connectors: tuple[Connector, ...]
    instances: tuple[Instance, ...]
    agents: tuple[CanonicalAgent, ...]
    operator_identities: tuple[tuple[str, str], ...]
    model_policy: ModelPolicy = ModelPolicy()

    @classmethod
    def parse(cls, raw: Any) -> RouterConfig:
        row = _mapping(raw, "runtime_router")
        _fields(row, _CONFIG_FIELDS, "runtime_router")
        enabled = row.get("enabled", False)
        mirror = row.get("kanban_mirror", False)
        if type(enabled) is not bool or type(mirror) is not bool:
            raise RouterConfigError("runtime_router flags must be booleans")
        if mirror:
            raise RouterConfigError("kanban_mirror_projection_unavailable")

        raw_path = row.get(
            "state_path",
            "${HERMES_HOME}/plugin-data/hermes-multica-bridge/runtime-router.sqlite3",
        )
        if enabled and isinstance(raw_path, str) and "${HERMES_HOME}" in raw_path:
            raise RouterConfigError(
                "enabled runtime_router.state_path must be shared across Hermes profiles"
            )
        if isinstance(raw_path, str) and "${HERMES_HOME}" in raw_path:
            hermes_home = os.environ.get("HERMES_HOME")
            if hermes_home:
                raw_path = raw_path.replace("${HERMES_HOME}", hermes_home)
            elif enabled:
                raise RouterConfigError(
                    "HERMES_HOME is required when runtime_router is enabled"
                )
            else:
                raw_path = str(
                    Path.home()
                    / ".hermes/plugin-data/hermes-multica-bridge/runtime-router.sqlite3"
                )
        path = _absolute_path(raw_path, "runtime_router.state_path")

        operator_path: Path | None = None
        raw_operator_path = row.get("operator_config_path")
        if raw_operator_path:
            if (
                isinstance(raw_operator_path, str)
                and "${HERMES_HOME}" in raw_operator_path
            ):
                hermes_home = os.environ.get("HERMES_HOME")
                if not hermes_home:
                    raise RouterConfigError(
                        "HERMES_HOME is required for operator_config_path"
                    )
                raw_operator_path = raw_operator_path.replace(
                    "${HERMES_HOME}", hermes_home
                )
            operator_path = _absolute_path(
                raw_operator_path, "runtime_router.operator_config_path"
            )

        connectors_raw = dict(_mapping(row.get("connectors", {}), "connectors"))
        instances_raw = dict(_mapping(row.get("instances", {}), "instances"))
        agents_raw = dict(_mapping(row.get("agents", {}), "agents"))
        if operator_path is not None:
            try:
                operator_path.lstat()
            except FileNotFoundError:
                overlay = None
            else:
                overlay = read_private_json(operator_path)
        else:
            overlay = None
        if overlay is not None:
            _fields(overlay, {"instances"}, "operator_config")
            overlay_instances = _mapping(
                overlay.get("instances", {}), "operator_config.instances"
            )
            for key, value in overlay_instances.items():
                if key in instances_raw:
                    raise RouterConfigError("operator_instance_conflict")
                instances_raw[key] = value

        tick, lease = row.get("tick_seconds", 30), row.get("lease_seconds", 900)
        if type(tick) is not int or not 5 <= tick <= 300:
            raise RouterConfigError("tick_seconds must be between 5 and 300")
        if type(lease) is not int or not 30 <= lease <= 3600:
            raise RouterConfigError("lease_seconds must be between 30 and 3600")
        unbound = row.get("unbound_policy", "reject")
        if unbound not in {"reject", "keep_current"}:
            raise RouterConfigError("unbound_policy must be reject or keep_current")
        worker_profile = _name(row.get("worker_profile", "default"), "worker_profile")
        cli_binary = row.get("cli_binary", "/usr/local/bin/multica")
        if (
            not isinstance(cli_binary, str)
            or not Path(cli_binary).is_absolute()
            or "\x00" in cli_binary
        ):
            raise RouterConfigError("cli_binary must be an absolute path")
        cli_timeout = row.get("cli_timeout_seconds", 30)
        if type(cli_timeout) is not int or not 5 <= cli_timeout <= 180:
            raise RouterConfigError("cli_timeout_seconds must be between 5 and 180")

        connectors: list[Connector] = []
        for key, value in connectors_raw.items():
            item = _mapping(value, "connector")
            _fields(item, {"profile", "platform", "label", "enabled"}, "connector")
            profile = _name(item.get("profile"), "connector.profile")
            platform = item.get("platform")
            if platform not in _PLATFORM:
                raise RouterConfigError("connector.platform is invalid")
            label = item.get("label", str(key))
            active = item.get("enabled", True)
            if (
                not isinstance(label, str)
                or not label
                or len(label) > 128
                or type(active) is not bool
            ):
                raise RouterConfigError("connector fields are invalid")
            connectors.append(
                Connector(_name(key, "connector_id"), profile, platform, label, active)
            )
        if len({(c.profile, c.platform) for c in connectors}) != len(connectors):
            raise RouterConfigError(
                "only one connector is allowed per profile and platform"
            )

        instances: list[Instance] = []
        for key, value in instances_raw.items():
            item = _mapping(value, "instance")
            _fields(item, _INSTANCE_FIELDS, "instance")
            instance_id = _name(key, "instance_id")
            workspace_id = item.get("workspace_id")
            base_url = item.get("base_url")
            active = item.get("enabled", True)
            parsed_url = urlsplit(base_url) if isinstance(base_url, str) else None
            if (
                not isinstance(workspace_id, str)
                or not workspace_id.strip()
                or parsed_url is None
                or parsed_url.scheme != "https"
                or not parsed_url.hostname
                or parsed_url.username
                or parsed_url.password
                or parsed_url.query
                or parsed_url.fragment
                or any(char in base_url for char in "\r\n\x00")
                or type(active) is not bool
            ):
                raise RouterConfigError("instance fields are invalid")
            instances.append(
                Instance(
                    instance_id,
                    _name(item.get("cli_profile"), "cli_profile"),
                    workspace_id,
                    base_url.rstrip("/"),
                    active,
                )
            )
        instance_ids = {instance.instance_id for instance in instances}

        agents: list[CanonicalAgent] = []
        for key, value in agents_raw.items():
            item = _mapping(value, "agent")
            _fields(item, _AGENT_FIELDS, "agent")
            instance_id = _name(item.get("instance_id"), "agent.instance_id")
            agent_id = item.get("agent_id")
            if (
                instance_id not in instance_ids
                or not isinstance(agent_id, str)
                or not _UUID.fullmatch(agent_id)
            ):
                raise RouterConfigError(
                    "agent instance or canonical agent id is invalid"
                )
            model_map = _mapping(item.get("model_by_runtime", {}), "model_by_runtime")
            if any(
                not isinstance(runtime, str)
                or not runtime
                or not isinstance(model, str)
                or not model
                for runtime, model in model_map.items()
            ):
                raise RouterConfigError(
                    "model_by_runtime entries must be non-empty strings"
                )
            allowed = item.get("allowed_runtime_ids", list(model_map))
            if not isinstance(allowed, list) or any(
                not isinstance(runtime, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", runtime)
                for runtime in allowed
            ):
                raise RouterConfigError("allowed_runtime_ids must be a string list")
            if (
                not allowed
                or len(set(allowed)) != len(allowed)
                or not set(model_map) <= set(allowed)
            ):
                raise RouterConfigError(
                    "runtime model mappings must be within allowed_runtime_ids"
                )
            principals = item.get("allowed_principal_ids", [])
            if (
                not isinstance(principals, list)
                or any(
                    not isinstance(principal, str) or not _UUID.fullmatch(principal)
                    for principal in principals
                )
                or len(set(principals)) != len(principals)
            ):
                raise RouterConfigError(
                    "allowed_principal_ids must be unique canonical UUIDs"
                )
            allowed_models_raw = _mapping(
                item.get("allowed_models_by_runtime", {}),
                "allowed_models_by_runtime",
            )
            allowed_models: dict[str, tuple[str, ...]] = {}
            for runtime, models in allowed_models_raw.items():
                if (
                    not isinstance(runtime, str)
                    or runtime not in allowed
                    or not isinstance(models, list)
                    or len(models) > 128
                    or any(
                        not isinstance(model, str)
                        or not model
                        or model != model.strip()
                        or len(model) > 128
                        or any(ord(char) < 32 for char in model)
                        for model in models
                    )
                    or len(set(models)) != len(models)
                ):
                    raise RouterConfigError("allowed_models_by_runtime is invalid")
                allowed_models[runtime] = tuple(models)
            agents.append(
                CanonicalAgent(
                    _name(key, "agent_ref"),
                    instance_id,
                    agent_id,
                    dict(model_map),
                    tuple(allowed),
                    tuple(principals),
                    allowed_models,
                )
            )
        if len({(agent.instance_id, agent.agent_id) for agent in agents}) != len(
            agents
        ):
            raise RouterConfigError(
                "canonical agent may be registered only once per instance"
            )

        model_policy_raw = _mapping(row.get("model_policy", {}), "model_policy")
        _fields(
            model_policy_raw,
            {"enabled", "allow_explicit_model", "capability_source", "rules", "catalog"},
            "model_policy",
        )
        policy_enabled = model_policy_raw.get("enabled", False)
        explicit_enabled = model_policy_raw.get("allow_explicit_model", False)
        capability_source = model_policy_raw.get("capability_source", "none")
        rules_raw = model_policy_raw.get("rules", [])
        if type(policy_enabled) is not bool or type(explicit_enabled) is not bool:
            raise RouterConfigError("model_policy_invalid")
        if not isinstance(capability_source, str) or capability_source not in {
            "none",
            "multica_catalog",
            "operator_catalog",
        }:
            raise RouterConfigError("model_capability_unknown")
        known_runtimes = {runtime for agent in agents for runtime in agent.allowed_runtime_ids}
        catalog_version = None
        catalog_checked_at = None
        catalog_ttl_seconds = None
        catalog_entries = None
        catalog_raw = model_policy_raw.get("catalog")
        if capability_source == "operator_catalog":
            catalog = _mapping(catalog_raw, "model_policy.catalog")
            _fields(catalog, {"catalog_version", "checked_at", "ttl_seconds", "entries"}, "model_policy.catalog")
            catalog_version = catalog.get("catalog_version")
            checked_at_raw = catalog.get("checked_at")
            catalog_ttl_seconds = catalog.get("ttl_seconds")
            entries_raw = catalog.get("entries")
            if (
                not isinstance(catalog_version, str)
                or not catalog_version.strip()
                or len(catalog_version) > 64
                or not isinstance(checked_at_raw, str)
                or type(catalog_ttl_seconds) is not int
                or not 60 <= catalog_ttl_seconds <= 31_536_000
                or not isinstance(entries_raw, list)
                or len(entries_raw) > 4096
            ):
                raise RouterConfigError("model_catalog_invalid")
            try:
                catalog_checked_at = datetime.fromisoformat(checked_at_raw)
            except ValueError:
                raise RouterConfigError("model_catalog_invalid") from None
            if catalog_checked_at.tzinfo is None or catalog_checked_at.utcoffset() is None:
                raise RouterConfigError("model_catalog_invalid")
            catalog_checked_at = catalog_checked_at.astimezone(UTC)
            catalog_entries = {}
            for entry_raw in entries_raw:
                entry = _mapping(entry_raw, "model_policy.catalog entry")
                _fields(entry, {"runtime_id", "model", "status"}, "model_policy.catalog entry")
                runtime_id, model, status = entry.get("runtime_id"), entry.get("model"), entry.get("status")
                if (
                    not isinstance(runtime_id, str)
                    or runtime_id not in known_runtimes
                    or not isinstance(model, str)
                    or not model
                    or model != model.strip()
                    or len(model) > 128
                    or not isinstance(status, str)
                    or status not in {"supported", "unsupported"}
                    or (runtime_id, model) in catalog_entries
                ):
                    raise RouterConfigError("model_catalog_invalid")
                catalog_entries[(runtime_id, model)] = status
        elif catalog_raw is not None:
            raise RouterConfigError("model_catalog_invalid")
        if not isinstance(rules_raw, list) or len(rules_raw) > 256:
            raise RouterConfigError("model_policy_invalid")
        selector_map = {
            "principal_ids": "principal_id",
            "platforms": "platform",
            "chat_ids": "chat_id",
            "thread_ids": "thread_id",
            "workspace_ids": "workspace_id",
            "squad_ids": "squad_id",
            "project_ids": "project_id",
            "agent_ids": "agent_id",
            "task_classes": "task_class",
        }
        parsed_rules: list[ModelRule] = []
        seen_rule_ids: set[str] = set()
        for raw_rule in rules_raw:
            rule = _mapping(raw_rule, "model_policy rule")
            _fields(rule, {"id", "priority", "match", "model", "runtime_ids", "fallback_models"}, "model_policy rule")
            rule_id = _name(rule.get("id"), "model_policy rule id")
            priority = rule.get("priority")
            model = rule.get("model")
            match_raw = _mapping(rule.get("match"), "model_policy match")
            if (
                rule_id in seen_rule_ids
                or type(priority) is not int
                or not 0 <= priority <= 1000
                or not isinstance(model, str)
                or not model
                or model != model.strip()
                or len(model) > 128
                or not match_raw
                or set(match_raw) - set(selector_map)
            ):
                raise RouterConfigError("model_policy_invalid")
            seen_rule_ids.add(rule_id)
            selectors: dict[str, tuple[str, ...]] = {}
            for dimension, values in match_raw.items():
                if (
                    not isinstance(values, list)
                    or not 1 <= len(values) <= 128
                    or any(not isinstance(value, str) or not value or len(value) > 512 for value in values)
                    or len(set(values)) != len(values)
                ):
                    raise RouterConfigError("model_policy_invalid")
                selectors[selector_map[dimension]] = tuple(values)
            runtime_ids = rule.get("runtime_ids", [])
            fallbacks = rule.get("fallback_models", [])
            if (
                not isinstance(runtime_ids, list)
                or any(not isinstance(runtime, str) for runtime in runtime_ids)
                or len(set(runtime_ids)) != len(runtime_ids)
                or any(runtime not in known_runtimes for runtime in runtime_ids)
                or not isinstance(fallbacks, list)
                or any(not isinstance(value, str) for value in fallbacks)
                or len(set(fallbacks)) != len(fallbacks)
                or any(not isinstance(value, str) or not value or value != value.strip() or len(value) > 128 for value in fallbacks)
            ):
                raise RouterConfigError("model_policy_invalid")
            if fallbacks and capability_source == "none":
                raise RouterConfigError("model_fallback_unverified")
            parsed_rules.append(
                ModelRule(rule_id, priority, selectors, model, tuple(runtime_ids), tuple(fallbacks))
            )
        if enabled and (not connectors or not instances or not agents):
            raise RouterConfigError(
                "enabled runtime_router requires connectors, instances, and canonical agents"
            )

        operator_rows = row.get("operators", [])
        if not isinstance(operator_rows, list):
            raise RouterConfigError("operators must be a list")
        operators: list[tuple[str, str]] = []
        connector_ids = {connector.connector_id for connector in connectors}
        for operator in operator_rows:
            item = _mapping(operator, "operator")
            _fields(item, {"connector_id", "platform_user_id"}, "operator")
            connector_id, user_id = (
                item.get("connector_id"),
                item.get("platform_user_id"),
            )
            if (
                connector_id not in connector_ids
                or not isinstance(user_id, str)
                or not user_id
            ):
                raise RouterConfigError(
                    "operator identity must reference a configured connector"
                )
            operators.append((connector_id, user_id))
        if len(set(operators)) != len(operators):
            raise RouterConfigError("operator identities must be unique")
        return cls(
            enabled,
            path,
            operator_path,
            cli_binary,
            cli_timeout,
            worker_profile,
            tick,
            lease,
            unbound,
            mirror,
            tuple(connectors),
            tuple(instances),
            tuple(agents),
            tuple(operators),
            ModelPolicy(
                policy_enabled,
                explicit_enabled,
                capability_source,
                tuple(parsed_rules),
                catalog_version,
                catalog_checked_at,
                catalog_ttl_seconds,
                catalog_entries,
            ),
        )

    def connector_for(self, profile: str, platform: str) -> Connector:
        matches = [
            item
            for item in self.connectors
            if item.profile == profile and item.platform == platform and item.enabled
        ]
        if not matches:
            raise RouterConfigError("connector_unresolved")
        if len(matches) != 1:
            raise RouterConfigError("connector_ambiguous")
        return matches[0]

    def instance(self, instance_id: str) -> Instance:
        matches = [
            item
            for item in self.instances
            if item.instance_id == instance_id and item.enabled
        ]
        if len(matches) != 1:
            raise RouterConfigError("instance_not_found")
        return matches[0]

    def agent(self, agent_ref: str) -> CanonicalAgent:
        matches = [item for item in self.agents if item.agent_ref == agent_ref]
        if len(matches) != 1:
            raise RouterConfigError("agent_ref_invalid")
        return matches[0]

    def is_operator(self, connector_id: str, user_id: str) -> bool:
        return (connector_id, user_id) in self.operator_identities


def service_cli_home(config: RouterConfig) -> Path:
    """Return a private Multica CLI HOME beside the shared router state."""
    state_dir = config.state_path.parent
    try:
        parent = state_dir.lstat()
    except OSError:
        raise RouterConfigError("router_state_directory_unsafe") from None
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise RouterConfigError("router_state_directory_unsafe")
    home = state_dir / "cli-home"
    try:
        home.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise RouterConfigError("router_cli_home_unsafe") from None
    try:
        info = home.lstat()
    except OSError:
        raise RouterConfigError("router_cli_home_unsafe") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RouterConfigError("router_cli_home_unsafe")
    return home
