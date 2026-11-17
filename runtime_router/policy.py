"""Pure runtime selection policy; this module performs no I/O."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .config import ModelPolicy


class ResolutionError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code


def route_request_policy_hash(route_fingerprint: str, project_id: str) -> str:
    """Bind an enqueued request to the exact route policy and selected project."""
    if (
        not isinstance(route_fingerprint, str)
        or not route_fingerprint
        or not isinstance(project_id, str)
        or not project_id
    ):
        raise ResolutionError("runtime_policy_invalid")
    value = {"route_fingerprint": route_fingerprint, "project_id": project_id}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Resolution:
    principal_id: str
    instance_id: str
    runtime_id: str
    model: str | None
    rule_id: str | None
    reason: str
    source: str
    model_rule_id: str | None = None
    model_source: str = "runtime_default"
    model_reason: str = "runtime_default"
    capability_source: str = "none"


@dataclass(frozen=True)
class ModelResolution:
    model: str | None
    rule_id: str | None
    source: str
    reason: str
    capability_source: str


def resolve_model(
    *,
    runtime_id: str,
    runtime: Mapping[str, Any],
    context: Mapping[str, Any],
    model_by_runtime: Mapping[str, str],
    allowed_models_by_runtime: Mapping[str, tuple[str, ...]],
    policy: ModelPolicy,
    explicit_model: str | None = None,
    now: datetime | None = None,
) -> ModelResolution:
    """Resolve a model after runtime selection without changing the runtime."""
    if explicit_model is not None and (
        not isinstance(explicit_model, str)
        or not explicit_model
        or explicit_model != explicit_model.strip()
        or len(explicit_model) > 128
    ):
        raise ResolutionError("model_policy_invalid")
    if not policy.enabled:
        if explicit_model is not None:
            raise ResolutionError("model_not_allowed")
        model = model_by_runtime.get(runtime_id)
        models = runtime.get("models")
        if model and isinstance(models, (list, tuple)) and model not in models:
            raise ResolutionError("model_unsupported")
        return ModelResolution(
            model,
            None,
            "agent_map" if model else "runtime_default",
            "model_by_runtime" if model else "empty_agent_model_default",
            "none",
        )

    selected_rule = None
    if explicit_model is not None:
        if not policy.allow_explicit_model:
            raise ResolutionError("model_not_allowed")
        model, source, reason = explicit_model, "explicit", "explicit_model"
    else:
        matches = []
        for rule in policy.rules:
            if rule.runtime_ids and runtime_id not in rule.runtime_ids:
                continue
            if all(
                context.get(key) in values
                for key, values in rule.match.items()
            ):
                matches.append(rule)
        if matches:
            priority = max(rule.priority for rule in matches)
            best = [rule for rule in matches if rule.priority == priority]
            if len(best) != 1:
                raise ResolutionError("model_policy_conflict")
            selected_rule = best[0]
            model, source, reason = selected_rule.model, "policy", "model_rule_match"
        else:
            model = model_by_runtime.get(runtime_id)
            source = "agent_map" if model else "runtime_default"
            reason = "model_by_runtime" if model else "empty_agent_model_default"

    allowlist = allowed_models_by_runtime.get(runtime_id, ())
    if model is not None and model not in allowlist:
        raise ResolutionError("model_not_allowed")

    capability_source = policy.capability_source
    models = runtime.get("models")
    if capability_source == "multica_catalog":
        if model is not None and (not isinstance(models, (list, tuple)) or any(
            not isinstance(item, str) or not item for item in models
        )):
            raise ResolutionError("model_capability_unknown")
        if model is not None and model not in models:
            fallback = next(
                (
                    candidate
                    for candidate in (selected_rule.fallback_models if selected_rule else ())
                    if candidate in allowlist and candidate in models
                ),
                None,
            )
            if fallback is None:
                raise ResolutionError("model_unsupported")
            model, source, reason = fallback, "policy", "catalog_confirmed_unsupported"
    elif capability_source == "operator_catalog":
        checked_at = policy.catalog_checked_at
        ttl = policy.catalog_ttl_seconds
        entries = policy.catalog_entries or {}
        current = now or datetime.now(UTC)
        if (
            checked_at is None
            or ttl is None
            or current.tzinfo is None
            or current.timestamp() >= checked_at.timestamp() + ttl
        ):
            raise ResolutionError("model_catalog_stale")
        if model is not None:
            status = entries.get((runtime_id, model))
            if status is None:
                raise ResolutionError("model_capability_unknown")
            if status == "unsupported":
                fallback = next(
                    (
                        candidate
                        for candidate in (selected_rule.fallback_models if selected_rule else ())
                        if candidate in allowlist
                        and entries.get((runtime_id, candidate)) == "supported"
                    ),
                    None,
                )
                if fallback is None:
                    raise ResolutionError("model_unsupported")
                model, source, reason = fallback, "policy", "catalog_confirmed_unsupported"
    elif capability_source != "none":
        # Config parsing rejects unsupported catalog implementations. Keep this
        # guard for callers that construct ModelPolicy directly in tests/plugins.
        raise ResolutionError("model_capability_unknown")

    return ModelResolution(
        model,
        selected_rule.rule_id if selected_rule else None,
        source,
        reason,
        capability_source,
    )


def resolve_runtime(
    *,
    identity: Mapping[str, Any] | None,
    binding: Mapping[str, Any] | None,
    exceptions: list[Mapping[str, Any]],
    context: Mapping[str, str],
    allowed_runtime_ids: set[str],
    runtime_catalog: Mapping[str, Mapping[str, Any]],
    model_by_runtime: Mapping[str, str],
    model_policy: ModelPolicy | None = None,
    allowed_models_by_runtime: Mapping[str, tuple[str, ...]] | None = None,
    explicit_model: str | None = None,
    explicit_runtime_id: str | None = None,
    now: datetime | None = None,
) -> Resolution:
    if identity is None:
        raise ResolutionError("principal_unresolved")
    if identity.get("status", "active") != "active":
        raise ResolutionError("principal_unresolved")
    if binding is None:
        raise ResolutionError("runtime_unbound")
    if binding.get("principal_id") != identity.get("principal_id"):
        raise ResolutionError("runtime_unbound")
    instance_id = binding.get("instance_id")
    default_runtime = binding.get("default_runtime_id")
    mode = binding.get("mode")
    if not isinstance(instance_id, str) or mode not in {"strict", "exceptions"}:
        raise ResolutionError("runtime_unbound")
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        raise ResolutionError("runtime_policy_invalid")
    strict_until = binding.get("strict_until")
    strict_active = mode == "strict"
    strict_expired = False
    if strict_active and strict_until:
        try:
            expiry = datetime.fromisoformat(str(strict_until))
        except (TypeError, ValueError):
            raise ResolutionError("runtime_policy_invalid") from None
        if expiry.tzinfo is None:
            raise ResolutionError("runtime_policy_invalid")
        strict_active = expiry > current_time
        strict_expired = not strict_active
    effective_mode = "strict" if strict_active else "exceptions"
    selected, rule_id, reason, source = (
        default_runtime,
        None,
        "binding_default",
        "binding",
    )
    if explicit_runtime_id is not None and (
        not isinstance(explicit_runtime_id, str) or not explicit_runtime_id
    ):
        raise ResolutionError("runtime_policy_invalid")
    if effective_mode == "exceptions" and explicit_runtime_id:
        if explicit_runtime_id not in allowed_runtime_ids:
            raise ResolutionError("runtime_not_allowed")
        selected, reason, source = explicit_runtime_id, "explicit_runtime", "explicit"
    elif effective_mode == "exceptions":
        matches: list[tuple[int, int, Mapping[str, Any]]] = []
        selector_keys = {
            "platform",
            "chat_id",
            "thread_id",
            "agent_id",
            "workspace_id",
            "squad_id",
            "project_id",
            "instance_id",
        }
        for rule in exceptions:
            enabled = rule.get("enabled", True)
            if enabled is False or (type(enabled) is int and enabled == 0):
                continue
            if enabled is not True and not (type(enabled) is int and enabled == 1):
                raise ResolutionError("runtime_policy_invalid")
            if rule.get("expires_at"):
                try:
                    expires = datetime.fromisoformat(str(rule["expires_at"]))
                    if expires.tzinfo is None or expires.utcoffset() is None:
                        raise ValueError
                    if expires <= current_time:
                        continue
                except (TypeError, ValueError):
                    raise ResolutionError("runtime_policy_invalid") from None
            selectors = rule.get("selectors_json", rule.get("selectors", {}))
            if (
                not isinstance(selectors, Mapping)
                or not selectors
                or set(selectors) - selector_keys
                or any(
                    not isinstance(key, str) or not isinstance(value, str) or not value
                    for key, value in selectors.items()
                )
                or type(rule.get("priority")) is not int
                or not isinstance(rule.get("runtime_id"), str)
                or not rule.get("runtime_id")
            ):
                raise ResolutionError("runtime_policy_invalid")
            if all(context.get(key, "") == value for key, value in selectors.items()):
                priority = rule.get("priority")
                matches.append((priority, len(selectors), rule))
        if matches:
            best_rank = max(
                (priority, specificity) for priority, specificity, _ in matches
            )
            best = [
                rule
                for priority, specificity, rule in matches
                if (priority, specificity) == best_rank
            ]
            if len(best) > 1:
                raise ResolutionError("rule_conflict")
            selected = best[0].get("runtime_id")
            rule_id = best[0].get("exception_id")
            reason, source = "exception_match", "exception"
    if strict_active:
        selected, rule_id, reason, source = (
            default_runtime,
            None,
            "strict_binding",
            "binding",
        )
    if not isinstance(selected, str) or not selected:
        raise ResolutionError("runtime_unbound")
    if selected not in allowed_runtime_ids:
        raise ResolutionError("runtime_not_allowed")
    runtime = runtime_catalog.get(selected)
    if runtime is None:
        raise ResolutionError("runtime_not_available_in_instance")
    if runtime.get("instance_id", instance_id) != instance_id:
        raise ResolutionError("runtime_not_available_in_instance")
    if runtime.get("status") != "online":
        raise ResolutionError(
            "runtime_offline"
            if runtime.get("status") == "offline"
            else "runtime_not_available_in_instance"
        )
    if runtime.get("accessible") is not True:
        raise ResolutionError("runtime_not_allowed")
    model_resolution = resolve_model(
        runtime_id=selected,
        runtime=runtime,
        context=context,
        model_by_runtime=model_by_runtime,
        allowed_models_by_runtime=allowed_models_by_runtime or {},
        policy=model_policy or ModelPolicy(),
        explicit_model=explicit_model,
        now=current_time,
    )
    if strict_expired and reason == "binding_default":
        reason, source = "strict_expired_fallback", "strict_expired_fallback"
    return Resolution(
        str(identity["principal_id"]),
        instance_id,
        selected,
        model_resolution.model,
        rule_id,
        reason,
        source,
        model_resolution.rule_id,
        model_resolution.source,
        model_resolution.reason,
        model_resolution.capability_source,
    )
