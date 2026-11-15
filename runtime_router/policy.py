"""Pure runtime selection policy; this module performs no I/O."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


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


def resolve_runtime(
    *,
    identity: Mapping[str, Any] | None,
    binding: Mapping[str, Any] | None,
    exceptions: list[Mapping[str, Any]],
    context: Mapping[str, str],
    allowed_runtime_ids: set[str],
    runtime_catalog: Mapping[str, Mapping[str, Any]],
    model_by_runtime: Mapping[str, str],
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
    model = model_by_runtime.get(selected)
    models = runtime.get("models")
    if model and isinstance(models, (list, tuple)) and model not in models:
        raise ResolutionError("model_unsupported")
    if strict_expired and reason == "binding_default":
        reason, source = "strict_expired_fallback", "strict_expired_fallback"
    return Resolution(
        str(identity["principal_id"]),
        instance_id,
        selected,
        model,
        rule_id,
        reason,
        source,
    )
