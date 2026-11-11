"""Immutable watcher notification policy and deterministic comment classification."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .errors import BridgeError

EVENT_TYPES = frozenset({"question", "blocked", "final", "failed", "cancelled"})
_MENTION = re.compile(r"(?<![\w@])@[\w](?:[\w.-]*[\w])?", re.UNICODE)


@dataclass(frozen=True)
class NotificationPolicy:
    mode: str = "verbose"
    events: tuple[str, ...] = ("question", "blocked", "final", "failed")
    question_prefixes: tuple[str, ...] = ("QUESTION:", "ВОПРОС:")
    report_prefixes: tuple[str, ...] = ("REPORT:", "ОТЧЁТ:")
    mention_operator: bool = True
    operator_mentions: tuple[str, ...] = ()
    final_statuses: tuple[str, ...] = ("done", "in_review")
    initial_lookback_minutes: int = 15
    max_attempts: int = 5
    sending_timeout_seconds: int = 300

    def public(self) -> dict[str, Any]:
        return asdict(self)

    def classify(self, text: str, status: str) -> str:
        normalized = text.strip().casefold()
        mentions = {m.group().casefold() for m in _MENTION.finditer(text)}
        addressed = bool(mentions) if not self.operator_mentions else bool(
            mentions & {m.casefold() for m in self.operator_mentions}
        )
        if any(normalized.startswith(p.casefold()) for p in self.question_prefixes):
            return "question"
        if self.mention_operator and status == "blocked" and addressed:
            return "question"
        if any(normalized.startswith(p.casefold()) for p in self.report_prefixes):
            return "report"
        return "plain"


def parse_notification_policy(raw: Any, allowed_statuses: tuple[str, ...]) -> NotificationPolicy:
    if raw is None:
        return NotificationPolicy()
    fields = NotificationPolicy.__dataclass_fields__
    if not isinstance(raw, dict) or set(raw) - set(fields):
        raise BridgeError("notification_policy_invalid", "Unsupported notification policy fields.")
    values = dict(raw)
    defaults = NotificationPolicy()
    for name in ("events", "question_prefixes", "report_prefixes", "operator_mentions", "final_statuses"):
        value = values.get(name, getattr(defaults, name))
        limit = 64 if name == "final_statuses" else 16
        if (not isinstance(value, (list, tuple)) or len(value) > limit
                or any(not isinstance(v, str) or not v.strip() or len(v) > (128 if name == "operator_mentions" else 32) for v in value)
                or len(set(value)) != len(value)):
            raise BridgeError("notification_policy_invalid", "Invalid notification policy list.")
        values[name] = tuple(value)
    policy = NotificationPolicy(**values)
    if policy.mode not in ("verbose", "quiet") or type(policy.mention_operator) is not bool:
        raise BridgeError("notification_policy_invalid", "Invalid notification mode or mention flag.")
    for name, low, high in (("initial_lookback_minutes", 0, 1440), ("max_attempts", 1, 10), ("sending_timeout_seconds", 60, 3600)):
        value = getattr(policy, name)
        if type(value) is not int or not low <= value <= high:
            raise BridgeError("notification_policy_invalid", "Notification numeric limit is invalid.")
    if set(policy.events) - EVENT_TYPES:
        raise BridgeError("notification_event_unknown", "Unknown notification event class.")
    if not policy.events or not policy.question_prefixes or not policy.report_prefixes:
        raise BridgeError("notification_policy_invalid", "Notification lists must not be empty.")
    if any(not _MENTION.fullmatch(m) for m in policy.operator_mentions):
        raise BridgeError("notification_policy_invalid", "Operator mentions must be mention tokens.")
    if policy.mode == "quiet":
        if not policy.final_statuses:
            raise BridgeError("notification_policy_invalid", "Quiet policy requires final statuses.")
        required = set(policy.final_statuses)
        if "cancelled" in policy.events:
            required.add("cancelled")
        if required - set(allowed_statuses):
            raise BridgeError("notification_policy_conflict", "Notification statuses are not allowed by the route.")
    return policy
