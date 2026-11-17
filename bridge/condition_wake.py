"""Validation helpers for two-phase, children-done condition wakeups."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import BridgeError

_DURATION = re.compile(r"([1-9][0-9]{0,5})(s|m|h|d)\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_FAILED_STATUSES = frozenset({"blocked", "cancelled", "failed"})
_MAX_CHILDREN = 500
_MAX_EPOCH = 253_402_300_799


def _valid_epoch(value: Any) -> bool:
    if type(value) is int:
        return 0 < value <= _MAX_EPOCH
    return type(value) is float and math.isfinite(value) and 0 < value <= _MAX_EPOCH


def _valid_stage_pair(stage: Any, count: Any) -> bool:
    return (stage is None and count is None) or (
        type(stage) is int and type(count) is int and 1 <= count <= stage <= _MAX_CHILDREN
    )


@dataclass(frozen=True)
class ConditionWakeSpec:
    """Validated immutable request details for one parent issue."""

    instruction: str
    stage: int | None
    expected_stage_count: int | None
    expires_in_seconds: int | None
    expires_at: int | None
    on_timeout: str

    def canonical(self) -> dict[str, Any]:
        return {
            "mode": "children_done",
            "instruction": self.instruction,
            "stage": self.stage,
            "expected_stage_count": self.expected_stage_count,
            "expires_in_seconds": self.expires_in_seconds,
            "expires_at": self.expires_at,
            "on_timeout": self.on_timeout,
        }

    @classmethod
    def from_canonical(cls, value: Any, *, allow_expired: bool = False) -> ConditionWakeSpec:
        """Load the sanitized immutable form stored by the runtime router."""
        fields = {
            "mode", "instruction", "stage", "expected_stage_count",
            "expires_in_seconds", "expires_at", "on_timeout",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("mode") != "children_done":
            raise BridgeError("condition_wake_invalid", "The saved condition-wake request is invalid.")
        stage, count = value.get("stage"), value.get("expected_stage_count")
        if not _valid_stage_pair(stage, count):
            raise BridgeError("condition_wake_stage_mismatch", "The saved stage plan is invalid.")
        seconds, expiry = value.get("expires_in_seconds"), value.get("expires_at")
        if (seconds is None) == (expiry is None):
            raise BridgeError("condition_wake_invalid", "The saved condition-wake expiry is invalid.")
        if seconds is not None and (type(seconds) is not int or not 60 <= seconds <= 90 * 86400):
            raise BridgeError("condition_wake_invalid", "The saved condition-wake expiry is invalid.")
        now = int(time.time())
        if expiry is not None and (
            type(expiry) is not int
            or not 0 < expiry <= now + 90 * 86400
            or (not allow_expired and expiry <= now)
        ):
            raise BridgeError("condition_wake_invalid", "The saved condition-wake expiry is invalid.")
        instruction = value.get("instruction")
        on_timeout = value.get("on_timeout")
        if (not isinstance(instruction, str) or not instruction.strip() or len(instruction) > 2000
                or on_timeout not in {"wake", "end"}):
            raise BridgeError("condition_wake_invalid", "The saved condition-wake request is invalid.")
        return cls(instruction.strip(), stage, count, seconds, expiry, on_timeout)

    def api_payload(
        self, *, agent_id: str, expires_at_override: float | None = None,
    ) -> dict[str, Any]:
        """Build the exact event-wakeup request for a verified assigned agent."""
        if not isinstance(agent_id, str):
            raise BridgeError("condition_wake_agent_unavailable", "The parent has no verified agent assignee.")
        try:
            parsed_agent_id = str(uuid.UUID(agent_id))
        except (ValueError, AttributeError):
            raise BridgeError("condition_wake_agent_unavailable", "The parent has no verified agent assignee.") from None
        if parsed_agent_id != agent_id:
            raise BridgeError("condition_wake_agent_unavailable", "The parent has no verified agent assignee.")
        condition: dict[str, Any] = {"type": "children_done"}
        if self.stage is not None:
            condition["stage"] = self.stage
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "kind": "event",
            "instruction": self.instruction,
            "condition": condition,
            "mode": "once",
            "on_timeout": self.on_timeout,
        }
        if expires_at_override is not None:
            if not _valid_epoch(expires_at_override):
                raise BridgeError("condition_wake_invalid", "The saved condition-wake expiry is invalid.")
            payload["expires_at"] = datetime.fromtimestamp(expires_at_override, UTC).isoformat()
        elif self.expires_in_seconds is not None:
            payload["expires_in_seconds"] = self.expires_in_seconds
        elif self.expires_at is not None:
            payload["expires_at"] = datetime.fromtimestamp(self.expires_at, UTC).isoformat()
        return payload


def parse_condition_wake(value: Any, *, allow_expired: bool = False) -> ConditionWakeSpec:
    """Parse the public condition_wake argument without guessing defaults."""
    allowed = {
        "enabled", "mode", "instruction", "stage", "expected_stage_count",
        "expires_in", "expires_at", "on_timeout",
    }
    if not isinstance(value, dict) or set(value) - allowed or value.get("enabled") is not True:
        raise BridgeError("condition_wake_invalid", "condition_wake must be explicitly enabled with supported fields.")
    if value.get("mode", "children_done") != "children_done":
        raise BridgeError("condition_wake_invalid", "Only children_done condition wake is supported.")
    instruction = value.get("instruction")
    if not isinstance(instruction, str) or not instruction.strip() or len(instruction) > 2000:
        raise BridgeError("condition_wake_invalid", "A bounded condition-wake instruction is required.")
    stage_present = "stage" in value
    count_present = "expected_stage_count" in value
    if stage_present != count_present:
        raise BridgeError("condition_wake_stage_mismatch", "stage and expected_stage_count must be supplied together.")
    stage = value.get("stage")
    count = value.get("expected_stage_count")
    if stage_present and (stage is None or not _valid_stage_pair(stage, count)):
        raise BridgeError(
            "condition_wake_stage_mismatch",
            "A staged plan needs a maximum stage ordinal and distinct-stage count between 1 and 500.",
        )
    if "expires_in" in value and "expires_at" in value:
        raise BridgeError("condition_wake_invalid", "Use expires_in or expires_at, not both.")
    expires_in_seconds = None
    expires_at = None
    if "expires_in" in value:
        duration = value["expires_in"]
        match = _DURATION.fullmatch(duration) if isinstance(duration, str) else None
        if match is None:
            raise BridgeError("condition_wake_invalid", "expires_in must be a bounded duration such as 72h.")
        expires_in_seconds = int(match.group(1)) * _DURATION_SECONDS[match.group(2)]
        if not 60 <= expires_in_seconds <= 90 * 86400:
            raise BridgeError("condition_wake_invalid", "expires_in is outside the supported range.")
    elif "expires_at" in value:
        raw_expiry = value["expires_at"]
        if isinstance(raw_expiry, str):
            try:
                parsed = datetime.fromisoformat(raw_expiry)
            except ValueError:
                parsed = None
            if parsed is None or parsed.tzinfo is None:
                raise BridgeError("condition_wake_invalid", "expires_at must be an RFC3339 timestamp with a timezone.")
            expires_at = int(parsed.timestamp())
        elif type(raw_expiry) is int:
            expires_at = raw_expiry
        else:
            raise BridgeError("condition_wake_invalid", "expires_at must be an RFC3339 timestamp or epoch seconds.")
        now = int(time.time())
        if expires_at is None or not 0 < expires_at <= now + 90 * 86400 or (
            not allow_expired and expires_at <= now
        ):
            raise BridgeError("condition_wake_invalid", "expires_at must be in the next 90 days.")
    else:
        raise BridgeError("condition_wake_invalid", "An explicit condition-wake expiry is required.")
    on_timeout = value.get("on_timeout", "end")
    if on_timeout not in {"wake", "end"}:
        raise BridgeError("condition_wake_invalid", "on_timeout must be wake or end.")
    return ConditionWakeSpec(
        instruction=instruction.strip(),
        stage=stage,
        expected_stage_count=count,
        expires_in_seconds=expires_in_seconds,
        expires_at=expires_at,
        on_timeout=on_timeout,
    )


def validate_child_tree(
    children: Any,
    *,
    parent_id: str,
    workspace_id: str,
    project_id: str,
    spec: ConditionWakeSpec,
) -> tuple[list[dict[str, Any]], str]:
    """Validate complete direct children and return immutable IDs/stages + fingerprint."""
    if not isinstance(children, list) or not 1 <= len(children) <= _MAX_CHILDREN:
        raise BridgeError("condition_wake_no_children", "The parent has no bounded, verifiable child stage plan.")
    if not _valid_stage_pair(spec.stage, spec.expected_stage_count):
        raise BridgeError("condition_wake_stage_mismatch", "The declared stage plan is invalid.")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    stage_values: set[int] = set()
    for child in children:
        if not isinstance(child, dict):
            raise BridgeError("condition_wake_stage_mismatch", "Multica returned an invalid child record.")
        issue_id = child.get("id")
        status = child.get("status")
        child_stage = child.get("stage")
        if (not isinstance(issue_id, str) or not _ID.fullmatch(issue_id) or issue_id in seen
                or child.get("parent_issue_id") != parent_id
                or child.get("workspace_id") != workspace_id
                or child.get("project_id") != project_id
                or not isinstance(status, str) or not status):
            raise BridgeError("condition_wake_stage_mismatch", "Child ownership or identity could not be verified.")
        if child_stage is not None and type(child_stage) is not int:
            raise BridgeError("condition_wake_stage_mismatch", "A child has an invalid stage value.")
        if spec.stage is None:
            if child_stage is not None:
                raise BridgeError("condition_wake_stage_mismatch", "An unstaged plan cannot contain staged children.")
        else:
            if child_stage is None or not 1 <= child_stage <= spec.stage:
                raise BridgeError("condition_wake_stage_mismatch", "A staged child is outside the declared stage range.")
            stage_values.add(child_stage)
        seen.add(issue_id)
        normalized.append({"id": issue_id, "stage": child_stage, "status": status})
    if spec.stage is not None:
        expected_count = spec.expected_stage_count
        if (expected_count > len(children) or len(stage_values) != expected_count
                or max(stage_values, default=0) != spec.stage):
            raise BridgeError(
                "condition_wake_stage_mismatch",
                "The child tree does not match the declared stage count and maximum ordinal.",
            )
    normalized.sort(key=lambda item: item["id"])
    immutable = [{"id": row["id"], "stage": row["stage"]} for row in normalized]
    fingerprint = hashlib.sha256(
        json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return normalized, fingerprint


def readiness_from_children(
    expected: list[dict[str, Any]], current: list[dict[str, Any]], *,
    parent_id: str | None = None, workspace_id: str | None = None, project_id: str | None = None,
) -> str:
    """Return ready only for the exact saved child set, with every status exactly done."""
    if not expected or len(current) != len(expected):
        return "approval_blocked"
    by_id = {row.get("id"): row for row in current if isinstance(row, dict)}
    if len(by_id) != len(current):
        return "approval_blocked"
    for saved in expected:
        row = by_id.get(saved.get("id"))
        if row is None or row.get("stage") != saved.get("stage"):
            return "approval_blocked"
        if ((parent_id is not None and row.get("parent_issue_id") != parent_id)
                or (workspace_id is not None and row.get("workspace_id") != workspace_id)
                or (project_id is not None and row.get("project_id") != project_id)):
            return "approval_blocked"
        if row.get("status") != "done":
            return "approval_blocked"
    return "ready"


def wakeup_matches_saved_children(
    wakeup: dict[str, Any], parent_id: str, instruction: str, children: list[dict[str, Any]],
) -> bool:
    """Correlate a readback wakeup to the immutable child tree captured at registration."""
    condition = wakeup.get("condition")
    if not isinstance(condition, dict):
        return False
    stages = {row.get("stage") for row in children if isinstance(row, dict)}
    staged = bool(stages) and None not in stages
    expected = {"type": "children_done"}
    if staged:
        if any(type(stage) is not int for stage in stages):
            return False
        expected["stage"] = max(stages)
    return (
        wakeup.get("id")
        and wakeup.get("issue_id") == parent_id
        and wakeup.get("mode") == "once"
        and wakeup.get("instruction") == instruction
        and condition == expected
    )


def condition_wakeup_matches(
    wakeup: dict[str, Any], parent_id: str, spec: ConditionWakeSpec, *, agent_id: str,
    expected_expires_at: float,
) -> bool:
    condition = wakeup.get("condition")
    if not isinstance(condition, dict):
        return False
    expected_condition = {"type": "children_done"}
    if spec.stage is not None:
        expected_condition["stage"] = spec.stage
    raw_expiry = wakeup.get("expires_at")
    try:
        parsed_expiry = datetime.fromisoformat(raw_expiry) if isinstance(raw_expiry, str) else None
        actual_expiry = parsed_expiry.timestamp() if parsed_expiry is not None and parsed_expiry.tzinfo else None
    except (OverflowError, ValueError):
        actual_expiry = None
    return (
        _valid_epoch(expected_expires_at)
        and actual_expiry is not None
        and abs(actual_expiry - expected_expires_at) <= 1
        and wakeup.get("issue_id") == parent_id
        and wakeup.get("agent_id") == agent_id
        and wakeup.get("kind") == "event"
        and wakeup.get("mode") == "once"
        and wakeup.get("instruction") == spec.instruction
        and condition == expected_condition
    )
