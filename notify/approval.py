"""Read-only correlation and readiness checks for approval wakeups."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from bridge.condition_wake import readiness_from_children, wakeup_matches_saved_children
from bridge.validation import strict_json_loads

from .config import Config, NotifyError
from .state import State
from .wake import load_webhook_policy, verify_configured_route, verify_webhook_policy

_ACTIVE_RUN_STATUSES = frozenset({
    "queued", "deferred", "dispatched", "running", "waiting_local_directory",
})


def _expiry_epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def _block(state: State, mapping: dict, code: str) -> str:
    state.approval_block(mapping["mapping_id"], code)
    return "blocked"


def _feature_ready(config: Config) -> bool:
    return bool(
        config.approval_ipc.get("enabled")
        and config.approval_ipc.get("native_delivery_suppressed") is True
        and config.wake.get("enabled")
    )


def _destination_matches(state: State, mapping: dict) -> dict | None:
    destination = state.approval_route(mapping["source_profile"], mapping["route_id"])
    if destination is None:
        return None
    try:
        workspace_data = json.loads(destination["workspace_data"])
    except (TypeError, ValueError, RecursionError):
        return None
    if (
        destination["subscription_id"] != mapping["subscription_id"]
        or destination["external_workspace_id"] != mapping["workspace_id"]
        or destination["workspace_key"] != mapping["workspace_key"]
        or (destination["project_id"] and destination["project_id"] != mapping["project_id"])
        or not isinstance(workspace_data, dict)
        or workspace_data.get("connection_id") != mapping["connection_id"]
        or not destination["enabled"]
        or not destination["wake_enabled"]
        or not destination["workspace_configured"]
        or not destination["workspace_enabled"]
        or not destination["account_configured"]
        or destination["account_platform"] != destination["platform"]
    ):
        return None
    return destination


def reconcile_mapping(
    state: State,
    config: Config,
    mapping: dict,
    *,
    api_factory: Callable,
    now: float | None = None,
) -> tuple[str, str | None]:
    """Reconcile one mapping using scoped, read-only Multica endpoints.

    Returns (state, job_id). Transient read failures leave the mapping pending;
    incomplete or contradictory evidence blocks it without delivery.
    """
    if mapping.get("status") != "pending":
        return (
            "blocked" if mapping.get("status") == "blocked" else "already_processed",
            None,
        )
    if not _feature_ready(config):
        return "disabled", None
    now = time.time() if now is None else now
    destination = _destination_matches(state, mapping)
    if destination is None:
        return _block(state, mapping, "approval_ready_destination_unverified"), None
    if (not isinstance(mapping.get("agent_id"), str) or not mapping["agent_id"]
            or not isinstance(mapping.get("project_id"), str) or not mapping["project_id"]):
        return _block(state, mapping, "approval_mapping_legacy_unverified"), None
    try:
        verify_configured_route(
            config.wake.get("routes", {}), mapping["source_profile"], mapping["route_id"]
        )
        webhook_policy = load_webhook_policy(Path(config.wake["webhook_policy_file"]))
        verify_webhook_policy(
            webhook_policy,
            mapping["source_profile"],
            mapping["route_id"],
            {
                "platform": destination["platform"],
                "chat_id": destination["chat_id"],
                "thread_id": destination["thread_id"],
                "chat_type": destination["chat_type"],
            },
        )
        api = api_factory(config, mapping["workspace_key"])
        reader = api.reader
        parent = reader.get_issue(mapping["parent_issue_id"])
        if (
            parent.get("id") != mapping["parent_issue_id"]
            or parent.get("workspace_id") != mapping["workspace_id"]
            or parent.get("project_id") != mapping["project_id"]
            or parent.get("assignee_type") != "agent"
            or parent.get("assignee_id") != mapping["agent_id"]
        ):
            return _block(state, mapping, "approval_mapping_invalid"), None
        wakeups = reader.list_issue_wakeups(mapping["parent_issue_id"])
        wakeup_rows = [row for row in wakeups if row.get("id") == mapping["wakeup_id"]]
        if len(wakeup_rows) != 1:
            return _block(state, mapping, "approval_wakeup_missing"), None
        wakeup = wakeup_rows[0]
        try:
            saved_children = strict_json_loads(mapping["child_ids_json"])
        except (ValueError, UnicodeError, RecursionError):
            return _block(state, mapping, "approval_mapping_invalid"), None
        if (
            wakeup.get("issue_id") != mapping["parent_issue_id"]
            or wakeup.get("agent_id") != mapping["agent_id"]
            or wakeup.get("kind") != "event"
            or wakeup.get("mode") != "once"
            or wakeup.get("instruction") != mapping["instruction"]
            or not wakeup_matches_saved_children(
                wakeup, mapping["parent_issue_id"], mapping["instruction"], saved_children
            )
        ):
            return _block(state, mapping, "approval_mapping_invalid"), None
        actual_expiry = _expiry_epoch(wakeup.get("expires_at"))
        if actual_expiry is None or abs(actual_expiry - mapping["expires_at"]) > 1:
            return _block(state, mapping, "approval_mapping_invalid"), None
        run_id = wakeup.get("last_task_id")
        if run_id is None:
            if wakeup.get("timed_out_at") is not None or now >= actual_expiry:
                return _block(state, mapping, "approval_wake_expired"), None
            if not wakeup.get("enabled"):
                return _block(state, mapping, "approval_wakeup_disabled"), None
            return "pending", None
        runs = reader.list_issue_wakeup_runs(mapping["parent_issue_id"], mapping["wakeup_id"])
        matching_runs = [row for row in runs if row.get("id") == run_id]
        if len(matching_runs) > 1:
            return _block(state, mapping, "approval_run_ambiguous"), None
        if not matching_runs:
            return "pending", None
        run = matching_runs[0]
        status = run.get("status")
        if status in _ACTIVE_RUN_STATUSES:
            return "pending", None
        if status != "completed" or not isinstance(run.get("completed_at"), str) or not run["completed_at"]:
            return _block(state, mapping, "approval_blocked"), None
        try:
            completed_at = datetime.fromisoformat(run["completed_at"])
            if completed_at.tzinfo is None:
                raise ValueError
        except (ValueError, OverflowError):
            return _block(state, mapping, "approval_run_invalid"), None
        children = reader.list_issue_children(mapping["parent_issue_id"])
        readiness = readiness_from_children(
            saved_children,
            children,
            parent_id=mapping["parent_issue_id"],
            workspace_id=mapping["workspace_id"],
            project_id=mapping["project_id"],
        )
        if readiness != "ready":
            return _block(state, mapping, "approval_blocked"), None
        identifier = parent.get("identifier")
        if not isinstance(identifier, str) or not identifier.strip():
            return _block(state, mapping, "approval_mapping_invalid"), None
        issue_url = reader.issue_link(identifier)
        if not isinstance(issue_url, str) or not issue_url.startswith("https://"):
            return _block(state, mapping, "approval_mapping_invalid"), None
        if destination["locale"] == "en":
            message = f"{identifier} is ready for human approval; all planned stages are done. {issue_url}"
        else:
            message = f"Задача {identifier} готова к проверке: все этапы завершены, требуется подтверждение. {issue_url}"
        job_id = state.approval_enqueue(
            mapping["mapping_id"], run_id, message, [row["status"] for row in children],
        )
        return ("ready", job_id) if job_id else ("already_processed", None)
    except NotifyError:
        return "unavailable", None
    except Exception:  # noqa: BLE001 - keep API/network and response details out of logs
        return "unavailable", None
