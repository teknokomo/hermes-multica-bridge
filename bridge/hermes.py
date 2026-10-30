"""Small adapter around the canonical Hermes Kanban database APIs."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .registry import TrustedRouteContext
from .validation import (
    SOURCE_BOARD_RE,
    SOURCE_TASK_ID_RE,
    WORKER_RUN_ID_RE,
    request_fingerprint,
    strict_json_loads,
    validate_tool_request,
)


@dataclass(frozen=True)
class WorkerContext:
    board: str
    task_id: str
    run_id: str
    database_path: Path


@dataclass(frozen=True)
class CurrentTask:
    request: dict[str, Any]
    trusted: TrustedRouteContext
    comments: tuple[dict[str, Any], ...]


def worker_context(environ: Mapping[str, str] | None = None) -> WorkerContext:
    """Read the task/run identity and the DB pin injected into a Hermes Kanban worker."""
    env = os.environ if environ is None else environ
    board = env.get("HERMES_KANBAN_BOARD", "")
    task_id = env.get("HERMES_KANBAN_TASK", "")
    run_id = env.get("HERMES_KANBAN_RUN_ID", "")
    database = env.get("HERMES_KANBAN_DB", "")
    if (
        not SOURCE_BOARD_RE.fullmatch(board)
        or not SOURCE_TASK_ID_RE.fullmatch(task_id)
        or not WORKER_RUN_ID_RE.fullmatch(run_id)
        or int(run_id) > 9_223_372_036_854_775_807
        or not database
    ):
        raise BridgeError(
            "worker_context_invalid",
            "The tool is available only inside an active pinned Hermes Kanban worker.",
        )
    path = Path(database).expanduser()
    if not path.is_absolute():
        raise BridgeError("worker_context_invalid", "The Hermes Kanban database pin is invalid.")
    return WorkerContext(board=board, task_id=task_id, run_id=run_id, database_path=path)


def _dispatch_kanban_tool(
    dispatch_tool: Callable[[str, dict[str, Any]], str],
    tool_name: str,
    arguments: dict[str, Any],
    *,
    error_code: str,
    error_message: str,
) -> dict[str, Any]:
    if not callable(dispatch_tool):
        raise BridgeError(error_code, error_message)
    try:
        result = dispatch_tool(tool_name, arguments)
    except BridgeError:
        raise
    except Exception as exc:
        raise BridgeError(error_code, error_message) from exc
    if not isinstance(result, str):
        raise BridgeError(error_code, error_message)
    try:
        payload = strict_json_loads(result)
    except (TypeError, ValueError, UnicodeError):
        raise BridgeError(error_code, error_message) from None
    if not isinstance(payload, dict):
        raise BridgeError(error_code, error_message)
    return payload


def _read_current_task_show(
    context: WorkerContext,
    dispatch_tool: Callable[[str, dict[str, Any]], str],
) -> tuple[dict[str, Any], dict[str, Any], tuple[dict[str, Any], ...]]:
    payload = _dispatch_kanban_tool(
        dispatch_tool,
        "kanban_show",
        {"task_id": context.task_id, "board": context.board},
        error_code="worker_context_invalid",
        error_message="The pinned Hermes Kanban task could not be read.",
    )
    task = payload.get("task")
    runs = payload.get("runs")
    comments = payload.get("comments")
    expected_run_id = int(context.run_id)
    if (
        not isinstance(task, dict)
        or task.get("id") != context.task_id
        or type(task.get("current_run_id")) is not int
        or task["current_run_id"] != expected_run_id
        or not isinstance(runs, list)
        or not isinstance(comments, list)
        or any(not isinstance(item, dict) or not isinstance(item.get("body"), str) for item in comments)
    ):
        raise BridgeError("worker_context_invalid", "The current Hermes Kanban task/run no longer matches.")
    current_runs = [
        run for run in runs
        if isinstance(run, dict) and type(run.get("id")) is int and run["id"] == expected_run_id
    ]
    if len(current_runs) != 1:
        raise BridgeError("worker_context_invalid", "The current Hermes Kanban task/run no longer matches.")
    return task, current_runs[0], tuple(comments)


def _worker_pid_matches(
    context: WorkerContext,
    *,
    kanban_db: Any | None = None,
    kanban_connect: Any | None = None,
) -> bool:
    if kanban_db is None or kanban_connect is None:
        # T38-DEBT-1: private Hermes Kanban DB access.
        # Needed only for worker_pid ownership; recheck after every Hermes upgrade.
        # Remove when a public API exposes worker_pid or kanban_worker_context().
        try:
            from hermes_cli import kanban_db as hermes_kanban_db
            from hermes_cli import kanban_db_connect as hermes_kanban_db_connect
        except ImportError as exc:  # pragma: no cover - only possible outside Hermes runtime
            raise BridgeError("hermes_unavailable", "The Hermes worker ownership API is unavailable.") from exc
        if kanban_db is None:
            kanban_db = hermes_kanban_db
        if kanban_connect is None:
            kanban_connect = hermes_kanban_db_connect
    try:
        with kanban_connect.connect_closing(db_path=context.database_path) as connection:
            task = kanban_db.get_task(connection, context.task_id)
            run = kanban_db.get_run(connection, int(context.run_id))
            return (
                task is not None
                and run is not None
                and getattr(task, "worker_pid", None) == os.getpid()
                and getattr(run, "worker_pid", None) == os.getpid()
            )
    except (OSError, ValueError, PermissionError, sqlite3.Error) as exc:
        raise BridgeError("worker_context_invalid", "The Hermes worker ownership could not be verified.") from exc


def read_current_task(
    environ: Mapping[str, str] | None = None,
    *,
    dispatch_tool: Callable[[str, dict[str, Any]], str],
) -> dict[str, Any]:
    """Read title/body via Hermes' public Kanban tool for the current worker."""
    context = worker_context(environ)
    task, _, _ = _read_current_task_show(context, dispatch_tool)
    return validate_tool_request(
        {
            "source": {
                "system": "hermes",
                "board": context.board,
                "task_id": context.task_id,
                "run_id": context.run_id,
            },
            "task": {"title": task.get("title"), "body": task.get("body") or ""},
        }
    )


def read_current_task_with_context(
    environ: Mapping[str, str] | None = None,
    *,
    dispatch_tool: Callable[[str, dict[str, Any]], str],
) -> CurrentTask:
    """Read public Kanban task/run facts and verify private worker PID ownership."""
    context = worker_context(environ)
    task, run, comments = _read_current_task_show(context, dispatch_tool)
    if (
        task.get("status") != "running"
        or run.get("status") != "running"
        or not _worker_pid_matches(context)
    ):
        raise BridgeError("worker_context_invalid", "The current Hermes Kanban task/run no longer matches.")
    profile = run.get("profile")
    assignee = task.get("assignee")
    profile = profile.strip() if isinstance(profile, str) else ""
    assignee = assignee.strip() if isinstance(assignee, str) else ""
    if not profile or not assignee:
        raise BridgeError("worker_context_invalid", "The active Hermes Kanban worker has no trusted profile/assignee.")
    request = validate_tool_request(
        {
            "source": {
                "system": "hermes",
                "board": context.board,
                "task_id": context.task_id,
                "run_id": context.run_id,
            },
            "task": {"title": task.get("title"), "body": task.get("body") or ""},
        }
    )
    return CurrentTask(
        request=request,
        trusted=TrustedRouteContext(
            board=context.board,
            task_id=context.task_id,
            run_id=context.run_id,
            profile=profile,
            assignee=assignee,
            state=task["status"],
        ),
        comments=comments,
    )


def add_current_task_comment(
    body: str,
    environ: Mapping[str, str] | None = None,
    *,
    dispatch_tool: Callable[[str, dict[str, Any]], str],
    dedupe_marker: str | None = None,
    expected_request_sha256: str | None = None,
) -> bool:
    """Append a bounded result comment using Hermes' public Kanban tool."""
    context = worker_context(environ)
    if not isinstance(body, str) or not body.strip() or len(body) > 8_192:
        raise BridgeError("result_invalid", "The result comment is empty or too large.")
    if dedupe_marker is not None and (
        not isinstance(dedupe_marker, str)
        or not dedupe_marker
        or len(dedupe_marker) > 160
        or dedupe_marker not in body
    ):
        raise BridgeError("result_invalid", "The result comment marker is invalid.")
    if expected_request_sha256 is not None and (
        not isinstance(expected_request_sha256, str)
        or len(expected_request_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_request_sha256)
    ):
        raise BridgeError("result_invalid", "The expected Hermes task fingerprint is invalid.")
    current = read_current_task_with_context(environ, dispatch_tool=dispatch_tool)
    if expected_request_sha256 is not None:
        current_fingerprint = request_fingerprint(current.request)
        if current_fingerprint != expected_request_sha256:
            raise BridgeError(
                "request_conflict",
                "The Hermes task changed while the Multica result was being read.",
            )
    if dedupe_marker is not None and any(dedupe_marker in item["body"] for item in current.comments):
        return False

    response = _dispatch_kanban_tool(
        dispatch_tool,
        "kanban_comment",
        {"task_id": context.task_id, "board": context.board, "body": body},
        error_code="hermes_write_failed",
        error_message="The result could not be appended to the Hermes task.",
    )
    comment_id = response.get("comment_id")
    if (
        response.get("ok") is not True
        or response.get("task_id") != context.task_id
        or not (type(comment_id) is int and comment_id > 0 or isinstance(comment_id, str) and comment_id)
    ):
        raise BridgeError("hermes_write_failed", "The result could not be appended to the Hermes task.")
    return True
