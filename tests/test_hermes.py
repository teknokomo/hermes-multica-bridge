from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.errors import BridgeError
from bridge.hermes import (
    _worker_pid_matches,
    add_current_task_comment,
    read_current_task,
    read_current_task_with_context,
    worker_context,
)
from bridge.validation import request_fingerprint
from tests.helpers import sample_request


def env(db: Path, *, run_id: str = "12") -> dict[str, str]:
    return {
        "HERMES_KANBAN_BOARD": "example-board",
        "HERMES_KANBAN_TASK": "task_12345678",
        "HERMES_KANBAN_RUN_ID": run_id,
        "HERMES_KANBAN_DB": str(db),
    }


def show_payload(*, task=None, run=None, comments=None) -> dict:
    task_fields = {
        "id": "task_12345678",
        "current_run_id": 12,
        "title": "Pinned title",
        "body": "Pinned body",
        "assignee": "worker-a",
        "status": "running",
    }
    run_fields = {"id": 12, "profile": "worker-a", "status": "running"}
    task_fields.update(task or {})
    run_fields.update(run or {})
    return {
        "task": task_fields,
        "runs": [run_fields],
        "comments": list(comments or []),
    }


class FakeDispatch:
    def __init__(self, payload=None, comment_result=None):
        self.payload = show_payload() if payload is None else payload
        self.comment_result = comment_result or {
            "ok": True,
            "task_id": "task_12345678",
            "comment_id": 37,
        }
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, tool_name: str, arguments: dict) -> str:
        self.calls.append((tool_name, arguments))
        if tool_name == "kanban_show":
            if isinstance(self.payload, BaseException):
                raise self.payload
            if isinstance(self.payload, str):
                return self.payload
            return json.dumps(self.payload)
        if tool_name == "kanban_comment":
            if isinstance(self.comment_result, BaseException):
                raise self.comment_result
            if isinstance(self.comment_result, str):
                return self.comment_result
            return json.dumps(self.comment_result)
        raise AssertionError(f"unexpected Hermes tool: {tool_name}")


class FakeConnect:
    def __init__(self, connection):
        self.connection = connection
        self.paths: list[Path] = []

    @contextlib.contextmanager
    def connect_closing(self, *, db_path):
        self.paths.append(db_path)
        yield self.connection


class HermesAdapterTests(unittest.TestCase):
    def test_worker_context_requires_absolute_pinned_db(self) -> None:
        with self.assertRaises(BridgeError):
            worker_context({})
        with self.assertRaises(BridgeError):
            worker_context(
                {
                    "HERMES_KANBAN_BOARD": "example-board",
                    "HERMES_KANBAN_TASK": "task_12345678",
                    "HERMES_KANBAN_RUN_ID": "12",
                    "HERMES_KANBAN_DB": "relative.db",
                }
            )

    def test_reads_task_through_public_kanban_show(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch()
            request = read_current_task(env(db), dispatch_tool=dispatch)

        self.assertEqual(request, sample_request(title="Pinned title", body="Pinned body"))
        self.assertEqual(
            dispatch.calls,
            [("kanban_show", {"task_id": "task_12345678", "board": "example-board"})],
        )

    def test_public_task_run_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch(show_payload(task={"current_run_id": 13}))
            with self.assertRaises(BridgeError):
                read_current_task(env(db), dispatch_tool=dispatch)

    def test_public_show_errors_are_normalized_without_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch(RuntimeError("private database path leaked"))
            with self.assertRaises(BridgeError) as raised:
                read_current_task(env(db), dispatch_tool=dispatch)

        self.assertEqual(raised.exception.code, "worker_context_invalid")
        self.assertNotIn("private database path", raised.exception.message)

    def test_reads_trusted_profile_assignee_status_and_comments_from_public_show(self) -> None:
        comments = [{"author": "worker-a", "body": "Previous result", "created_at": "now"}]
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch(show_payload(comments=comments))
            with patch("bridge.hermes._worker_pid_matches", return_value=True):
                current = read_current_task_with_context(env(db), dispatch_tool=dispatch)

        self.assertEqual(current.trusted.profile, "worker-a")
        self.assertEqual(current.trusted.assignee, "worker-a")
        self.assertEqual(current.trusted.state, "running")
        self.assertEqual(current.comments, tuple(comments))
        self.assertEqual(dispatch.calls[0][0], "kanban_show")

    def test_trusted_context_rejects_non_running_task_and_run(self) -> None:
        for payload in (
            show_payload(task={"status": "blocked"}),
            show_payload(run={"status": "completed"}),
        ):
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as directory,
                patch("bridge.hermes._worker_pid_matches", return_value=True),
                self.assertRaises(BridgeError) as raised,
            ):
                dispatch = FakeDispatch(payload)
                read_current_task_with_context(
                    env(Path(directory) / "kanban.db"), dispatch_tool=dispatch
                )
            self.assertEqual(raised.exception.code, "worker_context_invalid")

    def test_trusted_context_rejects_process_not_recorded_as_current_worker(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("bridge.hermes._worker_pid_matches", return_value=False),
            self.assertRaises(BridgeError) as raised,
        ):
            dispatch = FakeDispatch()
            read_current_task_with_context(
                env(Path(directory) / "kanban.db"), dispatch_tool=dispatch
            )
        self.assertEqual(raised.exception.code, "worker_context_invalid")

    def test_private_worker_pid_seam_reads_only_task_and_run_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            context = worker_context(env(db))
            task = types.SimpleNamespace(worker_pid=os.getpid())
            run = types.SimpleNamespace(worker_pid=os.getpid())
            api = types.SimpleNamespace(
                get_task=lambda _connection, task_id: task if task_id == context.task_id else None,
                get_run=lambda _connection, run_id: run if run_id == int(context.run_id) else None,
            )
            connect = FakeConnect(object())

            self.assertTrue(
                _worker_pid_matches(context, kanban_db=api, kanban_connect=connect)
            )
            self.assertEqual(connect.paths, [db])

    def test_private_worker_pid_seam_fails_closed_and_sanitizes_sqlite_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = worker_context(env(Path(directory) / "kanban.db"))
            api = types.SimpleNamespace(
                get_task=lambda *_args: (_ for _ in ()).throw(sqlite3.OperationalError("db locked")),
                get_run=lambda *_args: None,
            )
            with self.assertRaises(BridgeError) as raised:
                _worker_pid_matches(
                    context, kanban_db=api, kanban_connect=FakeConnect(object())
                )
        self.assertEqual(raised.exception.code, "worker_context_invalid")
        self.assertNotIn("db locked", raised.exception.message)

    def test_comment_marker_in_public_comments_prevents_duplicate_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            marker = "<!-- hmb-result:" + ("a" * 64) + " -->"
            dispatch = FakeDispatch(show_payload(comments=[{"body": f"existing\n{marker}"}]))
            with patch("bridge.hermes._worker_pid_matches", return_value=True):
                written = add_current_task_comment(
                    f"result\n{marker}",
                    env(db),
                    dispatch_tool=dispatch,
                    dedupe_marker=marker,
                )

        self.assertFalse(written)
        self.assertEqual([call[0] for call in dispatch.calls], ["kanban_show"])

    def test_comment_uses_public_arguments_and_confirms_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch()
            expected = sample_request(title="Pinned title", body="Pinned body")
            with patch("bridge.hermes._worker_pid_matches", return_value=True):
                written = add_current_task_comment(
                    "result",
                    env(db),
                    dispatch_tool=dispatch,
                    expected_request_sha256=request_fingerprint(expected),
                )

        self.assertTrue(written)
        self.assertEqual(
            dispatch.calls,
            [
                ("kanban_show", {"task_id": "task_12345678", "board": "example-board"}),
                (
                    "kanban_comment",
                    {"task_id": "task_12345678", "board": "example-board", "body": "result"},
                ),
            ],
        )

    def test_comment_rechecks_task_content_before_public_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch()
            expected = sample_request(title="Edited title", body="Pinned body")
            with (
                patch("bridge.hermes._worker_pid_matches", return_value=True),
                self.assertRaises(BridgeError) as raised,
            ):
                add_current_task_comment(
                    "result",
                    env(db),
                    dispatch_tool=dispatch,
                    expected_request_sha256=request_fingerprint(expected),
                )

        self.assertEqual(raised.exception.code, "request_conflict")
        self.assertEqual([call[0] for call in dispatch.calls], ["kanban_show"])

    def test_public_comment_failure_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "kanban.db"
            dispatch = FakeDispatch(comment_result=RuntimeError("secret database error"))
            with (
                patch("bridge.hermes._worker_pid_matches", return_value=True),
                self.assertRaises(BridgeError) as raised,
            ):
                add_current_task_comment("result", env(db), dispatch_tool=dispatch)

        self.assertEqual(raised.exception.code, "hermes_write_failed")
        self.assertNotIn("secret database error", raised.exception.message)


if __name__ == "__main__":
    unittest.main()
