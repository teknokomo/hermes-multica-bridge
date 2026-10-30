from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
from unittest.mock import Mock

from bridge.errors import BridgeError
from bridge.workspace_api import WorkspaceApiClient, WorkspaceApiFailure
from tests.helpers import TEST_ORIGIN


class _Response:
    status = 200

    def __init__(self, body: bytes):
        self.body = body
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body)
        body, self.body = self.body[:size], self.body[size:]
        return body

    def close(self) -> None:
        self.closed = True


class _InterruptibleSocket:
    def __init__(self, released: threading.Event):
        self.released = released
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def shutdown(self, _how: int) -> None:
        self.released.set()

    def close(self) -> None:
        self.released.set()


class _BlockingBodyResponse:
    status = 200

    def __init__(self):
        self.released = threading.Event()
        self.fp = self
        self.raw = self
        self._sock = _InterruptibleSocket(self.released)

    def read1(self, _size: int) -> bytes:
        self.released.wait(1.0)
        raise OSError("body read interrupted")

    def close(self) -> None:
        self.released.set()


class WorkspaceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.opener = Mock()
        self.client = WorkspaceApiClient(TEST_ORIGIN, "fake-multica-pat", "workspace-1", opener=self.opener)

    def test_create_issue_uses_configured_workspace_and_project(self) -> None:
        response = _Response(b'{"id":"issue-1","workspace_id":"workspace-1","project_id":"project-1"}')
        self.opener.open.return_value = response
        result = self.client.create_issue(title=" Task ", description="body", project_id="project-1",
                                          status="todo", assignee_id="member-1")
        request = self.opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(result["id"], "issue-1")
        self.assertEqual(request.get_header("X-workspace-id"), "workspace-1")
        self.assertEqual(payload["title"], "Task")
        self.assertEqual(payload["assignee_type"], "member")
        self.assertEqual(payload["project_id"], "project-1")
        self.assertTrue(response.closed)

    def test_comments_are_a_bounded_json_array(self) -> None:
        self.opener.open.return_value = _Response(b'[{"id":"comment-1","content":"hello"}]')
        self.assertEqual(self.client.list_comments("issue-1")[0]["id"], "comment-1")

    def test_http_client_error_proves_write_was_rejected(self) -> None:
        self.opener.open.side_effect = urllib.error.HTTPError(
            TEST_ORIGIN + "/api/issues", 400, "Bad Request", {}, None,
        )
        with self.assertRaises(WorkspaceApiFailure) as raised:
            self.client.create_issue(title="Task", description="", project_id="project-1", status="todo")
        self.assertEqual(raised.exception.outcome, "not_sent")

    def test_server_error_makes_write_unknown_and_is_never_retried(self) -> None:
        self.opener.open.side_effect = urllib.error.HTTPError(
            TEST_ORIGIN + "/api/issues", 500, "Server Error", {}, None,
        )
        with self.assertRaises(WorkspaceApiFailure) as raised:
            self.client.create_issue(title="Task", description="", project_id="project-1", status="todo")
        self.assertEqual(raised.exception.outcome, "unknown")
        self.assertEqual(self.opener.open.call_count, 1)

    def test_upload_accepts_bytes_without_creating_a_temporary_file(self) -> None:
        self.opener.open.return_value = _Response(b'{"id":"attachment-1"}')
        result = self.client.upload_issue_attachment("issue-1", "doc.pdf", "application/pdf", b"%PDF-test")
        request = self.opener.open.call_args.args[0]
        self.assertEqual(result["id"], "attachment-1")
        self.assertIn(b'name="issue_id"', request.data)
        self.assertIn(b"issue-1", request.data)

    def test_default_transport_interrupts_blocking_body_read_at_total_deadline(self) -> None:
        response = _BlockingBodyResponse()
        self.opener.open.return_value = response
        self.client.timeout = 0.05
        self.client._default_transport = True
        started = time.monotonic()

        with self.assertRaises(BridgeError) as raised:
            self.client.get_issue("issue-1")

        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIsNotNone(response._sock.timeout)
        self.assertTrue(response.released.is_set())

    def test_write_body_timeout_has_unknown_outcome(self) -> None:
        response = _BlockingBodyResponse()
        self.opener.open.return_value = response
        self.client.timeout = 0.05
        self.client._default_transport = True

        with self.assertRaises(WorkspaceApiFailure) as raised:
            self.client.create_issue(title="Task", description="", project_id="project-1", status="todo")

        self.assertEqual(raised.exception.code, "operation_unknown")
        self.assertEqual(raised.exception.outcome, "unknown")

    def test_invalid_comment_fails_before_http(self) -> None:
        with self.assertRaises(BridgeError):
            self.client.create_comment("issue-1", " \n")
        self.opener.open.assert_not_called()

    def test_invalid_issue_update_fails_before_http(self) -> None:
        with self.assertRaises(BridgeError):
            self.client.update_issue("issue-1", {"title": {"untrusted": "object"}})
        self.opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
