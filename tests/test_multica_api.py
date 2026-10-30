from __future__ import annotations

import io
import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from bridge.errors import BridgeError
from bridge.multica_api import MulticaApiClient
from bridge.validation import MAX_MULTICA_PAT_BYTES
from tests.helpers import TEST_ORIGIN, TEST_PAT, TEST_WEBHOOK_URL

TEST_WORKSPACE_ID = "workspace-example"


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = io.BytesIO(json.dumps(body).encode("utf-8"))

    def read(self, limit: int) -> bytes:
        return self.body.read(limit)

    def close(self) -> None:
        self.body.close()


class RoutingOpener:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float):
        self.requests.append(request)
        path = request.full_url.removeprefix(TEST_ORIGIN)
        response = self.routes[path]
        if isinstance(response, Exception):
            raise response
        return FakeResponse(response)


class SequencedRoutingOpener:
    def __init__(self, routes: dict[str, list[object]]):
        self.routes = {path: list(values) for path, values in routes.items()}
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float):
        self.requests.append(request)
        path = request.full_url.removeprefix(TEST_ORIGIN)
        values = self.routes[path]
        response = values.pop(0) if len(values) > 1 else values[0]
        if isinstance(response, Exception):
            raise response
        return FakeResponse(response)


class ClockedRoutingOpener(RoutingOpener):
    def __init__(self, routes: dict[str, object], clock):
        super().__init__(routes)
        self.clock = clock

    def open(self, request: urllib.request.Request, timeout: float):
        self.clock.value += 0.4
        return super().open(request, timeout)


class ResponseOpener:
    def __init__(self, response):
        self.response = response

    def open(self, _request: urllib.request.Request, timeout: float):
        return self.response


class ReadTimeoutResponse(FakeResponse):
    def read(self, limit: int) -> bytes:
        raise TimeoutError("simulated response timeout")


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class DripResponse(FakeResponse):
    def __init__(self, clock: FakeClock):
        super().__init__({})
        self.clock = clock

    def read1(self, _limit: int) -> bytes:
        self.clock.value += 0.6
        return b"x"


class InterruptibleSocket:
    def __init__(self, released: threading.Event):
        self.released = released
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def shutdown(self, _how: int) -> None:
        self.released.set()

    def close(self) -> None:
        self.released.set()


class BlockingBodyResponse:
    status = 200

    def __init__(self) -> None:
        self.released = threading.Event()
        self.fp = self
        self.raw = self
        self._sock = InterruptibleSocket(self.released)

    def read1(self, _limit: int) -> bytes:
        self.released.wait(1.0)
        raise OSError("body read interrupted")

    def close(self) -> None:
        self.released.set()


class ClosingContentLengthResponse:
    status = 200

    def __init__(self, payload: object) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.length = len(self._body)
        self.fp = self
        self.timeout: float | None = None

    def isclosed(self) -> bool:
        return self.fp is None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def read1(self, _limit: int) -> bytes:
        body = self._body
        self._body = b""
        self.length = 0
        self.fp = None
        return body

    def close(self) -> None:
        self.fp = None


class PrematureEofContentLengthResponse(ClosingContentLengthResponse):
    def __init__(self, payload: object) -> None:
        super().__init__(payload)
        self.length += 1

    def read1(self, _limit: int) -> bytes:
        if self._body:
            body = self._body
            self._body = b""
            self.length -= len(body)
            return body
        return b""


class MulticaApiTests(unittest.TestCase):
    def test_pat_limit_matches_isolated_credential_limit(self) -> None:
        MulticaApiClient(TEST_ORIGIN, "A" * MAX_MULTICA_PAT_BYTES, TEST_WORKSPACE_ID)
        for invalid in ("A" * (MAX_MULTICA_PAT_BYTES + 1), "tøken"):
            with self.subTest(invalid_length=len(invalid)), self.assertRaises(BridgeError) as raised:
                MulticaApiClient(TEST_ORIGIN, invalid, TEST_WORKSPACE_ID)
            self.assertEqual(raised.exception.code, "credential_invalid")

    def test_default_transport_accepts_body_when_content_length_is_fully_consumed(self) -> None:
        response = ClosingContentLengthResponse({"status": "ok"})
        client = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=ResponseOpener(response))
        client._default_transport = True

        result = client._get("/api/example")

        self.assertEqual(result, {"status": "ok"})
        self.assertIsNotNone(response.timeout)

    def test_default_transport_rejects_premature_eof_with_remaining_content_length(self) -> None:
        response = PrematureEofContentLengthResponse({"status": "ok"})
        client = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=ResponseOpener(response))
        client._default_transport = True

        with self.assertRaises(BridgeError) as raised:
            client._get("/api/example")

        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)

    def test_snapshot_reads_only_recorded_run_issue_and_comments(self) -> None:
        opener = RoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": {
                    "id": "run-1",
                    "autopilot_id": "autopilot-example",
                    "status": "completed",
                    "issue_id": "issue-1",
                    "task_id": "task-multica",
                    "result": {"summary": "done"},
                },
                "/api/issues/issue-1": {
                    "id": "issue-1",
                    "identifier": "ISS-1",
                    "title": "Work",
                    "status": "done",
                    "revision": 8,
                },
                "/api/issues/issue-1/comments": [
                    {
                        "id": "c1",
                        "content": "Completed successfully",
                        "author_type": "agent",
                        "issue_revision": 8,
                    }
                ],
            }
        )
        snapshot = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).snapshot(
            "autopilot-example", "run-1"
        )
        self.assertEqual(snapshot.execution_status, "succeeded")
        self.assertEqual(snapshot.issue_id, "issue-1")
        self.assertEqual(snapshot.source_revision, 8)
        self.assertIn("Completed successfully", snapshot.result_text)
        self.assertTrue(all(req.get_header("Authorization") == f"Bearer {TEST_PAT}" for req in opener.requests))
        self.assertTrue(all(req.get_header("X-workspace-id") == TEST_WORKSPACE_ID for req in opener.requests))

    def test_snapshot_redacts_pat_and_webhook_credentials_from_result_and_comment(self) -> None:
        webhook_token = TEST_WEBHOOK_URL.rsplit("/", 1)[-1]
        encoded_webhook = urllib.parse.quote(TEST_WEBHOOK_URL, safe="")
        opener = RoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": {
                    "id": "run-1",
                    "autopilot_id": "autopilot-example",
                    "status": "completed",
                    "issue_id": "issue-1",
                    "result": {
                        "summary": f"PAT={TEST_PAT}; webhook={TEST_WEBHOOK_URL}; token={webhook_token}",
                        "encoded_webhook": encoded_webhook,
                    },
                },
                "/api/issues/issue-1": {
                    "id": "issue-1",
                    "identifier": "ISS-1",
                    "status": "done",
                    "revision": 8,
                },
                "/api/issues/issue-1/comments": [
                    {
                        "id": "c1",
                        "content": f"PAT echo={TEST_PAT}; webhook echo={TEST_WEBHOOK_URL}",
                    }
                ],
            }
        )
        snapshot = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=opener,
            sensitive_values=(TEST_WEBHOOK_URL,),
        ).snapshot("autopilot-example", "run-1")

        self.assertIn("[REDACTED]", snapshot.result_text)
        for secret in (TEST_PAT, TEST_WEBHOOK_URL, webhook_token, encoded_webhook):
            self.assertNotIn(secret, snapshot.result_text)

    def test_snapshot_retries_when_issue_revision_changes_during_comment_read(self) -> None:
        opener = SequencedRoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": [
                    {
                        "id": "run-1",
                        "autopilot_id": "autopilot-example",
                        "status": "completed",
                        "issue_id": "issue-1",
                    }
                ],
                "/api/issues/issue-1": [
                    {"id": "issue-1", "identifier": "ISS-1", "status": "running", "revision": 7},
                    {"id": "issue-1", "identifier": "ISS-1", "status": "done", "revision": 8},
                    {"id": "issue-1", "identifier": "ISS-1", "status": "done", "revision": 8},
                ],
                "/api/issues/issue-1/comments": [
                    [{"id": "c1", "content": "done", "issue_revision": 8}],
                    [{"id": "c1", "content": "done", "issue_revision": 8}],
                ],
            }
        )

        snapshot = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).snapshot(
            "autopilot-example",
            "run-1",
        )

        self.assertEqual(snapshot.source_revision, 8)
        self.assertIn("Issue: ISS-1 (done).", snapshot.result_text)
        self.assertEqual(
            [request.full_url.removeprefix(TEST_ORIGIN) for request in opener.requests],
            [
                "/api/autopilots/autopilot-example/runs/run-1",
                "/api/issues/issue-1",
                "/api/issues/issue-1/comments",
                "/api/issues/issue-1",
                "/api/issues/issue-1/comments",
                "/api/issues/issue-1",
            ],
        )

    def test_unversioned_issue_does_not_inherit_comment_revision(self) -> None:
        opener = RoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": {
                    "id": "run-1",
                    "autopilot_id": "autopilot-example",
                    "status": "completed",
                    "issue_id": "issue-1",
                },
                "/api/issues/issue-1": {
                    "id": "issue-1",
                    "identifier": "ISS-1",
                    "status": "done",
                },
                "/api/issues/issue-1/comments": [
                    {"id": "c1", "content": "done", "issue_revision": 8}
                ],
            }
        )
        snapshot = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=opener,
        ).snapshot("autopilot-example", "run-1")
        self.assertIsNone(snapshot.source_revision)
        self.assertIn("done", snapshot.result_text)

    def test_snapshot_rejects_revision_outside_sqlite_integer_range(self) -> None:
        for issue_revision, comment_revision in (
            (1 << 63, None),
            (7, 1 << 63),
        ):
            opener = RoutingOpener(
                {
                    "/api/autopilots/autopilot-example/runs/run-1": {
                        "id": "run-1",
                        "autopilot_id": "autopilot-example",
                        "status": "completed",
                        "issue_id": "issue-1",
                    },
                    "/api/issues/issue-1": {
                        "id": "issue-1",
                        "revision": issue_revision,
                    },
                    "/api/issues/issue-1/comments": (
                        []
                        if comment_revision is None
                        else [{"id": "c1", "content": "done", "issue_revision": comment_revision}]
                    ),
                }
            )
            with self.subTest(issue_revision=issue_revision, comment_revision=comment_revision):
                with self.assertRaises(BridgeError) as raised:
                    MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).snapshot(
                        "autopilot-example",
                        "run-1",
                    )
                self.assertEqual(raised.exception.code, "invalid_api_response")

    def test_snapshot_rejects_malformed_supplied_issue_and_comment_revisions(self) -> None:
        malformed = (0, -1, 1.5, "8", True)
        for field, value in (("revision", item) for item in malformed):
            opener = RoutingOpener(
                {
                    "/api/issues/issue-1": {"id": "issue-1", field: value},
                    "/api/issues/issue-1/comments": [],
                }
            )
            client = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener)
            with self.subTest(field=field, value=value), self.assertRaises(BridgeError) as raised:
                client._read_coherent_issue_snapshot(
                    "issue-1", deadline=client.monotonic() + client.timeout,
                )
            self.assertEqual(raised.exception.code, "invalid_api_response")
            self.assertEqual(len(opener.requests), 1)

        for value in malformed:
            opener = RoutingOpener(
                {
                    "/api/issues/issue-1": {"id": "issue-1", "revision": 8},
                    "/api/issues/issue-1/comments": [
                        {"id": "comment-1", "content": "result", "issue_revision": value}
                    ],
                }
            )
            client = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener)
            with self.subTest(field="issue_revision", value=value), self.assertRaises(BridgeError) as raised:
                client._read_coherent_issue_snapshot(
                    "issue-1", deadline=client.monotonic() + client.timeout,
                )
            self.assertEqual(raised.exception.code, "invalid_api_response")
            self.assertEqual(len(opener.requests), 2)

    def test_snapshot_bounds_result_metadata_before_ipc(self) -> None:
        for field, value in (
            ("issue_id", "i" * 129),
            ("task_id", "task with spaces"),
        ):
            opener = RoutingOpener(
                {
                    "/api/autopilots/autopilot-example/runs/run-1": {
                        "id": "run-1",
                        "autopilot_id": "autopilot-example",
                        "status": "completed",
                        field: value,
                    }
                }
            )
            with self.subTest(field=field), self.assertRaises(BridgeError) as raised:
                MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).snapshot(
                    "autopilot-example",
                    "run-1",
                )
            self.assertEqual(raised.exception.code, "invalid_api_response")

        for malformed_status in ("x" * 200_000, ["completed"], {"value": "completed"}):
            opener = RoutingOpener(
                {
                    "/api/autopilots/autopilot-example/runs/run-1": {
                        "id": "run-1",
                        "autopilot_id": "autopilot-example",
                        "status": malformed_status,
                    }
                }
            )
            with self.subTest(status_type=type(malformed_status).__name__):
                snapshot = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).snapshot(
                    "autopilot-example",
                    "run-1",
                )
                self.assertEqual(snapshot.run_status, "unknown")
                self.assertEqual(snapshot.execution_status, "unknown")

    def test_run_identity_mismatch_is_rejected(self) -> None:
        opener = RoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": {
                    "id": "other-run",
                    "autopilot_id": "autopilot-example",
                    "status": "running",
                }
            }
        )
        with self.assertRaises(BridgeError) as raised:
            MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener).get_run(
                "autopilot-example", "run-1"
            )
        self.assertEqual(raised.exception.code, "invalid_api_response")

    def test_404_and_500_have_safe_retry_semantics(self) -> None:
        for status, expected_code, retryable in (
            (404, "result_not_found", False),
            (500, "api_unavailable", True),
        ):
            error = urllib.error.HTTPError(
                f"{TEST_ORIGIN}/api/x",
                status,
                "secret",
                {},
                io.BytesIO(b"secret"),
            )
            opener = RoutingOpener({"/api/x": error})
            client = MulticaApiClient(TEST_ORIGIN, TEST_PAT, TEST_WORKSPACE_ID, opener=opener)
            with self.subTest(status=status), self.assertRaises(BridgeError) as raised:
                client._get("/api/x")
            self.assertEqual(raised.exception.code, expected_code)
            self.assertEqual(raised.exception.retryable, retryable)

    def test_response_read_timeout_is_sanitized_and_retryable(self) -> None:
        client = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=ResponseOpener(ReadTimeoutResponse({})),
        )
        with self.assertRaises(BridgeError) as raised:
            client._get("/api/x")
        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertNotIn("simulated response timeout", raised.exception.message)

    def test_response_read_has_one_absolute_deadline(self) -> None:
        clock = FakeClock()
        client = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=ResponseOpener(DripResponse(clock)),
            timeout=1.0,
            monotonic=clock,
        )
        with self.assertRaises(BridgeError) as raised:
            client._get("/api/x")
        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertGreater(clock.value, 1.0)

    def test_default_transport_interrupts_blocking_body_read_at_absolute_deadline(self) -> None:
        response = BlockingBodyResponse()
        client = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=ResponseOpener(response),
            timeout=0.05,
        )
        client._default_transport = True
        started = time.monotonic()
        with self.assertRaises(BridgeError) as raised:
            client._get("/api/x")
        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIsNotNone(response._sock.timeout)

    def test_snapshot_shares_deadline_across_run_issue_and_comments(self) -> None:
        clock = FakeClock()
        opener = ClockedRoutingOpener(
            {
                "/api/autopilots/autopilot-example/runs/run-1": {
                    "id": "run-1",
                    "autopilot_id": "autopilot-example",
                    "status": "completed",
                    "issue_id": "issue-1",
                },
                "/api/issues/issue-1": {"id": "issue-1", "status": "done"},
                "/api/issues/issue-1/comments": [],
            },
            clock,
        )
        client = MulticaApiClient(
            TEST_ORIGIN,
            TEST_PAT,
            TEST_WORKSPACE_ID,
            opener=opener,
            timeout=1.0,
            monotonic=clock,
        )
        with self.assertRaises(BridgeError) as raised:
            client.snapshot("autopilot-example", "run-1")
        self.assertEqual(raised.exception.code, "api_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(len(opener.requests), 3)


if __name__ == "__main__":
    unittest.main()
