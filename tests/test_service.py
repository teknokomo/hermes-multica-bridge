from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.multica_api import MAX_API_RESPONSE_BYTES, ResultSnapshot
from bridge.protocol import MAX_IPC_RESPONSE_BYTES
from bridge.service import BridgeService, ServiceCredentials, _comment_text
from bridge.state import DeliverySnapshot, DeliveryStore
from bridge.webhook import WebhookResult, webhook_url_fingerprint
from tests.helpers import (
    TEST_HMAC_SECRET,
    TEST_ORIGIN,
    TEST_PAT,
    TEST_WEBHOOK_URL,
    sample_request,
    standard_connection,
)


class FakeWebhookClient:
    def __init__(self, result: WebhookResult, calls: list[dict], **_kwargs):
        self.result = result
        self.calls = calls

    def send(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self.result


class FakeApiClient:
    def __init__(self, snapshot: ResultSnapshot, calls: list[tuple], *args, **kwargs):
        self.value = snapshot
        self.calls = calls
        self.calls.append(("init", args, kwargs))

    def snapshot(self, autopilot_id: str, run_id: str) -> ResultSnapshot:
        self.calls.append(("snapshot", autopilot_id, run_id))
        return self.value


class ServiceTests(unittest.TestCase):
    def test_long_result_comment_keeps_dedupe_marker(self) -> None:
        fingerprint = "a" * 64
        request_id = "019a0000-0000-7000-8000-000000000001"
        marker = f"<!-- hmb-result:{request_id}:{fingerprint} -->"
        text = _comment_text("x" * 20_000, request_id, fingerprint)
        self.assertLessEqual(len(text), 8_192)
        self.assertTrue(text.endswith(marker))
        self.assertEqual(text.count(marker), 1)

    def test_isolated_result_response_is_bounded_by_encoded_ipc_bytes(self) -> None:
        fingerprint = "b" * 64
        snapshot = ResultSnapshot(
            "succeeded",
            "completed",
            "issue-1",
            "multica-task-1",
            ("🙂\\\"\x00" * 4_000),
            fingerprint,
        )
        config = standard_connection(security_mode="isolated", isolated_instance_id="example")
        service = self._service(config=config, snapshot=snapshot)
        service.send(sample_request())
        response = service.check_result(sample_request(run_id="13"))
        encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        self.assertLessEqual(len(encoded), MAX_IPC_RESPONSE_BYTES)
        self.assertTrue(
            response["comment_text"].endswith(
                f"<!-- hmb-result:{response['request_id']}:{fingerprint} -->"
            )
        )
        self.assertTrue(response["result"].endswith("…"))

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        state_dir = Path(self.temp.name) / "state"
        state_dir.mkdir(mode=0o700)
        self.store = DeliveryStore(state_dir / "deliveries.sqlite3")
        self.webhook_calls: list[dict] = []
        self.api_calls: list[tuple] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(
        self,
        *,
        config=None,
        result: WebhookResult | None = None,
        snapshot: ResultSnapshot | None = None,
        credentials: ServiceCredentials | None = None,
    ) -> BridgeService:
        config = config or standard_connection()
        result = result or WebhookResult(
            True,
            "accepted",
            "pending",
            "delivery-1",
            "run-1",
            200,
        )
        snapshot = snapshot or ResultSnapshot(
            "succeeded",
            "completed",
            "issue-1",
            "multica-task-1",
            "Multica execution status: succeeded.",
            "a" * 64,
        )
        credentials = credentials or ServiceCredentials(
            webhook_url=TEST_WEBHOOK_URL,
            hmac_signing_secret=TEST_HMAC_SECRET,
            multica_pat=TEST_PAT,
        )
        return BridgeService(
            config,
            credentials,
            self.store,
            webhook_client_factory=lambda **kwargs: FakeWebhookClient(result, self.webhook_calls, **kwargs),
            api_client_factory=lambda *args, **kwargs: FakeApiClient(snapshot, self.api_calls, *args, **kwargs),
        )

    def test_send_lifecycle_uses_stable_ledger_and_trusted_config(self) -> None:
        response = self._service().send(sample_request())
        self.assertTrue(response["ok"])
        self.assertEqual(response["run_id"], "run-1")
        self.assertEqual(len(self.webhook_calls), 1)
        call = self.webhook_calls[0]
        self.assertEqual(call["url"], TEST_WEBHOOK_URL)
        self.assertEqual(call["multica_origin"], TEST_ORIGIN)
        self.assertEqual(call["event_payload"], sample_request())
        self.assertEqual(call["hmac_secret"], TEST_HMAC_SECRET)

    def test_has_delivery_is_local_and_route_scoped(self) -> None:
        service = self._service()
        self.assertEqual(service.has_delivery(sample_request()), {"ok": True, "has_delivery": False})
        service.send(sample_request())
        self.assertEqual(service.has_delivery(sample_request()), {"ok": True, "has_delivery": True})
        self.assertEqual(self.api_calls, [])

    def test_disabled_route_keeps_existing_delivery_and_result_readable(self) -> None:
        enabled = self._service()
        enabled.send(sample_request())
        disabled = self._service(config=standard_connection(enabled=False))

        self.assertEqual(disabled.has_delivery(sample_request()), {"ok": True, "has_delivery": True})
        result = disabled.check_result(sample_request(run_id="13"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["execution_status"], "succeeded")

    def test_configured_payload_limit_is_passed_to_webhook_client(self) -> None:
        service = self._service(config=standard_connection(max_payload_bytes=4096))
        client_factory = service.webhook_client_factory
        captured = {}

        def capture_factory(**kwargs):
            captured.update(kwargs)
            return client_factory(**kwargs)

        service.webhook_client_factory = capture_factory
        service.send(sample_request())
        self.assertEqual(captured["max_payload_bytes"], 4096)

    def test_retry_after_http_408_reuses_the_stable_idempotency_key(self) -> None:
        result = WebhookResult(
            False,
            "failed",
            "unknown",
            http_status=408,
            error_code="http_error",
            retryable=True,
        )
        service = self._service(result=result)
        service.send(sample_request())
        service.send(sample_request())
        self.assertEqual(len(self.webhook_calls), 2)
        self.assertEqual(
            self.webhook_calls[0]["idempotency_key"],
            self.webhook_calls[1]["idempotency_key"],
        )

    def test_board_hmac_and_webhook_pin_fail_closed(self) -> None:
        with self.assertRaises(BridgeError) as denied:
            self._service().send(sample_request(board="other-board"))
        self.assertEqual(denied.exception.code, "route_denied")

        with self.assertRaises(BridgeError) as hmac:
            self._service(
                credentials=ServiceCredentials(
                    webhook_url=TEST_WEBHOOK_URL,
                    hmac_signing_secret=None,
                    multica_pat=TEST_PAT,
                )
            ).send(sample_request())
        self.assertEqual(hmac.exception.code, "credential_unavailable")

        with self.assertRaises(BridgeError) as pin:
            self._service(
                credentials=ServiceCredentials(
                    webhook_url=TEST_WEBHOOK_URL,
                    hmac_signing_secret=TEST_HMAC_SECRET,
                    multica_pat=TEST_PAT,
                    webhook_sha256="0" * 64,
                )
            ).send(sample_request())
        self.assertEqual(pin.exception.code, "credential_mismatch")

    def test_send_rejects_incomplete_connection_before_http(self) -> None:
        service = self._service(config=standard_connection(workspace_id=""))
        with self.assertRaises(BridgeError) as raised:
            service.send(sample_request())
        self.assertEqual(raised.exception.code, "configuration_incomplete")
        self.assertIn("workspace_id", raised.exception.message)
        self.assertEqual(self.webhook_calls, [])

    def test_webhook_client_factory_failure_does_not_reserve_attempt(self) -> None:
        config = standard_connection()

        def failing_factory(**_kwargs):
            raise RuntimeError("fixture client construction failure")

        service = BridgeService(
            config,
            ServiceCredentials(
                webhook_url=TEST_WEBHOOK_URL,
                hmac_signing_secret=TEST_HMAC_SECRET,
                multica_pat=TEST_PAT,
            ),
            self.store,
            webhook_client_factory=failing_factory,
        )
        with self.assertRaises(RuntimeError):
            service.send(sample_request())
        self.assertIsNone(
            self.store.get_delivery(
                connection_key=config.connection_key,
                source_board="example-board",
                source_task_id="task_12345678",
            )
        )

    def test_result_uses_only_recorded_run_and_reserves_comment_once(self) -> None:
        service = self._service()
        sent = service.send(sample_request())
        result = service.check_result(sample_request(run_id="13"))
        self.assertTrue(result["ok"])
        self.assertTrue(result["comment_required"])
        self.assertEqual(result["request_id"], sent["request_id"])
        self.assertEqual(self.api_calls[-1], ("snapshot", "autopilot-example", "run-1"))
        self.assertIn("<!-- hmb-result:", result["comment_text"])

        second = service.check_result(sample_request(run_id="14"))
        self.assertFalse(second["comment_required"])

    def test_revisionless_terminal_snapshot_can_publish_later_comment(self) -> None:
        snapshots = iter(
            (
                ResultSnapshot(
                    "succeeded",
                    "completed",
                    "issue-1",
                    "multica-task-1",
                    "Multica execution status: succeeded.",
                    "a" * 64,
                ),
                ResultSnapshot(
                    "succeeded",
                    "completed",
                    "issue-1",
                    "multica-task-1",
                    "Multica execution status: succeeded.\nFinal comment.",
                    "b" * 64,
                ),
            )
        )

        class SequencedApiClient:
            def __init__(self, *_args, **_kwargs):
                pass

            def snapshot(self, _autopilot_id: str, _run_id: str) -> ResultSnapshot:
                return next(snapshots)

        service = self._service()
        service.api_client_factory = SequencedApiClient
        sent = service.send(sample_request())

        first = service.check_result(sample_request())
        self.assertTrue(first["comment_required"])
        service.finish_result_comment_for_request(
            sample_request(),
            sent["request_id"],
            first["comment_fingerprint"],
            published=True,
        )

        second = service.check_result(sample_request(run_id="13"))
        self.assertTrue(second["comment_required"])
        self.assertEqual(second["comment_fingerprint"], "b" * 64)
        self.assertIn("Final comment.", second["comment_text"])

    def test_result_uses_recorded_destination_snapshot_after_current_config_changes(self) -> None:
        route_id = "018f0000-0000-7000-8000-000000000001"
        original = standard_connection()
        snapshot = DeliverySnapshot(
            route_id=route_id,
            connection_id="018f0000-0000-7000-8000-000000000002",
            workspace_key="018f0000-0000-7000-8000-000000000003",
            workspace_id=original.workspace_id,
            multica_origin=original.multica_origin,
            autopilot_id=original.autopilot_id,
            trigger_id=original.trigger_id,
            security_mode="standard",
            route_policy_fingerprint="route-policy-" + ("a" * 64),
        )
        credentials = ServiceCredentials(
            webhook_url=TEST_WEBHOOK_URL,
            hmac_signing_secret=TEST_HMAC_SECRET,
            multica_pat=TEST_PAT,
        )
        first = BridgeService(
            original,
            credentials,
            self.store,
            ledger_key=route_id,
            delivery_snapshot=snapshot,
            webhook_client_factory=lambda **kwargs: FakeWebhookClient(
                WebhookResult(True, "accepted", "pending", "delivery-1", "run-1", 200),
                self.webhook_calls,
                **kwargs,
            ),
            api_client_factory=lambda *args, **kwargs: FakeApiClient(
                ResultSnapshot(
                    "succeeded",
                    "completed",
                    "issue-1",
                    "multica-task-1",
                    "done",
                    "c" * 64,
                ),
                self.api_calls,
                *args,
                **kwargs,
            ),
        )
        first.send(sample_request())

        changed = standard_connection(
            multica_origin="https://replacement.example.org",
            autopilot_id="autopilot-replacement",
        )
        second = BridgeService(
            changed,
            credentials,
            self.store,
            ledger_key=route_id,
            api_client_factory=lambda *args, **kwargs: FakeApiClient(
                ResultSnapshot(
                    "succeeded",
                    "completed",
                    "issue-1",
                    "multica-task-1",
                    "done",
                    "c" * 64,
                ),
                self.api_calls,
                *args,
                **kwargs,
            ),
        )
        second.check_result(sample_request())
        init = [call for call in self.api_calls if call[0] == "init"][-1]
        self.assertEqual(init[1][0], original.multica_origin)
        self.assertEqual(init[1][2], original.workspace_id)
        self.assertEqual(init[2]["max_response_bytes"], MAX_API_RESPONSE_BYTES)
        self.assertEqual(init[2]["sensitive_values"], (TEST_WEBHOOK_URL,))
        self.assertEqual(self.api_calls[-1], ("snapshot", original.autopilot_id, "run-1"))

    def test_stale_concurrent_result_snapshot_is_not_returned_or_commented(self) -> None:
        stale_snapshot = ResultSnapshot(
            "running",
            "running",
            "issue-1",
            "multica-task-1",
            "Multica execution status: running.",
            "a" * 64,
        )
        service = self._service(snapshot=stale_snapshot)
        sent = service.send(sample_request())
        self.store.record_result(
            connection_key=service.ledger_key,
            request_id=sent["request_id"],
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="multica-task-1",
            result_sha256="b" * 64,
        )

        result = service.check_result(sample_request(run_id="13"))

        self.assertEqual(result["execution_status"], "succeeded")
        self.assertFalse(result["comment_required"])
        record = self.store.get_delivery(
            connection_key=service.ledger_key,
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_status, "succeeded")
        self.assertEqual(record.result_sha256, "b" * 64)

    def test_result_ack_is_bound_to_source_task_and_can_release_or_publish(self) -> None:
        service = self._service()
        sent = service.send(sample_request())
        result = service.check_result(sample_request())
        fingerprint = result["comment_fingerprint"]
        service.finish_result_comment_for_request(
            sample_request(),
            sent["request_id"],
            fingerprint,
            published=False,
        )
        retry = service.check_result(sample_request(run_id="13"))
        self.assertTrue(retry["comment_required"])
        service.finish_result_comment_for_request(
            sample_request(run_id="13"),
            sent["request_id"],
            fingerprint,
            published=True,
        )
        with self.assertRaises(BridgeError):
            service.finish_result_comment_for_request(
                sample_request(task_id="other_task"),
                sent["request_id"],
                fingerprint,
                published=True,
            )

    def test_task_content_change_after_delivery_is_rejected_for_result(self) -> None:
        service = self._service()
        service.send(sample_request())
        with self.assertRaises(BridgeError) as raised:
            service.check_result(sample_request(body="changed after delivery"))
        self.assertEqual(raised.exception.code, "request_conflict")

    def test_rejected_delivery_never_queries_reported_run_id(self) -> None:
        service = self._service(
            result=WebhookResult(
                False,
                "rejected",
                "unknown",
                "delivery-rejected",
                "run-untrusted",
                401,
                "unauthorized",
            )
        )
        sent = service.send(sample_request(task_id="task_rejected"))
        self.assertFalse(sent["ok"])
        result = service.check_result(sample_request(task_id="task_rejected"))
        self.assertEqual(result["delivery_status"], "rejected")
        self.assertFalse(result["comment_required"])
        self.assertEqual(self.api_calls, [])

    def test_result_tracking_disabled_or_missing_pat_is_rejected(self) -> None:
        disabled = standard_connection(result_tracking_enabled=False)
        service = self._service(config=disabled)
        service.send(sample_request())
        with self.assertRaises(BridgeError) as raised:
            service.check_result(sample_request())
        self.assertEqual(raised.exception.code, "result_tracking_disabled")

        missing_pat = self._service(
            credentials=ServiceCredentials(
                webhook_url=TEST_WEBHOOK_URL,
                hmac_signing_secret=TEST_HMAC_SECRET,
                multica_pat=None,
            )
        )
        missing_pat.send(sample_request(task_id="task_missing_pat"))
        with self.assertRaises(BridgeError) as raised:
            missing_pat.check_result(sample_request(task_id="task_missing_pat"))
        self.assertEqual(raised.exception.code, "credential_unavailable")

    def test_service_credentials_repr_hides_secret_values(self) -> None:
        credentials = ServiceCredentials(
            webhook_url=TEST_WEBHOOK_URL,
            hmac_signing_secret=TEST_HMAC_SECRET,
            multica_pat=TEST_PAT,
            webhook_sha256="a" * 64,
        )
        rendered = repr(credentials)
        self.assertNotIn(TEST_WEBHOOK_URL, rendered)
        self.assertNotIn(TEST_HMAC_SECRET, rendered)
        self.assertNotIn(TEST_PAT, rendered)
        self.assertIn("webhook_sha256", rendered)

    def test_webhook_fingerprint_pin_can_be_valid(self) -> None:
        credentials = ServiceCredentials(
            webhook_url=TEST_WEBHOOK_URL,
            hmac_signing_secret=TEST_HMAC_SECRET,
            multica_pat=TEST_PAT,
            webhook_sha256=webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN),
        )
        self.assertTrue(self._service(credentials=credentials).send(sample_request())["ok"])


if __name__ == "__main__":
    unittest.main()
