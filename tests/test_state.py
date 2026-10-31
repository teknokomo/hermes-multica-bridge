from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.state import DeliveryStore
from bridge.validation import request_fingerprint
from tests.helpers import sample_request


class StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state" / "deliveries.sqlite3"
        self.path.parent.mkdir(mode=0o700)
        self.store = DeliveryStore(self.path)
        self.fingerprint = request_fingerprint(sample_request())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _attempt(self, fingerprint: str | None = None):
        return self.store.begin_attempt(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
            fingerprint=fingerprint or self.fingerprint,
            max_requests=5,
            window_seconds=600,
            max_attempts=3,
        )

    def test_retries_keep_request_id_and_idempotency_key(self) -> None:
        first = self._attempt()
        self.store.finish_attempt(
            connection_key="conn-test",
            request_id=first.request_id,
            attempt_number=first.number,
            attempt_id=first.attempt_id,
            delivery_status="unknown",
            execution_status="unknown",
            delivery_id=None,
            run_id=None,
            http_status=None,
        )
        second = self._attempt()
        self.assertEqual(first.request_id, second.request_id)
        self.assertEqual(first.key, second.key)
        self.assertEqual(second.number, 2)

    def test_earlier_success_survives_later_retry_failure(self) -> None:
        first = self._attempt()
        second = self._attempt()
        self.store.finish_attempt(
            connection_key="conn-test",
            request_id=first.request_id,
            attempt_number=first.number,
            attempt_id=first.attempt_id,
            delivery_status="accepted",
            execution_status="pending",
            delivery_id="delivery-1",
            run_id="run-1",
            http_status=200,
        )
        self.store.finish_attempt(
            connection_key="conn-test",
            request_id=second.request_id,
            attempt_number=second.number,
            attempt_id=second.attempt_id,
            delivery_status="failed",
            execution_status="unknown",
            delivery_id=None,
            run_id=None,
            http_status=500,
        )
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.delivery_status, "accepted")
        self.assertEqual(record.run_id, "run-1")

    def test_changed_task_content_conflicts_with_existing_delivery(self) -> None:
        self._attempt()
        with self.assertRaises(BridgeError) as raised:
            self._attempt(request_fingerprint(sample_request(body="changed")))
        self.assertEqual(raised.exception.code, "request_conflict")

    def test_attempt_and_rate_limits_are_enforced(self) -> None:
        store = DeliveryStore(Path(self.temp.name) / "other" / "deliveries.sqlite3")
        for _ in range(2):
            attempt = store.begin_attempt(
                connection_key="conn-rate",
                source_board="example-board",
                source_task_id="task_rate",
                fingerprint=self.fingerprint,
                max_requests=2,
                window_seconds=600,
                max_attempts=3,
            )
            store.finish_attempt(
                connection_key="conn-rate",
                request_id=attempt.request_id,
                attempt_number=attempt.number,
                attempt_id=attempt.attempt_id,
                delivery_status="failed",
                execution_status="unknown",
                delivery_id=None,
                run_id=None,
                http_status=500,
            )
        with self.assertRaises(BridgeError) as raised:
            store.begin_attempt(
                connection_key="conn-rate",
                source_board="example-board",
                source_task_id="task_rate",
                fingerprint=self.fingerprint,
                max_requests=2,
                window_seconds=600,
                max_attempts=3,
            )
        self.assertEqual(raised.exception.code, "rate_limited")

    def test_connection_rate_limit_is_shared_across_route_partitions(self) -> None:
        self.store.reserve_connection_request(
            connection_id="connection-shared",
            max_requests=2,
            window_seconds=600,
            now=1000.0,
        )
        self.store.reserve_connection_request(
            connection_id="connection-shared",
            max_requests=2,
            window_seconds=600,
            now=1001.0,
        )
        with self.assertRaises(BridgeError) as raised:
            self.store.reserve_connection_request(
                connection_id="connection-shared",
                max_requests=2,
                window_seconds=600,
                now=1002.0,
            )
        self.assertEqual(raised.exception.code, "rate_limited")

        self.store.reserve_connection_request(
            connection_id="connection-other",
            max_requests=2,
            window_seconds=600,
            now=1002.0,
        )

    def test_result_comment_reservation_is_two_phase_and_deduplicated(self) -> None:
        attempt = self._attempt()
        self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
        )
        self.assertTrue(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
            )
        )
        self.store.finish_result_comment(
            connection_key="conn-test",
            request_id=attempt.request_id,
            comment_sha256="a" * 64,
            published=False,
        )
        self.assertTrue(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
            )
        )
        self.store.finish_result_comment(
            connection_key="conn-test",
            request_id=attempt.request_id,
            comment_sha256="a" * 64,
            published=True,
        )
        self.assertFalse(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
            )
        )
        self.assertFalse(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
            )
        )

    def test_stale_result_cannot_regress_state_or_reserve_old_comment(self) -> None:
        attempt = self._attempt()
        self.store.finish_attempt(
            connection_key="conn-test",
            request_id=attempt.request_id,
            attempt_number=attempt.number,
            attempt_id=attempt.attempt_id,
            delivery_status="accepted",
            execution_status="pending",
            delivery_id="delivery-1",
            run_id="run-1",
            http_status=200,
        )
        running = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
        )
        completed = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
        )
        stale = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
        )
        self.assertTrue(running.accepted)
        self.assertTrue(completed.accepted)
        self.assertFalse(stale.accepted)
        self.assertFalse(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
            )
        )
        self.assertTrue(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="b" * 64,
            )
        )
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_status, "succeeded")
        self.assertEqual(record.result_sha256, "b" * 64)

    def test_same_status_result_uses_server_revision_order(self) -> None:
        attempt = self._attempt()
        first = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            source_revision=10,
        )
        newer = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=12,
        )
        stale = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="c" * 64,
            source_revision=11,
        )
        ambiguous = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="d" * 64,
        )
        stale_same_fingerprint = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=5,
        )
        self.assertTrue(first.accepted)
        self.assertTrue(newer.accepted)
        self.assertFalse(stale.accepted)
        self.assertFalse(ambiguous.accepted)
        self.assertFalse(stale_same_fingerprint.accepted)
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_sha256, "b" * 64)
        self.assertEqual(record.result_source_revision, 12)

    def test_revisionless_same_status_result_uses_ordered_poll_generation(self) -> None:
        attempt = self._attempt()
        first_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        first = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            poll_generation=first_poll,
        )
        second_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        second = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            poll_generation=second_poll,
        )
        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_sha256, "b" * 64)

    def test_same_revision_changed_result_is_rejected_even_for_newer_poll(self) -> None:
        attempt = self._attempt()
        first_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        first = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            source_revision=12,
            poll_generation=first_poll,
        )
        second_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        second = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=12,
            poll_generation=second_poll,
        )
        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_sha256, "a" * 64)
        self.assertEqual(record.result_source_revision, 12)

    def test_older_concurrent_result_poll_cannot_overwrite_newer_poll(self) -> None:
        attempt = self._attempt()
        older_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        newer_poll = self.store.begin_result_poll(
            connection_key="conn-test",
            request_id=attempt.request_id,
        )
        newer = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            poll_generation=newer_poll,
        )
        stale = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            poll_generation=older_poll,
        )
        self.assertTrue(newer.accepted)
        self.assertFalse(stale.accepted)
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_sha256, "b" * 64)

    def test_status_progression_cannot_lower_server_revision(self) -> None:
        attempt = self._attempt()
        self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            source_revision=12,
        )
        stale_terminal = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=11,
        )
        terminal_without_revision = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
        )
        fresh_terminal = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="c" * 64,
            source_revision=13,
        )
        self.assertFalse(stale_terminal.accepted)
        self.assertFalse(terminal_without_revision.accepted)
        self.assertTrue(fresh_terminal.accepted)
        record = self.store.get_delivery(
            connection_key="conn-test",
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertEqual(record.result_status, "succeeded")
        self.assertEqual(record.result_sha256, "c" * 64)
        self.assertEqual(record.result_source_revision, 13)

    def test_pending_comment_blocks_new_result_until_ack(self) -> None:
        attempt = self._attempt()
        self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="running",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="a" * 64,
            source_revision=10,
        )
        self.assertTrue(
            self.store.reserve_result_comment(
                connection_key="conn-test",
                request_id=attempt.request_id,
                comment_sha256="a" * 64,
                now=100.0,
            )
        )
        blocked = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=11,
            checked_at=101.0,
        )
        self.assertFalse(blocked.accepted)
        self.store.finish_result_comment(
            connection_key="conn-test",
            request_id=attempt.request_id,
            comment_sha256="a" * 64,
            published=True,
        )
        accepted = self.store.record_result(
            connection_key="conn-test",
            request_id=attempt.request_id,
            execution_status="succeeded",
            target_issue_id="issue-1",
            target_task_id="target-1",
            result_sha256="b" * 64,
            source_revision=11,
            checked_at=102.0,
        )
        self.assertTrue(accepted.accepted)

    def test_latest_delivery_is_connection_partitioned(self) -> None:
        first = self._attempt()
        record = self.store.latest_delivery(connection_key="conn-test")
        self.assertEqual(record.request_id, first.request_id)
        self.assertIsNone(self.store.latest_delivery(connection_key="other"))

    def test_incompatible_existing_schema_is_rejected_without_mutation(self) -> None:
        directory = Path(self.temp.name) / "incompatible"
        directory.mkdir(mode=0o700)
        path = directory / "deliveries.sqlite3"
        conn = sqlite3.connect(path)
        conn.execute(
            """CREATE TABLE deliveries (
                connection_key TEXT NOT NULL,
                request_id TEXT NOT NULL,
                source_task_id TEXT NOT NULL,
                PRIMARY KEY (connection_key, request_id)
            )"""
        )
        conn.commit()
        conn.close()
        path.chmod(0o600)

        with self.assertRaises(BridgeError) as raised:
            DeliveryStore(path)
        self.assertEqual(raised.exception.code, "state_unavailable")

        conn = sqlite3.connect(path)
        try:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            columns = {row[1] for row in conn.execute("PRAGMA table_info(deliveries)")}
        finally:
            conn.close()
        self.assertEqual(tables, {"deliveries"})
        self.assertEqual(columns, {"connection_key", "request_id", "source_task_id"})


if __name__ == "__main__":
    unittest.main()
