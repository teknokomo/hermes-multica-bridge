from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from bridge.errors import BridgeError
from bridge.watcher_state import WatcherState


class WatcherStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "watcher" / "om73.sqlite3"
        self.state = WatcherState(self.path)
        self.mapping = {
            "profile": "om73", "issue_id": "issue-1", "route_id": "route-1",
            "platform": "telegram", "user_id": "user-1", "chat_id": "chat-1",
            "thread_id": None, "message_id": "message-1", "chat_type": "dm",
        }
        self.assertTrue(self.state.register_mapping(self.mapping))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_mapping_is_immutable_and_profile_scoped(self) -> None:
        self.assertTrue(self.state.register_mapping(self.mapping))
        self.assertFalse(self.state.register_mapping({**self.mapping, "chat_id": "other"}))
        self.assertEqual(self.state.mappings("om73", "route-1")[0]["issue_id"], "issue-1")
        self.assertEqual(self.state.mappings("default", "route-1"), [])

    def test_mapping_records_precise_registration_time(self) -> None:
        registration_time_ns = 1_798_000_000_123_456_000
        with patch("bridge.watcher_state.time.time_ns", return_value=registration_time_ns):
            self.assertTrue(self.state.register_mapping({**self.mapping, "issue_id": "issue-2"}))
        self.assertEqual(self.state.mapping("issue-2")["registered_at_ns"], registration_time_ns)

    def test_delivery_is_claimed_once_and_unknown_is_terminal(self) -> None:
        self.assertEqual(self.state.claim_delivery("event-1", "issue-1", "telegram", "chat-1"), "claimed")
        self.state.finish_delivery("event-1", "delivery_unknown", "transport_uncertain")
        self.assertEqual(self.state.claim_delivery("event-1", "issue-1", "telegram", "chat-1"), "delivery_unknown")

    def test_only_explicit_http_429_can_be_reclaimed(self) -> None:
        self.state.claim_delivery("retryable", "issue-1", "telegram", "chat-1")
        self.state.finish_delivery("retryable", "not_sent", "http_429")
        self.assertEqual(self.state.claim_delivery("retryable", "issue-1", "telegram", "chat-1"), "claimed")
        self.state.finish_delivery("retryable", "delivered", "accepted")
        self.assertEqual(self.state.claim_delivery("retryable", "issue-1", "telegram", "chat-1"), "delivered")

        self.state.claim_delivery("permanent", "issue-1", "telegram", "chat-1")
        self.state.finish_delivery("permanent", "not_sent", "http_400")
        self.assertEqual(self.state.claim_delivery("permanent", "issue-1", "telegram", "chat-1"), "not_sent")
        self.state.claim_delivery("unknown", "issue-1", "telegram", "chat-1")
        self.state.finish_delivery("unknown", "delivery_unknown", "transport_uncertain")
        self.assertEqual(self.state.claim_delivery("unknown", "issue-1", "telegram", "chat-1"), "delivery_unknown")

    def test_non_integer_revision_is_normalized_but_negative_integer_is_rejected(self) -> None:
        self.state.save_snapshot("issue-1", {"revision": "not-an-integer", "status": "todo"})
        self.assertEqual(self.state.snapshot("issue-1")["revision"], 0)
        with self.assertRaises(BridgeError) as raised:
            self.state.save_snapshot("issue-1", {"revision": -1, "status": "todo"})
        self.assertEqual(raised.exception.code, "watcher_api_response_invalid")

    def test_concurrent_delivery_claim_has_one_winner(self) -> None:
        barrier = threading.Barrier(2)

        def claim() -> str:
            barrier.wait(timeout=2)
            return self.state.claim_delivery("event-race", "issue-1", "telegram", "chat-1")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: claim(), range(2)))

        self.assertCountEqual(results, ["claimed", "sending"])

    def test_interrupted_send_becomes_delivery_unknown(self) -> None:
        self.state.claim_delivery("event-2", "issue-1", "telegram", "chat-1")
        reopened = WatcherState(self.path)
        self.assertEqual(reopened.claim_delivery("event-2", "issue-1", "telegram", "chat-1"), "delivery_unknown")

    def test_old_or_partial_state_is_rejected_without_migration(self) -> None:
        path = Path(self.temp.name) / "old" / "watcher.sqlite3"
        path.parent.mkdir(mode=0o700)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE mappings(issue_id TEXT PRIMARY KEY)")
        path.chmod(0o600)
        with self.assertRaises(BridgeError) as raised:
            WatcherState(path)
        self.assertEqual(raised.exception.code, "watcher_state_unavailable")

    def test_state_without_mapping_registration_timestamp_is_rejected(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("ALTER TABLE mappings DROP COLUMN registered_at_ns")
        with self.assertRaises(BridgeError) as raised:
            WatcherState(self.path)
        self.assertEqual(raised.exception.code, "watcher_state_unavailable")


if __name__ == "__main__":
    unittest.main()
