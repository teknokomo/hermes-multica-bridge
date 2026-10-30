from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.workspace_state import WorkspaceState


class WorkspaceStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state = WorkspaceState(Path(self.temp.name) / "profile" / "workspace.sqlite3")
        self.source = {
            "platform": "telegram", "user_id": "user-1", "chat_id": "chat-1",
            "thread_id": None, "message_id": "message-1", "chat_type": "dm",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _key(self, *, profile: str = "om73", route: str = "route-1", operation: str = "create_issue") -> str:
        return self.state.operation_key(profile, route, self.source, operation)

    def test_confirmed_write_returns_cached_result_without_second_post(self) -> None:
        key = self._key()
        payload_hash = self.state.payload_hash({"title": "first"})
        self.assertEqual(self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash).status, "ready")
        saved = {"id": "issue-1", "workspace_id": "workspace-1"}
        self.state.finish(key, status="accepted", result=saved)
        repeated = self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash)
        self.assertEqual(repeated.status, "accepted")
        self.assertEqual(repeated.result, saved)

    def test_same_source_operation_with_changed_payload_is_conflict(self) -> None:
        key = self._key()
        self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=self.state.payload_hash({"title": "first"}))
        with self.assertRaises(BridgeError) as raised:
            self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=self.state.payload_hash({"title": "changed"}))
        self.assertEqual(raised.exception.code, "operation_conflict")

    def test_not_sent_can_be_retried_but_unknown_cannot(self) -> None:
        key = self._key()
        payload_hash = self.state.payload_hash({"title": "retry"})
        self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash)
        self.state.finish(key, status="not_sent", detail="api_rejected")
        self.assertEqual(self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash).status, "ready")
        self.state.finish(key, status="operation_unknown", detail="transport_uncertain")
        self.assertEqual(self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash).status, "operation_unknown")

    def test_interrupted_write_becomes_unknown_on_clean_process_restart(self) -> None:
        key = self._key()
        payload_hash = self.state.payload_hash({"title": "possibly sent"})
        self.assertEqual(self.state.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash).status, "ready")
        reopened = WorkspaceState(self.state.path)
        result = reopened.begin(key=key, route_id="route-1", operation="create_issue", request_hash=payload_hash)
        self.assertEqual(result.status, "operation_unknown")
        self.assertEqual(result.detail, "process_interrupted")

    def test_idempotency_identity_is_scoped_by_profile_route_source_and_operation(self) -> None:
        base = self._key()
        self.assertNotEqual(base, self._key(profile="default"))
        self.assertNotEqual(base, self._key(route="route-2"))
        self.assertNotEqual(base, self.state.operation_key("om73", "route-1", {**self.source, "message_id": "message-2"}, "create_issue"))
        self.assertNotEqual(base, self._key(operation="create_comment"))

    def test_issue_mapping_cannot_be_retargeted(self) -> None:
        self.assertTrue(self.state.register_issue("issue-1", "route-1", self.source))
        self.assertTrue(self.state.register_issue("issue-1", "route-1", self.source))
        self.assertFalse(self.state.register_issue("issue-1", "route-2", self.source))

    def test_old_or_partial_state_schema_is_not_migrated(self) -> None:
        path = Path(self.temp.name) / "old" / "workspace.sqlite3"
        path.parent.mkdir(mode=0o700)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE operations(operation_key TEXT PRIMARY KEY)")
        path.chmod(0o600)
        with self.assertRaises(BridgeError) as raised:
            WorkspaceState(path)
        self.assertEqual(raised.exception.code, "state_unavailable")


if __name__ == "__main__":
    unittest.main()
