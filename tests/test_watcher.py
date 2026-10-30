from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

from bridge.errors import BridgeError
from bridge.watcher import Watcher, _event_issue_ids
from bridge.watcher_config import parse_watcher_config
from bridge.watcher_delivery import DeliveryResult
from bridge.watcher_state import WatcherState


def watcher_config(*, allow_groups: bool = False, chat_id: str = "chat-1"):
    return parse_watcher_config({
        "watcher": {"socket_path": "/run/hermes-multica-watcher/ipc.sock", "socket_gid": 12345,
                    "poll_seconds": 45, "request_timeout_seconds": 10, "max_message_chars": 3500},
        "profiles": {"om73": {
            "state_path": "/var/lib/hermes-multica-watcher/om73.sqlite3",
            "multica_pat_credential": "om73-pat", "max_token_credential": "om73-max",
            "telegram_token_credential": "om73-telegram", "own_multica_user_id": "own-user",
            "allowed_peer_uids": [1000], "routes": [{
                "route_id": "route-1", "name": "Workspace", "multica_origin": "https://multica.example.org",
                "workspace_id": "workspace-1", "project_id": "project-1",
                "source_platforms": ["telegram", "max"], "allowed_user_ids": ["user-1"],
                "allowed_chat_ids": [chat_id], "allow_groups": allow_groups,
                "allowed_statuses": ["todo", "done"],
            }],
        }},
    })


class _Api:
    def __init__(self, issue):
        self.issue = issue
        self.get_calls = 0
        self.fail_get_calls = set()
        self.comments = []

    def get_issue(self, issue_id):
        self.get_calls += 1
        if self.get_calls in self.fail_get_calls:
            raise BridgeError("watcher_api_unavailable", "Transient fixture failure.")
        return self.issue

    def list_comments(self, issue_id):
        return self.comments


class WatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.config = watcher_config()
        self.profile = self.config.profile("om73")
        self.route = self.config.route(self.profile, "route-1")
        self.issue = {"id": "issue-1", "workspace_id": "workspace-1", "project_id": "project-1",
                      "title": "Task", "status": "todo", "revision": 1, "updated_at": "2026-10-29"}
        self.watcher = object.__new__(Watcher)
        self.watcher.config = self.config
        self.watcher.states = {"om73": WatcherState(Path(self.temp.name) / "state" / "om73.sqlite3")}
        self.watcher.apis = {("om73", "route-1"): _Api(self.issue)}
        self.watcher.senders = {"om73": Mock()}
        self.watcher._stop = None
        self.watcher._event_queue = None
        self.mapping = {
            "profile": "om73", "issue_id": "issue-1", "route_id": "route-1", "platform": "telegram",
            "user_id": "user-1", "chat_id": "chat-1", "thread_id": None,
            "message_id": "message-1", "chat_type": "dm",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_mapping_requires_allowed_peer_source_and_exact_workspace_project(self) -> None:
        with self.assertRaises(BridgeError):
            self.watcher.register_mapping(self.mapping, peer_uid=2000)
        with self.assertRaises(BridgeError):
            self.watcher.register_mapping({**self.mapping, "chat_id": "other-chat"}, peer_uid=1000)
        with self.assertRaises(BridgeError):
            self.watcher.register_mapping({**self.mapping, "chat_type": "group"}, peer_uid=1000)
        self.watcher.apis[("om73", "route-1")].issue = {**self.issue, "project_id": "other-project"}
        with self.assertRaises(BridgeError):
            self.watcher.register_mapping(self.mapping, peer_uid=1000)
        self.assertIsNone(self.watcher.states["om73"].mapping("issue-1"))

    def test_telegram_thread_mapping_requires_deliverable_thread_id(self) -> None:
        for thread_id in (None, "0", "topic-nine"):
            with self.subTest(thread_id=thread_id), self.assertRaises(BridgeError) as raised:
                self.watcher.register_mapping(
                    {**self.mapping, "chat_type": "thread", "thread_id": thread_id}, peer_uid=1000,
                )
            self.assertEqual(raised.exception.code, "watcher_mapping_invalid")
        self.assertEqual(self.watcher.apis[("om73", "route-1")].get_calls, 0)
        self.assertIsNone(self.watcher.states["om73"].mapping("issue-1"))

    def test_mapping_is_durable_before_ack_and_reconciles_early_events(self) -> None:
        reconcile = Mock()
        self.watcher._reconcile = reconcile
        self.assertEqual(self.watcher.register_mapping(self.mapping, peer_uid=1000), {"ok": True, "mapping": "registered"})
        self.assertEqual(self.watcher.states["om73"].mapping("issue-1")["message_id"], "message-1")
        reconcile.assert_called_once_with(self.profile, self.route, "issue-1", initial=True)

    def test_initial_reconciliation_retries_after_transient_api_failure(self) -> None:
        state = self.watcher.states["om73"]
        api = self.watcher.apis[("om73", "route-1")]
        api.issue = {**self.issue, "revision": 2}
        api.fail_get_calls.add(2)  # Registration verification succeeds; initial reconcile fails once.
        sender = self.watcher.senders["om73"]
        sender.send.return_value = DeliveryResult("delivered", "accepted")

        self.watcher.register_mapping(self.mapping, peer_uid=1000)

        self.assertIsNone(state.snapshot("issue-1"))
        sender.send.assert_not_called()

        self.watcher._reconcile(self.profile, self.route, "issue-1")

        sender.send.assert_called_once()
        self.assertIn("Статус: todo", sender.send.call_args.args[1])
        self.assertIsNotNone(state.snapshot("issue-1"))

    def test_group_mapping_is_allowed_only_after_route_opt_in(self) -> None:
        config = watcher_config(allow_groups=True, chat_id="-1001234567890")
        watcher = object.__new__(Watcher)
        watcher.config = config
        watcher.states = {"om73": self.watcher.states["om73"]}
        watcher.apis = {("om73", "route-1"): _Api(self.issue)}
        watcher._reconcile = Mock()
        mapping = {
            **self.mapping, "chat_id": "-1001234567890", "chat_type": "group", "thread_id": None,
        }
        watcher.register_mapping(mapping, peer_uid=1000)
        self.assertEqual(watcher.states["om73"].mapping("issue-1")["chat_id"], "-1001234567890")

    def test_reconciliation_without_mapping_never_fetches_or_sends(self) -> None:
        self.watcher._reconcile(self.profile, self.route, "unmapped-issue")
        self.assertEqual(self.watcher.apis[("om73", "route-1")].get_calls, 0)
        self.watcher.senders["om73"].send.assert_not_called()

    def test_reconciliation_notifies_changed_issue_and_new_non_own_comments_once(self) -> None:
        state = self.watcher.states["om73"]
        registered_at = datetime(2026, 10, 29, 10, 30, tzinfo=UTC)
        registered_at_ns = int(registered_at.timestamp()) * 1_000_000_000
        with patch("bridge.watcher_state.time.time_ns", return_value=registered_at_ns):
            state.register_mapping(self.mapping)
        api = self.watcher.apis[("om73", "route-1")]
        api.issue = {**self.issue, "status": "done", "revision": 2, "created_at": "2026-10-29T10:00:00Z"}
        api.comments = [
            {"id": "old-comment", "author_id": "user-2", "content": "old", "created_at": "2026-10-29T09:00:00Z"},
            {"id": "historical-comment", "author_id": "user-2", "content": "до связи с чатом", "created_at": "2026-10-29T10:15:00Z"},
            {"id": "own-comment", "author_id": "own-user", "content": "internal", "created_at": "2026-10-29T11:00:00Z"},
            {"id": "comment-1", "author_id": "user-2", "content": "Новая информация", "created_at": "2026-10-29T12:00:00Z"},
        ]
        sender = self.watcher.senders["om73"]
        sender.send.return_value = DeliveryResult("delivered", "accepted")
        self.watcher._reconcile(self.profile, self.route, "issue-1", initial=True)
        self.watcher._reconcile(self.profile, self.route, "issue-1")
        self.assertEqual(sender.send.call_count, 2)
        self.assertIn("Статус: done", sender.send.call_args_list[0].args[1])
        self.assertIn("Новая информация", sender.send.call_args_list[1].args[1])
        self.assertNotIn("до связи с чатом", " ".join(call.args[1] for call in sender.send.call_args_list))
        self.assertNotIn("internal", " ".join(call.args[1] for call in sender.send.call_args_list))

    def test_comment_retries_if_delivery_claim_fails_before_send(self) -> None:
        state = self.watcher.states["om73"]
        state.register_mapping(self.mapping)
        state.save_snapshot("issue-1", self.issue)
        api = self.watcher.apis[("om73", "route-1")]
        api.comments = [{
            "id": "comment-claim-failure", "author_id": "user-2", "content": "Retry this comment",
        }]
        sender = self.watcher.senders["om73"]
        sender.send.return_value = DeliveryResult("delivered", "accepted")
        original_claim = state.claim_delivery
        attempts = 0

        def fail_first_claim(*args):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise BridgeError("watcher_state_unavailable", "Transient fixture failure.")
            return original_claim(*args)

        with patch.object(state, "claim_delivery", side_effect=fail_first_claim):
            with self.assertRaises(BridgeError):
                self.watcher._reconcile(self.profile, self.route, "issue-1")
            self.assertFalse(state.comment_seen("issue-1", "comment-claim-failure"))
            self.watcher._reconcile(self.profile, self.route, "issue-1")
            self.watcher._reconcile(self.profile, self.route, "issue-1")

        sender.send.assert_called_once()
        self.assertTrue(state.comment_seen("issue-1", "comment-claim-failure"))

    def test_description_change_is_detected_without_persisting_description(self) -> None:
        state = self.watcher.states["om73"]
        state.register_mapping(self.mapping)
        api = self.watcher.apis[("om73", "route-1")]
        api.issue = {**self.issue, "description": "private original description"}
        self.watcher._reconcile(self.profile, self.route, "issue-1", initial=True)
        api.issue = {**api.issue, "description": "private updated description"}
        sender = self.watcher.senders["om73"]
        sender.send.return_value = DeliveryResult("delivered", "accepted")

        self.watcher._reconcile(self.profile, self.route, "issue-1")
        self.watcher._reconcile(self.profile, self.route, "issue-1")

        sender.send.assert_called_once()
        snapshot = state.snapshot("issue-1")
        self.assertNotIn("description", snapshot)
        self.assertNotIn("private updated description", repr(snapshot))

    def test_websocket_reconnects_and_queues_only_supported_issue_event(self) -> None:
        async def exercise():
            watcher = self.watcher
            watcher._stop = asyncio.Event()
            watcher._event_queue = asyncio.Queue()
            api = watcher.apis[("om73", "route-1")]
            api.websocket_token = "fake-token"
            calls = []
            connections = []

            class Connection:
                def __init__(self, fail):
                    self.fail = fail
                    self.sent = []

                async def __aenter__(self):
                    if self.fail:
                        raise ConnectionError("offline")
                    return self

                async def __aexit__(self, *args):
                    return False

                async def send(self, value):
                    self.sent.append(value)

                async def recv(self):
                    return '{"type":"auth_ack"}'

                def __aiter__(self):
                    async def iterate():
                        yield '{"type":"issue:updated","payload":{"issue":{"id":"issue-1"}}}'
                        yield '{"type":"untrusted:event","payload":{"issue":{"id":"ignored"}}}'
                        watcher._stop.set()
                    return iterate()

            def connect(url, **kwargs):
                calls.append((url, kwargs))
                connection = Connection(fail=len(calls) == 1)
                connections.append(connection)
                return connection

            client = ModuleType("websockets.asyncio.client")
            client.connect = connect
            asyncio_module = ModuleType("websockets.asyncio")
            asyncio_module.__path__ = []
            root = ModuleType("websockets")
            root.__path__ = []
            sys.modules["websockets"] = root
            sys.modules["websockets.asyncio"] = asyncio_module
            sys.modules["websockets.asyncio.client"] = client
            try:
                await watcher._websocket_loop(self.profile, self.route)
            finally:
                for name in ("websockets.asyncio.client", "websockets.asyncio", "websockets"):
                    sys.modules.pop(name, None)
            self.assertEqual(len(calls), 2)
            self.assertIn("workspace_id=workspace-1", calls[1][0])
            self.assertEqual(json.loads(connections[1].sent[0]), {
                "type": "auth", "payload": {"token": "fake-token"},
            })
            self.assertEqual(watcher._event_queue.get_nowait(), ("om73", "route-1", {"issue_id": "issue-1"}))

        asyncio.run(exercise())

    def test_delivery_unknown_is_persisted_and_not_resent(self) -> None:
        state = self.watcher.states["om73"]
        state.register_mapping(self.mapping)
        sender = self.watcher.senders["om73"]
        sender.send.return_value = DeliveryResult("delivery_unknown", "transport_uncertain")
        with patch("bridge.watcher.wait_for_rate_slot"):
            self.watcher._deliver(self.profile, self.route, self.mapping, "issue:issue-1:2", "status")
            self.watcher._deliver(self.profile, self.route, self.mapping, "issue:issue-1:2", "status")
        sender.send.assert_called_once()
        key = hashlib.sha256(b"om73\0route-1\0issue:issue-1:2").hexdigest()
        self.assertEqual(state.claim_delivery(key, "issue-1", "telegram", "chat-1"), "delivery_unknown")

    def test_concurrent_reconcile_sends_an_event_once(self) -> None:
        state = self.watcher.states["om73"]
        state.register_mapping(self.mapping)
        sender = self.watcher.senders["om73"]
        send_started = threading.Event()
        finish_send = threading.Event()
        send_calls: list[tuple[object, ...]] = []

        def blocked_send(*args):
            send_calls.append(args)
            send_started.set()
            finish_send.wait(timeout=2)
            return DeliveryResult("delivered", "accepted")

        sender.send.side_effect = blocked_send
        def send() -> None:
            self.watcher._deliver(
                self.profile, self.route, self.mapping, "issue:issue-1:revision-2", "status"
            )
        first = threading.Thread(target=send)
        second = threading.Thread(target=send)
        with patch("bridge.watcher.wait_for_rate_slot"):
            first.start()
            self.assertTrue(send_started.wait(timeout=1), "first delivery did not enter the sender")
            second.start()
            second.join(timeout=1)
            finish_send.set()
            first.join(timeout=1)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(send_calls), 1)

    def test_max_direct_message_rate_limit_uses_the_actual_user_recipient(self) -> None:
        state = self.watcher.states["om73"]
        max_mapping = {**self.mapping, "platform": "max", "chat_type": "dm", "user_id": "42",
                       "chat_id": "dialog-identifier"}
        state.register_mapping({**max_mapping, "issue_id": "issue-1"})
        self.watcher.senders["om73"].send.return_value = DeliveryResult("delivered", "accepted")
        with patch.object(state, "reserve_chat_slot", return_value=0) as reserve, \
                patch("bridge.watcher.wait_for_rate_slot"):
            self.watcher._deliver(self.profile, self.route, max_mapping, "event-1", "status")
        reserve.assert_called_once_with("om73", "max", "42")

    def test_event_extracts_issue_ids_but_not_task_ids(self) -> None:
        self.assertEqual(_event_issue_ids({"payload": {
            "issue": {"id": "issue-1"}, "task": {"id": "task-1", "issue_id": "issue-2"},
            "comment": {"id": "comment-1", "issue_id": "issue-3"},
        }}), ("issue-1", "issue-2", "issue-3"))


if __name__ == "__main__":
    unittest.main()
