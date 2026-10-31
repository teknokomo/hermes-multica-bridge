from __future__ import annotations

import json
import struct
import unittest

from bridge.errors import BridgeError
from bridge.watcher_ipc import WatcherIpcClient, decode_frame


def _frame(body: str) -> bytes:
    encoded = body.encode("utf-8")
    return struct.pack("!I", len(encoded)) + encoded


class WatcherIpcTests(unittest.TestCase):
    def test_decode_frame_rejects_duplicate_keys_at_every_object_level(self) -> None:
        for payload in (
            '{"ok":true,"ok":false}',
            '{"ok":true,"mapping":{"issue_id":"first","issue_id":"second"}}',
        ):
            with self.subTest(payload=payload), self.assertRaises(BridgeError) as raised:
                decode_frame(_frame(payload))
            self.assertEqual(raised.exception.code, "watcher_ipc_invalid")

    def test_decode_frame_accepts_unambiguous_object(self) -> None:
        value = {"ok": True, "mapping": {"issue_id": "issue-1"}}
        self.assertEqual(decode_frame(_frame(json.dumps(value))), value)

    def test_client_rejects_telegram_thread_mapping_without_thread_id(self) -> None:
        mapping = {
            "profile": "om73", "issue_id": "issue-1", "route_id": "route-1",
            "platform": "telegram", "user_id": "user-1", "chat_id": "chat-1",
            "thread_id": None, "message_id": "message-1", "chat_type": "thread",
        }
        with self.assertRaises(BridgeError) as raised:
            WatcherIpcClient("/not-used.sock").register_issue(mapping)
        self.assertEqual(raised.exception.code, "watcher_ipc_invalid")


if __name__ == "__main__":
    unittest.main()
