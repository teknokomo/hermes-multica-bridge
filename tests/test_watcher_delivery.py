from __future__ import annotations

import json
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from bridge.watcher_delivery import DeliveryResult, PlatformSender, wait_for_rate_slot


class _Response:
    status = 200

    def __init__(self, body: bytes):
        self.body = body

    def read(self, size: int = -1) -> bytes:
        return self.body[:size]

    def close(self) -> None:
        pass


class _InterruptibleSocket:
    def __init__(self):
        self.closed = threading.Event()

    def settimeout(self, timeout: float) -> None:
        pass

    def shutdown(self, _how: int) -> None:
        self.closed.set()

    def close(self) -> None:
        self.closed.set()


class _SlowResponse:
    status = 200

    def __init__(self):
        self.transport = _InterruptibleSocket()
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=self.transport))
        self.closed = False

    def isclosed(self) -> bool:
        return self.closed

    def read1(self, _size: int = -1) -> bytes:
        if self.transport.closed.wait(timeout=2):
            raise OSError("response socket closed by deadline")
        return b'{"message":{"body":{"mid":"late"}}}'

    def close(self) -> None:
        self.closed = True
        self.transport.close()


class WatcherDeliveryTests(unittest.TestCase):
    def test_max_reply_uses_source_message_id_and_exact_chat(self) -> None:
        sender = PlatformSender(max_token="fake-max-token")
        captured = {}

        def open_request(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data)
            captured["authorization"] = request.get_header("Authorization")
            return _Response(b'{"message":{"body":{"mid":"reply-1"}}}')

        sender.opener = Mock(open=open_request)
        sender._default_transport = False
        result = sender.send({
            "platform": "max", "chat_type": "thread", "user_id": "42", "chat_id": "-1001",
            "thread_id": "topic-9", "message_id": "source-message-3",
        }, "Статус задачи")
        self.assertEqual(result, DeliveryResult("delivered", "accepted"))
        self.assertIn("chat_id=-1001", captured["url"])
        self.assertEqual(captured["payload"]["link"], {"type": "reply", "mid": "source-message-3"})
        self.assertNotEqual(captured["payload"]["link"]["mid"], "topic-9")
        self.assertEqual(captured["authorization"], "fake-max-token")

    def test_telegram_reply_requires_source_message_and_thread(self) -> None:
        sender = PlatformSender(telegram_token="123:fake")
        captured = {}

        def open_request(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data)
            return _Response(b'{"ok":true,"result":{"message_id":7}}')

        sender.opener = Mock(open=open_request)
        sender._default_transport = False
        result = sender.send({
            "platform": "telegram", "chat_type": "thread", "chat_id": "-1001",
            "message_id": "3", "thread_id": "9",
        }, "Статус задачи")
        self.assertEqual(result.status, "delivered")
        self.assertEqual(captured["payload"]["reply_parameters"]["message_id"], 3)
        self.assertEqual(captured["payload"]["message_thread_id"], 9)

    def test_slow_delivery_response_body_obeys_absolute_deadline(self) -> None:
        sender = PlatformSender(max_token="fake-max-token", timeout=0.05)
        response = _SlowResponse()
        sender.opener = Mock(open=Mock(return_value=response))
        started = time.monotonic()
        result = sender.send({
            "platform": "max", "chat_type": "dm", "user_id": "42", "chat_id": "chat-1",
            "message_id": "source-message-3",
        }, "Status")

        self.assertEqual(result, DeliveryResult("delivery_unknown", "response_timeout"))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(response.closed)

    def test_missing_exact_reply_target_is_not_sent(self) -> None:
        sender = PlatformSender(max_token="fake")
        result = sender.send({"platform": "max", "chat_type": "group", "chat_id": "-1001",
                              "thread_id": "topic-only"}, "No parent fallback")
        self.assertEqual(result, DeliveryResult("not_sent", "message_id_invalid"))

    def test_rate_slot_waits_for_entire_reserved_delay(self) -> None:
        with unittest.mock.patch("bridge.watcher_delivery.time.sleep") as sleep:
            wait_for_rate_slot(4.25)
        sleep.assert_called_once_with(4.25)


if __name__ == "__main__":
    unittest.main()
