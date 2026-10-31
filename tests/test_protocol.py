from __future__ import annotations

import json
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.protocol import BridgeIpcClient, validate_ipc_envelope
from tests.helpers import sample_request


class ProtocolTests(unittest.TestCase):
    def test_validates_operation_specific_envelopes(self) -> None:
        request = sample_request()
        self.assertEqual(validate_ipc_envelope({"operation": "readiness"}), {"operation": "readiness"})
        self.assertEqual(validate_ipc_envelope({"operation": "send", "request": request})["operation"], "send")
        self.assertEqual(
            validate_ipc_envelope({"operation": "has_delivery", "request": request})["operation"],
            "has_delivery",
        )
        ack = validate_ipc_envelope(
            {
                "operation": "finish_result_comment",
                "request": request,
                "request_id": "123e4567-e89b-12d3-a456-426614174000",
                "fingerprint": "a" * 64,
                "published": True,
            }
        )
        self.assertTrue(ack["published"])

    def test_rejects_extra_fields_and_invalid_ack_identity(self) -> None:
        with self.assertRaises(BridgeError):
            validate_ipc_envelope({"operation": "readiness", "request": sample_request()})
        with self.assertRaises(BridgeError):
            validate_ipc_envelope({"operation": "send", "request": sample_request(), "url": "https://attacker.invalid"})
        with self.assertRaises(BridgeError):
            validate_ipc_envelope(
                {
                    "operation": "finish_result_comment",
                    "request": sample_request(),
                    "request_id": "bad",
                    "fingerprint": "a" * 64,
                    "published": True,
                }
            )

    def test_client_sends_operation_envelope_and_parses_response(self) -> None:
        received: list[dict] = []

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                received.append(json.loads(self.rfile.readline()))
                self.wfile.write(b'{"ok":true,"delivery_status":"accepted"}\n')

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "bridge.sock")
            server = socketserver.ThreadingUnixStreamServer(path, Handler)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            result = BridgeIpcClient(path).send(sample_request())
            thread.join(timeout=2)
            server.server_close()
        self.assertTrue(result["ok"])
        self.assertEqual(received[0]["operation"], "send")
        self.assertEqual(received[0]["request"], sample_request())

    def test_client_readiness_has_no_task_payload(self) -> None:
        received: list[dict] = []

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                received.append(json.loads(self.rfile.readline()))
                self.wfile.write(b'{"ok":true,"ready":true,"policy_fingerprint":"policy-fixture"}\n')

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "bridge.sock")
            server = socketserver.ThreadingUnixStreamServer(path, Handler)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            result = BridgeIpcClient(path).readiness()
            thread.join(timeout=2)
            server.server_close()
        self.assertTrue(result["ready"])
        self.assertEqual(received, [{"operation": "readiness"}])

    def test_client_can_query_route_delivery_presence(self) -> None:
        received: list[dict] = []

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                received.append(json.loads(self.rfile.readline()))
                self.wfile.write(b'{"ok":true,"has_delivery":true}\n')

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "bridge.sock")
            server = socketserver.ThreadingUnixStreamServer(path, Handler)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            result = BridgeIpcClient(path).has_delivery(sample_request())
            thread.join(timeout=2)
            server.server_close()
        self.assertTrue(result["has_delivery"])
        self.assertEqual(received[0]["operation"], "has_delivery")

    def test_unavailable_socket_is_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(BridgeError) as raised:
            BridgeIpcClient(Path(directory) / "missing.sock", timeout=0.1).send(sample_request())
        self.assertEqual(raised.exception.code, "bridge_unavailable")
        self.assertTrue(raised.exception.retryable)

    def test_client_timeout_is_one_end_to_end_deadline(self) -> None:
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline()
                try:
                    for chunk in (b'{"', b'ok', b'":', b'true', b'}\n'):
                        time.sleep(0.04)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except BrokenPipeError:
                    pass

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "bridge.sock")
            server = socketserver.ThreadingUnixStreamServer(path, Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            started = time.monotonic()
            with self.assertRaises(BridgeError) as raised:
                BridgeIpcClient(path, timeout=0.1).send(sample_request())
            elapsed = time.monotonic() - started
            thread.join(timeout=1)
            server.server_close()
        self.assertEqual(raised.exception.code, "bridge_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertLess(elapsed, 0.2)


if __name__ == "__main__":
    unittest.main()
