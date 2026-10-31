from __future__ import annotations

import http.client
import io
import json
import socket
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from bridge.errors import BridgeError
from bridge.webhook import (
    DEFAULT_MAX_RESPONSE_BYTES,
    MulticaWebhookClient,
    _AbsoluteDeadlineExceeded,
    _DeadlineHTTPSConnection,
    _default_opener,
    _NoRedirect,
    encode_webhook_body,
    hmac_signature,
    validate_webhook_url,
    webhook_url_fingerprint,
)
from tests.helpers import TEST_HMAC_SECRET, TEST_ORIGIN, TEST_WEBHOOK_URL


class FakeResponse:
    status = 200

    def __init__(self, body: bytes):
        self._body = io.BytesIO(body)

    def read(self, limit: int) -> bytes:
        return self._body.read(limit)

    def close(self) -> None:
        self._body.close()


class IncompleteResponse(FakeResponse):
    def read(self, limit: int) -> bytes:
        raise http.client.IncompleteRead(b'{"status":')


class FramingErrorResponse(FakeResponse):
    def read(self, limit: int) -> bytes:
        raise http.client.LineTooLong("chunk framing line")


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class DripResponse(FakeResponse):
    def __init__(self, clock: FakeClock):
        super().__init__(b"")
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

    def __init__(self, body: bytes):
        self._body = body
        self.length = len(body)
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
    def __init__(self, body: bytes, missing_bytes: int = 1):
        super().__init__(body)
        self.length = len(body) + missing_bytes

    def read1(self, _limit: int) -> bytes:
        if self._body:
            body = self._body
            self._body = b""
            self.length -= len(body)
            self.fp = None
            return body
        return b""


class FakeOpener:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.request: urllib.request.Request | None = None
        self.calls = 0

    def open(self, request: urllib.request.Request, timeout: float):
        self.calls += 1
        self.request = request
        if self.error:
            raise self.error
        return self.response


def send(client: MulticaWebhookClient):
    return client.send(
        TEST_WEBHOOK_URL,
        multica_origin=TEST_ORIGIN,
        idempotency_key="hmb-test",
        event="hermes.task.dispatched",
        event_payload={"kind": "test"},
        hmac_secret=TEST_HMAC_SECRET,
        hmac_required=True,
    )


class WebhookTests(unittest.TestCase):
    def test_url_is_https_origin_bound_and_has_expected_path(self) -> None:
        self.assertEqual(validate_webhook_url(TEST_WEBHOOK_URL, TEST_ORIGIN), TEST_WEBHOOK_URL)
        for value in (
            TEST_WEBHOOK_URL.replace("https://", "http://"),
            TEST_WEBHOOK_URL.replace("multica.example.org", "attacker.example.org"),
            TEST_WEBHOOK_URL + "?x=1",
            TEST_WEBHOOK_URL.replace("/api/webhooks/autopilots/", "/api/webhooks/other/"),
            f"{TEST_ORIGIN}/api/webhooks/autopilots/awt_short",
            TEST_WEBHOOK_URL.replace("multica.example.org", "мультика.example.org"),
        ):
            with self.subTest(value=value), self.assertRaises(BridgeError):
                validate_webhook_url(value, TEST_ORIGIN)

        with self.assertRaises(BridgeError):
            webhook_url_fingerprint(
                TEST_WEBHOOK_URL.replace("multica.example.org", "мультика.example.org"),
                "https://мультика.example.org",
            )

    def test_fingerprint_is_stable_after_validation(self) -> None:
        one = webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN)
        self.assertEqual(len(one), 64)
        self.assertEqual(one, webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN))

    def test_default_opener_has_no_proxy_and_redirect_handler_denies_redirects(self) -> None:
        opener = _default_opener()
        proxies = [item.proxies for item in opener.handlers if isinstance(item, urllib.request.ProxyHandler)]
        self.assertTrue(all(not value for value in proxies))
        no_redirect = next(item for item in opener.handlers if isinstance(item, _NoRedirect))
        req = urllib.request.Request(TEST_WEBHOOK_URL)
        self.assertIsNone(no_redirect.redirect_request(req, None, 302, "Found", {}, "https://attacker.invalid"))

    def test_hmac_signs_exact_transmitted_bytes(self) -> None:
        response = FakeResponse(b'{"status":"accepted","delivery_id":"delivery-1","run_id":"run-1"}')
        opener = FakeOpener(response)
        client = MulticaWebhookClient(opener=opener)
        result = send(client)
        self.assertTrue(result.ok)
        body = opener.request.data
        self.assertIsInstance(body, bytes)
        self.assertEqual(
            opener.request.get_header("X-hub-signature-256"),
            hmac_signature(body, TEST_HMAC_SECRET),
        )
        self.assertEqual(
            body,
            encode_webhook_body("hermes.task.dispatched", {"kind": "test"}),
        )
        self.assertEqual(opener.request.get_header("Idempotency-key"), "hmb-test")

    def test_payload_limit_covers_serialized_and_preencoded_bodies(self) -> None:
        opener = FakeOpener(FakeResponse(b"{}"))
        client = MulticaWebhookClient(opener=opener, max_payload_bytes=32)
        for encoded_body, payload in (
            (None, {"data": "x" * 64}),
            (b"x" * 33, {"kind": "test"}),
        ):
            with self.subTest(preencoded=encoded_body is not None):
                with self.assertRaises(BridgeError) as raised:
                    client.send(
                        TEST_WEBHOOK_URL,
                        multica_origin=TEST_ORIGIN,
                        idempotency_key="hmb-test",
                        event="hermes.task.dispatched",
                        event_payload=payload,
                        hmac_secret=TEST_HMAC_SECRET,
                        hmac_required=True,
                        encoded_body=encoded_body,
                    )
                self.assertEqual(raised.exception.code, "request_too_large")
        self.assertEqual(opener.calls, 0)

    def test_missing_hmac_secret_fails_before_network(self) -> None:
        opener = FakeOpener(FakeResponse(b"{}"))
        with self.assertRaises(BridgeError) as raised:
            MulticaWebhookClient(opener=opener).send(
                TEST_WEBHOOK_URL,
                multica_origin=TEST_ORIGIN,
                idempotency_key="hmb-test",
                event="hermes.task.dispatched",
                event_payload={"kind": "test"},
                hmac_secret=None,
                hmac_required=True,
            )
        self.assertEqual(raised.exception.code, "credential_unavailable")
        self.assertEqual(opener.calls, 0)

    def test_response_statuses_are_classified(self) -> None:
        cases = {
            "accepted": (True, "pending"),
            "duplicate": (True, "unknown"),
            "skipped": (False, "skipped"),
            "ignored": (False, "not_started"),
            "rejected": (False, "unknown"),
        }
        for status, expected in cases.items():
            body = {"status": status, "delivery_id": "delivery-1"}
            if status not in {"ignored"}:
                body["run_id"] = "run-1"
            result = send(
                MulticaWebhookClient(
                    opener=FakeOpener(FakeResponse(json.dumps(body).encode("utf-8")))
                )
            )
            self.assertEqual((result.ok, result.execution_status), expected)
            if status == "rejected":
                self.assertIsNone(result.run_id)

    def test_duplicate_without_run_is_retryable_unknown_admission(self) -> None:
        result = send(
            MulticaWebhookClient(
                opener=FakeOpener(
                    FakeResponse(b'{"status":"duplicate","delivery_id":"delivery-1"}')
                )
            )
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "duplicate_without_run")
        self.assertTrue(result.retryable)

    def test_http_and_network_errors_do_not_leak_url(self) -> None:
        error = urllib.error.HTTPError(
            TEST_WEBHOOK_URL,
            429,
            "secret response",
            {"Retry-After": "15"},
            io.BytesIO(b"secret"),
        )
        result = send(MulticaWebhookClient(opener=FakeOpener(error=error)))
        self.assertEqual(result.error_code, "rate_limited")
        self.assertEqual(result.retry_after_seconds, 15)
        self.assertNotIn("awt_", repr(result.as_dict()))

        result = send(MulticaWebhookClient(opener=FakeOpener(error=TimeoutError())))
        self.assertEqual(result.delivery_status, "unknown")
        self.assertTrue(result.retryable)

        result = send(
            MulticaWebhookClient(
                opener=FakeOpener(error=http.client.BadStatusLine("malformed response"))
            )
        )
        self.assertEqual(result.error_code, "network_error")
        self.assertTrue(result.retryable)

    def test_http_408_is_retryable(self) -> None:
        error = urllib.error.HTTPError(
            TEST_WEBHOOK_URL,
            408,
            "request timeout",
            {},
            io.BytesIO(b"temporary"),
        )
        result = send(MulticaWebhookClient(opener=FakeOpener(error=error)))
        self.assertEqual(result.http_status, 408)
        self.assertEqual(result.error_code, "http_error")
        self.assertTrue(result.retryable)

    def test_response_size_duplicate_json_and_incomplete_read_fail_closed(self) -> None:
        too_big = send(
            MulticaWebhookClient(
                opener=FakeOpener(FakeResponse(b"x" * (DEFAULT_MAX_RESPONSE_BYTES + 1)))
            )
        )
        self.assertEqual(too_big.error_code, "response_too_large")

        duplicate = send(
            MulticaWebhookClient(
                opener=FakeOpener(
                    FakeResponse(
                        b'{"status":"rejected","status":"accepted","delivery_id":"d","run_id":"r"}'
                    )
                )
            )
        )
        self.assertEqual(duplicate.error_code, "invalid_response")

        incomplete = send(MulticaWebhookClient(opener=FakeOpener(IncompleteResponse(b""))))
        self.assertEqual(incomplete.error_code, "incomplete_response")
        self.assertTrue(incomplete.retryable)

        framing_error = send(MulticaWebhookClient(opener=FakeOpener(FramingErrorResponse(b""))))
        self.assertEqual(framing_error.error_code, "incomplete_response")
        self.assertTrue(framing_error.retryable)

    def test_response_read_has_absolute_total_deadline(self) -> None:
        clock = FakeClock()
        result = send(
            MulticaWebhookClient(
                opener=FakeOpener(DripResponse(clock)),
                timeout=1.0,
                monotonic=clock,
            )
        )
        self.assertEqual(result.error_code, "response_timeout")
        self.assertTrue(result.retryable)

    def test_default_transport_interrupts_one_blocking_body_read_at_absolute_deadline(self) -> None:
        response = BlockingBodyResponse()
        client = MulticaWebhookClient(opener=FakeOpener(response), timeout=0.05)
        client._default_transport = True
        started = time.monotonic()
        result = send(client)
        self.assertEqual(result.error_code, "response_timeout")
        self.assertTrue(result.retryable)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIsNotNone(response._sock.timeout)

    def test_default_transport_accepts_body_when_http_response_closes_after_content_length(self) -> None:
        response = ClosingContentLengthResponse(
            b'{"status":"accepted","delivery_id":"delivery-1","run_id":"run-1"}'
        )
        client = MulticaWebhookClient(opener=FakeOpener(response))
        client._default_transport = True

        result = send(client)

        self.assertTrue(result.ok)
        self.assertEqual(result.delivery_id, "delivery-1")
        self.assertEqual(result.run_id, "run-1")
        self.assertIsNotNone(response.timeout)

    def test_default_transport_rejects_premature_eof_with_remaining_content_length(self) -> None:
        response = PrematureEofContentLengthResponse(
            b'{"status":"accepted","delivery_id":"delivery-1","run_id":"run-1"}'
        )
        client = MulticaWebhookClient(opener=FakeOpener(response))
        client._default_transport = True

        result = send(client)

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "incomplete_response")
        self.assertTrue(result.retryable)

    def test_default_transport_interrupts_header_phase_at_absolute_deadline(self) -> None:
        client_sock, server_sock = socket.socketpair()
        connection = _DeadlineHTTPSConnection("multica.example.org", timeout=0.05)
        connection.sock = client_sock

        def blocked_getresponse(_connection):
            client_sock.recv(1)
            raise OSError("deadline socket closed")

        started = time.monotonic()
        try:
            with patch.object(
                http.client.HTTPSConnection, "getresponse", blocked_getresponse
            ), self.assertRaises(_AbsoluteDeadlineExceeded):
                connection.getresponse()
        finally:
            connection.close()
            server_sock.close()
        self.assertLess(time.monotonic() - started, 0.5)

    def test_default_transport_interrupts_tls_handshake_at_absolute_deadline(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        accepted: list[socket.socket] = []
        release = threading.Event()

        def accept_without_tls() -> None:
            peer, _address = listener.accept()
            accepted.append(peer)
            release.wait(1.0)
            peer.close()

        server = threading.Thread(target=accept_without_tls, daemon=True)
        server.start()
        connection = _DeadlineHTTPSConnection(
            "127.0.0.1",
            listener.getsockname()[1],
            timeout=0.05,
            context=ssl._create_unverified_context(),
        )
        started = time.monotonic()
        elapsed = 0.0
        try:
            with self.assertRaises(_AbsoluteDeadlineExceeded):
                connection.connect()
            elapsed = time.monotonic() - started
        finally:
            release.set()
            connection.close()
            listener.close()
            server.join(timeout=0.5)
        self.assertLess(elapsed, 0.5)

    def test_default_transport_bounds_blocked_dns_resolution(self) -> None:
        release = threading.Event()

        def blocked_getaddrinfo(*_args, **_kwargs):
            release.wait(1.0)
            return []

        connection = _DeadlineHTTPSConnection("multica.example.org", timeout=0.05)
        started = time.monotonic()
        try:
            with patch("bridge.webhook.socket.getaddrinfo", side_effect=blocked_getaddrinfo), self.assertRaises(
                _AbsoluteDeadlineExceeded
            ):
                connection._deadline_getaddrinfo("multica.example.org", 443)
        finally:
            release.set()
            connection.close()
        self.assertLess(time.monotonic() - started, 0.5)


if __name__ == "__main__":
    unittest.main()
