"""HTTPS-only Multica webhook transport with optional HMAC signing."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import queue
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .configuration import DEFAULT_MAX_PAYLOAD_BYTES, normalize_multica_origin
from .errors import BridgeError
from .validation import strict_json_loads

WEBHOOK_PATH_RE = re.compile(r"\A/api/webhooks/autopilots/awt_[A-Za-z0-9_-]{43}\Z")
SAFE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
DEFAULT_MAX_RESPONSE_BYTES = 16_384


def validate_webhook_url(value: str, multica_origin: str | None = None) -> str:
    """Validate a bearer webhook URL and, when supplied, bind it to one Multica origin."""
    if not isinstance(value, str) or not value or len(value) > 2048 or not value.isascii():
        raise BridgeError("credential_invalid", "The webhook credential is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise BridgeError("credential_invalid", "The webhook credential is invalid.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or not WEBHOOK_PATH_RE.fullmatch(parsed.path)
    ):
        raise BridgeError("credential_invalid", "The webhook credential is not an allowed HTTPS Autopilot URL.")
    if multica_origin:
        expected = normalize_multica_origin(multica_origin)
        actual = f"https://{parsed.netloc.lower()}"
        if actual != expected:
            raise BridgeError("credential_invalid", "The webhook credential does not match the configured Multica origin.")
    return value


def webhook_url_fingerprint(value: str, multica_origin: str | None = None) -> str:
    """Return a non-secret SHA-256 pin for the exact validated bearer URL."""
    validate_webhook_url(value, multica_origin)
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def encode_webhook_body(event: str, event_payload: dict[str, Any]) -> bytes:
    """Serialize exactly once so HMAC and HTTP use identical bytes."""
    if not isinstance(event, str) or not event or len(event) > 128:
        raise BridgeError("invalid_request", "The configured webhook event is invalid.")
    if not isinstance(event_payload, dict):
        raise BridgeError("invalid_request", "The webhook event payload must be an object.")
    try:
        return json.dumps(
            {"event": event, "eventPayload": event_payload},
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise BridgeError("invalid_request", "The webhook payload cannot be serialized safely.") from exc


def hmac_signature(body: bytes, secret: str) -> str:
    """Return the Multica-compatible X-Hub-Signature-256 value for raw body bytes."""
    if not isinstance(secret, str) or not secret or len(secret) > 4096:
        raise BridgeError("credential_invalid", "The HMAC signing secret is invalid.")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _AbsoluteDeadlineExceeded(Exception):
    """Internal marker used when the wall-clock HTTPS deadline expires."""


_DNS_RESOLVER_SLOTS = threading.BoundedSemaphore(4)


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    """Interrupt request/header I/O when urllib's per-operation timeout can be dripped."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.timeout is socket._GLOBAL_DEFAULT_TIMEOUT or self.timeout is None:
            timeout = 0.0
        else:
            timeout = max(0.0, float(self.timeout))
        self._deadline_at = time.monotonic() + timeout
        self._deadline_expired = threading.Event()
        self._deadline_timer = threading.Timer(timeout, self._expire_deadline)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()
        self._create_connection = self._create_deadline_connection

    def _remaining(self) -> float:
        remaining = self._deadline_at - time.monotonic()
        if remaining <= 0 or self._deadline_expired.is_set():
            self._deadline_expired.set()
            raise _AbsoluteDeadlineExceeded
        return max(0.001, remaining)

    def _create_deadline_connection(
        self,
        address: tuple[str, int],
        _timeout: object = socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        """Share one connect budget across all resolved addresses."""
        host, port = address
        last_error: OSError | None = None
        addresses = self._deadline_getaddrinfo(host, port)
        for family, socktype, proto, _canonname, sockaddr in addresses:
            candidate: socket.socket | None = None
            try:
                candidate = socket.socket(family, socktype, proto)
                candidate.settimeout(self._remaining())
                if source_address:
                    candidate.bind(source_address)
                candidate.connect(sockaddr)
                return candidate
            except _AbsoluteDeadlineExceeded:
                if candidate is not None:
                    candidate.close()
                raise
            except OSError as exc:
                last_error = exc
                if candidate is not None:
                    candidate.close()
        self._remaining()
        if last_error is not None:
            raise last_error
        raise OSError("getaddrinfo returned no usable addresses")

    def _deadline_getaddrinfo(self, host: str, port: int) -> list[tuple[Any, ...]]:
        """Bound libc resolver latency without allowing unbounded stuck resolver threads."""
        acquired = _DNS_RESOLVER_SLOTS.acquire(timeout=self._remaining())
        if not acquired:
            raise _AbsoluteDeadlineExceeded
        result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                result_queue.put_nowait((True, socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)))
            except Exception as exc:  # noqa: BLE001 - preserve resolver exception type for the caller
                result_queue.put_nowait((False, exc))
            finally:
                _DNS_RESOLVER_SLOTS.release()

        resolver = threading.Thread(target=resolve, name="hmb-dns-resolver", daemon=True)
        try:
            resolver.start()
        except Exception:
            _DNS_RESOLVER_SLOTS.release()
            raise
        try:
            ok, value = result_queue.get(timeout=self._remaining())
        except queue.Empty:
            raise _AbsoluteDeadlineExceeded from None
        self._remaining()
        if not ok:
            raise value
        return value

    def _expire_deadline(self) -> None:
        self._deadline_expired.set()
        current = self.sock
        if current is None:
            return
        try:
            current.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            current.close()
        except OSError:
            pass

    def connect(self) -> None:
        """Expose the SSL socket before its handshake so the absolute timer can interrupt it."""
        try:
            http.client.HTTPConnection.connect(self)
            server_hostname = self._tunnel_host or self.host
            self._remaining()
            self.sock = self._context.wrap_socket(
                self.sock,
                server_hostname=server_hostname,
                do_handshake_on_connect=False,
            )
            self.sock.settimeout(self._remaining())
            self.sock.do_handshake()
            self._remaining()
        except TimeoutError:
            self._deadline_expired.set()
            raise _AbsoluteDeadlineExceeded from None
        except Exception as exc:
            if self._deadline_expired.is_set() and not isinstance(exc, _AbsoluteDeadlineExceeded):
                raise _AbsoluteDeadlineExceeded from None
            raise

    def _cancel_deadline(self) -> None:
        self._deadline_timer.cancel()

    def request(self, *args: Any, **kwargs: Any) -> None:
        try:
            self._remaining()
            super().request(*args, **kwargs)
            self._remaining()
        except Exception as exc:
            self._cancel_deadline()
            if self._deadline_expired.is_set() and not isinstance(exc, _AbsoluteDeadlineExceeded):
                raise _AbsoluteDeadlineExceeded from None
            raise

    def getresponse(self) -> http.client.HTTPResponse:
        response: http.client.HTTPResponse | None = None
        try:
            response = super().getresponse()
            self._remaining()
        except Exception as exc:
            if response is not None:
                response.close()
            self._cancel_deadline()
            if self._deadline_expired.is_set() and not isinstance(exc, _AbsoluteDeadlineExceeded):
                raise _AbsoluteDeadlineExceeded from None
            raise
        self._cancel_deadline()
        return response

    def close(self) -> None:
        self._cancel_deadline()
        super().close()


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request):
        return self.do_open(_DeadlineHTTPSConnection, req, context=self._context)


def _default_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _DeadlineHTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )


def _set_response_timeout(response: Any, timeout: float) -> bool:
    """Apply the remaining absolute deadline to urllib's underlying TLS socket."""
    transport = _response_transport(response)
    if transport is None:
        return False
    setter = getattr(transport, "settimeout", None)
    try:
        setter(timeout)
        return True
    except (OSError, ValueError):
        return False


def _response_transport(response: Any) -> Any | None:
    """Find urllib's underlying socket-like transport without relying on one wrapper layout."""
    pending = [response]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        setter = getattr(current, "settimeout", None)
        if callable(setter):
            return current
        for name in ("fp", "raw", "_sock", "sock"):
            child = getattr(current, name, None)
            if child is not None:
                pending.append(child)
    return None


def _response_body_complete(response: Any) -> bool:
    """Return whether urllib already consumed the complete response body."""
    isclosed = getattr(response, "isclosed", None)
    if not callable(isclosed):
        return False
    try:
        if not isclosed():
            return False
    except (OSError, ValueError):
        return False
    remaining = getattr(response, "length", None)
    return not isinstance(remaining, int) or remaining <= 0


def _expire_response_deadline(response: Any, expired: threading.Event) -> None:
    """Interrupt a body read when one HTTPResponse.read1 call outlives the absolute deadline."""
    expired.set()
    transport = _response_transport(response)
    if transport is None:
        return
    shutdown = getattr(transport, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    close = getattr(transport, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass


@dataclass(frozen=True)
class WebhookResult:
    ok: bool
    delivery_status: str
    execution_status: str
    delivery_id: str | None = None
    run_id: str | None = None
    http_status: int | None = None
    error_code: str | None = None
    retryable: bool = False
    retry_after_seconds: int | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "delivery_status": self.delivery_status,
            "execution_status": self.execution_status,
        }
        for key, value in (
            ("delivery_id", self.delivery_id),
            ("run_id", self.run_id),
            ("http_status", self.http_status),
            ("error_code", self.error_code),
            ("retry_after_seconds", self.retry_after_seconds),
        ):
            if value is not None:
                result[key] = value
        if not self.ok or self.retryable:
            result["retryable"] = self.retryable
        return result


def _safe_identifier(value: Any) -> str | None:
    return value if isinstance(value, str) and SAFE_ID_RE.fullmatch(value) else None


def _invalid_response(status_code: int) -> WebhookResult:
    return WebhookResult(
        ok=False,
        delivery_status="unknown",
        execution_status="unknown",
        http_status=status_code,
        error_code="invalid_response",
        retryable=True,
    )


def _response_result(status_code: int, value: dict[str, Any]) -> WebhookResult:
    response_status = value.get("status")
    delivery_id = _safe_identifier(value.get("delivery_id"))
    run_id = _safe_identifier(value.get("run_id"))
    if response_status == "accepted" and delivery_id and run_id:
        return WebhookResult(True, "accepted", "pending", delivery_id, run_id, status_code)
    if response_status == "duplicate":
        if not delivery_id:
            return _invalid_response(status_code)
        if run_id:
            return WebhookResult(True, "duplicate", "unknown", delivery_id, run_id, status_code)
        return WebhookResult(
            False, "duplicate", "unknown", delivery_id, None, status_code,
            "duplicate_without_run", True,
        )
    if response_status == "skipped":
        if not delivery_id or not run_id:
            return _invalid_response(status_code)
        return WebhookResult(
            False, "skipped", "skipped", delivery_id, run_id, status_code, "delivery_skipped"
        )
    if response_status == "ignored":
        if not delivery_id:
            return _invalid_response(status_code)
        return WebhookResult(
            False, "ignored", "not_started", delivery_id, None, status_code, "delivery_ignored"
        )
    if response_status == "rejected":
        return WebhookResult(
            False, "rejected", "unknown", delivery_id, None, status_code, "unauthorized"
        )
    return _invalid_response(status_code)


class MulticaWebhookClient:
    """Bounded direct HTTPS client; callers provide trusted destination configuration."""

    def __init__(
        self,
        opener: Any | None = None,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if type(max_payload_bytes) is not int or max_payload_bytes < 1:
            raise BridgeError("configuration_invalid", "The webhook payload limit is invalid.")
        self._default_transport = opener is None
        self.opener = opener or _default_opener()
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_payload_bytes = max_payload_bytes
        self.monotonic = monotonic

    def send(
        self,
        url: str,
        *,
        multica_origin: str,
        idempotency_key: str,
        event: str,
        event_payload: dict[str, Any],
        hmac_secret: str | None,
        hmac_required: bool,
        encoded_body: bytes | None = None,
    ) -> WebhookResult:
        validate_webhook_url(url, multica_origin)
        body = encode_webhook_body(event, event_payload) if encoded_body is None else encoded_body
        if not isinstance(body, bytes):
            raise BridgeError("invalid_request", "The encoded webhook body is invalid.")
        if len(body) > self.max_payload_bytes:
            raise BridgeError("request_too_large", "The Multica webhook payload exceeds the configured size limit.")
        if hmac_required and not hmac_secret:
            raise BridgeError("credential_unavailable", "HMAC is enabled but its signing secret is unavailable.")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": idempotency_key,
            "User-Agent": "hermes-multica-bridge/0.2.0",
        }
        if hmac_secret:
            headers["X-Hub-Signature-256"] = hmac_signature(body, hmac_secret)
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        deadline = self.monotonic() + self.timeout
        try:
            response = self.opener.open(request, timeout=max(0.001, deadline - self.monotonic()))
        except urllib.error.HTTPError as exc:
            try:
                return self._http_error(exc.code, exc.headers)
            finally:
                exc.close()
        except _AbsoluteDeadlineExceeded:
            return WebhookResult(
                False,
                "unknown",
                "unknown",
                error_code="response_timeout",
                retryable=True,
            )
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            return WebhookResult(
                False, "unknown", "unknown", error_code="network_error", retryable=True
            )

        body_deadline_expired = threading.Event()
        body_deadline_timer: threading.Timer | None = None
        status_code: int | None = None
        try:
            status_code = int(response.status)
            raw = bytearray()
            reader = getattr(response, "read1", None)
            if not callable(reader):
                reader = response.read
            while len(raw) <= self.max_response_bytes:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    return WebhookResult(
                        False,
                        "unknown",
                        "unknown",
                        http_status=status_code,
                        error_code="response_timeout",
                        retryable=True,
                    )
                if self._default_transport and _response_body_complete(response):
                    break
                deadline_applied = _set_response_timeout(response, max(0.001, remaining))
                if self._default_transport and not deadline_applied:
                    return WebhookResult(
                        False,
                        "unknown",
                        "unknown",
                        http_status=status_code,
                        error_code="response_timeout",
                        retryable=True,
                    )
                if self._default_transport and body_deadline_timer is None:
                    body_deadline_timer = threading.Timer(
                        max(0.001, remaining),
                        _expire_response_deadline,
                        args=(response, body_deadline_expired),
                    )
                    body_deadline_timer.daemon = True
                    body_deadline_timer.start()
                chunk = reader(min(8_192, self.max_response_bytes + 1 - len(raw)))
                if body_deadline_expired.is_set():
                    return WebhookResult(
                        False,
                        "unknown",
                        "unknown",
                        http_status=status_code,
                        error_code="response_timeout",
                        retryable=True,
                    )
                if not chunk:
                    if self._default_transport and not _response_body_complete(response):
                        return WebhookResult(
                            False,
                            "unknown",
                            "unknown",
                            http_status=status_code,
                            error_code="incomplete_response",
                            retryable=True,
                        )
                    break
                raw.extend(chunk)
            if body_deadline_expired.is_set() or deadline - self.monotonic() <= 0:
                return WebhookResult(
                    False,
                    "unknown",
                    "unknown",
                    http_status=status_code,
                    error_code="response_timeout",
                    retryable=True,
                )
            if len(raw) > self.max_response_bytes:
                return WebhookResult(
                    False,
                    "unknown",
                    "unknown",
                    http_status=status_code,
                    error_code="response_too_large",
                    retryable=True,
                )
        except (http.client.HTTPException, OSError, TimeoutError):
            if body_deadline_expired.is_set():
                return WebhookResult(
                    False,
                    "unknown",
                    "unknown",
                    http_status=status_code,
                    error_code="response_timeout",
                    retryable=True,
                )
            return WebhookResult(
                False, "unknown", "unknown", error_code="incomplete_response", retryable=True
            )
        finally:
            if body_deadline_timer is not None:
                body_deadline_timer.cancel()
            response.close()
        if status_code is None:
            return WebhookResult(
                False,
                "unknown",
                "unknown",
                error_code="invalid_response",
                retryable=True,
            )
        return self._parse_response(status_code, bytes(raw))

    def _http_error(self, status: int, headers: Any) -> WebhookResult:
        code_by_status = {
            400: "invalid_request",
            401: "unauthorized",
            403: "forbidden",
            404: "webhook_not_found",
            413: "request_too_large",
            429: "rate_limited",
        }
        retry_after = None
        if status == 429:
            value = headers.get("Retry-After") if headers is not None else None
            if value and value.isascii() and value.isdigit() and len(value) <= 10:
                retry_after = min(int(value), 3600)
        return WebhookResult(
            ok=False,
            delivery_status="rejected" if status in {401, 403} else "failed",
            execution_status="unknown",
            http_status=status,
            error_code=code_by_status.get(
                status, "multica_server_error" if status >= 500 else "http_error"
            ),
            retryable=status in {408, 429} or status >= 500,
            retry_after_seconds=retry_after,
        )

    def _parse_response(self, status_code: int, raw: bytes) -> WebhookResult:
        if status_code < 200 or status_code >= 300:
            return self._http_error(status_code, None)
        try:
            value = strict_json_loads(raw)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
            return _invalid_response(status_code)
        if not isinstance(value, dict):
            return _invalid_response(status_code)
        return _response_result(status_code, value)
