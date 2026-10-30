"""At-most-once MAX and Telegram delivery for watcher notifications."""

from __future__ import annotations

import http.client
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .multica_api import _NoRedirect
from .webhook import (
    _AbsoluteDeadlineExceeded,
    _DeadlineHTTPSHandler,
    _expire_response_deadline,
    _response_body_complete,
    _set_response_timeout,
)

_NUMERIC_ID = re.compile(r"\A-?[0-9]{1,24}\Z")
_MAX_MESSAGE_CHARS = 4000


@dataclass(frozen=True)
class DeliveryResult:
    status: str
    detail: str


def _request(
    opener: Any,
    url: str,
    token: str,
    payload: dict[str, Any],
    *,
    max_api: bool,
    timeout: float,
    default_transport: bool,
) -> DeliveryResult:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if max_api:
        headers["Authorization"] = token
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    deadline = time.monotonic() + timeout
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return DeliveryResult("not_sent", "request_timeout")
        response = opener.open(request, timeout=remaining)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        return DeliveryResult("not_sent" if 400 <= status < 500 else "delivery_unknown", f"http_{status}")
    except _AbsoluteDeadlineExceeded:
        return DeliveryResult("delivery_unknown", "response_timeout")
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        return DeliveryResult("delivery_unknown", "transport_uncertain")
    body_deadline_expired = threading.Event()
    body_deadline_timer: threading.Timer | None = None
    try:
        status = int(response.status)
        if not default_transport:
            raw = response.read(65_537)
        else:
            raw_buffer = bytearray()
            reader = getattr(response, "read1", None)
            if not callable(reader):
                reader = response.read
            while len(raw_buffer) <= 65_536:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return DeliveryResult("delivery_unknown", "response_timeout")
                if _response_body_complete(response):
                    break
                if not _set_response_timeout(response, max(0.001, remaining)):
                    return DeliveryResult("delivery_unknown", "response_timeout")
                if body_deadline_timer is None:
                    body_deadline_timer = threading.Timer(
                        max(0.001, remaining),
                        _expire_response_deadline,
                        args=(response, body_deadline_expired),
                    )
                    body_deadline_timer.daemon = True
                    body_deadline_timer.start()
                chunk = reader(min(8_192, 65_537 - len(raw_buffer)))
                if body_deadline_expired.is_set():
                    return DeliveryResult("delivery_unknown", "response_timeout")
                if not chunk:
                    if not _response_body_complete(response):
                        return DeliveryResult("delivery_unknown", "response_uncertain")
                    break
                raw_buffer.extend(chunk)
            if body_deadline_expired.is_set() or deadline - time.monotonic() <= 0:
                return DeliveryResult("delivery_unknown", "response_timeout")
            raw = bytes(raw_buffer)
    except (OSError, TimeoutError, http.client.HTTPException):
        detail = "response_timeout" if body_deadline_expired.is_set() else "response_uncertain"
        return DeliveryResult("delivery_unknown", detail)
    finally:
        if body_deadline_timer is not None:
            body_deadline_timer.cancel()
        response.close()
    if not 200 <= status < 300:
        return DeliveryResult("not_sent" if 400 <= status < 500 else "delivery_unknown", f"http_{status}")
    if len(raw) > 65_536:
        return DeliveryResult("delivery_unknown", "response_oversized")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return DeliveryResult("delivery_unknown", "response_invalid")
    accepted = isinstance(result, dict) and (
        result.get("ok") is True if not max_api else isinstance(result.get("message"), dict)
    )
    return DeliveryResult("delivered" if accepted else "delivery_unknown", "accepted" if accepted else "response_uncertain")


class PlatformSender:
    def __init__(self, *, max_token: str = "", telegram_token: str = "", timeout: float = 10.0):
        self.max_token = max_token
        self.telegram_token = telegram_token
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _DeadlineHTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )
        self._default_transport = True
        self.timeout = timeout

    def send(self, mapping: dict[str, Any], text: str) -> DeliveryResult:
        if not isinstance(text, str) or not text.strip() or len(text) > _MAX_MESSAGE_CHARS:
            return DeliveryResult("not_sent", "message_invalid")
        platform = mapping.get("platform")
        if platform == "telegram":
            return self._telegram(mapping, text)
        if platform == "max":
            return self._max(mapping, text)
        return DeliveryResult("not_sent", "platform_unsupported")

    def _telegram(self, mapping: dict[str, Any], text: str) -> DeliveryResult:
        token = self.telegram_token
        if not token:
            return DeliveryResult("not_sent", "credential_missing")
        chat_id = mapping.get("chat_id")
        message_id = mapping.get("message_id")
        if not isinstance(chat_id, str) or not chat_id or not _NUMERIC_ID.fullmatch(chat_id):
            return DeliveryResult("not_sent", "chat_id_invalid")
        if not isinstance(message_id, str) or not _NUMERIC_ID.fullmatch(message_id) or int(message_id) < 1:
            return DeliveryResult("not_sent", "message_id_invalid")
        payload: dict[str, Any] = {
            "chat_id": int(chat_id),
            "text": text,
            "reply_parameters": {"message_id": int(message_id), "allow_sending_without_reply": False},
        }
        if mapping.get("chat_type") == "thread":
            thread_id = mapping.get("thread_id")
            if not isinstance(thread_id, str) or not _NUMERIC_ID.fullmatch(thread_id) or int(thread_id) < 1:
                return DeliveryResult("not_sent", "thread_id_invalid")
            payload["message_thread_id"] = int(thread_id)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        return _request(
            self.opener, url, "", payload, max_api=False, timeout=self.timeout,
            default_transport=self._default_transport,
        )

    def _max(self, mapping: dict[str, Any], text: str) -> DeliveryResult:
        token = self.max_token
        if not token:
            return DeliveryResult("not_sent", "credential_missing")
        # MAX's reply link takes the source message ID.  A Hermes thread/topic ID
        # identifies a conversation, not the message to which this notification replies.
        message_id = mapping.get("message_id")
        if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
            return DeliveryResult("not_sent", "message_id_invalid")
        payload = {"text": text, "link": {"type": "reply", "mid": message_id}, "notify": True}
        query: dict[str, str]
        if mapping.get("chat_type") == "dm":
            user_id = mapping.get("user_id")
            if not isinstance(user_id, str) or not _NUMERIC_ID.fullmatch(user_id) or int(user_id) < 1:
                return DeliveryResult("not_sent", "user_id_invalid")
            query = {"user_id": user_id}
        else:
            chat_id = mapping.get("chat_id")
            if not isinstance(chat_id, str) or not _NUMERIC_ID.fullmatch(chat_id):
                return DeliveryResult("not_sent", "chat_id_invalid")
            query = {"chat_id": chat_id}
        url = "https://botapi.max.ru/messages?" + urllib.parse.urlencode(query)
        return _request(
            self.opener, url, token, payload, max_api=True, timeout=self.timeout,
            default_transport=self._default_transport,
        )


def wait_for_rate_slot(delay: float) -> None:
    if delay > 0:
        # The reservation is durable and already advances the per-chat deadline.
        # Sleeping only a capped portion could violate MAX's per-chat rate limit
        # when a backlog contains more than a few queued notifications.
        time.sleep(delay)
