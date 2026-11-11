"""Bounded platform adapters with explicit retry and anchor outcomes."""

from __future__ import annotations

import http.client
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from bridge.multica_api import _NoRedirect
from bridge.validation import strict_json_loads
from bridge.webhook import (
    _AbsoluteDeadlineExceeded,
    _DeadlineHTTPSHandler,
    _expire_response_deadline,
    _response_body_complete,
    _set_response_timeout,
)


@dataclass(frozen=True)
class Result:
    outcome: str
    code: str
    retry_after: float = 0


def response(
    status: int, data: dict, anchor: bool, header: str | None = None
) -> Result:
    if 200 <= status < 300:
        if data.get("ok") is True or isinstance(data.get("message"), dict):
            return Result("delivered", "accepted")
        return Result("retry", "response_uncertain")
    if status == 429:
        raw = (
            data.get("parameters", {}).get("retry_after", header or 0)
            if isinstance(data.get("parameters", {}), dict)
            else 0
        )
        try:
            delay = min(600, max(0, float(raw)))
        except (ValueError, TypeError):
            delay = 0
        return Result("retry", "http_429", delay)
    if status == 408:
        return Result("retry", "http_408")
    # Only a proven rejection of the reply target permits dropping the anchor.
    description = str(data.get("description", "")).casefold()
    reply_error = data.get("code") in {
        "message.not.found",
        "message.link.invalid",
    } or any(
        value in description
        for value in ("message to be replied not found", "reply message not found")
    )
    if status == 400 and anchor and reply_error:
        return Result("anchor", "anchor_invalid")
    return Result("terminal" if 400 <= status < 500 else "retry", f"http_{status}")


class Sender:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _DeadlineHTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    def send(self, payload: dict, token: str) -> Result:
        telegram = payload["platform"] == "telegram"
        body = {"text": payload["text"]}
        anchor = payload.get("anchor_message_id")
        if telegram:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            body["chat_id"] = int(payload["chat_id"])
            if payload["thread_id"]:
                body["message_thread_id"] = int(payload["thread_id"])
            if anchor:
                body["reply_parameters"] = {
                    "message_id": int(anchor),
                    "allow_sending_without_reply": False,
                }
            headers = {}
        else:
            target = "user_id" if payload["chat_type"] == "dm" else "chat_id"
            url = "https://botapi.max.ru/messages?" + urllib.parse.urlencode(
                {target: payload["chat_id"]}
            )
            if anchor:
                body["link"] = {"type": "reply", "mid": anchor}
            headers = {"Authorization": token}
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            url,
            data=json.dumps(body, ensure_ascii=False).encode(),
            headers=headers,
            method="POST",
        )
        result = None
        timer = None
        deadline = time.monotonic() + self.timeout
        try:
            try:
                result = self.opener.open(req, timeout=self.timeout)
                status = result.status
            except urllib.error.HTTPError as exc:
                result, status = exc, exc.code
            timer = threading.Timer(
                max(0.001, deadline - time.monotonic()),
                _expire_response_deadline,
                args=(result, threading.Event()),
            )
            timer.daemon = True
            timer.start()
            chunks = bytearray()
            while not _response_body_complete(result):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not _set_response_timeout(result, remaining):
                    return Result("retry", "response_uncertain")
                part = getattr(result, "read1", result.read)(
                    min(8192, 65537 - len(chunks))
                )
                if not part:
                    if not _response_body_complete(result):
                        return Result("retry", "response_uncertain")
                    break
                chunks.extend(part)
                if len(chunks) > 65536:
                    return Result("retry", "response_oversized")
            try:
                data = strict_json_loads(chunks)
            except RecursionError:
                return Result("retry", "response_uncertain")
            except (ValueError, UnicodeError):
                data = {}
            if not isinstance(data, dict):
                data = {}
            return response(
                status, data, bool(anchor), result.headers.get("Retry-After")
            )
        except (
            _AbsoluteDeadlineExceeded,
            OSError,
            TimeoutError,
            urllib.error.URLError,
            http.client.HTTPException,
        ):
            return Result("retry", "transport_uncertain")
        finally:
            if timer:
                timer.cancel()
            if result is not None:
                result.close()
