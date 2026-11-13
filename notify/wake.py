"""Bounded snapshot creation and signed loopback admission for completion wakes."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from bridge.validation import strict_json_loads

from .config import NotifyError, private_read, require

MAX_SNAPSHOT_BYTES = 24 * 1024
MAX_BODY_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
ROUTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def canonical_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def load_webhook_policy(path: Path) -> dict[tuple[str, str], dict]:
    """Read a sanitized, operator-owned export without opening Hermes home."""
    raw = private_read(path, 262_144, modes=(0o600, 0o640))
    try:
        document = strict_json_loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise NotifyError("wake_webhook_policy_invalid") from None
    require(
        isinstance(document, dict)
        and set(document) == {"routes"}
        and isinstance(document["routes"], list)
        and 0 < len(document["routes"]) <= 256,
        "wake_webhook_policy_invalid",
    )
    result = {}
    fields = {
        "profile",
        "route",
        "events",
        "deliver",
        "deliver_extra",
        "deliver_only",
        "cron_job",
        "mirror_to_session",
        "script_configured",
        "skills",
        "coalesce_enabled",
        "toolsets",
        "hmac_configured",
        "prompt_policy",
    }
    for row in document["routes"]:
        require(
            isinstance(row, dict) and set(row) == fields,
            "wake_webhook_policy_invalid",
        )
        profile, route = row["profile"], row["route"]
        require(
            isinstance(profile, str)
            and profile in {"default", "om73"}
            and isinstance(route, str)
            and ROUTE_NAME.fullmatch(route) is not None,
            "wake_webhook_policy_invalid",
        )
        require(
            row["events"] == ["task.completed"]
            and isinstance(row["deliver"], str)
            and row["deliver"] in {"telegram", "max"}
            and isinstance(row["deliver_extra"], dict)
            and set(row["deliver_extra"]) == {"chat_id", "thread_id"}
            and all(
                isinstance(row["deliver_extra"][key], str)
                and 0 < len(row["deliver_extra"][key]) <= 128
                for key in ("chat_id",)
            )
            and isinstance(row["deliver_extra"]["thread_id"], str)
            and len(row["deliver_extra"]["thread_id"]) <= 128
            and row["deliver_only"] is False
            and row["cron_job"] is False
            and row["mirror_to_session"] is False
            and row["script_configured"] is False
            and row["skills"] == []
            and row["coalesce_enabled"] is False
            and row["hmac_configured"] is True
            and row["prompt_policy"] == "snapshot_only_final"
            and isinstance(row["toolsets"], list)
            and 0 < len(row["toolsets"]) <= 32
            and all(
                isinstance(value, str)
                and 0 < len(value) <= 64
                and value == value.strip()
                and value.casefold() not in {"all", "*", "plugin", "plugins", "default"}
                and "multica" not in value.casefold()
                for value in row["toolsets"]
            ),
            "wake_webhook_policy_invalid",
        )
        key = (profile, route)
        require(key not in result, "wake_webhook_policy_invalid")
        result[key] = row
    return result


def verify_configured_route(
    routes: dict[str, dict], profile: str, route: str
) -> dict:
    """Require one current config binding for a persisted wake route."""
    matches = [row for row in routes.values() if row.get("route") == route]
    if not matches:
        raise NotifyError("wake_route_unavailable")
    require(len(matches) == 1, "wake_route_unavailable")
    configured = matches[0]
    require(configured.get("profile") == profile, "wake_route_profile_mismatch")
    return configured


def verify_webhook_policy(
    policy: dict[tuple[str, str], dict], profile: str, route: str, source: dict
) -> None:
    """Fail closed unless the exported route pins the exact subscription destination."""
    row = policy.get((profile, route))
    if row is None:
        if any(route_name == route for _, route_name in policy):
            raise NotifyError("wake_route_profile_mismatch")
        raise NotifyError("wake_route_unavailable")
    extra = row["deliver_extra"]
    matches = (
        row["deliver"] == source.get("platform")
        and extra.get("chat_id") == source.get("chat_id")
        and extra.get("thread_id") == source.get("thread_id")
        and (
            source.get("platform") == "telegram"
            and source.get("chat_type") == "thread"
            and bool(source.get("thread_id"))
            or source.get("platform") == "max"
            and source.get("chat_type") == "group"
            and source.get("thread_id") == ""
        )
    )
    require(matches, "wake_route_policy_mismatch")


def encode(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _comment_key(comment: dict) -> tuple[float, str]:
    created_at = comment.get("created_at")
    comment_id = comment.get("id")
    require(
        isinstance(created_at, str)
        and len(created_at) <= 64
        and isinstance(comment_id, str)
        and 0 < len(comment_id) <= 128,
        "wake_snapshot_insufficient",
    )
    try:
        parsed = datetime.fromisoformat(created_at)
        require(parsed.tzinfo is not None, "wake_snapshot_insufficient")
    except (ValueError, OverflowError):
        raise NotifyError("wake_snapshot_insufficient") from None
    return parsed.timestamp(), comment_id


def build_payload(
    *,
    wake_id: str,
    profile: str,
    subscription: dict,
    issue: dict,
    comments: list[dict],
    issue_url: str,
    workspace_id: str,
    transition_seq: int,
) -> bytes:
    """Build a fully bounded immutable webhook request body."""
    require(canonical_uuid(wake_id), "wake_snapshot_insufficient")
    require(profile in {"default", "om73"}, "wake_snapshot_insufficient")
    require(
        all(
            isinstance(issue.get(key), str) and issue[key]
            for key in ("id", "identifier", "title", "status")
        )
        and (
            issue.get("description") is None
            or isinstance(issue.get("description"), str)
        ),
        "wake_snapshot_insufficient",
    )
    require(
        isinstance(issue_url, str)
        and issue_url.startswith("https://")
        and isinstance(workspace_id, str)
        and isinstance(issue.get("project_id"), str)
        and issue["project_id"]
        and type(transition_seq) is int
        and transition_seq > 0,
        "wake_snapshot_insufficient",
    )
    require(
        subscription.get("platform") in {"telegram", "max"}
        and isinstance(subscription.get("chat_id"), str)
        and isinstance(subscription.get("thread_id"), str)
        and subscription.get("chat_type") in {"group", "thread"},
        "wake_snapshot_insufficient",
    )

    normalized = []
    for row in comments:
        require(
            isinstance(row, dict)
            and isinstance(row.get("content"), str)
            and len(row["content"]) <= 65536,
            "wake_snapshot_insufficient",
        )
        sort_at, comment_id = _comment_key(row)
        author_type = row.get("author_type") or "unknown"
        require(
            isinstance(author_type, str) and len(author_type) <= 64,
            "wake_snapshot_insufficient",
        )
        normalized.append(
            (
                sort_at,
                comment_id,
                {
                    "id": comment_id,
                    "author_type": author_type,
                    "content": row["content"],
                    "created_at": row["created_at"],
                },
            )
        )
    normalized.sort(key=lambda row: (row[0], row[1]))
    truncated = len(normalized) > 50
    selected = [row[2] for row in normalized[-50:]]
    snapshot = {
        "title": issue["title"],
        "status": issue["status"],
        "issue_url": issue_url,
        "description": issue.get("description") or "",
        "comments": selected,
        "comments_truncated": truncated,
    }
    body = {
        "event": "task.completed",
        "event_type": "task.completed",
        "type": "task.completed",
        "source": "multica",
        "wake_id": wake_id,
        "issue_id": issue["id"],
        "issue_key": issue["identifier"],
        "workspace_id": workspace_id,
        "project_id": issue["project_id"],
        "transition_seq": transition_seq,
        "profile": profile,
        "origin": {
            "platform": subscription["platform"],
            "chat_id": subscription["chat_id"],
            "thread_id": subscription["thread_id"],
            "chat_type": subscription["chat_type"],
        },
        "snapshot": snapshot,
    }
    while selected:
        snapshot_raw = encode(snapshot)
        body_raw = encode(body)
        if len(snapshot_raw) <= MAX_SNAPSHOT_BYTES and len(body_raw) <= MAX_BODY_BYTES:
            return body_raw
        selected.pop(0)
        snapshot["comments_truncated"] = True
    snapshot_raw = encode(snapshot)
    body_raw = encode(body)
    if len(snapshot_raw) <= MAX_SNAPSHOT_BYTES and len(body_raw) <= MAX_BODY_BYTES:
        return body_raw
    raise NotifyError("wake_snapshot_insufficient")


@dataclass(frozen=True)
class WakeResult:
    status: str
    error_code: str = ""


def classify_admission(status: int, raw: bytes) -> WakeResult:
    if len(raw) > MAX_RESPONSE_BYTES:
        return WakeResult("delivery_unknown", "wake_response_oversized")
    try:
        body = strict_json_loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        body = None
    response_status = body.get("status") if isinstance(body, dict) else None
    if isinstance(response_status, str):
        if status in {200, 202} and response_status in {"accepted", "queued"}:
            return WakeResult("sent")
        if status == 200 and response_status == "duplicate":
            return WakeResult("sent")
        if 200 <= status < 300 and response_status == "ignored":
            return WakeResult("dead", "wake_route_ignored")
        if status == 409 and response_status == "duplicate":
            return WakeResult("sent")
    if 400 <= status < 500:
        return WakeResult("dead", f"wake_http_{status}")
    if status >= 500:
        return WakeResult("delivery_unknown", f"wake_http_{status}")
    return WakeResult("delivery_unknown", "wake_response_uncertain")


class WakeSender:
    """Send one exact-body HMAC V2 request to the local Hermes listener."""

    def __init__(self, base_url: str, timeout: int = 10):
        require(
            isinstance(base_url, str)
            and base_url.isascii()
            and len(base_url) <= 128
            and base_url == base_url.strip(),
            "wake_config_invalid",
        )
        try:
            parts = urlsplit(base_url)
            port = parts.port
        except ValueError:
            raise NotifyError("wake_config_invalid") from None
        require(
            parts.scheme == "http"
            and parts.hostname in {"127.0.0.1", "::1"}
            and not parts.username
            and not parts.password
            and not parts.query
            and not parts.fragment
            and parts.path in {"", "/"}
            and port is not None
            and 1 <= port <= 65535,
            "wake_config_invalid",
        )
        self.host, self.port, self.timeout = parts.hostname, port, timeout

    def send(self, payload: bytes, *, profile: str, route: str, wake_id: str, secret: str):
        require(
            len(payload) <= MAX_BODY_BYTES
            and profile in {"default", "om73"}
            and ROUTE_NAME.fullmatch(route) is not None
            and canonical_uuid(wake_id)
            and bool(secret),
            "wake_request_invalid",
        )
        timestamp = str(int(time.time()))
        signature = hmac.new(
            secret.encode("utf-8"), timestamp.encode("ascii") + b"." + payload, hashlib.sha256
        ).hexdigest()
        path = f"/p/{profile}/webhooks/{route}"
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=self.timeout
        )
        deadline = time.monotonic() + self.timeout
        timer = None
        response = None
        expired = threading.Event()
        try:
            connection.connect()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return WakeResult("delivery_unknown", "wake_transport_uncertain")
            transport = connection.sock

            def interrupt():
                expired.set()
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # Interrupt headers and body reads even if a peer keeps trickling
            # bytes. Keep this socket reference when HTTPConnection detaches it.
            timer = threading.Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
            connection.request(
                "POST",
                path,
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Webhook-Timestamp": timestamp,
                    "X-Webhook-Signature-V2": signature,
                    "X-Request-ID": wake_id,
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if expired.is_set() or time.monotonic() >= deadline:
                return WakeResult("delivery_unknown", "wake_transport_uncertain")
            if response.length not in (None, 0):
                return WakeResult("delivery_unknown", "wake_response_incomplete")
            return classify_admission(response.status, body)
        except (OSError, TimeoutError, http.client.HTTPException):
            return WakeResult("delivery_unknown", "wake_transport_uncertain")
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            if response is not None:
                response.close()
            connection.close()
