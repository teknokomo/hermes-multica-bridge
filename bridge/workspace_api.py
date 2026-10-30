"""Bounded Multica issue API used by profile-authorized Workspace routes."""

from __future__ import annotations

import http.client
import json
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .configuration import normalize_multica_origin
from .errors import BridgeError
from .multica_api import MAX_API_RESPONSE_BYTES, _NoRedirect
from .validation import MAX_MULTICA_PAT_BYTES, strict_json_loads
from .webhook import (
    _AbsoluteDeadlineExceeded,
    _DeadlineHTTPSHandler,
    _expire_response_deadline,
    _response_body_complete,
    _set_response_timeout,
)

MAX_ATTACHMENT_BYTES = 10_485_760
MAX_WRITE_BODY_BYTES = MAX_ATTACHMENT_BYTES + 262_144
MAX_COMMENT_CHARS = 16_000
MAX_TITLE_CHARS = 4_096
MAX_DESCRIPTION_CHARS = 65_536
_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class WorkspaceApiFailure(BridgeError):
    """An API failure with evidence about whether a write was rejected."""

    outcome: str

    def __init__(self, code: str, message: str, *, outcome: str, retryable: bool = False):
        super().__init__(code, message, retryable=retryable)
        self.outcome = outcome


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise BridgeError("invalid_arguments", f"{field} is invalid.")
    return value


def _json_object(raw: bytes, *, expected: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw)
    except (ValueError, json.JSONDecodeError):
        raise WorkspaceApiFailure("invalid_api_response", "Multica returned an invalid response.", outcome="unknown") from None
    if not isinstance(value, dict):
        raise WorkspaceApiFailure("invalid_api_response", "Multica returned an invalid response.", outcome="unknown")
    if expected == "issue":
        issue_id = value.get("id")
        if not isinstance(issue_id, str) or not _ID_RE.fullmatch(issue_id):
            raise WorkspaceApiFailure("invalid_api_response", "Multica returned an issue without a valid ID.", outcome="unknown")
    if expected == "comment" and not isinstance(value.get("id"), str):
        raise WorkspaceApiFailure("invalid_api_response", "Multica returned a comment without a valid ID.", outcome="unknown")
    if expected == "attachment" and not isinstance(value.get("id"), str):
        raise WorkspaceApiFailure("invalid_api_response", "Multica returned an attachment without a valid ID.", outcome="unknown")
    return value


class WorkspaceApiClient:
    """No redirect following, no proxy inheritance, bounded bodies, and no write retries."""

    def __init__(self, origin: str, pat: str, workspace_id: str, *, timeout: float = 15.0,
                 opener: Any | None = None, max_response_bytes: int = MAX_API_RESPONSE_BYTES):
        self.origin = normalize_multica_origin(origin)
        try:
            pat_bytes = pat.encode("ascii") if isinstance(pat, str) else b""
        except UnicodeEncodeError:
            pat_bytes = b""
        if not pat or len(pat_bytes) != len(pat) or len(pat_bytes) > MAX_MULTICA_PAT_BYTES or any(ch.isspace() for ch in pat):
            raise BridgeError("credential_invalid", "The Multica API credential is invalid.")
        self.workspace_id = _identifier(workspace_id, "workspace_id")
        self._pat = pat
        self.timeout = timeout
        self.max_response_bytes = min(max_response_bytes, MAX_API_RESPONSE_BYTES)
        self._default_transport = opener is None
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _DeadlineHTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
        )

    def _request(self, method: str, path: str, *, body: bytes | None = None,
                 content_type: str = "application/json", write: bool = False,
                 expected: str | None = None) -> dict[str, Any] | bytes:
        if not path.startswith("/api/") or "?" in path or "#" in path or len(path) > 512:
            raise BridgeError("invalid_request", "The Multica API path is invalid.")
        if body is not None and len(body) > MAX_WRITE_BODY_BYTES:
            raise BridgeError("request_too_large", "The Multica request exceeds the configured size limit.")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._pat}",
            "X-Workspace-ID": self.workspace_id,
            "User-Agent": "hermes-multica-bridge/0.1.0",
            "X-Client-Platform": "daemon",
            "X-Client-Version": "0.1.0",
        }
        if body is not None:
            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(len(body))
        request = urllib.request.Request(self.origin + path, data=body, headers=headers, method=method)
        deadline = time.monotonic() + max(0.001, float(self.timeout))
        try:
            response = self.opener.open(request, timeout=max(0.001, deadline - time.monotonic()))
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if write and 400 <= status < 500:
                raise WorkspaceApiFailure("api_rejected", "Multica rejected the requested change.", outcome="not_sent") from None
            if write:
                raise WorkspaceApiFailure("operation_unknown", "Multica may have accepted the change; do not repeat it automatically.", outcome="unknown") from None
            raise BridgeError("api_unavailable", "Multica could not return the requested resource.", retryable=status == 429 or status >= 500) from None
        except (_AbsoluteDeadlineExceeded, urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            if write:
                raise WorkspaceApiFailure("operation_unknown", "Multica may have accepted the change; do not repeat it automatically.", outcome="unknown") from None
            raise BridgeError("api_unavailable", "Multica is unavailable.", retryable=True) from None
        body_deadline_expired = threading.Event()
        body_deadline_timer: threading.Timer | None = None
        try:
            status = int(response.status)
            if not 200 <= status < 300:
                if write:
                    raise WorkspaceApiFailure("operation_unknown", "Multica may have accepted the change; do not repeat it automatically.", outcome="unknown")
                raise BridgeError("api_unavailable", "Multica returned an unexpected response.", retryable=status == 429 or status >= 500)
            chunks = bytearray()
            reader = getattr(response, "read1", None)
            if not callable(reader):
                reader = response.read
            while len(chunks) <= self.max_response_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Multica response deadline expired")
                if self._default_transport and _response_body_complete(response):
                    break
                deadline_applied = _set_response_timeout(response, remaining)
                if self._default_transport and not deadline_applied:
                    raise TimeoutError("Multica response deadline is unavailable")
                if self._default_transport and body_deadline_timer is None:
                    body_deadline_timer = threading.Timer(
                        remaining,
                        _expire_response_deadline,
                        args=(response, body_deadline_expired),
                    )
                    body_deadline_timer.daemon = True
                    body_deadline_timer.start()
                part = reader(min(65_536, self.max_response_bytes + 1 - len(chunks)))
                if body_deadline_expired.is_set():
                    raise TimeoutError("Multica response deadline expired")
                if not part:
                    if self._default_transport and not _response_body_complete(response):
                        raise http.client.IncompleteRead(b"", 1)
                    break
                chunks.extend(part)
            if body_deadline_expired.is_set() or deadline - time.monotonic() <= 0:
                raise TimeoutError("Multica response deadline expired")
            raw = bytes(chunks)
        except WorkspaceApiFailure:
            raise
        except (_AbsoluteDeadlineExceeded, OSError, TimeoutError, http.client.HTTPException):
            if write:
                raise WorkspaceApiFailure("operation_unknown", "Multica may have accepted the change; do not repeat it automatically.", outcome="unknown") from None
            raise BridgeError("api_unavailable", "Multica returned an incomplete response.", retryable=True) from None
        finally:
            if body_deadline_timer is not None:
                body_deadline_timer.cancel()
            response.close()
        if len(raw) > self.max_response_bytes:
            if write:
                raise WorkspaceApiFailure("operation_unknown", "Multica may have accepted the change; inspect it before retrying.", outcome="unknown")
            raise BridgeError("invalid_api_response", "Multica returned a response that is too large.")
        if expected is None:
            return raw
        return _json_object(raw, expected=expected)

    def get_issue(self, issue_id: str) -> dict[str, Any]:
        issue_id = _identifier(issue_id, "issue_id")
        result = self._request("GET", f"/api/issues/{urllib.parse.quote(issue_id, safe='')}", expected="issue")
        if not isinstance(result, dict):
            raise BridgeError("invalid_api_response", "Multica returned an invalid issue response.")
        return result

    def create_issue(self, *, title: str, description: str, project_id: str, status: str,
                     parent_issue_id: str | None = None, assignee_id: str | None = None) -> dict[str, Any]:
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
            raise BridgeError("invalid_arguments", "Issue title is empty or too long.")
        if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS:
            raise BridgeError("invalid_arguments", "Issue description is too long.")
        project_id = _identifier(project_id, "project_id")
        status = _identifier(status, "status")
        payload: dict[str, Any] = {
            "title": title.strip(), "description": description, "project_id": project_id, "status": status,
        }
        if parent_issue_id:
            payload["parent_issue_id"] = _identifier(parent_issue_id, "parent_issue_id")
        if assignee_id:
            payload.update(assignee_type="member", assignee_id=_identifier(assignee_id, "assignee_id"))
        result = self._request("POST", "/api/issues", body=json.dumps(payload, ensure_ascii=False).encode(), write=True, expected="issue")
        if not isinstance(result, dict):
            raise BridgeError("invalid_api_response", "Multica returned an invalid issue response.")
        return result

    def create_comment(self, issue_id: str, content: str) -> dict[str, Any]:
        issue_id = _identifier(issue_id, "issue_id")
        if not isinstance(content, str) or not content.strip() or len(content) > MAX_COMMENT_CHARS:
            raise BridgeError("invalid_arguments", "Comment is empty or too long.")
        result = self._request(
            "POST", f"/api/issues/{urllib.parse.quote(issue_id, safe='')}/comments",
            body=json.dumps({"content": content.strip(), "type": "comment"}, ensure_ascii=False).encode(),
            write=True, expected="comment",
        )
        if not isinstance(result, dict):
            raise BridgeError("invalid_api_response", "Multica returned an invalid comment response.")
        return result

    def list_comments(self, issue_id: str) -> list[dict[str, Any]]:
        issue_id = _identifier(issue_id, "issue_id")
        raw = self._request(
            "GET", f"/api/issues/{urllib.parse.quote(issue_id, safe='')}/comments"
        )
        if not isinstance(raw, bytes):
            raise BridgeError("invalid_api_response", "Multica returned an invalid comments response.")
        try:
            value = strict_json_loads(raw)
        except (ValueError, json.JSONDecodeError):
            raise BridgeError("invalid_api_response", "Multica returned an invalid comments response.") from None
        if not isinstance(value, list) or len(value) > 500:
            raise BridgeError("invalid_api_response", "Multica returned an invalid comments response.")
        if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in value):
            raise BridgeError("invalid_api_response", "Multica returned invalid comment records.")
        return value

    def update_issue(self, issue_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        issue_id = _identifier(issue_id, "issue_id")
        if not updates or set(updates) - {"title", "description", "status", "assignee_id", "assignee_type"}:
            raise BridgeError("invalid_arguments", "Issue updates contain unsupported fields.")
        clean_updates = dict(updates)
        if "title" in clean_updates:
            title = clean_updates["title"]
            if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
                raise BridgeError("invalid_arguments", "Issue title is empty or too long.")
            clean_updates["title"] = title.strip()
        if "description" in clean_updates and (
            not isinstance(clean_updates["description"], str)
            or len(clean_updates["description"]) > MAX_DESCRIPTION_CHARS
        ):
            raise BridgeError("invalid_arguments", "Issue description is too long.")
        if "status" in clean_updates:
            clean_updates["status"] = _identifier(clean_updates["status"], "status")
        if "assignee_id" in clean_updates:
            clean_updates["assignee_id"] = _identifier(clean_updates["assignee_id"], "assignee_id")
        if "assignee_type" in clean_updates and clean_updates["assignee_type"] != "member":
            raise BridgeError("invalid_arguments", "Only human member assignees are supported.")
        result = self._request(
            "PUT", f"/api/issues/{urllib.parse.quote(issue_id, safe='')}",
            body=json.dumps(clean_updates, ensure_ascii=False).encode(), write=True, expected="issue",
        )
        if not isinstance(result, dict):
            raise BridgeError("invalid_api_response", "Multica returned an invalid issue response.")
        return result

    def upload_issue_attachment(self, issue_id: str, filename: str, media_type: str, data: bytes) -> dict[str, Any]:
        issue_id = _identifier(issue_id, "issue_id")
        if not isinstance(data, bytes) or not data or len(data) > MAX_ATTACHMENT_BYTES:
            raise BridgeError("attachment_invalid", "Attachment is empty or exceeds the safe size limit.")
        boundary = "hmb-" + secrets.token_hex(24)
        safe_name = filename.replace("\\", "_").replace('"', "_").replace("\r", "_").replace("\n", "_")[:180]
        prefix = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\n"
            f"Content-Type: {media_type}\r\n\r\n"
        ).encode()
        suffix = (
            f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"issue_id\"\r\n\r\n{issue_id}"
            f"\r\n--{boundary}--\r\n"
        ).encode()
        result = self._request(
            "POST", "/api/upload-file", body=prefix + data + suffix,
            content_type=f"multipart/form-data; boundary={boundary}", write=True, expected="attachment",
        )
        if not isinstance(result, dict):
            raise BridgeError("invalid_api_response", "Multica returned an invalid attachment response.")
        return result
