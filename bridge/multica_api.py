"""Minimal read-only Multica API client used to track one known Autopilot run."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .configuration import normalize_multica_origin
from .errors import BridgeError
from .validation import MAX_MULTICA_PAT_BYTES, strict_json_loads
from .webhook import (
    _AbsoluteDeadlineExceeded,
    _DeadlineHTTPSHandler,
    _expire_response_deadline,
    _NoRedirect,
    _response_body_complete,
    _set_response_timeout,
)

MAX_API_RESPONSE_BYTES = 1_048_576
MAX_RESULT_TEXT_CHARS = 6_000
MAX_SNAPSHOT_READ_ATTEMPTS = 3
SQLITE_MAX_INTEGER = (1 << 63) - 1
MULTICA_METADATA_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MULTICA_RUN_STATUSES = frozenset({"issue_created", "running", "completed", "failed", "skipped"})
REDACTED_TEXT = "[REDACTED]"
MIN_REDACTION_LENGTH = 8


def _redaction_values(values: Iterable[str | None]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    secrets: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        secrets.add(value)
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme and parsed.netloc and parsed.path:
            path_token = parsed.path.rstrip("/").rsplit("/", 1)[-1]
            if path_token:
                secrets.add(path_token)
    result = []
    for secret in sorted(secrets, key=len, reverse=True):
        variants = {
            secret,
            json.dumps(secret, ensure_ascii=False)[1:-1],
            urllib.parse.quote(secret, safe=""),
            urllib.parse.quote_plus(secret),
        }
        result.append((secret, tuple(sorted(variants, key=len, reverse=True))))
    return tuple(result)


def _redact_text(value: str, secrets: tuple[tuple[str, tuple[str, ...]], ...]) -> str:
    for secret, variants in secrets:
        if not any(variant and variant in value for variant in variants):
            continue
        if len(secret) < MIN_REDACTION_LENGTH:
            return REDACTED_TEXT
        for variant in variants:
            if variant:
                value = value.replace(variant, REDACTED_TEXT)
    return value


def _redact_values(value: Any, secrets: tuple[tuple[str, tuple[str, ...]], ...]) -> Any:
    if isinstance(value, str):
        return _redact_text(value, secrets)
    if isinstance(value, list):
        return [_redact_values(item, secrets) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            safe_key = _redact_text(key, secrets) if isinstance(key, str) else key
            if safe_key in redacted:
                suffix = 1
                while f"{safe_key}#{suffix}" in redacted:
                    suffix += 1
                safe_key = f"{safe_key}#{suffix}"
            redacted[safe_key] = _redact_values(item, secrets)
        return redacted
    return value


def _metadata_identifier(value: Any, field: str) -> str | None:
    """Accept only compact identifiers that can safely cross the bounded IPC response."""
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not MULTICA_METADATA_ID_RE.fullmatch(value):
        raise BridgeError("invalid_api_response", f"Multica returned an invalid {field}.")
    return value


def _source_revision(value: Any) -> int | None:
    """Validate a supplied Multica revision; only a missing/null value is revisionless."""
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise BridgeError("invalid_api_response", "Multica returned an invalid result revision.")
    if value > SQLITE_MAX_INTEGER:
        raise BridgeError("invalid_api_response", "Multica returned an invalid result revision.")
    return value


def _api_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _DeadlineHTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )


@dataclass(frozen=True)
class ResultSnapshot:
    execution_status: str
    run_status: str
    issue_id: str | None
    task_id: str | None
    result_text: str
    fingerprint: str
    source_revision: int | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "execution_status": self.execution_status,
            "run_status": self.run_status,
        }
        if self.issue_id:
            value["issue_id"] = self.issue_id
        if self.task_id:
            value["task_id"] = self.task_id
        if self.result_text:
            value["result"] = self.result_text
        return value


class MulticaApiClient:
    """Read only a recorded run and its directly linked issue/comments."""

    def __init__(
        self,
        origin: str,
        pat: str,
        workspace_id: str,
        *,
        opener: Any | None = None,
        timeout: float = 10.0,
        max_response_bytes: int = MAX_API_RESPONSE_BYTES,
        monotonic: Callable[[], float] = time.monotonic,
        sensitive_values: Iterable[str | None] = (),
    ):
        self.origin = normalize_multica_origin(origin)
        try:
            pat_bytes = pat.encode("ascii") if isinstance(pat, str) else b""
        except UnicodeEncodeError:
            pat_bytes = b""
        if (
            not isinstance(pat, str)
            or not pat
            or len(pat_bytes) > MAX_MULTICA_PAT_BYTES
            or len(pat_bytes) != len(pat)
            or any(ch.isspace() for ch in pat)
        ):
            raise BridgeError("credential_invalid", "The Multica API credential is invalid.")
        if not isinstance(workspace_id, str) or not MULTICA_METADATA_ID_RE.fullmatch(workspace_id):
            raise BridgeError("configuration_invalid", "The Multica workspace identifier is invalid.")
        self.pat = pat
        self._redaction_values = _redaction_values((pat, *sensitive_values))
        self.workspace_id = workspace_id
        self._default_transport = opener is None
        self.opener = opener or _api_opener()
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.monotonic = monotonic

    def _get(self, path: str, *, deadline: float | None = None) -> Any:
        if not path.startswith("/api/") or "?" in path or "#" in path:
            raise BridgeError("invalid_request", "The Multica API path is invalid.")
        if deadline is None:
            deadline = self.monotonic() + self.timeout
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True)
        request = urllib.request.Request(
            f"{self.origin}{path}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.pat}",
                "X-Workspace-ID": self.workspace_id,
                "User-Agent": "hermes-multica-bridge/0.1.0",
                "X-Client-Platform": "daemon",
                "X-Client-Version": "0.1.0",
            },
            method="GET",
        )
        try:
            response = self.opener.open(request, timeout=max(0.001, remaining))
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 401:
                raise BridgeError("api_unauthorized", "Multica rejected the result credential.") from None
            if status == 403:
                raise BridgeError("api_forbidden", "The result credential cannot read this Multica resource.") from None
            if status == 404:
                raise BridgeError("result_not_found", "The recorded Multica run or issue no longer exists.") from None
            raise BridgeError(
                "api_unavailable",
                "Multica could not return the recorded result.",
                retryable=status == 429 or status >= 500,
            ) from None
        except _AbsoluteDeadlineExceeded:
            raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True) from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            raise BridgeError("api_unavailable", "Multica is unavailable for result tracking.", retryable=True) from None
        body_deadline_expired = threading.Event()
        body_deadline_timer: threading.Timer | None = None
        try:
            if int(response.status) < 200 or int(response.status) >= 300:
                raise BridgeError("api_unavailable", "Multica returned an unexpected result status.", retryable=True)
            raw = bytearray()
            reader = getattr(response, "read1", None)
            if not callable(reader):
                reader = response.read
            while len(raw) <= self.max_response_bytes:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True)
                if self._default_transport and _response_body_complete(response):
                    break
                deadline_applied = _set_response_timeout(response, max(0.001, remaining))
                if self._default_transport and not deadline_applied:
                    raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True)
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
                    raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True)
                if not chunk:
                    if self._default_transport and not _response_body_complete(response):
                        raise BridgeError(
                            "api_unavailable",
                            "Multica returned an incomplete result response.",
                            retryable=True,
                        )
                    break
                raw.extend(chunk)
            if body_deadline_expired.is_set() or deadline - self.monotonic() <= 0:
                raise BridgeError("api_unavailable", "Multica result tracking timed out.", retryable=True)
            if len(raw) > self.max_response_bytes:
                raise BridgeError("result_too_large", "The Multica result response exceeds the allowed size.")
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            if body_deadline_expired.is_set():
                raise BridgeError(
                    "api_unavailable",
                    "Multica result tracking timed out.",
                    retryable=True,
                ) from None
            raise BridgeError("api_unavailable", "Multica is unavailable for result tracking.", retryable=True) from None
        finally:
            if body_deadline_timer is not None:
                body_deadline_timer.cancel()
            response.close()
        try:
            return strict_json_loads(bytes(raw))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise BridgeError("invalid_api_response", "Multica returned an invalid result response.") from exc

    def get_run(self, autopilot_id: str, run_id: str, *, deadline: float | None = None) -> dict[str, Any]:
        raw = self._get(
            f"/api/autopilots/{urllib.parse.quote(autopilot_id, safe='')}/runs/{urllib.parse.quote(run_id, safe='')}",
            deadline=deadline,
        )
        if not isinstance(raw, dict) or raw.get("id") != run_id or raw.get("autopilot_id") != autopilot_id:
            raise BridgeError("invalid_api_response", "Multica returned a mismatched Autopilot run.")
        return raw

    def get_issue(self, issue_id: str, *, deadline: float | None = None) -> dict[str, Any]:
        raw = self._get(f"/api/issues/{urllib.parse.quote(issue_id, safe='')}", deadline=deadline)
        if not isinstance(raw, dict) or raw.get("id") != issue_id:
            raise BridgeError("invalid_api_response", "Multica returned a mismatched issue.")
        return raw

    def list_comments(self, issue_id: str, *, deadline: float | None = None) -> list[dict[str, Any]]:
        raw = self._get(f"/api/issues/{urllib.parse.quote(issue_id, safe='')}/comments", deadline=deadline)
        if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
            raise BridgeError("invalid_api_response", "Multica returned an invalid issue comment list.")
        return raw

    def _read_coherent_issue_snapshot(
        self,
        issue_id: str,
        *,
        deadline: float,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int | None]:
        """Read issue fields and comments without assigning a newer revision to stale issue data."""
        issue = self.get_issue(issue_id, deadline=deadline)
        issue_revision = _source_revision(issue.get("revision"))
        if issue_revision is None:
            comments = self.list_comments(issue_id, deadline=deadline)
            # Comment issue_revision does not version the unversioned Issue fields or
            # Autopilot run fields included in the result fingerprint. Keep the whole
            # snapshot revisionless and order successive reads by the local poll generation.
            return issue, comments, None

        for _attempt in range(MAX_SNAPSHOT_READ_ATTEMPTS):
            comments = self.list_comments(issue_id, deadline=deadline)
            max_comment_revision: int | None = None
            for item in comments:
                comment_revision = _source_revision(item.get("issue_revision"))
                if comment_revision is not None:
                    max_comment_revision = max(max_comment_revision or 0, comment_revision)

            issue_after = self.get_issue(issue_id, deadline=deadline)
            issue_after_revision = _source_revision(issue_after.get("revision"))
            if issue_after_revision is None:
                raise BridgeError(
                    "invalid_api_response",
                    "Multica returned an inconsistent issue revision.",
                )
            if (
                issue_after_revision == issue_revision
                and (max_comment_revision is None or max_comment_revision <= issue_after_revision)
            ):
                return issue_after, comments, issue_after_revision
            issue = issue_after
            issue_revision = issue_after_revision

        raise BridgeError(
            "api_unavailable",
            "Multica result state changed while it was being read.",
            retryable=True,
        )

    def snapshot(self, autopilot_id: str, run_id: str) -> ResultSnapshot:
        deadline = self.monotonic() + self.timeout
        run = self.get_run(autopilot_id, run_id, deadline=deadline)
        raw_run_status = run.get("status")
        run_status = (
            raw_run_status
            if isinstance(raw_run_status, str) and raw_run_status in MULTICA_RUN_STATUSES
            else "unknown"
        )
        normalized = {
            "issue_created": "pending",
            "running": "running",
            "completed": "succeeded",
            "failed": "failed",
            "skipped": "skipped",
        }.get(run_status, "unknown")
        issue_id = _metadata_identifier(run.get("issue_id"), "issue identifier")
        task_id = _metadata_identifier(run.get("task_id"), "task identifier")

        details: dict[str, Any] = {
            "status": normalized,
            "run_status": run_status,
            "run_result": run.get("result"),
            "failure_reason": run.get("failure_reason") if normalized == "failed" else None,
            "reason_code": run.get("reason_code") if normalized in {"failed", "skipped"} else None,
        }
        source_revision: int | None = None
        if issue_id:
            issue, comments, source_revision = self._read_coherent_issue_snapshot(
                issue_id,
                deadline=deadline,
            )
            details["issue"] = {
                "id": issue_id,
                "identifier": issue.get("identifier"),
                "title": issue.get("title"),
                "status": issue.get("status"),
            }
            # Preserve only bounded semantic comment content; attachments and identity metadata are irrelevant here.
            semantic_comments = [
                {
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "author_type": item.get("author_type"),
                    "content": item.get("content"),
                    "created_at": item.get("created_at"),
                }
                for item in comments[-20:]
                if isinstance(item.get("content"), str) and item.get("content")
            ]
            details["comments"] = semantic_comments

        details = _redact_values(details, self._redaction_values)
        canonical = json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        rendered = _render_result(details)
        return ResultSnapshot(
            normalized,
            run_status,
            issue_id,
            task_id,
            rendered,
            fingerprint,
            source_revision,
        )


def _render_result(details: dict[str, Any]) -> str:
    """Produce a bounded human-readable result without reproducing the full API response."""
    status = str(details.get("status") or "unknown")
    parts = [f"Multica execution status: {status}."]
    issue = details.get("issue")
    if isinstance(issue, dict):
        identifier = issue.get("identifier") or issue.get("id")
        if identifier:
            parts.append(f"Issue: {identifier} ({issue.get('status') or 'unknown'}).")
    run_result = details.get("run_result")
    if run_result not in (None, "", {}, []):
        rendered = run_result if isinstance(run_result, str) else json.dumps(run_result, ensure_ascii=False, sort_keys=True)
        parts.append(f"Result: {rendered}")
    elif status in {"failed", "skipped"}:
        reason = details.get("reason_code") or details.get("failure_reason")
        if reason:
            parts.append(f"Reason: {reason}")
    comments = details.get("comments")
    if isinstance(comments, list) and comments:
        latest = comments[-1].get("content")
        if isinstance(latest, str) and latest:
            parts.append(f"Latest issue comment: {latest}")
    text = "\n".join(parts)
    if len(text) > MAX_RESULT_TEXT_CHARS:
        text = text[: MAX_RESULT_TEXT_CHARS - 1] + "…"
    return text
