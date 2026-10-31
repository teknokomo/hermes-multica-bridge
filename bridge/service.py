"""Transport-independent delivery and result-tracking orchestration."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .configuration import ConnectionConfig
from .errors import BridgeError
from .multica_api import MAX_API_RESPONSE_BYTES, MulticaApiClient
from .protocol import MAX_IPC_RESPONSE_BYTES
from .state import DeliverySnapshot, DeliveryStore
from .validation import request_fingerprint, validate_tool_request
from .webhook import MulticaWebhookClient, encode_webhook_body, webhook_url_fingerprint


@dataclass(frozen=True)
class ServiceCredentials:
    webhook_url: str = field(repr=False)
    hmac_signing_secret: str | None = field(default=None, repr=False)
    multica_pat: str | None = field(default=None, repr=False)
    webhook_sha256: str | None = None


class BridgeService:
    """Apply one validated connection policy to send and result operations."""

    def __init__(
        self,
        config: ConnectionConfig,
        credentials: ServiceCredentials,
        store: DeliveryStore,
        *,
        ledger_key: str | None = None,
        delivery_snapshot: DeliverySnapshot | None = None,
        webhook_client_factory: Callable[..., MulticaWebhookClient] = MulticaWebhookClient,
        api_client_factory: Callable[..., MulticaApiClient] = MulticaApiClient,
    ) -> None:
        self.config = config
        self.credentials = credentials
        self.store = store
        self.ledger_key = ledger_key or config.connection_key
        self.delivery_snapshot = delivery_snapshot
        self.webhook_client_factory = webhook_client_factory
        self.api_client_factory = api_client_factory

    def _admit(self, request: dict[str, Any], *, allow_disabled: bool = False) -> dict[str, Any]:
        normalized = validate_tool_request(request)
        if not self.config.enabled and not allow_disabled:
            raise BridgeError("connection_disabled", "The Multica connection is disabled.")
        readiness = tuple(
            error
            for error in self.config.readiness_errors()
            if not (allow_disabled and error == "disabled")
        )
        if readiness:
            raise BridgeError(
                "configuration_incomplete",
                "The Multica connection configuration is incomplete: " + ", ".join(readiness) + ".",
            )
        if normalized["source"]["board"] not in self.config.source_boards:
            raise BridgeError("route_denied", "This Hermes Kanban board is not allowed by the connection policy.")
        return normalized

    def _validate_credentials_for_send(self) -> None:
        actual = webhook_url_fingerprint(self.credentials.webhook_url, self.config.multica_origin)
        if self.credentials.webhook_sha256 and actual != self.credentials.webhook_sha256:
            raise BridgeError("credential_mismatch", "The webhook credential does not match the trusted configuration.")
        if self.config.hmac_enabled and not self.credentials.hmac_signing_secret:
            raise BridgeError("credential_unavailable", "HMAC is enabled but its signing secret is unavailable.")

    def send(self, request: dict[str, Any]) -> dict[str, Any]:
        normalized = self._admit(request)
        self._validate_credentials_for_send()
        body = encode_webhook_body(self.config.event, normalized)
        if len(body) > self.config.max_payload_bytes:
            raise BridgeError("request_too_large", "The Multica webhook payload exceeds the configured size limit.")
        client = self.webhook_client_factory(
            timeout=float(self.config.request_timeout_seconds),
            max_response_bytes=self.config.max_response_bytes,
            max_payload_bytes=self.config.max_payload_bytes,
        )
        fingerprint = request_fingerprint(normalized)
        attempt = self.store.begin_attempt(
            connection_key=self.ledger_key,
            source_board=normalized["source"]["board"],
            source_task_id=normalized["source"]["task_id"],
            fingerprint=fingerprint,
            max_requests=self.config.max_requests_per_window,
            window_seconds=self.config.window_seconds,
            max_attempts=self.config.max_attempts_per_request,
            snapshot=self.delivery_snapshot,
        )
        try:
            result = client.send(
                self.credentials.webhook_url,
                multica_origin=self.config.multica_origin,
                idempotency_key=attempt.key,
                event=self.config.event,
                event_payload=normalized,
                hmac_secret=self.credentials.hmac_signing_secret,
                hmac_required=self.config.hmac_enabled,
                encoded_body=body,
            )
        except BridgeError:
            self.store.finish_attempt(
                connection_key=self.ledger_key,
                request_id=attempt.request_id,
                attempt_number=attempt.number,
                attempt_id=attempt.attempt_id,
                delivery_status="failed",
                execution_status="unknown",
                delivery_id=None,
                run_id=None,
                http_status=None,
            )
            raise
        self.store.finish_attempt(
            connection_key=self.ledger_key,
            request_id=attempt.request_id,
            attempt_number=attempt.number,
            attempt_id=attempt.attempt_id,
            delivery_status=result.delivery_status,
            execution_status=result.execution_status,
            delivery_id=result.delivery_id,
            run_id=result.run_id,
            http_status=result.http_status,
        )
        response = result.as_dict()
        response["request_id"] = attempt.request_id
        return response

    def check_result(self, request: dict[str, Any]) -> dict[str, Any]:
        normalized = self._admit(request, allow_disabled=True)
        if not self.config.result_tracking_enabled:
            raise BridgeError("result_tracking_disabled", "Result tracking is disabled for this connection.")
        if not self.credentials.multica_pat:
            raise BridgeError("credential_unavailable", "The Multica result credential is not configured.")
        record = self.store.get_delivery(
            connection_key=self.ledger_key,
            source_board=normalized["source"]["board"],
            source_task_id=normalized["source"]["task_id"],
        )
        if record is None:
            raise BridgeError("delivery_not_found", "This Hermes task has no recorded Multica delivery.")
        if record.request_sha256 != request_fingerprint(normalized):
            raise BridgeError("request_conflict", "The Hermes task changed after its Multica delivery was recorded.")
        if record.route_id is not None and record.route_id != self.ledger_key:
            raise BridgeError("route_snapshot_conflict", "The recorded delivery belongs to a different Route.")
        if record.delivery_status not in {"accepted", "duplicate"} or not record.run_id:
            return {
                "ok": True,
                "request_id": record.request_id,
                "delivery_status": record.delivery_status,
                "execution_status": record.execution_status,
                "comment_required": False,
            }

        multica_origin = record.multica_origin or self.config.multica_origin
        workspace_id = record.workspace_id or self.config.workspace_id
        autopilot_id = record.autopilot_id or self.config.autopilot_id
        poll_generation = self.store.begin_result_poll(
            connection_key=self.ledger_key,
            request_id=record.request_id,
        )
        client = self.api_client_factory(
            multica_origin,
            self.credentials.multica_pat,
            workspace_id,
            timeout=float(self.config.request_timeout_seconds),
            max_response_bytes=MAX_API_RESPONSE_BYTES,
            sensitive_values=(self.credentials.webhook_url,),
        )
        snapshot = client.snapshot(autopilot_id, record.run_id)
        update = self.store.record_result(
            connection_key=self.ledger_key,
            request_id=record.request_id,
            execution_status=snapshot.execution_status,
            target_issue_id=snapshot.issue_id,
            target_task_id=snapshot.task_id,
            result_sha256=snapshot.fingerprint,
            source_revision=snapshot.source_revision,
            poll_generation=poll_generation,
        )
        current = self.store.get_delivery(
            connection_key=self.ledger_key,
            source_board=normalized["source"]["board"],
            source_task_id=normalized["source"]["task_id"],
        )
        if current is None:
            raise BridgeError("state_unavailable", "The delivery record no longer exists.")
        if not update.accepted or current.result_sha256 != snapshot.fingerprint:
            return {
                "ok": True,
                "request_id": current.request_id,
                "delivery_status": current.delivery_status,
                "execution_status": current.result_status or current.execution_status,
                "comment_required": False,
            }

        comment_required = False
        if current.result_comment_sha256 != snapshot.fingerprint:
            comment_required = self.store.reserve_result_comment(
                connection_key=self.ledger_key,
                request_id=record.request_id,
                comment_sha256=snapshot.fingerprint,
            )
        response = {
            "ok": True,
            "request_id": record.request_id,
            "delivery_status": record.delivery_status,
            **snapshot.as_dict(),
            "comment_required": comment_required,
        }
        if comment_required:
            response["comment_fingerprint"] = snapshot.fingerprint
            response["comment_marker"] = _comment_marker(record.request_id, snapshot.fingerprint)
            response["comment_text"] = _comment_text(
                snapshot.result_text,
                record.request_id,
                snapshot.fingerprint,
            )
        if self.config.security_mode == "isolated":
            response = _fit_ipc_result_response(
                response,
                snapshot.result_text,
                record.request_id,
                snapshot.fingerprint,
            )
        return response

    def has_delivery(self, request: dict[str, Any]) -> dict[str, Any]:
        """Report route-scoped delivery presence without external I/O or secrets."""
        normalized = self._admit(request, allow_disabled=True)
        record = self.store.get_delivery(
            connection_key=self.ledger_key,
            source_board=normalized["source"]["board"],
            source_task_id=normalized["source"]["task_id"],
        )
        return {"ok": True, "has_delivery": record is not None}

    def finish_result_comment(self, request_id: str, fingerprint: str, *, published: bool) -> None:
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise BridgeError("invalid_arguments", "The result comment fingerprint is invalid.")
        self.store.finish_result_comment(
            connection_key=self.ledger_key,
            request_id=request_id,
            comment_sha256=fingerprint,
            published=published,
        )

    def finish_result_comment_for_request(
        self,
        request: dict[str, Any],
        request_id: str,
        fingerprint: str,
        *,
        published: bool,
    ) -> None:
        """Acknowledge a comment only when it belongs to the caller's admitted Hermes task."""
        normalized = self._admit(request, allow_disabled=True)
        record = self.store.get_delivery(
            connection_key=self.ledger_key,
            source_board=normalized["source"]["board"],
            source_task_id=normalized["source"]["task_id"],
        )
        if record is None or record.request_id != request_id:
            raise BridgeError("delivery_not_found", "The result comment does not belong to this Hermes task.")
        self.finish_result_comment(request_id, fingerprint, published=published)


def _comment_marker(request_id: str, fingerprint: str) -> str:
    return f"<!-- hmb-result:{request_id}:{fingerprint} -->"


def _comment_text(result_text: str, request_id: str, fingerprint: str) -> str:
    prefix = "[Hermes Multica Bridge]\n"
    suffix = f"\n{_comment_marker(request_id, fingerprint)}"
    body = result_text.strip()
    available = 8_192 - len(prefix) - len(suffix)
    if len(body) > available:
        body = body[: max(0, available - 1)] + "…"
    return f"{prefix}{body}{suffix}"


def _fit_ipc_result_response(
    response: dict[str, Any],
    result_text: str,
    request_id: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Trim display text until the complete UTF-8 JSON response fits the Isolated IPC budget."""

    def size(value: dict[str, Any]) -> int:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1

    if size(response) <= MAX_IPC_RESPONSE_BYTES:
        return response

    def candidate(prefix_chars: int) -> dict[str, Any]:
        truncated = result_text
        if prefix_chars < len(result_text):
            truncated = result_text[:prefix_chars] + "…"
        value = dict(response)
        if "result" in value:
            value["result"] = truncated
        if "comment_text" in value:
            value["comment_text"] = _comment_text(truncated, request_id, fingerprint)
        return value

    low = 0
    high = len(result_text)
    best = candidate(0)
    if size(best) > MAX_IPC_RESPONSE_BYTES:
        raise BridgeError("internal_error", "The result metadata exceeds the local IPC size limit.")
    while low <= high:
        middle = (low + high) // 2
        current = candidate(middle)
        if size(current) <= MAX_IPC_RESPONSE_BYTES:
            best = current
            low = middle + 1
        else:
            high = middle - 1
    return best


def comment_fingerprint(text: str) -> str:
    """Expose a deterministic helper for diagnostics/tests without storing comment bodies."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
