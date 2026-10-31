"""Bounded JSON-lines protocol between the Hermes plugin and Isolated sender."""

from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .validation import MAX_IPC_REQUEST_BYTES, strict_json_loads, validate_tool_request

MAX_IPC_RESPONSE_BYTES = 16_384
IPC_OPERATIONS = frozenset(
    {"readiness", "send", "has_delivery", "check_result", "finish_result_comment"}
)
REQUEST_ID_RE = re.compile(r"\A[0-9A-Fa-f-]{32,64}\Z")
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def validate_ipc_envelope(value: Any) -> dict[str, Any]:
    """Validate the complete model-independent operation sent over the local socket."""
    if not isinstance(value, dict) or not isinstance(value.get("operation"), str):
        raise BridgeError("invalid_request", "The local bridge request is invalid.")
    operation = value["operation"]
    if operation not in IPC_OPERATIONS:
        raise BridgeError("invalid_request", "The local bridge operation is unsupported.")

    if operation == "readiness":
        if set(value) != {"operation"}:
            raise BridgeError("invalid_request", "The local readiness request has unsupported fields.")
        return {"operation": operation}

    if operation in {"send", "has_delivery", "check_result"}:
        if set(value) != {"operation", "request"}:
            raise BridgeError("invalid_request", "The local bridge request has unsupported fields.")
        return {"operation": operation, "request": validate_tool_request(value["request"])}

    if set(value) != {"operation", "request", "request_id", "fingerprint", "published"}:
        raise BridgeError("invalid_request", "The local bridge acknowledgement has unsupported fields.")
    request_id = value["request_id"]
    fingerprint = value["fingerprint"]
    published = value["published"]
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise BridgeError("invalid_request", "The local bridge request id is invalid.")
    if not isinstance(fingerprint, str) or not SHA256_RE.fullmatch(fingerprint):
        raise BridgeError("invalid_request", "The local bridge result fingerprint is invalid.")
    if type(published) is not bool:
        raise BridgeError("invalid_request", "The local bridge acknowledgement status is invalid.")
    return {
        "operation": operation,
        "request": validate_tool_request(value["request"]),
        "request_id": request_id,
        "fingerprint": fingerprint,
        "published": published,
    }


class BridgeIpcClient:
    def __init__(self, socket_path: str | Path, timeout: float = 20.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def send(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.call({"operation": "send", "request": request})

    def readiness(self) -> dict[str, Any]:
        return self.call({"operation": "readiness"})

    def check_result(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.call({"operation": "check_result", "request": request})

    def has_delivery(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.call({"operation": "has_delivery", "request": request})

    def finish_result_comment(
        self,
        request: dict[str, Any],
        request_id: str,
        fingerprint: str,
        *,
        published: bool,
    ) -> dict[str, Any]:
        return self.call(
            {
                "operation": "finish_result_comment",
                "request": request,
                "request_id": request_id,
                "fingerprint": fingerprint,
                "published": published,
            }
        )

    def call(self, envelope: dict[str, Any]) -> dict[str, Any]:
        normalized = validate_ipc_envelope(envelope)
        raw = json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_IPC_REQUEST_BYTES:
            raise BridgeError("request_too_large", "The complete local request exceeds the IPC size limit.")
        deadline = time.monotonic() + self.timeout

        def set_remaining_timeout(client: socket.socket) -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            client.settimeout(remaining)

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                set_remaining_timeout(client)
                client.connect(self.socket_path)
                set_remaining_timeout(client)
                client.sendall(raw + b"\n")
                client.shutdown(socket.SHUT_WR)
                chunks = bytearray()
                while len(chunks) <= MAX_IPC_RESPONSE_BYTES:
                    set_remaining_timeout(client)
                    part = client.recv(min(2048, MAX_IPC_RESPONSE_BYTES + 1 - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                if len(chunks) > MAX_IPC_RESPONSE_BYTES:
                    raise BridgeError("invalid_bridge_response", "The trusted sender returned an invalid response.")
                if not chunks.endswith(b"\n"):
                    raise BridgeError(
                        "bridge_unavailable",
                        "The trusted sender ended before returning a complete response.",
                        retryable=True,
                    )
        except BridgeError:
            raise
        except (OSError, TimeoutError):
            raise BridgeError(
                "bridge_unavailable",
                "The trusted Multica sender is unavailable.",
                retryable=True,
            ) from None
        try:
            response = strict_json_loads(bytes(chunks[:-1]))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            raise BridgeError("invalid_bridge_response", "The trusted sender returned an invalid response.") from None
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise BridgeError("invalid_bridge_response", "The trusted sender returned an invalid response.")
        return response
