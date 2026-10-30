"""Strict validation shared by the Hermes plugin and the trusted sender."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .errors import BridgeError

MAX_IPC_REQUEST_BYTES = 131_072
MAX_MULTICA_PAT_BYTES = 8_192
MAX_TASK_TITLE_CHARS = 4_096
MAX_TASK_BODY_CHARS = 65_536
SOURCE_TASK_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
SOURCE_BOARD_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
WORKER_RUN_ID_RE = re.compile(r"\A[1-9][0-9]{0,18}\Z")
TELEGRAM_THREAD_ID_RE = re.compile(r"\A[0-9]{1,24}\Z")


def _valid_telegram_thread_id(value: Any) -> bool:
    return isinstance(value, str) and TELEGRAM_THREAD_ID_RE.fullmatch(value) is not None and int(value) > 0


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str) -> Any:
    """Decode JSON while rejecting duplicate keys and non-standard constants."""

    def reject_constant(_value: str) -> None:
        raise ValueError("non-standard JSON constant")

    return json.loads(data, object_pairs_hook=_unique_object, parse_constant=reject_constant)


def _validated_string(value: Any, *, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        raise BridgeError("invalid_arguments", f"{field} has an invalid value.")
    return value


def _validated_identifier(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise BridgeError("invalid_arguments", f"{field} has an invalid format.")
    return value


def validate_tool_request(value: Any) -> dict[str, Any]:
    """Validate the model-independent request copied from trusted Hermes Kanban state."""
    if not isinstance(value, dict) or set(value) != {"source", "task"}:
        raise BridgeError("invalid_arguments", "The request has missing or unsupported fields.")

    source = value["source"]
    if not isinstance(source, dict) or set(source) != {"system", "board", "task_id", "run_id"}:
        raise BridgeError("invalid_arguments", "The request source has missing or unsupported fields.")
    if source["system"] != "hermes":
        raise BridgeError("invalid_arguments", "The request source system is unsupported.")
    board = _validated_identifier(source["board"], SOURCE_BOARD_RE, "source.board")
    task_id = _validated_identifier(source["task_id"], SOURCE_TASK_ID_RE, "source.task_id")
    run_id = _validated_identifier(source["run_id"], WORKER_RUN_ID_RE, "source.run_id")
    if int(run_id) > 9_223_372_036_854_775_807:
        raise BridgeError("invalid_arguments", "source.run_id has an invalid format.")

    task = value["task"]
    if not isinstance(task, dict) or set(task) != {"title", "body"}:
        raise BridgeError("invalid_arguments", "The request task has missing or unsupported fields.")
    title = _validated_string(task["title"], field="task.title", maximum=MAX_TASK_TITLE_CHARS)
    body = _validated_string(
        task["body"], field="task.body", maximum=MAX_TASK_BODY_CHARS, allow_empty=True
    )

    request = {
        "source": {"system": "hermes", "board": board, "task_id": task_id, "run_id": run_id},
        "task": {"title": title, "body": body},
    }
    encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_IPC_REQUEST_BYTES:
        raise BridgeError("request_too_large", "The complete request exceeds the IPC size limit.")
    return request


def request_fingerprint(request: dict[str, Any]) -> str:
    """Hash logical task data while excluding the worker run used only for caller authorization."""
    normalized = validate_tool_request(request)
    operation = {
        "source": {
            "system": "hermes",
            "board": normalized["source"]["board"],
            "task_id": normalized["source"]["task_id"],
        },
        "task": normalized["task"],
    }
    encoded = json.dumps(operation, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def idempotency_key(connection_key: str, request_id: str) -> str:
    """Return the same opaque key for every retry of the same logical request."""
    digest = hashlib.sha256(f"{connection_key}\0{request_id}".encode()).hexdigest()
    return f"hmb-{digest}"
