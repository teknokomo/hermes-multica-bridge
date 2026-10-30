"""Bounded local IPC between the Hermes plugin and the isolated watcher."""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .validation import _valid_telegram_thread_id, strict_json_loads

MAX_IPC_FRAME = 16_384
_FRAME = struct.Struct("!I")
_MAPPING_FIELDS = frozenset({
    "profile", "issue_id", "route_id", "platform", "user_id", "chat_id",
    "thread_id", "message_id", "chat_type",
})


def encode_frame(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not raw or len(raw) > MAX_IPC_FRAME:
        raise BridgeError("watcher_ipc_invalid", "Watcher IPC request exceeds the safe size limit.")
    return _FRAME.pack(len(raw)) + raw


def decode_frame(raw: bytes) -> dict[str, Any]:
    if len(raw) < _FRAME.size:
        raise BridgeError("watcher_ipc_invalid", "Watcher IPC response is incomplete.")
    size = _FRAME.unpack(raw[:_FRAME.size])[0]
    if not 0 < size <= MAX_IPC_FRAME or len(raw) != _FRAME.size + size:
        raise BridgeError("watcher_ipc_invalid", "Watcher IPC response has an invalid frame size.")
    try:
        value = strict_json_loads(raw[_FRAME.size:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise BridgeError("watcher_ipc_invalid", "Watcher IPC response is invalid JSON.") from None
    if not isinstance(value, dict):
        raise BridgeError("watcher_ipc_invalid", "Watcher IPC response is not an object.")
    return value


class WatcherIpcClient:
    def __init__(self, path: str | Path | None = None, *, timeout: float = 3.0):
        self.path = Path(path or os.environ.get("HMB_WATCHER_SOCKET", "/run/hermes-multica-watcher/ipc.sock"))
        self.timeout = min(max(float(timeout), 0.1), 10.0)

    def register_issue(self, mapping: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(mapping, dict) or set(mapping) != _MAPPING_FIELDS:
            raise BridgeError("watcher_ipc_invalid", "Watcher mapping fields are incomplete or unsupported.")
        for key, value in mapping.items():
            if key == "thread_id" and value is None:
                continue
            if not isinstance(value, str) or not value or len(value) > 256:
                raise BridgeError("watcher_ipc_invalid", "Watcher mapping contains an invalid identifier.")
        if (mapping["platform"] == "telegram" and mapping["chat_type"] == "thread"
                and not _valid_telegram_thread_id(mapping["thread_id"])):
            raise BridgeError("watcher_ipc_invalid", "Telegram thread mappings require a valid thread identifier.")
        return self._request({"operation": "register_issue", "mapping": mapping})

    def readiness(self) -> dict[str, Any]:
        return self._request({"operation": "readiness"})

    def _request(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise BridgeError("watcher_ipc_unavailable", "Watcher IPC socket is unavailable.")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(str(self.path))
                conn.sendall(encode_frame(request))
                header = _read_exact(conn, _FRAME.size)
                size = _FRAME.unpack(header)[0]
                if not 0 < size <= MAX_IPC_FRAME:
                    raise BridgeError("watcher_ipc_invalid", "Watcher IPC response has an invalid size.")
                response = decode_frame(header + _read_exact(conn, size))
        except BridgeError:
            raise
        except OSError as exc:
            raise BridgeError("watcher_ipc_unavailable", "Watcher IPC is unavailable.") from exc
        if response.get("ok") is not True:
            raise BridgeError(
                str(response.get("error_code") or "watcher_mapping_rejected"),
                "Watcher did not confirm the issue mapping.",
            )
        return response


def _read_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise BridgeError("watcher_ipc_invalid", "Watcher IPC connection closed mid-frame.")
        data.extend(chunk)
    return bytes(data)
