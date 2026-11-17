"""Narrow writer client for notify's separate approval-mapping socket."""

from __future__ import annotations

import json
import math
import re
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .notify_contract import APPROVAL_SOCKET_PATH, READINESS_PROFILES
from .validation import strict_json_loads

MAX_FRAME = 16 * 1024
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class ApprovalMappingClient:
    """Only sends approval_mapping.put; it has no notify DB or read capability."""

    def __init__(self, path: str = APPROVAL_SOCKET_PATH, *, timeout: float = 1.0):
        self.path = path
        self.timeout = timeout

    def put(self, mapping: dict[str, Any]) -> str:
        required = {
            "version", "op", "parent_issue_id", "wakeup_id", "route_id",
            "source_profile", "instruction", "expires_at",
        }
        if (not isinstance(mapping, dict) or set(mapping) != required
                or type(mapping.get("version")) is not int or mapping.get("version") != 1
                or mapping.get("op") != "approval_mapping.put"
                or not isinstance(mapping.get("source_profile"), str)
                or mapping.get("source_profile") not in READINESS_PROFILES
                or any(not isinstance(mapping.get(key), str) or not _SAFE_ID.fullmatch(mapping[key])
                       for key in ("parent_issue_id", "wakeup_id", "route_id"))
                or not isinstance(mapping.get("instruction"), str)
                or not mapping["instruction"].strip() or len(mapping["instruction"]) > 2000
                or type(mapping.get("expires_at")) not in {int, float}
                or not ApprovalMappingClient._valid_expiry(mapping["expires_at"])):
            raise BridgeError("approval_mapping_invalid", "The approval mapping request is invalid.")
        try:
            info = Path(self.path).lstat()
            if not stat.S_ISSOCK(info.st_mode):
                raise OSError("not a socket")
            body = json.dumps(mapping, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_FRAME:
                raise OSError("request too large")
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                self._set_timeout(client, deadline)
                client.connect(self.path)
                self._set_timeout(client, deadline)
                client.sendall(struct.pack("!I", len(body)) + body)
                size = struct.unpack("!I", self._receive(client, 4, deadline))[0]
                if size < 2 or size > MAX_FRAME:
                    raise OSError("invalid response frame")
                response = strict_json_loads(self._receive(client, size, deadline))
        except BridgeError:
            raise
        except (OSError, ValueError, UnicodeError, struct.error, RecursionError):
            raise BridgeError("approval_mapping_unavailable", "Notify could not accept the approval mapping.") from None
        if (not isinstance(response, dict) or set(response) - {"ok", "status", "error_code"}
                or response.get("ok") is not True or response.get("status") not in {"accepted", "duplicate"}):
            code = response.get("error_code") if isinstance(response, dict) else None
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
                code = "approval_mapping_unavailable"
            raise BridgeError(code, "Notify did not confirm the approval mapping.")
        return response["status"]

    @staticmethod
    def _valid_expiry(value: Any) -> bool:
        if type(value) is int:
            return 0 < value <= 253_402_300_799
        return type(value) is float and math.isfinite(value) and 0 < value <= 253_402_300_799

    @staticmethod
    def _set_timeout(client: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("approval mapping exchange deadline exceeded")
        client.settimeout(remaining)

    @staticmethod
    def _receive(client: socket.socket, size: int, deadline: float) -> bytes:
        data = bytearray()
        while len(data) < size:
            ApprovalMappingClient._set_timeout(client, deadline)
            part = client.recv(size - len(data))
            if not part or time.monotonic() > deadline:
                raise OSError("short response")
            data.extend(part)
        return bytes(data)
