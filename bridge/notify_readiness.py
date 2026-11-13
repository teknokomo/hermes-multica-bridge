"""Bounded read-only client for the notification service project readiness socket."""

from __future__ import annotations

import json
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .notify_contract import READINESS_PROFILES, READINESS_SOCKET_PATH
from .validation import strict_json_loads

MAX_FRAME = 16 * 1024
MAX_PROJECTS = 32
DEFAULT_SOCKET = READINESS_SOCKET_PATH


class NotifyReadinessClient:
    def __init__(self, path: str = DEFAULT_SOCKET, *, timeout: float = 0.5):
        self.path = path
        self.timeout = timeout

    def check(self, profile: str, projects: list[dict[str, str]]) -> list[dict[str, Any]]:
        if (profile not in READINESS_PROFILES or not isinstance(projects, list)
                or not 1 <= len(projects) <= MAX_PROJECTS):
            raise BridgeError("invalid_arguments", "The wake readiness request is invalid.")
        if any(
            not isinstance(item, dict)
            or set(item) != {"workspace_id", "project_id"}
            or any(
                not isinstance(item.get(key), str) or not 0 < len(item[key]) <= 128
                for key in ("workspace_id", "project_id")
            )
            for item in projects
        ):
            raise BridgeError("invalid_arguments", "The wake readiness project list is invalid.")
        if len({(item["workspace_id"], item["project_id"]) for item in projects}) != len(projects):
            raise BridgeError("invalid_arguments", "The wake readiness project list contains duplicates.")
        try:
            info = Path(self.path).lstat()
            if not stat.S_ISSOCK(info.st_mode):
                raise OSError("not a socket")
            body = json.dumps({"profile": profile, "projects": projects}, separators=(",", ":")).encode()
            if len(body) > MAX_FRAME:
                raise BridgeError("invalid_arguments", "The wake readiness request is too large.")
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                self._set_remaining_timeout(client, deadline)
                client.connect(self.path)
                self._set_remaining_timeout(client, deadline)
                client.sendall(struct.pack("!I", len(body)) + body)
                size = struct.unpack("!I", self._receive(client, 4, deadline))[0]
                if size < 2 or size > MAX_FRAME:
                    raise OSError("invalid response frame")
                response = strict_json_loads(self._receive(client, size, deadline))
        except BridgeError:
            raise
        except (OSError, ValueError, UnicodeError, struct.error, RecursionError):
            raise BridgeError("source_unavailable", "The notification readiness service is unavailable.") from None
        if not isinstance(response, dict) or response.get("ok") is not True or not isinstance(response.get("projects"), list):
            raise BridgeError("source_unavailable", "The notification readiness service returned no usable status.")
        results = response["projects"]
        if len(results) != len(projects) or any(
            not isinstance(item, dict)
            or set(item) != {"workspace_id", "project_id", "wake_ready", "reason", "wake_route_id"}
            or any(not isinstance(item[key], str) or not 0 < len(item[key]) <= 128
                   for key in ("workspace_id", "project_id"))
            or type(item["wake_ready"]) is not bool
            or not isinstance(item["reason"], str) or len(item["reason"]) > 64
            or item["wake_route_id"] is not None
            and (not isinstance(item["wake_route_id"], str) or not 0 < len(item["wake_route_id"]) <= 64)
            for item in results
        ):
            raise BridgeError("source_unavailable", "The notification readiness service returned an invalid status.")
        expected = [(item["workspace_id"], item["project_id"]) for item in projects]
        actual = [(item["workspace_id"], item["project_id"]) for item in results]
        if actual != expected:
            raise BridgeError("source_unavailable", "The notification readiness response did not match the request.")
        return results

    @staticmethod
    def _set_remaining_timeout(client: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("readiness exchange deadline exceeded")
        client.settimeout(remaining)

    @staticmethod
    def _receive(client: socket.socket, size: int, deadline: float) -> bytes:
        data = bytearray()
        while len(data) < size:
            NotifyReadinessClient._set_remaining_timeout(client, deadline)
            part = client.recv(size - len(data))
            if time.monotonic() > deadline:
                raise TimeoutError("readiness exchange deadline exceeded")
            if not part:
                raise OSError("short response")
            data.extend(part)
        return bytes(data)
