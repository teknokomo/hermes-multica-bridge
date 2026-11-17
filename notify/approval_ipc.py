"""Peer-authenticated, single-operation approval mapping IPC."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import socket
import stat
import struct
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from bridge.condition_wake import ConditionWakeSpec, validate_child_tree
from bridge.validation import strict_json_loads

from .api import Multica
from .config import Config, NotifyError, identifier, require
from .state import State, encoded
from .wake import load_webhook_policy, verify_webhook_policy

MAX_FRAME = 16 * 1024
_PROFILE_SET = frozenset({"default", "om73"})
_ROUTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_TEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TREE_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CHILDREN = 500


def _frame(value: dict[str, Any]) -> bytes:
    body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        body = b'{"ok":false,"error_code":"ipc_response_too_large"}'
    return struct.pack("!I", len(body)) + body


class ApprovalMappingServer:
    """Accepts only approval mappings; the socket is separate from read-only readiness IPC."""

    def __init__(self, config: Config, state: State, *, api_factory=Multica):
        self.config = config
        self.state = state
        self.api_factory = api_factory
        self.path = Path(config.approval_ipc["socket_path"])
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        if not self.config.approval_ipc.get("enabled"):
            return
        try:
            parent = self.path.parent
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
                raise NotifyError("notify_ipc_path_untrusted")
            os.chmod(parent, 0o711)  # nosec B103 - cross-UID traversal; every peer is checked with SO_PEERCRED
            try:
                existing = self.path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                    raise NotifyError("notify_ipc_path_untrusted")
                self.path.unlink()
            self._server = await asyncio.start_unix_server(
                self._handle, path=str(self.path), limit=MAX_FRAME + 4,
            )
            os.chmod(self.path, 0o666)  # nosec B103 - SO_PEERCRED restricts every caller
        except (OSError, NotifyError) as exc:
            if self.path.exists() and self.path.is_socket():
                self.path.unlink(missing_ok=True)
            if isinstance(exc, NotifyError):
                raise
            raise NotifyError("notify_ipc_unavailable") from exc

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            info = self.path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
                self.path.unlink()
        except FileNotFoundError:
            pass

    async def refresh(self, config: Config) -> None:
        if config.approval_ipc["socket_path"] != str(self.path):
            raise NotifyError("notify_config_reload_failed")
        self.config = config

    def _peer(self, writer: asyncio.StreamWriter, profile: str | None = None) -> bool:
        sock = writer.get_extra_info("socket")
        if sock is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        except (OSError, struct.error):
            return False
        return any(
            peer["uid"] == uid and (profile is None or profile in peer["profiles"])
            for peer in self.config.approval_ipc["peers"]
        )

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes:
        prefix = await asyncio.wait_for(reader.readexactly(4), timeout=2)
        size = struct.unpack("!I", prefix)[0]
        if not 2 <= size <= MAX_FRAME:
            raise ValueError("frame size")
        return await asyncio.wait_for(reader.readexactly(size), timeout=2)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not self._peer(writer):
                writer.write(_frame({"ok": False, "error_code": "approval_mapping_unauthorized"}))
                await writer.drain()
                return
            raw = await self._read_frame(reader)
            try:
                request = strict_json_loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                writer.write(_frame({"ok": False, "error_code": "approval_mapping_invalid"}))
                await writer.drain()
                return
            if not self._valid_request(request) or not self._peer(writer, request["source_profile"]):
                writer.write(_frame({"ok": False, "error_code": "approval_mapping_unauthorized"}))
                await writer.drain()
                return
            try:
                result = await asyncio.to_thread(self._put, request)
                writer.write(_frame({"ok": True, "status": result}))
            except NotifyError as exc:
                writer.write(_frame({"ok": False, "error_code": exc.code}))
            await writer.drain()
        except (asyncio.IncompleteReadError, TimeoutError, OSError, ValueError):
            try:
                writer.write(_frame({"ok": False, "error_code": "approval_mapping_invalid"}))
                await writer.drain()
            except OSError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    @staticmethod
    def _valid_request(request: Any) -> bool:
        return (
            isinstance(request, dict)
            and set(request) == {
                "version", "op", "parent_issue_id", "wakeup_id", "route_id",
                "bridge_route_id", "source_profile", "instruction", "expires_at",
                "expected_stage_count", "registered_child_ids", "registered_tree_fingerprint",
            }
            and type(request.get("version")) is int and request["version"] == 1
            and request.get("op") == "approval_mapping.put"
            and isinstance(request.get("source_profile"), str)
            and request.get("source_profile") in _PROFILE_SET
            and all(isinstance(request.get(key), str) and _TEXT_RE.fullmatch(request[key])
                    for key in ("parent_issue_id", "wakeup_id"))
            and isinstance(request.get("route_id"), str) and _ROUTE_RE.fullmatch(request["route_id"])
            and isinstance(request.get("bridge_route_id"), str) and _TEXT_RE.fullmatch(request["bridge_route_id"])
            and isinstance(request.get("instruction"), str)
            and bool(request["instruction"].strip()) and len(request["instruction"]) <= 2000
            and (
                request.get("expected_stage_count") is None
                or (
                    type(request["expected_stage_count"]) is int
                    and 1 <= request["expected_stage_count"] <= 500
                )
            )
            and isinstance(request.get("registered_child_ids"), list)
            and 1 <= len(request["registered_child_ids"]) <= _MAX_CHILDREN
            and all(isinstance(value, str) and _TEXT_RE.fullmatch(value)
                    for value in request["registered_child_ids"])
            and request["registered_child_ids"] == sorted(set(request["registered_child_ids"]))
            and isinstance(request.get("registered_tree_fingerprint"), str)
            and _TREE_FINGERPRINT.fullmatch(request["registered_tree_fingerprint"])
            and type(request["expires_at"]) in {int, float}
            and ((type(request["expires_at"]) is int
                  and 0 < request["expires_at"] <= 253_402_300_799)
                 or (type(request["expires_at"]) is float
                     and math.isfinite(request["expires_at"])
                     and 0 < request["expires_at"] <= 253_402_300_799))
        )

    @staticmethod
    def _canonical_agent_id(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            canonical = str(uuid.UUID(value))
        except (ValueError, AttributeError):
            return None
        return canonical if canonical == value else None

    @staticmethod
    def _expiry_epoch(value: Any) -> float | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                return None
            return parsed.timestamp()
        except (OverflowError, ValueError):
            return None

    def _put(self, request: dict[str, Any]) -> str:
        require(self.config.approval_ipc.get("enabled"), "approval_mapping_unavailable")
        require(
            self.config.approval_ipc.get("native_delivery_suppressed") is True,
            "approval_ready_delivery_unverified",
        )
        require(self.config.wake.get("enabled"), "approval_mapping_unavailable")
        profile, route_id = request["source_profile"], request["route_id"]
        route = next((value for value in self.config.wake["routes"].values()
                      if value["profile"] == profile and value["route"] == route_id), None)
        require(route is not None, "approval_ready_destination_unverified")
        destination = self.state.approval_route(profile, route_id)
        require(
            destination is not None and destination["enabled"] and destination["wake_enabled"]
            and destination["workspace_configured"] and destination["workspace_enabled"]
            and destination["account_configured"],
            "approval_ready_destination_unverified",
        )
        try:
            workspace_data = json.loads(destination["workspace_data"])
        except (TypeError, ValueError):
            raise NotifyError("approval_mapping_invalid") from None
        connection_id = workspace_data.get("connection_id") if isinstance(workspace_data, dict) else None
        if not isinstance(connection_id, str):
            raise NotifyError("approval_mapping_invalid")
        try:
            connection_id = identifier(connection_id)
            parent_id = identifier(request["parent_issue_id"])
            wakeup_id = identifier(request["wakeup_id"])
        except NotifyError:
            raise NotifyError("approval_mapping_invalid") from None
        try:
            policy = load_webhook_policy(Path(self.config.wake["webhook_policy_file"]))
            verify_webhook_policy(policy, profile, route_id, {
                "platform": destination["platform"], "chat_id": destination["chat_id"],
                "thread_id": destination["thread_id"], "chat_type": destination["chat_type"],
            })
        except NotifyError:
            raise NotifyError("approval_ready_destination_unverified") from None
        api = self.api_factory(self.config, destination["workspace_key"])
        try:
            parent = api.reader.get_issue(parent_id)
            if (parent.get("id") != parent_id
                    or parent.get("workspace_id") != destination["external_workspace_id"]
                    or not isinstance(parent.get("project_id"), str) or not parent["project_id"]
                    or (destination["project_id"] and parent.get("project_id") != destination["project_id"])):
                raise NotifyError("approval_mapping_invalid")
            agent_id = self._canonical_agent_id(parent.get("assignee_id"))
            if parent.get("assignee_type") != "agent" or agent_id is None:
                raise NotifyError("approval_mapping_invalid")
            wakeups = api.reader.list_issue_wakeups(parent_id)
            matching = [row for row in wakeups if row.get("id") == wakeup_id]
            if len(matching) != 1:
                raise NotifyError("approval_mapping_invalid")
            wakeup = matching[0]
            condition = wakeup.get("condition")
            if (wakeup.get("issue_id") != parent_id or wakeup.get("agent_id") != agent_id
                    or wakeup.get("kind") != "event" or wakeup.get("mode") != "once"
                    or wakeup.get("instruction") != request["instruction"]
                    or not isinstance(condition, dict) or condition.get("type") != "children_done"
                    or set(condition) - {"type", "stage"}
                    or ("stage" in condition and (type(condition["stage"]) is not int or condition["stage"] < 1))):
                raise NotifyError("approval_mapping_invalid")
            actual_expiry = self._expiry_epoch(wakeup.get("expires_at"))
            requested_expiry = float(request["expires_at"])
            last_task_id = wakeup.get("last_task_id")
            existing = self.state.approval_mapping(
                connection_id, destination["external_workspace_id"], profile, parent_id,
            )
            if (actual_expiry is None
                    or abs(actual_expiry - requested_expiry) > 1
                    or (last_task_id is not None and (
                        not isinstance(last_task_id, str) or not last_task_id
                        or not _TEXT_RE.fullmatch(last_task_id)
                    ))
                    or (existing is None and actual_expiry <= time.time() and not last_task_id)
                    or (existing is None and not wakeup.get("enabled") and not wakeup.get("last_task_id"))
                    or (existing is None and wakeup.get("timed_out_at") is not None)):
                raise NotifyError("approval_mapping_invalid")
            stage = condition.get("stage")
            expected_stage_count = request["expected_stage_count"]
            if (
                (stage is None) != (expected_stage_count is None)
                or (
                    stage is not None
                    and expected_stage_count is not None
                    and expected_stage_count > stage
                )
            ):
                raise NotifyError("approval_mapping_invalid")
            spec = ConditionWakeSpec(
                instruction=request["instruction"], stage=stage,
                expected_stage_count=expected_stage_count,
                expires_in_seconds=None, expires_at=None, on_timeout="end",
            )
            children, fingerprint = validate_child_tree(
                api.reader.list_issue_children(parent_id), parent_id=parent_id,
                workspace_id=destination["external_workspace_id"], project_id=parent["project_id"], spec=spec,
            )
            current_child_ids = [row["id"] for row in children]
            if (current_child_ids != request["registered_child_ids"]
                    or fingerprint != request["registered_tree_fingerprint"]):
                raise NotifyError("approval_mapping_tree_changed")
        except NotifyError:
            raise
        except Exception:  # noqa: BLE001 - stable internal API boundary
            raise NotifyError("approval_mapping_invalid") from None
        mapping = {
            "connection_id": connection_id,
            "workspace_id": destination["external_workspace_id"],
            "workspace_key": destination["workspace_key"],
            "source_profile": profile,
            "parent_issue_id": parent_id,
            "wakeup_id": wakeup_id,
            "route_id": route_id,
            "subscription_id": destination["subscription_id"],
            "instruction": request["instruction"],
            "agent_id": agent_id,
            "project_id": parent["project_id"],
            "expires_at": actual_expiry,
            "child_ids_json": encoded([{"id": row["id"], "stage": row["stage"]} for row in children]),
            "tree_fingerprint": fingerprint,
        }
        _mapping_id, created = self.state.put_approval_mapping(mapping)
        return "accepted" if created else "duplicate"
