"""Read-only, peer-authenticated project wake readiness IPC for bridge profiles."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Any

from bridge.notify_contract import READINESS_PROFILES
from bridge.validation import strict_json_loads

from .config import Config, NotifyError
from .state import State
from .wake import load_webhook_policy, verify_webhook_policy

MAX_FRAME = 16 * 1024
MAX_PROJECTS = 32
_PROFILE_SET = READINESS_PROFILES


def _encode(value: dict[str, Any]) -> bytes:
    body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        body = b'{"ok":false,"error_code":"ipc_response_too_large"}'
    return struct.pack("!I", len(body)) + body


class ReadinessServer:
    def __init__(self, config: Config, state: State):
        self.config = config
        self.state = state
        self.path = Path(config.readiness_ipc["socket_path"])
        self._server: asyncio.AbstractServer | None = None
        self._policy: dict | None = None

    async def start(self, *, policy: dict | None = None) -> None:
        if not self.config.readiness_ipc.get("enabled"):
            return
        try:
            parent = self.path.parent
            parent_info = parent.lstat()
            if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
                    or parent_info.st_uid != os.getuid()):
                raise NotifyError("notify_ipc_path_untrusted")
            # This dedicated RuntimeDirectory contains only the authenticated socket.
            # Permit traversal to the authenticated socket without exposing directory entries.
            os.chmod(parent, 0o711)  # nosec B103 - traverse only; socket peers are authenticated by SO_PEERCRED
        except OSError as exc:
            raise NotifyError("notify_ipc_unavailable") from exc
        try:
            existing = self.path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise NotifyError("notify_ipc_path_untrusted")
            self.path.unlink()
        try:
            self._policy = policy if policy is not None else load_webhook_policy(
                Path(self.config.wake["webhook_policy_file"])
            )
            self._server = await asyncio.start_unix_server(self._handle, path=str(self.path), limit=MAX_FRAME + 4)
            # Cross-UID peers connect here; _peer_allowed() authorizes every peer via SO_PEERCRED.
            os.chmod(self.path, 0o666)  # nosec B103
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
            current = self.path.lstat()
            if stat.S_ISSOCK(current.st_mode) and current.st_uid == os.getuid():
                self.path.unlink()
        except FileNotFoundError:
            pass

    async def refresh(self, config: Config, *, policy: dict | None = None) -> None:
        if config.readiness_ipc["socket_path"] != str(self.path):
            raise NotifyError("notify_config_reload_failed")
        next_policy = policy if policy is not None else load_webhook_policy(
            Path(config.wake["webhook_policy_file"])
        )
        self.config = config
        self._policy = next_policy

    def _peer_allowed(self, writer: asyncio.StreamWriter, profile: str) -> bool:
        sock = writer.get_extra_info("socket")
        if sock is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        except (OSError, struct.error):
            return False
        return any(peer["uid"] == uid and profile in peer["profiles"] for peer in self.config.readiness_ipc["peers"])

    def _peer_uid_allowed(self, writer: asyncio.StreamWriter) -> bool:
        sock = writer.get_extra_info("socket")
        if sock is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        except (OSError, struct.error):
            return False
        return any(peer["uid"] == uid for peer in self.config.readiness_ipc["peers"])

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes:
        prefix = await asyncio.wait_for(reader.readexactly(4), timeout=2)
        size = struct.unpack("!I", prefix)[0]
        if size < 2 or size > MAX_FRAME:
            raise ValueError("frame size")
        return await asyncio.wait_for(reader.readexactly(size), timeout=2)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not self._peer_uid_allowed(writer):
                writer.write(_encode({"ok": False, "error_code": "ipc_peer_denied"}))
                await writer.drain()
                return
            # Read only the fixed prefix first; reject oversize frames before JSON parsing.
            raw = await self._read_frame(reader)
            try:
                request = strict_json_loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                writer.write(_encode({"ok": False, "error_code": "ipc_request_invalid"}))
                await writer.drain()
                return
            if (not isinstance(request, dict) or set(request) != {"profile", "projects"}
                    or not isinstance(request.get("profile"), str)
                    or request["profile"] not in _PROFILE_SET
                    or not isinstance(request.get("projects"), list)
                    or not 1 <= len(request["projects"]) <= MAX_PROJECTS):
                writer.write(_encode({"ok": False, "error_code": "ipc_request_invalid"}))
                await writer.drain()
                return
            profile = request["profile"]
            if not self._peer_allowed(writer, profile):
                writer.write(_encode({"ok": False, "error_code": "ipc_peer_denied"}))
                await writer.drain()
                return
            projects = request["projects"]
            if any(not isinstance(item, dict) or set(item) != {"workspace_id", "project_id"}
                   or not all(isinstance(item.get(key), str) and 0 < len(item[key]) <= 128
                              for key in ("workspace_id", "project_id")) for item in projects):
                writer.write(_encode({"ok": False, "error_code": "ipc_request_invalid"}))
                await writer.drain()
                return
            if len({(item["workspace_id"], item["project_id"]) for item in projects}) != len(projects):
                writer.write(_encode({"ok": False, "error_code": "ipc_request_invalid"}))
                await writer.drain()
                return
            result = await asyncio.to_thread(self._readiness, profile, projects)
            writer.write(_encode({"ok": True, "projects": result}))
            await writer.drain()
        except (asyncio.IncompleteReadError, TimeoutError, OSError, ValueError):
            try:
                writer.write(_encode({"ok": False, "error_code": "ipc_request_invalid"}))
                await writer.drain()
            except OSError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    def _readiness(self, profile: str, projects: list[dict[str, str]]) -> list[dict[str, Any]]:
        response = []
        try:
            project_ids = sorted({project["project_id"] for project in projects})
            query = """SELECT ws.profile,ws.route,ws.enabled AS wake_enabled,s.enabled AS subscription_enabled,
                s.platform,s.chat_id,s.thread_id,s.chat_type,s.workspace_id AS workspace_key,s.project_id,
                w.data_json,w.configured AS workspace_configured,w.enabled AS workspace_enabled,
                a.configured AS account_configured FROM wake_subscriptions ws
                JOIN subscriptions s ON s.id=ws.subscription_id
                JOIN workspaces w ON w.id=s.workspace_id JOIN accounts a ON a.name=s.account
                WHERE ws.enabled=1 AND s.enabled=1 AND s.project_id = ?
                ORDER BY ws.profile,ws.route LIMIT 4097"""
            rows = []
            for project_id in project_ids:
                rows.extend(self.state.rows(query, (project_id,)))
                if len(rows) > 4096:
                    raise ValueError("readiness row limit")
            configured_routes = self.config.wake.get("routes", {})
            policy = self._policy or {}
        except Exception:  # noqa: BLE001 - expose only a stable unavailable result
            return [{"workspace_id": p["workspace_id"], "project_id": p["project_id"],
                     "wake_ready": False, "reason": "source_unavailable", "wake_route_id": None}
                    for p in projects]
        for project in projects:
            ready, reason = False, "wake_missing"
            matched_route = None
            for row in rows:
                try:
                    workspace_data = json.loads(row["data_json"])
                    external_workspace = workspace_data.get("workspace_id") if isinstance(workspace_data, dict) else None
                    if external_workspace != project["workspace_id"] or row["project_id"] != project["project_id"]:
                        continue
                    if not row["workspace_configured"] or not row["workspace_enabled"] or not row["account_configured"]:
                        reason = "wake_source_unavailable"
                        continue
                    route = next((item for item in configured_routes.values()
                                  if item["route"] == row["route"] and item["profile"] == row["profile"]), None)
                    if not self.config.wake.get("enabled") or route is None:
                        reason = "wake_route_unavailable"
                        continue
                    try:
                        verify_webhook_policy(policy, row["profile"], row["route"], {
                            "platform": row["platform"], "chat_id": row["chat_id"],
                            "thread_id": row["thread_id"], "chat_type": row["chat_type"],
                        })
                    except NotifyError:
                        reason = "wake_route_policy_mismatch"
                        continue
                    ready, reason, matched_route = True, "ready", row["route"]
                    break
                except (ValueError, TypeError, KeyError):
                    reason = "wake_source_unavailable"
            response.append({"workspace_id": project["workspace_id"], "project_id": project["project_id"],
                             "wake_ready": ready, "reason": reason,
                             "wake_route_id": matched_route})
        return response
