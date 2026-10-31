"""Isolated Multica event watcher with polling reconciliation and at-most-once delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import socket
import stat
import struct
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from .errors import BridgeError
from .validation import _valid_telegram_thread_id
from .watcher_api import watcher_api
from .watcher_config import (
    WatcherConfig,
    WatcherProfile,
    WatcherRoute,
    load_watcher_config,
    read_systemd_credential,
)
from .watcher_delivery import PlatformSender, wait_for_rate_slot
from .watcher_ipc import MAX_IPC_FRAME, decode_frame, encode_frame
from .watcher_state import WatcherState

logger = logging.getLogger("hermes_multica_bridge.watcher")
_FRAME = struct.Struct("!I")
_EVENT_TYPES = frozenset({
    "issue:created", "issue:updated", "comment:created", "task:completed", "task:failed",
})


def _event_issue_ids(frame: dict[str, Any]) -> tuple[str, ...]:
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return ()
    found: set[str] = set()
    for key in ("issue_id", "target_issue_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            found.add(value)
    for key in ("issue", "comment", "task"):
        item = payload.get(key)
        if isinstance(item, dict):
            for field in ("id", "issue_id", "target_issue_id"):
                value = item.get(field)
                if isinstance(value, str) and value:
                    if field == "id" and key != "issue":
                        continue
                    found.add(value)
    return tuple(sorted(found))


def _to_websocket_url(origin: str, workspace_id: str) -> str:
    parsed = urlsplit(origin)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunsplit((scheme, parsed.netloc, "/ws", urlencode({"workspace_id": workspace_id}), ""))


def _comment_is_after_registration(comment_created_at: Any, registered_at_ns: Any) -> bool:
    if not isinstance(comment_created_at, str) or type(registered_at_ns) is not int or registered_at_ns < 0:
        return False
    try:
        parsed = datetime.fromisoformat(comment_created_at)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        return False
    delta = parsed.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    comment_created_at_ns = (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000
    )
    return comment_created_at_ns > registered_at_ns


class Watcher:
    def __init__(self, config: WatcherConfig):
        self.config = config
        self.states: dict[str, WatcherState] = {}
        self.apis: dict[tuple[str, str], Any] = {}
        self.senders: dict[str, PlatformSender] = {}
        self._stop = asyncio.Event()
        self._event_queue: asyncio.Queue[tuple[str, str, dict[str, Any]]] = asyncio.Queue(maxsize=2048)
        for profile in config.profiles:
            self.states[profile.name] = WatcherState(profile.state_path)
            pat = read_systemd_credential(profile.multica_pat_credential)
            max_token = read_systemd_credential(profile.max_token_credential) if profile.max_token_credential else ""
            telegram_token = read_systemd_credential(profile.telegram_token_credential) if profile.telegram_token_credential else ""
            self.senders[profile.name] = PlatformSender(max_token=max_token, telegram_token=telegram_token)
            for route in profile.routes:
                self.apis[(profile.name, route.route_id)] = watcher_api(
                    route.multica_origin, pat, route.workspace_id, timeout=config.request_timeout_seconds,
                )

    @staticmethod
    def _mapping_fields(mapping: Any) -> dict[str, Any]:
        expected = {
            "profile", "issue_id", "route_id", "platform", "user_id", "chat_id",
            "thread_id", "message_id", "chat_type",
        }
        if not isinstance(mapping, dict) or set(mapping) != expected:
            raise BridgeError("watcher_mapping_invalid", "The issue mapping is incomplete or contains unsupported fields.")
        for key, value in mapping.items():
            if key == "thread_id" and value is None:
                continue
            if not isinstance(value, str) or not value or len(value) > 256:
                raise BridgeError("watcher_mapping_invalid", "The issue mapping contains an invalid identifier.")
        if mapping["platform"] not in {"max", "telegram"} or mapping["chat_type"] not in {"dm", "group", "channel", "thread"}:
            raise BridgeError("watcher_mapping_invalid", "The source platform or chat type is unsupported.")
        if (mapping["platform"] == "telegram" and mapping["chat_type"] == "thread"
                and not _valid_telegram_thread_id(mapping["thread_id"])):
            raise BridgeError("watcher_mapping_invalid", "Telegram thread mappings require a valid thread identifier.")
        return mapping

    def _authorize_mapping(self, profile: WatcherProfile, route: WatcherRoute, mapping: dict[str, Any], peer_uid: int) -> None:
        if peer_uid not in profile.allowed_peer_uids:
            raise BridgeError("watcher_peer_denied", "The Hermes process is not allowed to register watcher mappings.")
        if mapping["platform"] not in route.source_platforms:
            raise BridgeError("watcher_source_denied", "The source platform is not enabled for this route.")
        if mapping["user_id"] not in route.allowed_user_ids or mapping["chat_id"] not in route.allowed_chat_ids:
            raise BridgeError("watcher_source_denied", "The source user or chat is not enabled for this route.")
        if mapping["chat_type"] in {"group", "channel", "thread"} and not route.allow_groups:
            raise BridgeError("watcher_source_denied", "Group delivery is disabled for this route.")

    def register_mapping(self, mapping_value: Any, peer_uid: int) -> dict[str, Any]:
        mapping = self._mapping_fields(mapping_value)
        profile = self.config.profile(mapping["profile"])
        route = self.config.route(profile, mapping["route_id"])
        self._authorize_mapping(profile, route, mapping, peer_uid)
        api = self.apis[(profile.name, route.route_id)]
        issue = api.get_issue(mapping["issue_id"])
        self._verify_issue(issue, route)
        state = self.states[profile.name]
        existing = state.mapping(mapping["issue_id"])
        if not state.register_mapping(mapping):
            raise BridgeError("watcher_mapping_conflict", "This issue is already mapped to a different source.")
        # Reconcile immediately after durable registration. This catches an
        # update/comment event that arrived before the mapping was installed.
        self._reconcile(profile, route, mapping["issue_id"], initial=existing is None)
        return {"ok": True, "mapping": "registered"}

    @staticmethod
    def _verify_issue(issue: dict[str, Any], route: WatcherRoute) -> None:
        if issue.get("workspace_id") != route.workspace_id or issue.get("project_id") != route.project_id:
            raise BridgeError("watcher_issue_route_mismatch", "The issue does not belong to this watcher route.")

    def _reconcile(self, profile: WatcherProfile, route: WatcherRoute, issue_id: str, *, initial: bool = False) -> None:
        state = self.states[profile.name]
        mapping = state.mapping(issue_id)
        if mapping is None or mapping["route_id"] != route.route_id:
            return
        api = self.apis[(profile.name, route.route_id)]
        try:
            issue = api.get_issue(issue_id)
            self._verify_issue(issue, route)
            comments = api.list_comments(issue_id)
        except BridgeError as exc:
            logger.warning("Watcher reconciliation failed for route %s with %s", route.route_id, exc.code)
            return
        previous = state.snapshot(issue_id)
        # No snapshot means the first reconciliation did not complete; keep
        # initial semantics when a later event or poll retries it.
        initial = initial or previous is None
        next_fingerprint = state.issue_fingerprint(issue)
        revision = issue.get("revision")
        status = issue.get("status")
        if previous is None:
            if initial and type(revision) is int and revision > 1 and status in route.allowed_statuses:
                snapshot_ready = self._notify_issue(profile, route, mapping, issue, "reconciled")
            else:
                snapshot_ready = True
        elif next_fingerprint != previous["content_hash"] and status in route.allowed_statuses:
            revision_tag = str(revision) if type(revision) is int else "revisionless"
            snapshot_ready = self._notify_issue(
                profile, route, mapping, issue, f"{revision_tag}:{next_fingerprint}"
            )
        else:
            snapshot_ready = True
        if snapshot_ready:
            state.save_snapshot(issue_id, issue)

        registered_at_ns = mapping.get("registered_at_ns")
        for comment in comments:
            comment_id = comment.get("id")
            if not isinstance(comment_id, str):
                continue
            if state.comment_seen(issue_id, comment_id):
                continue
            if initial and not _comment_is_after_registration(comment.get("created_at"), registered_at_ns):
                state.mark_comment_seen(issue_id, comment_id)
                continue
            if comment.get("author_id") == profile.own_multica_user_id:
                state.mark_comment_seen(issue_id, comment_id)
                continue
            content = comment.get("content")
            if not isinstance(content, str) or not content.strip():
                state.mark_comment_seen(issue_id, comment_id)
                continue
            author = comment.get("author_type")
            label = "Комментарий Multica" + (f" ({author})" if isinstance(author, str) and author else "")
            delivered = self._deliver(
                profile, route, mapping, f"comment:{comment_id}", f"{label}: {content.strip()}"
            )
            if delivered:
                state.mark_comment_seen(issue_id, comment_id)

    def _notify_issue(
        self, profile: WatcherProfile, route: WatcherRoute, mapping: dict[str, Any], issue: dict[str, Any], suffix: str,
    ) -> bool:
        title = issue.get("title") if isinstance(issue.get("title"), str) else "Задача Multica"
        status = issue.get("status") if isinstance(issue.get("status"), str) else "неизвестен"
        revision = issue.get("revision")
        detail = f"Multica: {title}\nСтатус: {status}"
        if type(revision) is int:
            detail += f"\nИзменение #{revision}"
        return self._deliver(profile, route, mapping, f"issue:{issue['id']}:{suffix}", detail)

    def _deliver(
        self, profile: WatcherProfile, route: WatcherRoute, mapping: dict[str, Any], event_key: str, text: str,
    ) -> bool:
        key = hashlib.sha256(f"{profile.name}\0{route.route_id}\0{event_key}".encode()).hexdigest()
        state = self.states[profile.name]
        claim = state.claim_delivery(key, mapping["issue_id"], mapping["platform"], mapping["chat_id"])
        if claim == "sending":
            return False
        if claim != "claimed":
            return True
        try:
            if mapping["platform"] == "max":
                recipient_id = mapping["user_id"] if mapping["chat_type"] == "dm" else mapping["chat_id"]
                delay = state.reserve_chat_slot(profile.name, "max", recipient_id)
                wait_for_rate_slot(delay)
            elif mapping["platform"] == "telegram":
                delay = state.reserve_chat_slot(
                    profile.name, "telegram", mapping["chat_id"], interval_ms=1_100
                )
                wait_for_rate_slot(delay)
            result = self.senders[profile.name].send(mapping, text[: self.config.max_message_chars])
            state.finish_delivery(key, result.status, result.detail)
            return not (result.status == "not_sent" and result.detail == "http_429")
        except Exception:  # noqa: BLE001 - an unexpected send failure has an ambiguous delivery outcome
            try:
                state.finish_delivery(key, "delivery_unknown", "unexpected_delivery_error")
            except BridgeError:
                return False
            logger.error("Watcher delivery outcome is unknown for route %s", route.route_id)
            return True

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        try:
            if sock is None or not hasattr(socket, "SO_PEERCRED"):
                raise BridgeError("watcher_peer_unavailable", "Peer credentials are unavailable.")
            raw_creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, peer_uid, _ = struct.unpack("3i", raw_creds)
            if not any(peer_uid in profile.allowed_peer_uids for profile in self.config.profiles):
                raise BridgeError("watcher_peer_denied", "The Hermes process is not allowed to register watcher mappings.")
            header = await asyncio.wait_for(reader.readexactly(_FRAME.size), timeout=3)
            size = _FRAME.unpack(header)[0]
            if not 0 < size <= MAX_IPC_FRAME:
                raise BridgeError("watcher_ipc_invalid", "Watcher IPC frame exceeds the safe size limit.")
            body = await asyncio.wait_for(reader.readexactly(size), timeout=3)
            request = decode_frame(header + body)
            if request == {"operation": "readiness"}:
                response = {"ok": True, "ready": True}
            elif set(request) == {"operation", "mapping"} and request.get("operation") == "register_issue":
                response = await asyncio.to_thread(self.register_mapping, request.get("mapping"), peer_uid)
            else:
                raise BridgeError("watcher_ipc_invalid", "Watcher IPC operation is unsupported.")
        except BridgeError as exc:
            response = {"ok": False, "error_code": exc.code}
        except (TimeoutError, asyncio.IncompleteReadError, OSError, ValueError, TypeError):
            response = {"ok": False, "error_code": "watcher_ipc_invalid"}
        try:
            writer.write(encode_frame(response))
            await writer.drain()
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _websocket_loop(self, profile: WatcherProfile, route: WatcherRoute) -> None:
        api = self.apis[(profile.name, route.route_id)]
        token = api.websocket_token
        backoff = 1
        while not self._stop.is_set():
            try:
                from websockets.asyncio.client import connect

                async with connect(
                    _to_websocket_url(route.multica_origin, route.workspace_id),
                    open_timeout=10,
                    close_timeout=2,
                    ping_interval=20,
                    max_size=65_536,
                ) as websocket:
                    await websocket.send(json.dumps({"type": "auth", "payload": {"token": token}}))
                    ack = json.loads(await asyncio.wait_for(websocket.recv(), timeout=10))
                    if not isinstance(ack, dict) or ack.get("type") != "auth_ack":
                        raise BridgeError("watcher_websocket_auth", "Multica WebSocket did not confirm authentication.")
                    backoff = 1
                    async for raw in websocket:
                        if not isinstance(raw, str) or len(raw) > 65_536:
                            continue
                        try:
                            frame = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(frame, dict) or frame.get("type") not in _EVENT_TYPES:
                            continue
                        for issue_id in _event_issue_ids(frame):
                            try:
                                self._event_queue.put_nowait((profile.name, route.route_id, {"issue_id": issue_id}))
                            except asyncio.QueueFull:
                                logger.warning("Watcher event queue is full for route %s", route.route_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect on any transport or protocol failure
                code = exc.code if isinstance(exc, BridgeError) else type(exc).__name__
                logger.warning("Multica WebSocket disconnected for route %s (%s)", route.route_id, code)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff)
            except TimeoutError:
                pass
            backoff = min(backoff * 2, 60)

    async def _poll_route(self, profile: WatcherProfile, route: WatcherRoute) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.config.poll_seconds)
                return
            except TimeoutError:
                pass
            mappings = self.states[profile.name].mappings(profile.name, route.route_id)
            await asyncio.gather(*(
                asyncio.to_thread(self._reconcile, profile, route, mapping["issue_id"])
                for mapping in mappings
            ), return_exceptions=True)

    async def _consume_events(self) -> None:
        while not self._stop.is_set():
            try:
                profile_name, route_id, event = await asyncio.wait_for(self._event_queue.get(), timeout=1)
            except TimeoutError:
                continue
            try:
                profile = self.config.profile(profile_name)
                route = self.config.route(profile, route_id)
                await asyncio.to_thread(self._reconcile, profile, route, event["issue_id"])
            except BridgeError as exc:
                logger.warning("Watcher event reconciliation refused for route %s (%s)", route_id, exc.code)
            except Exception as exc:  # noqa: BLE001 - one malformed event must not stop the queue consumer
                logger.error("Watcher event reconciliation failed for route %s (%s)", route_id, type(exc).__name__)
            finally:
                self._event_queue.task_done()

    async def run(self) -> None:
        socket_path = self.config.socket_path
        try:
            directory = socket_path.parent
            directory_info = directory.lstat()
            if (not stat.S_ISDIR(directory_info.st_mode)
                    or directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o022):
                raise BridgeError("watcher_socket_untrusted", "Watcher socket directory has unsafe metadata.")
            if self.config.socket_gid not in os.getgroups() and self.config.socket_gid != os.getegid():
                raise BridgeError("watcher_socket_untrusted", "Watcher process is not a member of the configured socket group.")
            try:
                existing = socket_path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.geteuid():
                    raise BridgeError("watcher_socket_untrusted", "An unexpected file occupies the watcher socket path.")
                socket_path.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            os.chown(socket_path, os.geteuid(), self.config.socket_gid)
            os.chmod(socket_path, 0o660)  # nosec B103 -- only the trusted Gateway group may register mappings
            listener.listen(16)
        except BridgeError:
            raise
        except OSError as exc:
            raise BridgeError("watcher_socket_unavailable", "Watcher IPC socket could not be created.") from exc
        listener.setblocking(False)
        server = await asyncio.start_unix_server(self._serve_client, sock=listener, limit=MAX_IPC_FRAME + 4)
        tasks = [asyncio.create_task(self._consume_events(), name="watcher-events")]
        for profile in self.config.profiles:
            for route in profile.routes:
                tasks.append(asyncio.create_task(self._websocket_loop(profile, route), name=f"ws-{route.route_id}"))
                tasks.append(asyncio.create_task(self._poll_route(profile, route), name=f"poll-{route.route_id}"))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except NotImplementedError:
                pass
        async with server:
            await self._stop.wait()
            server.close()
            await server.wait_closed()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            socket_path.unlink()
        except OSError:
            pass


def main() -> int:
    logging.basicConfig(level=os.environ.get("HMB_LOG_LEVEL", "INFO"), format="%(levelname)s %(message)s")
    config_path = os.environ.get("HMB_WATCHER_CONFIG", "/etc/hermes-multica-watcher/watcher.toml")
    try:
        watcher = Watcher(load_watcher_config(config_path))
        asyncio.run(watcher.run())
    except BridgeError as exc:
        logger.error("Watcher stopped (%s)", exc.code)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
