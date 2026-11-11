"""Single-process collection, recovery, reload and independent outbox workers."""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import random
import signal
import sqlite3
import time
from contextlib import AsyncExitStack
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

from bridge.errors import BridgeError
from bridge.validation import strict_json_loads

from .api import Multica
from .config import (
    NotifyError,
    atomic_private,
    credential,
    load_config,
    private_dir,
    require,
)
from .delivery import Sender
from .policy import reconcile
from .state import State, epoch

LOG = logging.getLogger("hermes_multica_notify")
EVENT_TYPES = {
    "issue:created",
    "issue:updated",
    "comment:created",
    "task:completed",
    "task:failed",
}


def log(event: str, **fields) -> None:
    # Callers supply identifiers and fixed codes only, never exception text or source bodies.
    LOG.info(json.dumps({"event": event, **fields}, ensure_ascii=False))


async def blocking(function, *args):
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.gather(task, return_exceptions=True)
        raise


def full_delay(config, *, initial=False, rng=None):
    rng = rng or random.SystemRandom()
    if initial:
        return rng.uniform(0, 30)
    jitter = config.service["full_reconcile_jitter_seconds"]
    return config.service["full_reconcile_seconds"] + rng.uniform(-jitter, jitter)


class Service:
    def __init__(self, config_path: Path, *, api_factory=Multica, sender=None):
        self.path = config_path.resolve()
        self.config = load_config(self.path)
        self.state: State
        self.api_factory = api_factory
        self.sender = sender or Sender(self.config.service["request_timeout_seconds"])
        self.stop = asyncio.Event()
        self.reload_requested = asyncio.Event()
        self.locks: dict[str, asyncio.Lock] = {}
        self.wakes: dict[str, asyncio.Event] = {}
        self.full_slots = asyncio.Semaphore(
            self.config.service["full_reconcile_parallelism"]
        )
        self.delivery_slots = asyncio.Semaphore(self.config.service["delivery_workers"])
        # Dispatch remains serialized through completion: stalled workers cannot bunch
        # previously reserved slots into a burst. Collection runs independently.
        self.dispatch_lock = asyncio.Lock()
        self.scheduled: set[str] = set()
        self.collectors: list[asyncio.Task] = []
        self.deliveries: set[asyncio.Task] = set()

    def scan(self, key: str, api: Multica, full: bool) -> None:
        now = time.time()
        subs = self.state.rows(
            "SELECT * FROM subscriptions WHERE enabled=1 AND workspace_id=?", (key,)
        )
        if not subs:
            return
        cursor = self.state.rows("SELECT * FROM cursors WHERE workspace_id=?", (key,))[
            0
        ]
        since = max(
            0,
            (cursor["poll_until"] or min(s["since"] for s in subs))
            - self.config.service["poll_overlap_seconds"],
        )
        gap = max(0, now - (cursor["poll_until"] or now))
        recovery = gap > self.config.service["poll_overlap_seconds"]
        self.state.cursor(key, history_gap_seconds=gap, recovery_mode=int(recovery))
        projects = {s["project_id"] for s in subs}
        if "" in projects:
            projects = {""}
        ids = set()
        for project in sorted(projects):
            for row in api.issues(
                project, None if full else since, None if full else now
            ):
                ids.add(row["id"])
        pending = self.state.rows(
            "SELECT id,issue_id,task_id,event_type FROM hints WHERE workspace_id=? AND status='pending'",
            (key,),
        )
        ids.update(h["issue_id"] for h in pending)
        acknowledged = set()
        for issue_id in sorted(ids):
            require(
                not getattr(self, "stop", None) or not self.stop.is_set(),
                "notify_stopping",
            )
            try:
                issue, comments, runs, link = api.snapshot(issue_id)
            except BridgeError as exc:
                if exc.code not in {"result_not_found", "api_forbidden"}:
                    raise
                # A permanently unreadable hinted object must not poison a workspace.
                with self.state.transaction() as db:
                    db.executemany(
                        "UPDATE hints SET status='rejected',processed_at=? WHERE id=?",
                        [
                            (time.time(), h["id"])
                            for h in pending
                            if h["issue_id"] == issue_id
                        ],
                    )
                log("notify_issue_unreadable", workspace=key, code=exc.code)
                continue
            count = reconcile(
                self.state,
                self.config,
                key,
                issue,
                comments,
                runs,
                link,
                recovery=recovery,
            )
            confirmed = {
                run.get("id") or run.get("task_id")
                for run in runs
                if run.get("issue_id") == issue_id
                and run.get("status") == "failed"
                and any(
                    epoch(run.get(field)) is not None
                    for field in ("completed_at", "updated_at", "created_at")
                )
            }
            for hint in pending:
                if hint["issue_id"] == issue_id and (
                    hint["event_type"] != "task:failed" or hint["task_id"] in confirmed
                ):
                    acknowledged.add(hint["id"])
            if count:
                log(
                    "notifications_created",
                    workspace=key,
                    count=count,
                    issue=issue["identifier"],
                )
        # Only hints included in this pass are acknowledged; concurrent new hints survive.
        with self.state.transaction() as db:
            db.executemany(
                "UPDATE hints SET status='processed',processed_at=? WHERE id=?",
                [(time.time(), hint_id) for hint_id in acknowledged],
            )
        values = {
            "poll_until": now,
            "last_error": "",
            "recovery_mode": 0,
            "source_history_limited": int(api.limited),
        }
        if full:
            values["last_full"] = now
        self.state.cursor(key, **values)
        log(
            "events_ingested",
            workspace=key,
            count=len(ids),
            cursor_lag_seconds=max(0, time.time() - now),
        )

    async def collect(self, key: str) -> None:
        backoff = 1
        api = None
        await self.pause(full_delay(self.config, initial=True))
        next_full = time.time()
        while not self.stop.is_set():
            try:
                async with self.locks[key]:
                    if api is None:
                        api = await blocking(self.api_factory, self.config, key)
                        await blocking(api.check_cli)
                        self.state.cursor(key, source_history_limited=int(api.limited))
                    row = self.state.rows(
                        "SELECT * FROM cursors WHERE workspace_id=?", (key,)
                    )[0]
                    full = (
                        time.time() >= next_full
                        or row["last_full"] is None
                        or (
                            row["poll_until"] is not None
                            and time.time() - row["poll_until"]
                            > self.config.service["poll_overlap_seconds"]
                        )
                    )
                    if full:
                        async with self.full_slots:
                            await blocking(self.scan, key, api, True)
                        next_full = time.time() + full_delay(self.config)
                    else:
                        await blocking(self.scan, key, api, False)
                backoff = 1
                try:
                    await asyncio.wait_for(
                        self.wakes[key].wait(), self.config.service["poll_seconds"]
                    )
                    self.wakes[key].clear()
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except (
                NotifyError,
                BridgeError,
                OSError,
                sqlite3.Error,
                ValueError,
            ) as exc:
                code = (
                    exc.code
                    if isinstance(exc, (NotifyError, BridgeError))
                    else "notify_workspace_unavailable"
                )
                self.state.cursor(key, last_error=code)
                log("notify_workspace_unavailable", workspace=key)
                api = None
                await self.pause(backoff)
                backoff = min(60, backoff * 2)

    async def websocket(self, key: str) -> None:
        backoff = 1
        while not self.stop.is_set():
            try:
                from websockets.asyncio.client import connect

                workspace = self.config.workspaces[key]
                parsed = urlsplit(workspace["origin"])
                url = urlunsplit(
                    (
                        "wss",
                        parsed.netloc,
                        "/ws",
                        urlencode({"workspace_id": workspace["workspace_id"]}),
                        "",
                    )
                )
                token = credential(workspace["pat_credential"])
                async with connect(
                    url,
                    open_timeout=10,
                    close_timeout=2,
                    ping_interval=20,
                    max_size=65536,
                ) as conn:
                    await conn.send(
                        json.dumps({"type": "auth", "payload": {"token": token}})
                    )
                    ack = strict_json_loads(await asyncio.wait_for(conn.recv(), 10))
                    require(
                        isinstance(ack, dict) and ack.get("type") == "auth_ack",
                        "notify_workspace_unavailable",
                    )
                    self.state.cursor(key, ws_connected=1)
                    backoff = 1
                    async for raw in conn:
                        try:
                            frame = strict_json_loads(raw)
                            if (
                                isinstance(frame, dict)
                                and frame.get("type") in EVENT_TYPES
                            ):
                                self.state.hint(key, frame)
                                self.wakes[key].set()
                        except (ValueError, UnicodeError):
                            log("notify_event_invalid", workspace=key)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - transport and protocol failures reconnect without logging secret-bearing exceptions
                self.state.cursor(key, ws_connected=0)
                log("notify_ws_disconnected", workspace=key)
            self.state.cursor(key, ws_connected=0)
            await self.pause(backoff)
            backoff = min(60, backoff * 2)

    async def deliver(self, row: dict) -> None:
        try:
            async with self.delivery_slots, self.dispatch_lock:
                payload = json.loads(row["payload_json"])
                account = self.config.accounts.get(payload["account"])
                if not account or account["platform"] != payload["platform"]:
                    return
                token = credential(account["token_credential"])
                slot = self.state.reserve(payload, time.time())
                await self.pause(max(0, slot - time.time()))
                if self.stop.is_set():
                    return
                current = self.config
                account = current.accounts.get(payload["account"])
                if not account or account["platform"] != payload["platform"]:
                    return
                token = credential(account["token_credential"])
                claim = self.state.claim(
                    row["id"],
                    time.time(),
                    current.service["max_attempts"],
                    current.service["sending_timeout_seconds"],
                )
                if not claim:
                    return
                # Claim rereads the durable payload, including persisted anchor fallback.
                payload = json.loads(claim["payload_json"])
                try:
                    result = await blocking(self.sender.send, payload, token)
                finally:
                    # Base the next slot on completion, never on an overdue reservation.
                    await blocking(self.state.reserve, payload, time.time())
                if self.state.finish(
                    claim,
                    result.outcome,
                    result.code,
                    current.service["max_attempts"],
                    result.retry_after,
                ):
                    status = self.state.rows(
                        "SELECT status,last_error FROM notifications WHERE id=?",
                        (claim["id"],),
                    )[0]
                    event = {
                        "delivered": "delivered",
                        "retry": "retried",
                        "dead": "dead",
                        "cancelled": "cancelled",
                    }.get(status["status"], "delivery_result")
                    log(
                        event,
                        notification=claim["id"],
                        event_key=claim["event_key"],
                        code=status["last_error"],
                    )
        except (NotifyError, OSError, sqlite3.Error, ValueError) as exc:
            if isinstance(exc, NotifyError):
                await blocking(self.state.defer_unclaimed, row["id"], exc.code)
            log("notify_delivery_unavailable")
        finally:
            self.scheduled.discard(row["id"])

    async def pause(self, delay: float) -> None:
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=max(0.001, delay))
        except TimeoutError:
            pass

    def start_collectors(self) -> None:
        for key, row in self.config.workspaces.items():
            if key in self.config.workspace_errors:
                self.state.cursor(key, last_error="notify_config_invalid")
            if row.get("enabled", True):
                self.locks.setdefault(key, asyncio.Lock())
                self.wakes[key] = asyncio.Event()
                self.collectors += [
                    asyncio.create_task(self.collect(key)),
                    asyncio.create_task(self.websocket(key)),
                ]

    async def reload(self) -> None:
        try:
            candidate = load_config(self.path)
            require(not candidate.workspace_errors, "notify_config_reload_failed")
            require(
                candidate.service["db_path"] == self.config.service["db_path"]
                and candidate.service["runtime_dir"]
                == self.config.service["runtime_dir"]
                and candidate.service["delivery_workers"]
                == self.config.service["delivery_workers"]
                and candidate.service["request_timeout_seconds"]
                == self.config.service["request_timeout_seconds"],
                "notify_config_reload_failed",
            )
            async with AsyncExitStack() as stack:
                for key in sorted(self.locks):
                    await stack.enter_async_context(self.locks[key])
                self.state.project(candidate)
                for task in self.collectors:
                    task.cancel()
                await asyncio.gather(*self.collectors, return_exceptions=True)
                self.collectors = []
                with self.state.transaction() as db:
                    db.execute("UPDATE cursors SET ws_connected=0")
                self.config = candidate
                self.full_slots = asyncio.Semaphore(
                    candidate.service["full_reconcile_parallelism"]
                )
                self.start_collectors()
            log("notify_config_reloaded")
        except (NotifyError, OSError, sqlite3.Error, ValueError):
            log("notify_config_reload_failed")

    async def run(self) -> None:
        runtime = Path(self.config.service["runtime_dir"])
        private_dir(runtime)
        fd = os.open(
            runtime / "service.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        owns_lock = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                owns_lock = True
            except BlockingIOError:
                raise NotifyError("notify_already_running") from None
            self.state = State(Path(self.config.service["db_path"]), create=True)
            self.state.project(self.config)
            with self.state.transaction() as db:
                db.execute("UPDATE cursors SET ws_connected=0")
            start = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
            atomic_private(
                runtime / "pid.json",
                json.dumps(
                    {"pid": os.getpid(), "start": start, "config": str(self.path)}
                ).encode(),
            )
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGHUP, self.reload_requested.set)
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self.stop.set)
            self.start_collectors()
            last_prune = 0
            last_heartbeat = 0
            while not self.stop.is_set():
                if time.time() - last_heartbeat >= 1:
                    with self.state.transaction() as db:
                        db.execute(
                            "INSERT OR REPLACE INTO metadata VALUES('heartbeat',?)",
                            (str(time.time()),),
                        )
                    last_heartbeat = time.time()
                if self.reload_requested.is_set():
                    self.reload_requested.clear()
                    await self.reload()
                for row in self.state.due(time.time()):
                    if row["id"] not in self.scheduled:
                        self.scheduled.add(row["id"])
                        task = asyncio.create_task(self.deliver(row))
                        self.deliveries.add(task)
                        task.add_done_callback(self.deliveries.discard)
                if time.time() - last_prune > 60:
                    self.state.prune(self.config)
                    last_prune = time.time()
                await self.pause(0.2)
        finally:
            self.stop.set()
            for task in self.collectors:
                task.cancel()
            await asyncio.gather(
                *self.collectors, *self.deliveries, return_exceptions=True
            )
            if owns_lock:
                if hasattr(self, "state"):
                    with self.state.transaction() as db:
                        db.execute("UPDATE cursors SET ws_connected=0")
                        db.execute("DELETE FROM metadata WHERE key='heartbeat'")
                (runtime / "pid.json").unlink(missing_ok=True)
                if hasattr(self, "state"):
                    self.state.db.close()
            os.close(fd)
