"""Transactional registries, durable receipts and fenced notification outbox."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import Config, NotifyError, identifier, private_dir, require

EVENTS = {"question", "blocked", "final", "failed", "cancelled"}
MAX_PENDING_HINTS_PER_WORKSPACE = 10_000
SCHEMA = {
    "accounts": "name TEXT PRIMARY KEY, platform TEXT NOT NULL, data_json TEXT NOT NULL, configured INTEGER NOT NULL",
    "workspaces": "id TEXT PRIMARY KEY, origin TEXT NOT NULL, workspace_id TEXT NOT NULL, data_json TEXT NOT NULL, configured INTEGER NOT NULL, enabled INTEGER NOT NULL",
    "subscriptions": """id TEXT PRIMARY KEY, platform TEXT NOT NULL, account TEXT NOT NULL REFERENCES accounts(name),
        chat_id TEXT NOT NULL, thread_id TEXT NOT NULL DEFAULT '', chat_type TEXT NOT NULL, anchor_message_id TEXT,
        workspace_id TEXT NOT NULL REFERENCES workspaces(id), project_id TEXT NOT NULL DEFAULT '', squad_id TEXT NOT NULL DEFAULT '',
        labels_json TEXT NOT NULL, events_json TEXT NOT NULL, mode TEXT NOT NULL, label TEXT NOT NULL, locale TEXT NOT NULL,
        shadow INTEGER NOT NULL, enabled INTEGER NOT NULL, since REAL NOT NULL, created_at REAL NOT NULL,
        disabled_reason TEXT NOT NULL DEFAULT '',
        UNIQUE(platform,account,chat_id,thread_id,workspace_id,project_id,squad_id)""",
    "issues": """workspace_id TEXT NOT NULL, issue_id TEXT NOT NULL, data_json TEXT NOT NULL,
        status TEXT NOT NULL, revision INTEGER, status_entered_at TEXT, cycle_started_at REAL,
        transition_seq INTEGER NOT NULL, last_observed_at REAL NOT NULL,
        PRIMARY KEY(workspace_id,issue_id)""",
    "events": """id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, event_key TEXT NOT NULL,
        event_type TEXT NOT NULL, issue_id TEXT NOT NULL, payload_json TEXT, created_at REAL NOT NULL,
        UNIQUE(workspace_id,event_key)""",
    "notifications": """id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL REFERENCES subscriptions(id), event_key TEXT NOT NULL,
        payload_json TEXT, status TEXT NOT NULL CHECK(status IN ('pending','sending','delivered','retry','dead','cancelled')),
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL, lease_until REAL, lease_token TEXT,
        last_error TEXT NOT NULL DEFAULT '', anchor_fallback INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL, updated_at REAL NOT NULL, UNIQUE(subscription_id,event_key)""",
    "processed_keys": "subscription_id TEXT NOT NULL REFERENCES subscriptions(id), event_key TEXT NOT NULL, PRIMARY KEY(subscription_id,event_key)",
    "hints": """id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, issue_id TEXT NOT NULL, task_id TEXT,
        event_type TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL, processed_at REAL""",
    "cursors": """workspace_id TEXT PRIMARY KEY, poll_until REAL, last_full REAL, ws_connected INTEGER NOT NULL DEFAULT 0,
        history_gap_seconds REAL NOT NULL DEFAULT 0, recovery_mode INTEGER NOT NULL DEFAULT 0,
        source_history_limited INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL""",
    "rate_slots": "key TEXT PRIMARY KEY, next_at REAL NOT NULL",
    "metadata": "key TEXT PRIMARY KEY, value TEXT NOT NULL",
}


def encoded(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def subscription(raw: dict[str, Any], config: Config, now: float) -> dict[str, Any]:
    code = "notify_subscription_invalid"
    allowed = {
        "platform",
        "account",
        "chat_id",
        "chat_type",
        "workspace_id",
        "thread_id",
        "anchor_message_id",
        "project_id",
        "squad_id",
        "labels",
        "events",
        "mode",
        "label",
        "locale",
        "shadow",
        "enabled",
        "since",
    }
    require(
        not set(raw) - allowed
        and {"platform", "account", "chat_id", "chat_type", "workspace_id"} <= set(raw),
        code,
    )
    row = {
        "thread_id": "",
        "project_id": "",
        "squad_id": "",
        "anchor_message_id": None,
        "mode": "quiet",
        "label": "",
        "locale": "ru",
        "shadow": False,
        "enabled": True,
        "labels": [],
        "events": ["question", "blocked", "final", "failed"],
        "since": now,
    } | raw
    require(row["workspace_id"] not in config.workspace_errors, code)
    require(
        row["account"] in config.accounts and row["workspace_id"] in config.workspaces,
        code,
    )
    require(row["platform"] == config.accounts[row["account"]]["platform"], code)
    require(
        row["chat_type"] in {"dm", "group", "thread"}
        and row["mode"] in {"quiet", "verbose"}
        and row["locale"] in {"ru", "en"},
        code,
    )
    require(type(row["enabled"]) is bool and type(row["shadow"]) is bool, code)
    require(
        isinstance(row["chat_id"], str)
        and re.fullmatch(r"-?[0-9]{1,23}", row["chat_id"]) is not None
        and int(row["chat_id"]) != 0,
        code,
    )
    require(isinstance(row["thread_id"], str), code)
    if row["chat_type"] == "thread":
        require(
            row["platform"] == "telegram"
            and re.fullmatch(r"[0-9]{1,24}", row["thread_id"]) is not None
            and int(row["thread_id"]) > 0,
            code,
        )
    else:
        require(row["thread_id"] == "", code)
    if row["chat_type"] == "dm":
        require(row["chat_id"].isdigit() and int(row["chat_id"]) > 0, code)
    if row["anchor_message_id"] is not None:
        require(
            isinstance(row["anchor_message_id"], str)
            and 0 < len(row["anchor_message_id"]) <= 256,
            code,
        )
        if row["platform"] == "telegram":
            require(
                re.fullmatch(r"[0-9]{1,256}", row["anchor_message_id"]) is not None
                and int(row["anchor_message_id"]) > 0,
                code,
            )
    for key in ("project_id", "squad_id"):
        if row[key]:
            identifier(row[key])
    for key, maximum in (("labels", 64), ("events", 5)):
        require(
            isinstance(row[key], list)
            and len(row[key]) <= maximum
            and all(isinstance(v, str) and 0 < len(v) <= 128 for v in row[key])
            and len(set(row[key])) == len(row[key]),
            code,
        )
    require(bool(row["events"]) and set(row["events"]) <= EVENTS, code)
    require(isinstance(row["label"], str) and len(row["label"]) <= 128, code)
    if isinstance(row["since"], str):
        row["since"] = epoch(row["since"])
    require(type(row["since"]) in {float, int} and 0 <= row["since"] <= now, code)
    return row


class State:
    def __init__(self, path: Path, *, create: bool = False):
        self.path, self.lock = path, threading.RLock()
        if create:
            private_dir(path.parent)
        require(path.exists() or create, "notify_state_unavailable")
        if path.exists():
            import stat

            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(
                    stat.S_ISREG(info.st_mode)
                    and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600,
                    "notify_permissions_invalid",
                )
            finally:
                os.close(fd)
        else:
            fd = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600
            )
            os.close(fd)
        self.db = sqlite3.connect(
            str(path), timeout=5, isolation_level=None, check_same_thread=False
        )
        self.db.row_factory = sqlite3.Row
        try:
            tables = {
                r[0]
                for r in self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            require(
                (not tables and version == 0 and create)
                or (tables == set(SCHEMA) and version == 1),
                "notify_migration_failed",
            )
            if tables:
                reference = sqlite3.connect(":memory:")
                try:
                    for table, columns in SCHEMA.items():
                        reference.execute(f"CREATE TABLE {table} ({columns})")
                        actual = [
                            tuple(r)
                            for r in self.db.execute(f"PRAGMA table_info({table})")
                        ]
                        expected = list(
                            reference.execute(f"PRAGMA table_info({table})")
                        )
                        require(actual == expected, "notify_migration_failed")
                        current_sql = self.db.execute(
                            "SELECT sql FROM sqlite_master WHERE name=?", (table,)
                        ).fetchone()[0]
                        expected_sql = reference.execute(
                            "SELECT sql FROM sqlite_master WHERE name=?", (table,)
                        ).fetchone()[0]
                        require(
                            " ".join(current_sql.split())
                            == " ".join(expected_sql.split()),
                            "notify_migration_failed",
                        )
                finally:
                    reference.close()
            require(
                self.db.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                "notify_migration_failed",
            )
            self.db.execute("PRAGMA foreign_keys=ON")
            if not tables:
                with self.transaction():
                    for table, columns in SCHEMA.items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    self.db.execute(
                        "CREATE INDEX due ON notifications(status,next_attempt_at)"
                    )
                    self.db.execute(
                        "CREATE INDEX subscription_workspace ON subscriptions(workspace_id,enabled)"
                    )
                    self.db.execute(
                        "CREATE INDEX pending_hint_workspace ON hints(workspace_id,status)"
                    )
                    self.db.execute("PRAGMA user_version=1")
            self.db.execute("PRAGMA journal_mode=WAL")
            os.chmod(path, 0o600)
        except (sqlite3.Error, NotifyError):
            self.db.close()
            raise NotifyError("notify_migration_failed") from None

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def rows(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args)]

    def project(self, config: Config) -> None:
        with self.transaction() as db:
            for key, row in config.workspaces.items():
                prior = db.execute(
                    "SELECT * FROM workspaces WHERE id=?", (key,)
                ).fetchone()
                if (
                    prior
                    and key not in config.workspace_errors
                    and db.execute(
                        "SELECT 1 FROM subscriptions WHERE workspace_id=? LIMIT 1",
                        (key,),
                    ).fetchone()
                ):
                    require(
                        (prior["origin"], prior["workspace_id"])
                        == (row["origin"].rstrip("/"), row["workspace_id"]),
                        "notify_config_reload_failed",
                    )
            for key, row in config.accounts.items():
                prior = db.execute(
                    "SELECT * FROM accounts WHERE name=?", (key,)
                ).fetchone()
                require(
                    not prior
                    or not db.execute(
                        "SELECT 1 FROM subscriptions WHERE account=? LIMIT 1", (key,)
                    ).fetchone()
                    or prior["platform"] == row["platform"],
                    "notify_config_reload_failed",
                )
            db.execute("UPDATE workspaces SET configured=0")
            db.execute("UPDATE accounts SET configured=0")
            for key, row in config.workspaces.items():
                if key in config.workspace_errors:
                    prior = db.execute(
                        "SELECT * FROM workspaces WHERE id=?", (key,)
                    ).fetchone()
                    if prior:
                        row = dict(
                            row,
                            origin=prior["origin"],
                            workspace_id=prior["workspace_id"],
                        )
                db.execute(
                    "INSERT INTO workspaces VALUES(?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,workspace_id=excluded.workspace_id,data_json=excluded.data_json,configured=1,enabled=excluded.enabled",
                    (
                        key,
                        row["origin"].rstrip("/"),
                        row["workspace_id"],
                        encoded(row),
                        int(row.get("enabled", True)),
                    ),
                )
                db.execute(
                    "INSERT OR IGNORE INTO cursors(workspace_id,updated_at) VALUES(?,?)",
                    (key, time.time()),
                )
            for key, row in config.accounts.items():
                db.execute(
                    "INSERT INTO accounts VALUES(?,?,?,1) ON CONFLICT(name) DO UPDATE SET platform=excluded.platform,data_json=excluded.data_json,configured=1",
                    (key, row["platform"], encoded(row)),
                )
            orphans = db.execute("""SELECT s.id FROM subscriptions s JOIN accounts a ON a.name=s.account
                JOIN workspaces w ON w.id=s.workspace_id WHERE a.configured=0 OR w.configured=0""").fetchall()
            for item in orphans:
                self._disable(db, item["id"], "orphaned_subscription")
            db.execute(
                "INSERT OR REPLACE INTO metadata VALUES(?,?)",
                (
                    "projection_hash",
                    hashlib.sha256(
                        encoded(
                            {
                                "accounts": config.accounts,
                                "workspaces": config.workspaces,
                            }
                        ).encode()
                    ).hexdigest(),
                ),
            )

    def add_subscriptions(
        self, rows: list[dict], *, skip_existing: bool = False
    ) -> list[str]:
        ids = []
        try:
            with self.transaction() as db:
                for row in rows:
                    sid = str(uuid.uuid4())
                    values = [sid] + [
                        row[k]
                        for k in (
                            "platform",
                            "account",
                            "chat_id",
                            "thread_id",
                            "chat_type",
                            "anchor_message_id",
                            "workspace_id",
                            "project_id",
                            "squad_id",
                        )
                    ]
                    values += [
                        encoded(row["labels"]),
                        encoded(row["events"]),
                        row["mode"],
                        row["label"],
                        row["locale"],
                        int(row["shadow"]),
                        int(row["enabled"]),
                        row["since"],
                        time.time(),
                        "",
                    ]
                    if skip_existing:
                        existing = db.execute(
                            "SELECT id FROM subscriptions WHERE platform=? AND account=? AND chat_id=? AND thread_id=? AND workspace_id=? AND project_id=? AND squad_id=?",
                            tuple(
                                row[k]
                                for k in (
                                    "platform",
                                    "account",
                                    "chat_id",
                                    "thread_id",
                                    "workspace_id",
                                    "project_id",
                                    "squad_id",
                                )
                            ),
                        ).fetchone()
                        if existing:
                            continue
                    db.execute(
                        "INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        values,
                    )
                    db.execute(
                        "UPDATE cursors SET last_full=NULL WHERE workspace_id=?",
                        (row["workspace_id"],),
                    )
                    ids.append(sid)
        except sqlite3.IntegrityError:
            raise NotifyError("notify_subscription_duplicate") from None
        return ids

    def add_subscription(self, row: dict) -> str:
        return self.add_subscriptions([row])[0]

    @staticmethod
    def _disable(db, sid: str, reason: str) -> None:
        db.execute(
            "UPDATE subscriptions SET enabled=0,disabled_reason=? WHERE id=?",
            (reason, sid),
        )
        db.execute(
            "UPDATE notifications SET status='cancelled',last_error=?,updated_at=? WHERE subscription_id=? AND status IN ('pending','retry')",
            (reason, time.time(), sid),
        )

        # Preserve the intervening disable even when the subscription is re-enabled
        # before an inflight attempt finishes. Success may commit; failure cannot retry.
        db.execute(
            "UPDATE notifications SET last_error='subscription_disabled',updated_at=? WHERE subscription_id=? AND status='sending'",
            (time.time(), sid),
        )

    def toggle(self, sid: str, enabled: bool) -> None:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM subscriptions WHERE id=?", (sid,)
            ).fetchone()
            require(row is not None, "notify_subscription_invalid")
            if not enabled:
                self._disable(db, sid, "subscription_disabled")
            elif not row["enabled"]:
                require(
                    db.execute(
                        "SELECT configured FROM accounts WHERE name=?",
                        (row["account"],),
                    ).fetchone()[0]
                    == 1
                    and db.execute(
                        "SELECT configured FROM workspaces WHERE id=?",
                        (row["workspace_id"],),
                    ).fetchone()[0]
                    == 1,
                    "orphaned_subscription",
                )
                db.execute(
                    "UPDATE subscriptions SET enabled=1,since=?,disabled_reason='' WHERE id=?",
                    (time.time(), sid),
                )
                db.execute(
                    "UPDATE cursors SET last_full=NULL WHERE workspace_id=?",
                    (row["workspace_id"],),
                )

    def due(self, now: float) -> list[dict]:
        with self.transaction() as db:
            db.execute(
                "UPDATE notifications SET status='cancelled',last_error='subscription_disabled',updated_at=? WHERE status='sending' AND lease_until<=? AND (last_error='subscription_disabled' OR subscription_id IN (SELECT id FROM subscriptions WHERE enabled=0))",
                (now, now),
            )
        return self.rows(
            """SELECT n.* FROM notifications n JOIN subscriptions s ON s.id=n.subscription_id
            JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
            WHERE s.enabled=1 AND a.configured=1 AND w.configured=1 AND w.enabled=1 AND
            ((n.status IN ('pending','retry') AND COALESCE(n.next_attempt_at,0)<=?) OR (n.status='sending' AND n.lease_until<=?))
            ORDER BY n.created_at LIMIT 100""",
            (now, now),
        )

    def defer_unclaimed(self, nid: str, code: str) -> None:
        with self.transaction() as db:
            db.execute(
                "UPDATE notifications SET next_attempt_at=?,last_error=? WHERE id=? AND status IN ('pending','retry')",
                (time.time() + 30, code, nid),
            )

    def reserve(self, payload: dict, now: float, *, completed: bool = False) -> float:
        # deliver reserves before claim and after send. The completion floor uses
        # the actual POST completion time so an overdue slot cannot undercut it.
        group = payload.get("platform") == "telegram" and payload.get("chat_type") in {
            "group",
            "thread",
        }
        chat_step = 1.5 if group else 0.5
        chat_floor = 3.0 if group else 1.0
        keys = [
            (f"chat:{payload['platform']}:{payload['chat_id']}", chat_step, chat_floor),
            (f"account:{payload['platform']}:{payload['account']}", 0.05, 0.05),
        ]
        with self.transaction() as db:
            at = now
            for key, _, _ in keys:
                row = db.execute(
                    "SELECT next_at FROM rate_slots WHERE key=?", (key,)
                ).fetchone()
                at = max(at, row[0] if row else now)
            for key, step, floor in keys:
                next_at = at + step
                if completed:
                    next_at = max(next_at, now + floor)
                db.execute(
                    "INSERT OR REPLACE INTO rate_slots VALUES(?,?)", (key, next_at)
                )
            return at

    def claim(self, nid: str, now: float, attempts: int, lease: int) -> dict | None:
        with self.transaction() as db:
            row = db.execute(
                """SELECT n.*,s.enabled FROM notifications n JOIN subscriptions s ON s.id=n.subscription_id
                JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
                WHERE n.id=? AND a.configured=1 AND w.configured=1 AND w.enabled=1""",
                (nid,),
            ).fetchone()
            if not row or not row["enabled"]:
                return None
            if (
                row["status"] == "sending"
                and row["last_error"] == "subscription_disabled"
            ):
                if (row["lease_until"] or 0) <= now:
                    db.execute(
                        "UPDATE notifications SET status='cancelled',updated_at=? WHERE id=?",
                        (now, nid),
                    )
                return None
            eligible = (
                row["status"] in ("pending", "retry")
                and (row["next_attempt_at"] or 0) <= now
            )
            eligible |= row["status"] == "sending" and (row["lease_until"] or 0) <= now
            if not eligible:
                return None
            if row["attempts"] >= attempts:
                db.execute(
                    "UPDATE notifications SET status='dead',last_error=?,updated_at=? WHERE id=?",
                    (f"retry_exhausted:{row['attempts']}", now, nid),
                )
                logging.getLogger("hermes_multica_notify").warning(
                    encoded(
                        {
                            "event": "retry_exhausted",
                            "notification": nid,
                            "attempts": row["attempts"],
                        }
                    )
                )
                return None
            destination = db.execute(
                "SELECT * FROM subscriptions WHERE id=?", (row["subscription_id"],)
            ).fetchone()
            body = json.loads(row["payload_json"])
            fields = ("platform", "account", "chat_id", "thread_id", "chat_type")
            if any(body.get(key) != destination[key] for key in fields):
                db.execute(
                    "UPDATE notifications SET status='dead',last_error='notify_destination_changed',updated_at=? WHERE id=?",
                    (now, nid),
                )
                return None
            token = str(uuid.uuid4())
            db.execute(
                "UPDATE notifications SET status='sending',attempts=attempts+1,lease_token=?,lease_until=?,updated_at=? WHERE id=?",
                (token, now + lease, now, nid),
            )
            return dict(
                db.execute("SELECT * FROM notifications WHERE id=?", (nid,)).fetchone()
            )

    def finish(
        self,
        claim: dict,
        outcome: str,
        detail: str,
        maximum: int,
        retry_after: float = 0,
    ) -> bool:
        now = time.time()
        with self.transaction() as db:
            row = db.execute(
                """SELECT n.*,s.enabled FROM notifications n JOIN subscriptions s ON s.id=n.subscription_id
                WHERE n.id=? AND n.status='sending' AND n.lease_token=? AND n.attempts=?""",
                (claim["id"], claim["lease_token"], claim["attempts"]),
            ).fetchone()
            if not row:
                return False
            payload = row["payload_json"]
            fallback = row["anchor_fallback"]
            next_at = None
            if outcome == "delivered":
                status, payload = "delivered", None
            elif not row["enabled"] or row["last_error"] == "subscription_disabled":
                status, detail = "cancelled", "subscription_disabled"
            elif outcome == "anchor" and not fallback and row["attempts"] < maximum:
                status, fallback = "retry", 1
                body = json.loads(payload)
                body["anchor_message_id"] = None
                payload = encoded(body)
                next_at = now
            elif outcome in {"terminal", "anchor"}:
                status = "dead"
            elif row["attempts"] >= maximum:
                status, detail = "dead", f"retry_exhausted:{row['attempts']}"
                logging.getLogger("hermes_multica_notify").warning(
                    encoded(
                        {
                            "event": "retry_exhausted",
                            "notification": row["id"],
                            "attempts": row["attempts"],
                        }
                    )
                )
            else:
                status = "retry"
                delay = (30, 60, 120, 300, 600)[min(row["attempts"] - 1, 4)]
                next_at = now + min(600, max(delay, retry_after))
            db.execute(
                """UPDATE notifications SET status=?,payload_json=?,last_error=?,anchor_fallback=?,next_attempt_at=?,
                lease_until=NULL,lease_token=NULL,updated_at=? WHERE id=?""",
                (status, payload, detail, fallback, next_at, now, row["id"]),
            )
            metric = "metric:" + status
            db.execute(
                "INSERT INTO metadata(key,value) VALUES(?,'1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1",
                (metric,),
            )
            return True

    def replay(self, nid: str, days: int) -> bool:
        with self.transaction() as db:
            row = db.execute(
                "SELECT n.*,s.enabled FROM notifications n JOIN subscriptions s ON s.id=n.subscription_id WHERE n.id=?",
                (nid,),
            ).fetchone()
            require(row is not None, "notify_replay_invalid")
            if row["status"] in ("pending", "sending", "retry"):
                return False
            require(
                row["enabled"]
                and row["status"] in ("dead", "cancelled")
                and row["payload_json"]
                and row["updated_at"] >= time.time() - days * 86400,
                "notify_replay_invalid",
            )
            db.execute(
                "UPDATE notifications SET status='pending',attempts=0,next_attempt_at=NULL,lease_token=NULL,lease_until=NULL,last_error='',updated_at=? WHERE id=?",
                (time.time(), nid),
            )
            return True

    def hint(self, workspace: str, event: dict) -> bool:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            return False
        obj = (
            payload.get("comment")
            or payload.get("task")
            or payload.get("issue")
            or payload
        )
        if not isinstance(obj, dict):
            return False
        event_type = event.get("type", "")
        if not isinstance(event_type, str) or not event_type:
            return False
        issue_id = (
            obj.get("issue_id")
            if event_type.startswith(("comment:", "task:"))
            else obj.get("id")
        )
        if not isinstance(issue_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", issue_id
        ):
            key = hashlib.sha256(encoded(event).encode()).hexdigest()
            with self.transaction() as db:
                db.execute(
                    "INSERT OR IGNORE INTO hints VALUES(?,?,?,?,?,?,?,?)",
                    (
                        key,
                        workspace,
                        "",
                        None,
                        "invalid",
                        "rejected",
                        time.time(),
                        time.time(),
                    ),
                )
            return False
        task_id = obj.get("id") if event_type.startswith("task:") else None
        identity = encoded(
            [
                workspace,
                event_type,
                issue_id,
                obj.get("id"),
                obj.get("revision"),
                obj.get("updated_at"),
            ]
        )
        with self.transaction() as db:
            if event_type == "task:failed":
                duplicate = db.execute(
                    "SELECT 1 FROM hints WHERE workspace_id=? AND issue_id=? AND event_type=? AND task_id IS ? AND status='pending' LIMIT 1",
                    (workspace, issue_id, event_type, task_id),
                ).fetchone()
            else:
                duplicate = db.execute(
                    "SELECT 1 FROM hints WHERE workspace_id=? AND issue_id=? AND event_type=? AND status='pending' LIMIT 1",
                    (workspace, issue_id, event_type),
                ).fetchone()
            if duplicate:
                return True
            pending_count = db.execute(
                "SELECT COUNT(*) FROM hints WHERE workspace_id=? AND status='pending'",
                (workspace,),
            ).fetchone()[0]
            if pending_count >= MAX_PENDING_HINTS_PER_WORKSPACE:
                now = time.time()
                db.execute(
                    "UPDATE cursors SET last_error='notify_hint_backlog_full',source_history_limited=1,updated_at=? WHERE workspace_id=?",
                    (now, workspace),
                )
                db.execute(
                    "INSERT INTO metadata(key,value) VALUES('metric:pending_hints_rejected','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1"
                )
                return False
            db.execute(
                "INSERT OR IGNORE INTO hints VALUES(?,?,?,?,?,?,?,NULL)",
                (
                    hashlib.sha256(identity.encode()).hexdigest(),
                    workspace,
                    issue_id,
                    task_id,
                    event_type,
                    "pending",
                    time.time(),
                ),
            )
        return True

    def cursor(self, workspace: str, **values) -> None:
        statements = {
            "poll_until": "UPDATE cursors SET poll_until=?,updated_at=? WHERE workspace_id=?",
            "last_full": "UPDATE cursors SET last_full=?,updated_at=? WHERE workspace_id=?",
            "ws_connected": "UPDATE cursors SET ws_connected=?,updated_at=? WHERE workspace_id=?",
            "history_gap_seconds": "UPDATE cursors SET history_gap_seconds=?,updated_at=? WHERE workspace_id=?",
            "recovery_mode": "UPDATE cursors SET recovery_mode=?,updated_at=? WHERE workspace_id=?",
            "source_history_limited": "UPDATE cursors SET source_history_limited=?,updated_at=? WHERE workspace_id=?",
            "last_error": "UPDATE cursors SET last_error=?,updated_at=? WHERE workspace_id=?",
        }
        require(set(values) <= set(statements))
        with self.transaction() as db:
            for key, value in values.items():
                db.execute(statements[key], (value, time.time(), workspace))

    def prune(self, config: Config, now: float | None = None) -> None:
        now = now or time.time()
        with self.transaction() as db:
            db.execute(
                "DELETE FROM events WHERE created_at<?",
                (now - config.service["retention_events_days"] * 86400,),
            )
            db.execute(
                "UPDATE notifications SET payload_json=NULL WHERE status IN ('dead','cancelled') AND updated_at<?",
                (now - config.service["replay_retention_days"] * 86400,),
            )
            db.execute(
                "DELETE FROM notifications WHERE status IN ('delivered','dead','cancelled') AND payload_json IS NULL AND updated_at<?",
                (now - config.service["retention_notifications_days"] * 86400,),
            )
            db.execute(
                "DELETE FROM hints WHERE (status='processed' AND processed_at<?) OR (status='rejected' AND processed_at<?)",
                (now - 86400, now - 7 * 86400),
            )

    def status(self) -> dict:
        now = time.time()
        rows = self.rows("SELECT value FROM metadata WHERE key='heartbeat'")
        heartbeat = float(rows[0]["value"]) if rows else 0
        ready = heartbeat > 0 and 0 <= now - heartbeat < 30
        workspaces = self.rows(
            "SELECT c.*,w.enabled,w.configured FROM cursors c JOIN workspaces w ON w.id=c.workspace_id"
        )
        for row in workspaces:
            row["cursor_lag_seconds"] = (
                max(0, now - row["poll_until"]) if row["poll_until"] else None
            )
            row["degraded"] = bool(
                row["enabled"]
                and row["configured"]
                and (not ready or row["last_error"])
            )
            if not ready:
                row["ws_connected"] = 0
        return {
            "ready": ready,
            "heartbeat_age_seconds": max(0, now - heartbeat) if heartbeat else None,
            "workspaces": workspaces,
            "metrics": self.rows(
                "SELECT key,value FROM metadata WHERE key LIKE 'metric:%'"
            ),
            "notifications": self.rows(
                "SELECT status,COUNT(*) AS count FROM notifications GROUP BY status"
            ),
            "oldest_pending_age": max(
                0,
                time.time()
                - (
                    self.rows(
                        "SELECT MIN(created_at) AS oldest FROM notifications WHERE status IN ('pending','retry','sending')"
                    )[0]["oldest"]
                    or time.time()
                ),
            ),
            "hints": self.rows(
                "SELECT status,COUNT(*) AS count,MIN(created_at) AS oldest FROM hints GROUP BY status"
            ),
        }
