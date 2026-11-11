"""Private clean-start persistence for watcher mappings, snapshots, and delivery outcomes."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import BridgeError

_UNCHANGED = object()


class WatcherState:
    def __init__(self, path: str | Path):
        requested = Path(path)
        directory = requested.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory_info = directory.lstat()
        except OSError as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher state directory is unavailable.") from exc
        if (not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode)
                or directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o077):
            raise BridgeError("watcher_state_untrusted", "Watcher state directory has unsafe ownership or permissions.")
        self.path = directory / requested.name
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher database is unavailable.") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise BridgeError("watcher_state_untrusted", "Watcher database has unsafe permissions.")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _initialize(self) -> None:
        db = self._connect()
        try:
            table_columns = {
                "mappings": {"issue_id", "profile", "route_id", "platform", "user_id", "chat_id",
                             "thread_id", "message_id", "chat_type", "created_at", "registered_at_ns"},
                "issue_snapshots": {
                    "issue_id", "revision", "status", "title", "priority", "updated_at", "content_hash",
                },
                "seen_comments": {"issue_id", "comment_id"},
                "deliveries": {"delivery_key", "issue_id", "platform", "chat_id", "status", "detail", "updated_at"},
                "chat_rate_limit": {"profile", "platform", "chat_id", "next_send_ms"},
            }
            existing_tables = {
                row["name"] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            additions = {
                "deliveries": {"attempts": "INTEGER NOT NULL DEFAULT 0", "next_retry_at": "INTEGER",
                               "event_type": "TEXT", "payload_json": "TEXT"},
                "issue_snapshots": {"status_entered_at": "TEXT", "cycle_started_at": "TEXT"},
            }
            if existing_tables:
                if existing_tables != set(table_columns):
                    raise BridgeError("watcher_state_migration_failed", "Unsupported watcher tables.")
                old_shape = True
                new_shape = True
                for table, expected in table_columns.items():
                    actual = {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}
                    old_shape = old_shape and actual == expected
                    new_shape = new_shape and actual == expected | set(additions.get(table, {}))
                if not (old_shape or new_shape):
                    raise BridgeError("watcher_state_migration_failed", "Unsupported watcher columns.")
            db.execute("BEGIN IMMEDIATE")
            schema = """
                CREATE TABLE IF NOT EXISTS mappings (
                    issue_id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    thread_id TEXT,
                    message_id TEXT NOT NULL,
                    chat_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    registered_at_ns INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS mappings_profile_route ON mappings(profile, route_id);
                CREATE TABLE IF NOT EXISTS issue_snapshots (
                    issue_id TEXT PRIMARY KEY REFERENCES mappings(issue_id) ON DELETE CASCADE,
                    revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seen_comments (
                    issue_id TEXT NOT NULL REFERENCES mappings(issue_id) ON DELETE CASCADE,
                    comment_id TEXT NOT NULL,
                    PRIMARY KEY(issue_id, comment_id)
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_key TEXT PRIMARY KEY,
                    issue_id TEXT NOT NULL REFERENCES mappings(issue_id) ON DELETE CASCADE,
                    platform TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('sending','delivered','not_sent','delivery_unknown')),
                    detail TEXT,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chat_rate_limit (
                    profile TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    next_send_ms INTEGER NOT NULL,
                    PRIMARY KEY(profile, platform, chat_id)
                );
            """
            for statement in schema.split(";"):
                if statement.strip():
                    db.execute(statement)
            for table, fields in additions.items():
                columns = {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}
                for column, declaration in fields.items():
                    if column not in columns:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
            db.execute("UPDATE issue_snapshots SET status_entered_at=updated_at WHERE status_entered_at IS NULL")
            db.execute(
                "UPDATE deliveries SET status='delivery_unknown', detail='process_interrupted', updated_at=? "
                "WHERE status='sending' AND payload_json IS NULL", (int(time.time()),)
            )
            db.commit()
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("watcher_state_migration_failed", "Watcher state migration failed.") from exc
        finally:
            db.close()

    @staticmethod
    def _mapping_tuple(mapping: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(mapping.get(key) for key in (
            "profile", "route_id", "platform", "user_id", "chat_id", "thread_id", "message_id", "chat_type"
        ))

    def register_mapping(self, mapping: dict[str, Any]) -> bool:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM mappings WHERE issue_id=?", (mapping["issue_id"],)).fetchone()
            expected = self._mapping_tuple(mapping)
            if row is not None:
                actual = tuple(row[key] for key in (
                    "profile", "route_id", "platform", "user_id", "chat_id", "thread_id", "message_id", "chat_type"
                ))
                db.rollback()
                return actual == expected
            db.execute(
                "INSERT INTO mappings(issue_id,profile,route_id,platform,user_id,chat_id,thread_id,message_id,chat_type,created_at,registered_at_ns) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (mapping["issue_id"], *expected, int(time.time()), time.time_ns()),
            )
            db.commit()
            return True
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("watcher_state_unavailable", "Watcher mapping could not be recorded.") from exc
        finally:
            db.close()

    def mapping(self, issue_id: str) -> dict[str, Any] | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM mappings WHERE issue_id=?", (issue_id,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def mappings(self, profile: str, route_id: str) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT * FROM mappings WHERE profile=? AND route_id=? ORDER BY created_at,issue_id",
                (profile, route_id),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            db.close()

    def snapshot(self, issue_id: str) -> dict[str, Any] | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM issue_snapshots WHERE issue_id=?", (issue_id,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    @staticmethod
    def issue_fingerprint(issue: dict[str, Any]) -> str:
        fields = ("title", "description", "status", "priority", "assignee_id", "assignee_type", "parent_issue_id")
        content = {
            field: issue.get(field) if isinstance(issue.get(field), str) else ""
            for field in fields
        }
        serialized = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def save_snapshot(self, issue_id: str, issue: dict[str, Any], *, _db: sqlite3.Connection | None = None, _cycle_start: Any = _UNCHANGED) -> None:
        revision = issue.get("revision", 0)
        if type(revision) is not int:
            revision = 0
        if revision < 0:
            raise BridgeError("watcher_api_response_invalid", "Multica returned an invalid issue revision.")
        values = (
            issue_id, revision, str(issue.get("status") or ""), str(issue.get("title") or ""),
            str(issue.get("priority") or ""), str(issue.get("updated_at") or ""),
            self.issue_fingerprint(issue),
        )
        db = _db if _db is not None else self._connect()
        try:
            prior = db.execute("SELECT status,status_entered_at,cycle_started_at FROM issue_snapshots WHERE issue_id=?", (issue_id,)).fetchone()
            try:
                entered = datetime.fromisoformat(values[5])
                if entered.tzinfo is None:
                    raise ValueError("missing timezone")
            except ValueError:
                entered = datetime.now(UTC)
            if prior is not None and prior["status"] != values[2]:
                try:
                    old_entered = datetime.fromisoformat(prior["status_entered_at"] or "")
                    if old_entered.tzinfo is not None and entered <= old_entered:
                        entered = max(datetime.now(UTC), old_entered + timedelta(microseconds=1))
                except ValueError:
                    pass
            cycle = prior["cycle_started_at"] if prior is not None else None
            if _cycle_start is not _UNCHANGED:
                cycle = _cycle_start
            db.execute(
                "INSERT INTO issue_snapshots(issue_id,revision,status,title,priority,updated_at,content_hash,status_entered_at,cycle_started_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(issue_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,"
                "title=excluded.title,priority=excluded.priority,updated_at=excluded.updated_at,"
                "content_hash=excluded.content_hash,status_entered_at=CASE WHEN issue_snapshots.status != excluded.status "
                "THEN excluded.status_entered_at ELSE issue_snapshots.status_entered_at END,cycle_started_at=excluded.cycle_started_at",
                (*values, entered.isoformat(), cycle),
            )
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher issue snapshot could not be recorded.") from exc
        finally:
            if _db is None:
                db.close()

    def mark_comment_seen(self, issue_id: str, comment_id: str, *, _db: sqlite3.Connection | None = None) -> bool:
        db = _db if _db is not None else self._connect()
        try:
            cursor = db.execute(
                "INSERT OR IGNORE INTO seen_comments(issue_id,comment_id) VALUES(?,?)", (issue_id, comment_id)
            )
            return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher comment state could not be recorded.") from exc
        finally:
            if _db is None:
                db.close()

    def comment_seen(self, issue_id: str, comment_id: str) -> bool:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT 1 FROM seen_comments WHERE issue_id=? AND comment_id=?", (issue_id, comment_id)
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher comment state could not be read.") from exc
        finally:
            db.close()

    def claim_delivery(self, delivery_key: str, issue_id: str, platform: str, chat_id: str) -> str:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,detail FROM deliveries WHERE delivery_key=?", (delivery_key,)).fetchone()
            if row is not None:
                if row["status"] == "not_sent" and row["detail"] == "http_429":
                    db.execute(
                        "UPDATE deliveries SET status='sending',detail='',updated_at=? WHERE delivery_key=?",
                        (int(time.time()), delivery_key),
                    )
                    db.commit()
                    return "claimed"
                db.rollback()
                return str(row["status"])
            db.execute(
                "INSERT INTO deliveries(delivery_key,issue_id,platform,chat_id,status,updated_at) VALUES(?,?,?,?,'sending',?)",
                (delivery_key, issue_id, platform, chat_id, int(time.time())),
            )
            db.commit()
            return "claimed"
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("watcher_state_unavailable", "Watcher delivery could not be recorded.") from exc
        finally:
            db.close()

    def finish_delivery(self, delivery_key: str, status: str, detail: str = "") -> None:
        if status not in {"delivered", "not_sent", "delivery_unknown"}:
            raise ValueError("invalid watcher delivery status")
        db = self._connect()
        try:
            cursor = db.execute(
                "UPDATE deliveries SET status=?,detail=?,updated_at=? WHERE delivery_key=? AND status='sending'",
                (status, detail[:120], int(time.time()), delivery_key),
            )
            if cursor.rowcount != 1:
                raise BridgeError("watcher_state_conflict", "Watcher delivery state changed unexpectedly.")
        finally:
            db.close()

    def enqueue_notification(self, key: str, mapping: dict[str, Any], payload: dict[str, Any], *, _db: sqlite3.Connection | None = None) -> bool:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > 16_384:
            raise BridgeError("watcher_payload_invalid", "Notification payload exceeds the limit.")
        db = _db if _db is not None else self._connect()
        try:
            cursor = db.execute(
                "INSERT OR IGNORE INTO deliveries"
                "(delivery_key,issue_id,platform,chat_id,status,detail,updated_at,event_type,payload_json,next_retry_at) "
                "VALUES(?,?,?,?,'not_sent','pending',?,?,?,0)",
                (key, mapping["issue_id"], mapping["platform"], mapping["chat_id"],
                 int(time.time()), payload["event_type"], raw),
            )
            return cursor.rowcount == 1
        finally:
            if _db is None:
                db.close()

    def pending_notifications(self) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            return [dict(r) for r in db.execute(
                "SELECT * FROM deliveries WHERE payload_json IS NOT NULL "
                "AND detail NOT LIKE 'retry_exhausted:%' AND status != 'delivered'"
            )]
        finally:
            db.close()

    def claim_notification(self, key: str, max_attempts: int, sending_timeout: int, *, now: int | None = None) -> int | None:
        clock = int(time.time()) if now is None else now
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM deliveries WHERE delivery_key=?", (key,)).fetchone()
            if (row is None or row["payload_json"] is None or row["status"] == "delivered"
                    or str(row["detail"]).startswith("retry_exhausted:")
                    or (row["next_retry_at"] is not None and row["next_retry_at"] > clock)
                    or (row["status"] == "sending" and row["updated_at"] >= clock - sending_timeout)):
                db.rollback()
                return None
            if row["attempts"] >= max_attempts:
                self._terminal_notification(db, row, clock)
                db.commit()
                logging.getLogger("hermes_multica_bridge.watcher").warning(
                    "route_id=%s retry_exhausted=1", json.loads(row["payload_json"]).get("route_id", "unknown")
                )
                return None
            attempt = row["attempts"] + 1
            updated = db.execute("UPDATE deliveries SET status='sending',attempts=?,updated_at=?,next_retry_at=NULL "
                                 "WHERE delivery_key=? AND attempts=? AND status=? AND updated_at=?",
                                 (attempt, clock, key, row["attempts"], row["status"], row["updated_at"]))
            if updated.rowcount != 1:
                db.rollback()
                return None
            db.commit()
            return attempt
        finally:
            db.close()

    @staticmethod
    def _terminal_notification(db: sqlite3.Connection, row: sqlite3.Row, clock: int) -> None:
        payload = json.loads(row["payload_json"])
        for comment_id in payload.get("comment_ids", []):
            db.execute("INSERT OR IGNORE INTO seen_comments VALUES(?,?)", (row["issue_id"], comment_id))
        db.execute("UPDATE deliveries SET status='delivery_unknown',detail=?,next_retry_at=NULL,updated_at=? "
                   "WHERE delivery_key=?", (f"retry_exhausted:{row['attempts']}", clock, row["delivery_key"]))

    def finish_notification(
        self, key: str, attempt: int, status: str, detail: str, max_attempts: int, *, now: int | None = None,
    ) -> str:
        if status not in {"delivered", "not_sent", "delivery_unknown"}:
            raise ValueError("invalid delivery status")
        clock = int(time.time()) if now is None else now
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM deliveries WHERE delivery_key=? AND status='sending' AND attempts=?",
                             (key, attempt)).fetchone()
            if row is None:
                db.rollback()
                return "stale"
            if status == "delivered":
                payload = json.loads(row["payload_json"])
                for comment_id in payload.get("comment_ids", []):
                    db.execute("INSERT OR IGNORE INTO seen_comments VALUES(?,?)", (row["issue_id"], comment_id))
                db.execute("UPDATE deliveries SET status='delivered',detail=?,payload_json=NULL,next_retry_at=NULL,"
                           "updated_at=? WHERE delivery_key=? AND status='sending' AND attempts=?", (detail[:120], clock, key, attempt))
                result = "delivered"
            elif attempt >= max_attempts:
                self._terminal_notification(db, row, clock)
                result = "retry_exhausted"
            else:
                delay = (30, 60, 120, 300, 600)[min(attempt - 1, 4)]
                db.execute("UPDATE deliveries SET status=?,detail=?,next_retry_at=?,updated_at=? "
                           "WHERE delivery_key=? AND status='sending' AND attempts=?",
                           (status, detail[:120], clock + delay, clock, key, attempt))
                result = "retry_scheduled"
            db.commit()
            return result
        finally:
            db.close()

    def reserve_chat_slot(self, profile: str, platform: str, chat_id: str, *, interval_ms: int = 510) -> float:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            now_ms = int(time.time() * 1000)
            row = db.execute(
                "SELECT next_send_ms FROM chat_rate_limit WHERE profile=? AND platform=? AND chat_id=?",
                (profile, platform, chat_id),
            ).fetchone()
            send_at = max(now_ms, int(row["next_send_ms"]) if row else now_ms)
            next_at = send_at + interval_ms
            db.execute(
                "INSERT INTO chat_rate_limit(profile,platform,chat_id,next_send_ms) VALUES(?,?,?,?) "
                "ON CONFLICT(profile,platform,chat_id) DO UPDATE SET next_send_ms=excluded.next_send_ms",
                (profile, platform, chat_id, next_at),
            )
            db.commit()
            return max(0.0, (send_at - now_ms) / 1000)
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("watcher_state_unavailable", "Watcher rate limit could not be recorded.") from exc
        finally:
            db.close()
