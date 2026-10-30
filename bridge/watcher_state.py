"""Private clean-start persistence for watcher mappings, snapshots, and delivery outcomes."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from .errors import BridgeError


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
            if existing_tables and existing_tables != set(table_columns):
                raise BridgeError("watcher_state_unavailable", "Watcher state is not a clean state store.")
            db.executescript("""
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
            """)
            for table, required_columns in table_columns.items():
                columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                if columns != required_columns:
                    raise BridgeError("watcher_state_unavailable", "Watcher state schema is unsupported; create a clean state store.")
            db.execute(
                "UPDATE deliveries SET status='delivery_unknown', detail='process_interrupted', updated_at=? "
                "WHERE status='sending'", (int(time.time()),)
            )
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher state database is not a supported clean store.") from exc
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

    def save_snapshot(self, issue_id: str, issue: dict[str, Any]) -> None:
        revision = issue.get("revision", 0)
        if type(revision) is not int or revision < 0:
            raise BridgeError("watcher_api_response_invalid", "Multica returned an invalid issue revision.")
        values = (
            issue_id, revision, str(issue.get("status") or ""), str(issue.get("title") or ""),
            str(issue.get("priority") or ""), str(issue.get("updated_at") or ""),
            self.issue_fingerprint(issue),
        )
        db = self._connect()
        try:
            db.execute(
                "INSERT INTO issue_snapshots(issue_id,revision,status,title,priority,updated_at,content_hash) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(issue_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,"
                "title=excluded.title,priority=excluded.priority,updated_at=excluded.updated_at,"
                "content_hash=excluded.content_hash",
                values,
            )
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher issue snapshot could not be recorded.") from exc
        finally:
            db.close()

    def mark_comment_seen(self, issue_id: str, comment_id: str) -> bool:
        db = self._connect()
        try:
            cursor = db.execute(
                "INSERT OR IGNORE INTO seen_comments(issue_id,comment_id) VALUES(?,?)", (issue_id, comment_id)
            )
            return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise BridgeError("watcher_state_unavailable", "Watcher comment state could not be recorded.") from exc
        finally:
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
            row = db.execute("SELECT status FROM deliveries WHERE delivery_key=?", (delivery_key,)).fetchone()
            if row is not None:
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
