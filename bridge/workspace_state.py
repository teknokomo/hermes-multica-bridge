"""Profile-local operation ledger and watcher mappings for Workspace routes."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BridgeError


@dataclass(frozen=True)
class Operation:
    key: str
    status: str
    result: dict[str, Any] | None
    detail: str | None


class WorkspaceState:
    """A clean, profile-scoped database; it never opens the Autopilot state file."""

    def __init__(self, path: str | Path):
        requested = Path(path)
        directory = requested.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = directory.lstat()
        except OSError as exc:
            raise BridgeError("state_unavailable", "Workspace state directory is unavailable.") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise BridgeError("state_untrusted", "Workspace state directory has unsafe ownership or permissions.")
        self.path = directory / requested.name
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise BridgeError("state_unavailable", "Workspace state database is unavailable.") from exc
        try:
            file_info = os.fstat(fd)
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.geteuid()
                    or file_info.st_mode & 0o077):
                raise BridgeError("state_untrusted", "Workspace state database has unsafe permissions.")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 3000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            existing_tables = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if existing_tables and existing_tables != {"operations", "issue_mappings"}:
                raise BridgeError("state_unavailable", "Workspace state is not a clean profile state store.")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    operation_key TEXT PRIMARY KEY,
                    route_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('in_progress','accepted','not_sent','operation_unknown')),
                    result_json TEXT,
                    detail TEXT,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS issue_mappings (
                    issue_id TEXT PRIMARY KEY,
                    route_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    thread_id TEXT,
                    message_id TEXT NOT NULL,
                    chat_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(operations)")}
            required = {"operation_key", "route_id", "operation", "request_hash", "status", "result_json", "detail", "updated_at"}
            if columns != required:
                raise BridgeError("state_unavailable", "Workspace state schema is unsupported; create a clean profile state store.")
            mapping_columns = {row["name"] for row in connection.execute("PRAGMA table_info(issue_mappings)")}
            required_mapping_columns = {
                "issue_id", "route_id", "platform", "user_id", "chat_id", "thread_id",
                "message_id", "chat_type", "created_at",
            }
            if mapping_columns != required_mapping_columns:
                raise BridgeError("state_unavailable", "Workspace mapping state is unsupported; create a clean profile state store.")
            connection.execute(
                "UPDATE operations SET status='operation_unknown', detail='process_interrupted', updated_at=? "
                "WHERE status='in_progress'",
                (int(time.time()),),
            )
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "Workspace state database is not a supported clean store.") from exc
        finally:
            connection.close()

    def begin(self, *, key: str, route_id: str, operation: str, request_hash: str) -> Operation:
        now = int(time.time())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM operations WHERE operation_key = ?", (key,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO operations(operation_key,route_id,operation,request_hash,status,updated_at) "
                    "VALUES(?,?,?,?,'in_progress',?)",
                    (key, route_id, operation, request_hash, now),
                )
                connection.commit()
                return Operation(key, "ready", None, None)
            if row["request_hash"] != request_hash or row["route_id"] != route_id or row["operation"] != operation:
                connection.rollback()
                raise BridgeError("operation_conflict", "This source message already has a different operation of this type.")
            status = str(row["status"])
            if status == "not_sent":
                connection.execute(
                    "UPDATE operations SET status='in_progress', result_json=NULL, detail=NULL, updated_at=? WHERE operation_key=?",
                    (now, key),
                )
                connection.commit()
                return Operation(key, "ready", None, None)
            result = json.loads(row["result_json"]) if row["result_json"] else None
            connection.commit()
            return Operation(key, status, result, row["detail"])
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Workspace operation state could not be recorded.") from exc
        finally:
            connection.close()

    def finish(self, key: str, *, status: str, result: dict[str, Any] | None = None, detail: str | None = None) -> None:
        if status not in {"accepted", "not_sent", "operation_unknown"}:
            raise ValueError("invalid workspace operation status")
        result_json = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if result is not None else None
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE operations SET status=?, result_json=?, detail=?, updated_at=? WHERE operation_key=? AND status='in_progress'",
                (status, result_json, detail, int(time.time()), key),
            )
            if cursor.rowcount != 1:
                raise BridgeError("state_conflict", "Workspace operation state changed unexpectedly.")
        finally:
            connection.close()

    def register_issue(self, issue_id: str, route_id: str, source: dict[str, Any]) -> bool:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM issue_mappings WHERE issue_id=?", (issue_id,)).fetchone()
            expected = (route_id, source["platform"], source["user_id"], source["chat_id"],
                        source.get("thread_id"), source["message_id"], source["chat_type"])
            if row is not None:
                actual = tuple(row[key] for key in (
                    "route_id", "platform", "user_id", "chat_id", "thread_id", "message_id", "chat_type"
                ))
                connection.rollback()
                return actual == expected
            connection.execute(
                "INSERT INTO issue_mappings(issue_id,route_id,platform,user_id,chat_id,thread_id,message_id,chat_type,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (issue_id, route_id, source["platform"], source["user_id"], source["chat_id"],
                 source.get("thread_id"), source["message_id"], source["chat_type"], int(time.time())),
            )
            connection.commit()
            return True
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Workspace issue mapping could not be recorded.") from exc
        finally:
            connection.close()

    def issue_mapping(self, issue_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM issue_mappings WHERE issue_id=?", (issue_id,)).fetchone()
        finally:
            connection.close()
        return dict(row) if row else None

    @staticmethod
    def operation_key(profile: str, route_id: str, source: dict[str, Any], operation: str) -> str:
        import hashlib

        canonical = json.dumps(
            {"profile": profile, "route_id": route_id, "source": source, "operation": operation},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def payload_hash(payload: Any) -> str:
        import hashlib

        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
