"""Profile-local operation ledger and watcher mappings for Workspace routes."""

from __future__ import annotations

import hashlib
import json
import os
import re
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
        # Do not change journal mode until the database has passed the exact
        # schema check. An unsupported database must remain byte-for-byte
        # untouched by the plugin.
        connection = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 3000")
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            existing_tables = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            old_tables = {"operations", "issue_mappings"}
            current_tables = old_tables | {"condition_wake_intents"}
            if version not in {0, 1, 2} or (existing_tables and existing_tables not in (old_tables, current_tables)):
                raise BridgeError("state_unavailable", "Workspace state schema is unsupported; create a clean profile state store.")

            operations_columns = {
                "operation_key", "route_id", "operation", "request_hash", "status",
                "result_json", "detail", "updated_at",
            }
            mapping_columns = {
                "issue_id", "route_id", "platform", "user_id", "chat_id", "thread_id",
                "message_id", "chat_type", "created_at",
            }
            intent_columns = {
                "intent_key", "route_id", "connection_id", "workspace_id", "source_profile",
                "parent_issue_id", "request_hash", "config_json", "status", "children_json",
                "tree_fingerprint", "wakeup_id", "wakeup_expires_at", "mapping_status", "detail",
                "created_at", "updated_at",
            }
            legacy_intent_columns = intent_columns - {"wakeup_expires_at"}
            if existing_tables:
                if {row["name"] for row in connection.execute("PRAGMA table_info(operations)")} != operations_columns:
                    raise BridgeError("state_unavailable", "Workspace operation state is unsupported; create a clean profile state store.")
                if {row["name"] for row in connection.execute("PRAGMA table_info(issue_mappings)")} != mapping_columns:
                    raise BridgeError("state_unavailable", "Workspace mapping state is unsupported; create a clean profile state store.")
                actual_intent_columns = ({
                    row["name"] for row in connection.execute("PRAGMA table_info(condition_wake_intents)")
                } if "condition_wake_intents" in existing_tables else set())
                accepted_intent_columns = (
                    {"condition_wake_intents": legacy_intent_columns} if version == 1
                    else {"condition_wake_intents": intent_columns} if version == 2
                    else {}
                )
                if actual_intent_columns and actual_intent_columns != accepted_intent_columns.get(
                    "condition_wake_intents", intent_columns
                ):
                    raise BridgeError("state_unavailable", "Workspace condition-wake state is unsupported.")

            if not existing_tables:
                if version != 0:
                    raise BridgeError("state_unavailable", "Workspace state schema is unsupported.")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("""CREATE TABLE operations (
                    operation_key TEXT PRIMARY KEY, route_id TEXT NOT NULL, operation TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('in_progress','accepted','not_sent','operation_unknown')),
                    result_json TEXT, detail TEXT, updated_at INTEGER NOT NULL)""")
                connection.execute("""CREATE TABLE issue_mappings (
                    issue_id TEXT PRIMARY KEY, route_id TEXT NOT NULL, platform TEXT NOT NULL,
                    user_id TEXT NOT NULL, chat_id TEXT NOT NULL, thread_id TEXT,
                    message_id TEXT NOT NULL, chat_type TEXT NOT NULL, created_at INTEGER NOT NULL)""")
                self._create_condition_wake_table(connection)
                connection.execute("PRAGMA user_version=2")
                connection.commit()
            elif version == 0 and existing_tables == old_tables:
                # The 0.6.0 state store had no user_version. Accept only its
                # complete exact schema, then add the new table atomically.
                connection.execute("BEGIN IMMEDIATE")
                self._create_condition_wake_table(connection)
                connection.execute("PRAGMA user_version=2")
                connection.commit()
            elif version == 1 and existing_tables != current_tables:
                raise BridgeError("state_unavailable", "Workspace state schema is unsupported.")
            elif version == 1:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("ALTER TABLE condition_wake_intents ADD COLUMN wakeup_expires_at REAL")
                connection.execute("PRAGMA user_version=2")
                connection.commit()
            elif version == 2 and existing_tables != current_tables:
                raise BridgeError("state_unavailable", "Workspace state schema is unsupported.")
            elif version == 0 and existing_tables == current_tables:
                # A crash after creating the table but before setting the version
                # is not a documented migration state; do not infer its origin.
                raise BridgeError("state_unavailable", "Workspace state migration is incomplete.")

            connection.execute(
                "UPDATE operations SET status='operation_unknown', detail='process_interrupted', updated_at=? "
                "WHERE status='in_progress'",
                (int(time.time()),),
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise BridgeError("state_unavailable", "Workspace state database is not a supported clean store.") from exc
        finally:
            connection.close()

    @staticmethod
    def _create_condition_wake_table(connection: sqlite3.Connection) -> None:
        connection.execute("""CREATE TABLE condition_wake_intents (
            intent_key TEXT PRIMARY KEY,
            route_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            source_profile TEXT NOT NULL,
            parent_issue_id TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            config_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','registering','registered','blocked')),
            children_json TEXT,
            tree_fingerprint TEXT,
            wakeup_id TEXT,
            mapping_status TEXT NOT NULL DEFAULT 'pending' CHECK(mapping_status IN ('pending','registered','blocked')),
            wakeup_expires_at REAL,
            detail TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(connection_id,workspace_id,source_profile,parent_issue_id),
            UNIQUE(connection_id,workspace_id,source_profile,wakeup_id))""")
        connection.execute(
            "CREATE INDEX condition_wake_status ON condition_wake_intents(status,updated_at)"
        )

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

    def put_condition_wake_intent(
        self, *, route_id: str, connection_id: str, workspace_id: str, source_profile: str,
        parent_issue_id: str, request_hash: str, config: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist the create-phase intent; exact repeats are idempotent."""
        config_json = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        key_material = f"{connection_id}\x00{workspace_id}\x00{source_profile}\x00{parent_issue_id}"
        intent_key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        now = int(time.time())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM condition_wake_intents WHERE connection_id=? AND workspace_id=? AND source_profile=? AND parent_issue_id=?",
                (connection_id, workspace_id, source_profile, parent_issue_id),
            ).fetchone()
            if row is not None:
                if (row["route_id"], row["request_hash"], row["config_json"]) != (route_id, request_hash, config_json):
                    raise BridgeError("operation_conflict", "This parent already has a different condition-wake intent.")
                connection.commit()
                return dict(row)
            connection.execute(
                """INSERT INTO condition_wake_intents(
                    intent_key,route_id,connection_id,workspace_id,source_profile,parent_issue_id,
                    request_hash,config_json,status,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,'pending',?,?)""",
                (intent_key, route_id, connection_id, workspace_id, source_profile, parent_issue_id,
                 request_hash, config_json, now, now),
            )
            connection.commit()
            return dict(connection.execute("SELECT * FROM condition_wake_intents WHERE intent_key=?", (intent_key,)).fetchone())
        except BridgeError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Condition-wake intent could not be recorded.") from exc
        finally:
            connection.close()

    def condition_wake_intent(
        self, *, connection_id: str, workspace_id: str, source_profile: str, parent_issue_id: str,
    ) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM condition_wake_intents WHERE connection_id=? AND workspace_id=? AND source_profile=? AND parent_issue_id=?",
                (connection_id, workspace_id, source_profile, parent_issue_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def begin_condition_wake_registration(
        self, intent_key: str, *, children: list[dict[str, Any]], fingerprint: str,
        wakeup_expires_at: float,
    ) -> str:
        """Claim the only possible POST, or demand read-only reconciliation after interruption."""
        stable_children = [
            {"id": row["id"], "stage": row.get("stage")}
            for row in children
        ]
        children_json = json.dumps(stable_children, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        now = int(time.time())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM condition_wake_intents WHERE intent_key=?", (intent_key,)).fetchone()
            if row is None:
                raise BridgeError("condition_wake_pending", "No condition-wake intent exists for this parent.")
            if row["status"] == "registered":
                if row["tree_fingerprint"] != fingerprint:
                    raise BridgeError("condition_wake_stage_mismatch", "The saved child plan has changed.")
                connection.commit()
                return "registered"
            if row["status"] == "blocked":
                raise BridgeError(row["detail"] or "approval_wake_unavailable", "Condition-wake registration is blocked.")
            if row["status"] == "registering":
                if row["tree_fingerprint"] != fingerprint or row["children_json"] != children_json:
                    raise BridgeError("condition_wake_stage_mismatch", "The saved child plan has changed during registration.")
                connection.commit()
                return "reconcile"
            connection.execute(
                "UPDATE condition_wake_intents SET status='registering',children_json=?,tree_fingerprint=?,wakeup_expires_at=?,detail='registration_claimed',updated_at=? WHERE intent_key=? AND status='pending'",
                (children_json, fingerprint, wakeup_expires_at, now, intent_key),
            )
            connection.commit()
            return "claimed"
        except BridgeError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Condition-wake registration state could not be claimed.") from exc
        finally:
            connection.close()

    def release_condition_wake_claim(self, intent_key: str, *, detail: str = "api_rejected") -> None:
        """Return a proven-not-sent native wake request to pending for a safe retry."""
        safe_detail = detail if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", detail or "") else "api_rejected"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE condition_wake_intents SET status='pending',children_json=NULL,tree_fingerprint=NULL,"
                "wakeup_expires_at=NULL,detail=?,updated_at=? WHERE intent_key=? AND status='registering' AND wakeup_id IS NULL",
                (safe_detail, int(time.time()), intent_key),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise BridgeError("state_conflict", "Condition-wake registration state changed unexpectedly.")
            connection.commit()
        except BridgeError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Condition-wake registration state could not be released.") from exc
        finally:
            connection.close()

    def finish_condition_wake_registration(
        self, intent_key: str, *, status: str, wakeup_id: str | None = None, detail: str = "",
    ) -> None:
        if status not in {"registered", "blocked"} or (status == "registered") != bool(wakeup_id):
            raise ValueError("invalid condition-wake registration result")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE condition_wake_intents SET status=?,wakeup_id=COALESCE(?,wakeup_id),detail=?,mapping_status=?,updated_at=? WHERE intent_key=? AND status IN ('registering','registered')",
                (status, wakeup_id, detail[:128], "pending" if status == "registered" else "blocked", int(time.time()), intent_key),
            )
            if cursor.rowcount != 1:
                raise BridgeError("state_conflict", "Condition-wake registration state changed unexpectedly.")
            connection.commit()
        except BridgeError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Condition-wake registration result could not be saved.") from exc
        finally:
            connection.close()

    def finish_condition_wake_mapping(self, intent_key: str, *, status: str, detail: str = "") -> None:
        if status not in {"registered", "blocked"}:
            raise ValueError("invalid condition-wake mapping result")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE condition_wake_intents SET mapping_status=?,detail=?,updated_at=? WHERE intent_key=? AND status='registered'",
                (status, detail[:128], int(time.time()), intent_key),
            )
            if cursor.rowcount != 1:
                raise BridgeError("state_conflict", "Condition-wake mapping state changed unexpectedly.")
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise BridgeError("state_unavailable", "Condition-wake mapping state could not be recorded.") from exc
        finally:
            connection.close()

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
