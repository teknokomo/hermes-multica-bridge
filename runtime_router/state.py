"""Durable, single-host router queue and policy state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import RouterConfigError

SCHEMA_VERSION = 5
ACTIVE_STATES = ("switching", "creating", "waiting", "reconciling", "cancelling")
TERMINAL_STATES = {"done", "failed", "cancelled"}
_PRINCIPAL_ID = re.compile(
    r"\A(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|"
    r"[0-9A-HJKMNP-TV-Z]{26})\Z"
)
_TABLES = {
    "connectors",
    "principals",
    "principal_identities",
    "runtime_bindings",
    "runtime_exceptions",
    "router_requests",
    "router_events",
    "router_worker_state",
}
_V1_TABLES = _TABLES - {"router_worker_state"}
_V1_COLUMNS = {
    "connectors": (
        "connector_id",
        "profile",
        "platform",
        "label",
        "enabled",
        "created_at",
    ),
    "principals": (
        "principal_id",
        "display_name",
        "status",
        "created_at",
        "updated_at",
    ),
    "principal_identities": (
        "identity_id",
        "principal_id",
        "connector_id",
        "platform_user_id",
        "verified_at",
        "status",
    ),
    "runtime_bindings": (
        "binding_id",
        "principal_id",
        "instance_id",
        "default_runtime_id",
        "mode",
        "strict_until",
        "updated_at",
        "updated_by",
    ),
    "runtime_exceptions": (
        "exception_id",
        "binding_id",
        "name",
        "priority",
        "selectors_json",
        "runtime_id",
        "enabled",
        "expires_at",
        "created_at",
        "updated_at",
    ),
    "router_requests": (
        "request_id",
        "idempotency_key",
        "payload_hash",
        "principal_id",
        "connector_id",
        "instance_id",
        "agent_id",
        "agent_ref",
        "route_id",
        "target_runtime_id",
        "target_model",
        "project_id",
        "payload_json",
        "state",
        "priority",
        "attempts",
        "issue_id",
        "issue_url",
        "resolved_rule_id",
        "resolution_json",
        "lease_owner",
        "lease_token",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "created_at",
        "updated_at",
    ),
    "router_events": (
        "event_id",
        "request_id",
        "event_type",
        "actor",
        "rule_id",
        "runtime_id",
        "agent_id",
        "issue_id",
        "error_code",
        "details_json",
        "created_at",
    ),
}
_V2_COLUMNS = {
    **_V1_COLUMNS,
    "router_worker_state": (
        "singleton",
        "worker_id",
        "state",
        "heartbeat_at",
        "last_tick_at",
        "last_error_code",
    ),
}
_V3_COLUMNS = {
    **_V2_COLUMNS,
    "router_requests": (
        *_V2_COLUMNS["router_requests"],
        "cancel_source_state",
        "reconcile_source_state",
    ),
}
_V4_COLUMNS = {
    **_V3_COLUMNS,
    "router_worker_state": (
        *_V3_COLUMNS["router_worker_state"],
        "terminal_sweep_cursor",
    ),
}
_V5_COLUMNS = {
    **_V4_COLUMNS,
    "router_requests": (
        *_V4_COLUMNS["router_requests"],
        "target_model_rule_id",
        "target_model_source",
        "target_model_reason",
    ),
}
_TRANSITIONS = {
    "queued": {"switching", "cancelled", "blocked"},
    "switching": {
        "queued",
        "creating",
        "cancelling",
        "reconciling",
        "blocked",
        "failed",
    },
    "creating": {
        "queued",
        "waiting",
        "cancelling",
        "reconciling",
        "blocked",
        "failed",
    },
    "waiting": {"done", "failed", "cancelled", "cancelling", "reconciling", "blocked"},
    "reconciling": {
        "queued",
        "waiting",
        "cancelling",
        "done",
        "failed",
        "cancelled",
        "blocked",
    },
    "cancelling": {"cancelled", "done", "failed", "reconciling", "blocked"},
    "blocked": {"queued", "cancelled", "reconciling"},
    "done": set(),
    "failed": set(),
    "cancelled": set(),
}


def _encode(value: Any, *, limit: int = 131_072) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        raise RouterConfigError("router_payload_invalid") from None
    if len(encoded.encode("utf-8")) > limit:
        raise RouterConfigError("router_payload_too_large")
    return encoded


def _now() -> int:
    return int(time.time())


def _valid_timestamp(value: str | None) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


class RouterStore:
    """SQLite state; external Multica CLI calls never run inside DB transactions."""

    def __init__(self, path: str | Path):
        requested = Path(path)
        if not requested.is_absolute() or ".." in requested.parts:
            raise RouterConfigError("router_state_path_invalid")
        requested.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = requested.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise RouterConfigError("router_state_directory_unsafe")
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(requested, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RouterConfigError("router_state_file_unsafe")
        finally:
            os.close(fd)
        self.path = requested
        self._initialize()

    def _raw_connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def connect(self) -> sqlite3.Connection:
        db = self._raw_connect()
        db.execute("PRAGMA journal_mode=WAL")
        return db

    @staticmethod
    def _table_names(db: sqlite3.Connection) -> set[str]:
        return {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    @staticmethod
    def _schema_matches(
        db: sqlite3.Connection, expected: dict[str, tuple[str, ...]]
    ) -> bool:
        if RouterStore._table_names(db) != set(expected):
            return False
        for table, columns in expected.items():
            actual = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
            if actual != columns:
                return False
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('view','trigger') LIMIT 1"
        ).fetchone():
            return False
        index_names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
        }
        return index_names == {"one_active_per_agent", "queued_order"}

    def _initialize(self) -> None:
        db = self._raw_connect()
        try:
            names = RouterStore._table_names(db)
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if names == _V1_TABLES and version == 1:
                if not RouterStore._schema_matches(db, _V1_COLUMNS):
                    raise RouterConfigError("router_database_schema_unsupported")
                try:
                    db.executescript("""
                        BEGIN IMMEDIATE;
                        CREATE TABLE router_worker_state(
                            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                            worker_id TEXT NOT NULL,
                            state TEXT NOT NULL CHECK(state IN ('running','idle','error')),
                            heartbeat_at INTEGER NOT NULL,
                            last_tick_at INTEGER NOT NULL,
                            last_error_code TEXT);
                        PRAGMA user_version=2;
                        COMMIT;
                    """)
                except sqlite3.Error as exc:
                    if db.in_transaction:
                        db.rollback()
                    raise RouterConfigError("router_database_migration_failed") from exc
                names = self._table_names(db)
                version = db.execute("PRAGMA user_version").fetchone()[0]
            if names == _TABLES and version == 2:
                if not RouterStore._schema_matches(db, _V2_COLUMNS):
                    raise RouterConfigError("router_database_schema_unsupported")
                try:
                    db.executescript("""
                        BEGIN IMMEDIATE;
                        ALTER TABLE router_requests ADD COLUMN cancel_source_state TEXT
                            CHECK(cancel_source_state IS NULL OR cancel_source_state IN
                                ('switching','creating','waiting','reconciling','cancelling'));
                        ALTER TABLE router_requests ADD COLUMN reconcile_source_state TEXT
                            CHECK(reconcile_source_state IS NULL OR reconcile_source_state IN
                                ('switching','creating','waiting','reconciling','cancelling'));
                        PRAGMA user_version=3;
                        COMMIT;
                    """)
                except sqlite3.Error as exc:
                    if db.in_transaction:
                        db.rollback()
                    raise RouterConfigError("router_database_migration_failed") from exc
                names = self._table_names(db)
                version = db.execute("PRAGMA user_version").fetchone()[0]
            if names == _TABLES and version == 3:
                if not RouterStore._schema_matches(db, _V3_COLUMNS):
                    raise RouterConfigError("router_database_schema_unsupported")
                try:
                    db.executescript("""
                        BEGIN IMMEDIATE;
                        ALTER TABLE router_worker_state ADD COLUMN terminal_sweep_cursor TEXT;
                        PRAGMA user_version=4;
                        COMMIT;
                    """)
                except sqlite3.Error as exc:
                    if db.in_transaction:
                        db.rollback()
                    raise RouterConfigError("router_database_migration_failed") from exc
                names = self._table_names(db)
                version = db.execute("PRAGMA user_version").fetchone()[0]
            if names == _TABLES and version == 4:
                if not RouterStore._schema_matches(db, _V4_COLUMNS):
                    raise RouterConfigError("router_database_schema_unsupported")
                try:
                    db.executescript("""
                        BEGIN IMMEDIATE;
                        ALTER TABLE router_requests ADD COLUMN target_model_rule_id TEXT;
                        ALTER TABLE router_requests ADD COLUMN target_model_source TEXT;
                        ALTER TABLE router_requests ADD COLUMN target_model_reason TEXT;
                        PRAGMA user_version=5;
                        COMMIT;
                    """)
                except sqlite3.Error as exc:
                    if db.in_transaction:
                        db.rollback()
                    raise RouterConfigError("router_database_migration_failed") from exc
                names = self._table_names(db)
                version = db.execute("PRAGMA user_version").fetchone()[0]
            if names and (
                version != SCHEMA_VERSION
                or not RouterStore._schema_matches(db, _V5_COLUMNS)
            ):
                raise RouterConfigError("router_database_schema_unsupported")
            if names:
                integrity = db.execute("PRAGMA quick_check").fetchone()[0]
                if integrity != "ok":
                    raise RouterConfigError("router_database_integrity_failed")
                db.execute("PRAGMA journal_mode=WAL")
                return
            if version != 0:
                raise RouterConfigError("router_database_schema_unsupported")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE connectors(
                    connector_id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    platform TEXT NOT NULL CHECK(platform IN ('telegram','max')),
                    label TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    created_at INTEGER NOT NULL,
                    UNIQUE(profile,platform));
                CREATE TABLE principals(
                    principal_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL);
                CREATE TABLE principal_identities(
                    identity_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                    connector_id TEXT NOT NULL REFERENCES connectors(connector_id),
                    platform_user_id TEXT NOT NULL,
                    verified_at INTEGER,
                    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                    UNIQUE(connector_id,platform_user_id));
                CREATE TABLE runtime_bindings(
                    binding_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                    instance_id TEXT NOT NULL,
                    default_runtime_id TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('strict','exceptions')),
                    strict_until TEXT,
                    updated_at INTEGER NOT NULL,
                    updated_by TEXT NOT NULL,
                    UNIQUE(principal_id,instance_id));
                CREATE TABLE runtime_exceptions(
                    exception_id TEXT PRIMARY KEY,
                    binding_id TEXT NOT NULL REFERENCES runtime_bindings(binding_id),
                    name TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    selectors_json TEXT NOT NULL,
                    runtime_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    expires_at TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL);
                CREATE TABLE router_requests(
                    request_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_hash TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    connector_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_ref TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    target_runtime_id TEXT,
                    target_model TEXT,
                    project_id TEXT,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    issue_id TEXT,
                    issue_url TEXT,
                    resolved_rule_id TEXT,
                    resolution_json TEXT,
                    lease_owner TEXT,
                    lease_token TEXT,
                    lease_expires_at INTEGER,
                    heartbeat_at INTEGER,
                    last_error_code TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    cancel_source_state TEXT CHECK(cancel_source_state IS NULL OR cancel_source_state IN
                        ('switching','creating','waiting','reconciling','cancelling')),
                    reconcile_source_state TEXT CHECK(reconcile_source_state IS NULL OR reconcile_source_state IN
                        ('switching','creating','waiting','reconciling','cancelling')),
                    target_model_rule_id TEXT,
                    target_model_source TEXT,
                    target_model_reason TEXT);
                CREATE UNIQUE INDEX one_active_per_agent
                    ON router_requests(instance_id,agent_id)
                    WHERE state IN ('switching','creating','waiting','reconciling','cancelling');
                CREATE INDEX queued_order
                    ON router_requests(state,priority DESC,created_at ASC);
                CREATE TABLE router_events(
                    event_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL REFERENCES router_requests(request_id),
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    rule_id TEXT,
                    runtime_id TEXT,
                    agent_id TEXT,
                    issue_id TEXT,
                    error_code TEXT,
                    details_json TEXT,
                    created_at INTEGER NOT NULL);
                CREATE TABLE router_worker_state(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    worker_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('running','idle','error')),
                    heartbeat_at INTEGER NOT NULL,
                    last_tick_at INTEGER NOT NULL,
                    last_error_code TEXT,
                    terminal_sweep_cursor TEXT);
                PRAGMA user_version=5;
                COMMIT;
            """)
        except sqlite3.Error as exc:
            if db.in_transaction:
                db.rollback()
            raise RouterConfigError("router_database_initialization_failed") from exc
        finally:
            db.close()

    def upsert_connector(
        self,
        connector_id: str,
        profile: str,
        platform: str,
        label: str,
        enabled: bool = True,
    ) -> None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT profile,platform FROM connectors WHERE connector_id=?",
                (connector_id,),
            ).fetchone()
            if existing and (existing["profile"], existing["platform"]) != (
                profile,
                platform,
            ):
                raise RouterConfigError("connector_id_immutable")
            conflict = db.execute(
                "SELECT connector_id FROM connectors WHERE profile=? AND platform=? AND connector_id<>?",
                (profile, platform, connector_id),
            ).fetchone()
            if conflict:
                raise RouterConfigError("connector_ambiguous")
            db.execute(
                "INSERT INTO connectors VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(connector_id) DO UPDATE SET label=excluded.label,enabled=excluded.enabled",
                (connector_id, profile, platform, label, int(enabled), _now()),
            )
            db.commit()

    def create_principal(self, principal_id: str, display_name: str) -> None:
        if (
            not isinstance(principal_id, str)
            or not _PRINCIPAL_ID.fullmatch(principal_id)
            or not isinstance(display_name, str)
            or not display_name.strip()
            or len(display_name) > 128
        ):
            raise RouterConfigError("invalid_arguments")
        now = _now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO principals VALUES(?,?,'active',?,?) "
                "ON CONFLICT(principal_id) DO UPDATE SET display_name=excluded.display_name,updated_at=excluded.updated_at",
                (principal_id, display_name.strip(), now, now),
            )
            db.commit()

    def link_identity(
        self,
        identity_id: str,
        principal_id: str,
        connector_id: str,
        user_id: str,
        *,
        verified: bool = True,
    ) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (identity_id, principal_id, connector_id, user_id)
        ):
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            principal = db.execute(
                "SELECT status FROM principals WHERE principal_id=?", (principal_id,)
            ).fetchone()
            connector = db.execute(
                "SELECT enabled FROM connectors WHERE connector_id=?", (connector_id,)
            ).fetchone()
            if principal is None or principal["status"] != "active":
                raise RouterConfigError("principal_unresolved")
            if connector is None or not connector["enabled"]:
                raise RouterConfigError("connector_unresolved")
            existing = db.execute(
                "SELECT identity_id,principal_id,status FROM principal_identities "
                "WHERE connector_id=? AND platform_user_id=?",
                (connector_id, user_id),
            ).fetchone()
            if existing:
                if (
                    existing["principal_id"] == principal_id
                    and existing["status"] == "active"
                ):
                    db.commit()
                    return
                raise RouterConfigError("identity_conflict")
            try:
                db.execute(
                    "INSERT INTO principal_identities VALUES(?,?,?,?,?,'active')",
                    (
                        identity_id,
                        principal_id,
                        connector_id,
                        user_id,
                        _now() if verified else None,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RouterConfigError("identity_conflict") from exc
            db.commit()

    def set_binding(
        self,
        binding_id: str,
        principal_id: str,
        instance_id: str,
        runtime_id: str,
        mode: str,
        strict_until: str | None,
        actor: str,
    ) -> None:
        if (
            mode not in {"strict", "exceptions"}
            or not all(
                isinstance(value, str) and value
                for value in (binding_id, principal_id, instance_id, runtime_id, actor)
            )
            or not _valid_timestamp(strict_until)
        ):
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO runtime_bindings VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(principal_id,instance_id) DO UPDATE SET "
                    "default_runtime_id=excluded.default_runtime_id,mode=excluded.mode,"
                    "strict_until=excluded.strict_until,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                    (
                        binding_id,
                        principal_id,
                        instance_id,
                        runtime_id,
                        mode,
                        strict_until,
                        _now(),
                        actor,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RouterConfigError("runtime_binding_invalid") from exc
            db.commit()

    def add_exception(
        self,
        exception_id: str,
        binding_id: str,
        name: str,
        priority: int,
        selectors: dict[str, str],
        runtime_id: str,
        expires_at: str | None,
    ) -> None:
        allowed_selectors = {
            "platform",
            "chat_id",
            "thread_id",
            "agent_id",
            "workspace_id",
            "squad_id",
            "project_id",
            "instance_id",
        }
        if (
            not isinstance(exception_id, str)
            or not exception_id
            or not isinstance(binding_id, str)
            or not binding_id
            or not isinstance(name, str)
            or not name.strip()
            or len(name) > 128
            or type(priority) is not int
            or not -1000 <= priority <= 1000
            or not isinstance(selectors, dict)
            or not selectors
            or len(selectors) > 8
            or set(selectors) - allowed_selectors
            or any(
                not isinstance(value, str) or not value or len(value) > 256
                for value in selectors.values()
            )
            or not runtime_id
            or not _valid_timestamp(expires_at)
        ):
            raise RouterConfigError("invalid_arguments")
        body = _encode(selectors, limit=4096)
        now = _now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM runtime_bindings WHERE binding_id=?", (binding_id,)
            ).fetchone():
                raise RouterConfigError("runtime_unbound")
            duplicate = db.execute(
                "SELECT 1 FROM runtime_exceptions WHERE binding_id=? AND name=? AND enabled=1",
                (binding_id, name),
            ).fetchone()
            if duplicate:
                raise RouterConfigError("exception_name_conflict")
            db.execute(
                "INSERT INTO runtime_exceptions VALUES(?,?,?,?,?,?,1,?,?,?)",
                (
                    exception_id,
                    binding_id,
                    name,
                    priority,
                    body,
                    runtime_id,
                    expires_at,
                    now,
                    now,
                ),
            )
            db.commit()

    def remove_exception(self, binding_id: str, exception_id: str) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE runtime_exceptions SET enabled=0,updated_at=? "
                "WHERE binding_id=? AND exception_id=? AND enabled=1",
                (_now(), binding_id, exception_id),
            )
            db.commit()
            return cursor.rowcount == 1

    def list_principals(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT principal_id,display_name,status,created_at,updated_at "
                    "FROM principals ORDER BY display_name,principal_id"
                )
            ]

    def list_identities(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        query = (
            "SELECT i.identity_id,i.principal_id,p.display_name,i.connector_id,c.profile,c.platform,"
            "i.platform_user_id,i.verified_at,i.status FROM principal_identities i "
            "JOIN principals p USING(principal_id) JOIN connectors c USING(connector_id)"
        )
        args: tuple[Any, ...] = ()
        if principal_id:
            query += " WHERE i.principal_id=?"
            args = (principal_id,)
        query += " ORDER BY i.principal_id,c.profile,c.platform"
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, args)]

    def list_bindings(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM runtime_bindings"
        args: tuple[Any, ...] = ()
        if principal_id:
            query += " WHERE principal_id=?"
            args = (principal_id,)
        query += " ORDER BY principal_id,instance_id"
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, args)]

    def list_exceptions(self, binding_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT exception_id,binding_id,name,priority,selectors_json,runtime_id,enabled,expires_at,created_at,updated_at "
                    "FROM runtime_exceptions WHERE binding_id=? ORDER BY priority DESC,name",
                    (binding_id,),
                )
            ]

    def runtime_metrics(self, principal_id: str | None = None) -> dict[str, Any]:
        with self.connect() as db:
            counts_sql = "SELECT state,COUNT(*) AS count FROM router_requests"
            count_args: tuple[Any, ...] = ()
            if principal_id is not None:
                counts_sql += " WHERE principal_id=?"
                count_args = (principal_id,)
            counts_sql += " GROUP BY state"
            counts = {
                row["state"]: row["count"] for row in db.execute(counts_sql, count_args)
            }
            query = (
                "SELECT request_id,principal_id,instance_id,agent_id,state,issue_id,updated_at,last_error_code "
                "FROM router_requests WHERE state IN ('switching','creating','waiting','reconciling','cancelling')"
            )
            parameters: tuple[Any, ...] = ()
            if principal_id is not None:
                query += " AND principal_id=?"
                parameters = (principal_id,)
            query += " ORDER BY updated_at DESC"
            active = [dict(row) for row in db.execute(query, parameters)]
            worker = db.execute(
                "SELECT worker_id,state,heartbeat_at,last_tick_at,last_error_code "
                "FROM router_worker_state WHERE singleton=1"
            ).fetchone()
        return {
            "queue_depth": counts.get("queued", 0),
            "states": counts,
            "active": active,
            "worker": dict(worker) if worker else None,
            "worker_heartbeat_at": worker["heartbeat_at"] if worker else None,
        }

    def record_worker_heartbeat(
        self, worker_id: str, state: str, *, error: str | None = None
    ) -> None:
        if (
            not isinstance(worker_id, str)
            or not worker_id
            or len(worker_id) > 128
            or state not in {"running", "idle", "error"}
            or error is not None
            and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error)
        ):
            raise RouterConfigError("invalid_worker_heartbeat")
        now = _now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO router_worker_state(singleton,worker_id,state,heartbeat_at,last_tick_at,last_error_code,terminal_sweep_cursor) "
                "VALUES(1,?,?,?,?,?,NULL) ON CONFLICT(singleton) DO UPDATE SET worker_id=excluded.worker_id, "
                "state=excluded.state,heartbeat_at=excluded.heartbeat_at,last_tick_at=excluded.last_tick_at, "
                "last_error_code=excluded.last_error_code",
                (worker_id, state, now, now, error),
            )
            db.commit()

    def terminal_sweep_cursor(self) -> str | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT terminal_sweep_cursor FROM router_worker_state WHERE singleton=1"
            ).fetchone()
        return row["terminal_sweep_cursor"] if row else None

    def set_terminal_sweep_cursor(self, request_id: str) -> None:
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise RouterConfigError("invalid_worker_cursor")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE router_worker_state SET terminal_sweep_cursor=? WHERE singleton=1",
                (request_id,),
            )
            db.commit()

    @staticmethod
    def inspect(path: str | Path) -> dict[str, Any]:
        path = Path(path)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RouterConfigError("router_database_permissions_unsafe")
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            version = db.execute("PRAGMA user_version").fetchone()[0]
            journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            schema_matches = RouterStore._schema_matches(db, _V5_COLUMNS)
        finally:
            db.close()
        if (
            version != SCHEMA_VERSION
            or integrity != "ok"
            or journal_mode.lower() != "wal"
            or not schema_matches
        ):
            raise RouterConfigError("router_database_integrity_failed")
        return {
            "integrity": integrity,
            "schema": version,
            "journal_mode": journal_mode,
            "permissions": stat.S_IMODE(info.st_mode),
        }

    def check(self) -> dict[str, Any]:
        return self.inspect(self.path)

    @classmethod
    def read_active(cls, path: str | Path, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise RouterConfigError("invalid_arguments")
        cls.inspect(path)
        path = Path(path)
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            rows = db.execute(
                "SELECT * FROM router_requests WHERE state IN (?,?,?,?,?) "
                "ORDER BY updated_at,request_id LIMIT ?",
                (*ACTIVE_STATES, limit),
            )
            return [dict(row) for row in rows]
        finally:
            db.close()

    @classmethod
    def read_runtime_metrics(cls, path: str | Path) -> dict[str, Any]:
        cls.inspect(path)
        path = Path(path)
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            counts = {
                row["state"]: row["count"]
                for row in db.execute(
                    "SELECT state,COUNT(*) AS count FROM router_requests GROUP BY state"
                )
            }
            active = [
                dict(row)
                for row in db.execute(
                    "SELECT request_id,principal_id,instance_id,agent_id,state,issue_id,updated_at,last_error_code "
                    "FROM router_requests WHERE state IN "
                    "('switching','creating','waiting','reconciling','cancelling') ORDER BY updated_at DESC"
                )
            ]
            worker = db.execute(
                "SELECT worker_id,state,heartbeat_at,last_tick_at,last_error_code "
                "FROM router_worker_state WHERE singleton=1"
            ).fetchone()
        finally:
            db.close()
        return {
            "queue_depth": counts.get("queued", 0),
            "states": counts,
            "active": active,
            "worker": dict(worker) if worker else None,
            "worker_heartbeat_at": worker["heartbeat_at"] if worker else None,
        }

    def enqueue(
        self,
        *,
        request_id: str,
        key: str,
        principal_id: str,
        connector_id: str,
        instance_id: str,
        agent_id: str,
        agent_ref: str,
        route_id: str,
        project_id: str | None,
        payload: dict[str, Any],
        priority: int = 0,
        runtime_id: str | None = None,
        model: str | None = None,
        model_rule_id: str | None = None,
        model_source: str | None = None,
        model_reason: str | None = None,
        resolution: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        body = _encode(payload)
        immutable = {
            "payload": payload,
            "principal_id": principal_id,
            "connector_id": connector_id,
            "instance_id": instance_id,
            "agent_id": agent_id,
            "agent_ref": agent_ref,
            "route_id": route_id,
            "project_id": project_id,
            "priority": priority,
        }
        digest = hashlib.sha256(_encode(immutable).encode("utf-8")).hexdigest()
        now = _now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM router_requests WHERE idempotency_key=?", (key,)
            ).fetchone()
            if existing:
                if existing["payload_hash"] != digest:
                    raise RouterConfigError("request_conflict")
                db.commit()
                return dict(existing), False
            try:
                db.execute(
                    "INSERT INTO router_requests(request_id,idempotency_key,payload_hash,principal_id,connector_id,"
                    "instance_id,agent_id,agent_ref,route_id,target_runtime_id,target_model,project_id,payload_json,"
                    "target_model_rule_id,target_model_source,target_model_reason,state,priority,resolved_rule_id,"
                    "resolution_json,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'queued',?,?,?,?,?)",
                    (
                        request_id,
                        key,
                        digest,
                        principal_id,
                        connector_id,
                        instance_id,
                        agent_id,
                        agent_ref,
                        route_id,
                        runtime_id,
                        model,
                        project_id,
                        body,
                        model_rule_id,
                        model_source,
                        model_reason,
                        priority,
                        (resolution or {}).get("rule_id"),
                        _encode(resolution) if resolution else None,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RouterConfigError("agent_request_conflict") from exc
            self.event(
                db,
                request_id,
                "created",
                actor=principal_id,
                runtime_id=runtime_id,
                agent_id=agent_id,
                rule_id=(resolution or {}).get("rule_id"),
            )
            row = db.execute(
                "SELECT * FROM router_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            db.commit()
            return dict(row), True

    @staticmethod
    def event(
        db: sqlite3.Connection, request_id: str, event_type: str, **fields: Any
    ) -> None:
        db.execute(
            "INSERT INTO router_events(event_id,request_id,event_type,actor,rule_id,runtime_id,agent_id,"
            "issue_id,error_code,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                secrets.token_hex(16),
                request_id,
                event_type,
                fields.get("actor"),
                fields.get("rule_id"),
                fields.get("runtime_id"),
                fields.get("agent_id"),
                fields.get("issue_id"),
                fields.get("error_code"),
                _encode(fields.get("details", {}), limit=8192),
                _now(),
            ),
        )

    def record_event(
        self,
        request_id: str,
        event_type: str,
        *,
        error: str | None = None,
        issue_id: str | None = None,
        agent_id: str | None = None,
        runtime_id: str | None = None,
        rule_id: str | None = None,
        actor: str | None = None,
    ) -> None:
        if not event_type or len(event_type) > 64:
            raise RouterConfigError("invalid_event")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM router_requests WHERE request_id=?", (request_id,)
            ).fetchone():
                raise RouterConfigError("request_not_found")
            self.event(
                db,
                request_id,
                event_type,
                actor=actor,
                agent_id=agent_id,
                issue_id=issue_id,
                runtime_id=runtime_id,
                rule_id=rule_id,
                error_code=error,
            )
            db.commit()

    def claim_next(
        self, owner: str, lease_seconds: int, enabled_profiles: set[str] | None = None
    ) -> dict[str, Any] | None:
        now, token = _now(), secrets.token_urlsafe(24)
        if not owner or type(lease_seconds) is not int or lease_seconds < 30:
            raise RouterConfigError("invalid_lease")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            expired = db.execute(
                "SELECT request_id,state,agent_id FROM router_requests "
                "WHERE state IN ('switching','creating') AND lease_expires_at IS NOT NULL AND lease_expires_at<?",
                (now,),
            ).fetchall()
            for row in expired:
                db.execute(
                    "UPDATE router_requests SET last_error_code=?,state='reconciling',lease_owner=NULL,"
                    "lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL,updated_at=? "
                    "WHERE request_id=? AND state=?",
                    (
                        f"lease_expired:{row['state']}",
                        now,
                        row["request_id"],
                        row["state"],
                    ),
                )
                self.event(
                    db,
                    row["request_id"],
                    "recovered",
                    agent_id=row["agent_id"],
                    error_code=f"lease_expired:{row['state']}",
                )
            row = None
            offset = 0
            while row is None:
                candidates = db.execute(
                    "SELECT q.* FROM router_requests q WHERE q.state='queued' AND NOT EXISTS ("
                    "SELECT 1 FROM router_requests a WHERE a.instance_id=q.instance_id AND a.agent_id=q.agent_id "
                    "AND a.state IN ('switching','creating','waiting','reconciling','cancelling')) "
                    "ORDER BY q.priority DESC,q.created_at ASC,q.request_id ASC LIMIT 500 OFFSET ?",
                    (offset,),
                ).fetchall()
                if not candidates:
                    break
                for candidate in candidates:
                    if enabled_profiles is None:
                        row = candidate
                        break
                    try:
                        payload = json.loads(candidate["payload_json"])
                        profile = payload.get("source", {}).get("profile")
                    except (ValueError, TypeError, AttributeError, RecursionError):
                        continue
                    if profile in enabled_profiles:
                        row = candidate
                        break
                offset += len(candidates)
                if len(candidates) < 500:
                    break
            if row is None:
                db.commit()
                return None
            cursor = db.execute(
                "UPDATE router_requests SET state='switching',attempts=attempts+1,lease_owner=?,lease_token=?,"
                "lease_expires_at=?,heartbeat_at=?,updated_at=? WHERE request_id=? AND state='queued'",
                (owner, token, now + lease_seconds, now, now, row["request_id"]),
            )
            if cursor.rowcount != 1:
                db.rollback()
                return None
            self.event(
                db,
                row["request_id"],
                "switch_started",
                actor=owner,
                agent_id=row["agent_id"],
                runtime_id=row["target_runtime_id"],
            )
            claimed = dict(
                db.execute(
                    "SELECT * FROM router_requests WHERE request_id=?",
                    (row["request_id"],),
                ).fetchone()
            )
            db.commit()
            return claimed

    def transition(
        self,
        request_id: str,
        state: str,
        *,
        token: str | None = None,
        expected: set[str] | None = None,
        error: str | None = None,
        runtime_id: str | None = None,
        model: str | None = None,
        issue: dict[str, Any] | None = None,
        resolution: dict[str, Any] | None = None,
        lease_seconds: int = 900,
    ) -> bool:
        now = _now()
        if state not in _TRANSITIONS:
            raise RouterConfigError("invalid_request_state")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT * FROM router_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if (
                current is None
                or expected is not None
                and current["state"] not in expected
                or token is not None
                and current["lease_token"] != token
                or state not in _TRANSITIONS[current["state"]]
            ):
                db.rollback()
                return False
            keep_lock = state in ACTIVE_STATES
            lease_token = current["lease_token"] if keep_lock else None
            lease_owner = current["lease_owner"] if keep_lock else None
            lease_expires_at = current["lease_expires_at"] if keep_lock else None
            heartbeat_at = current["heartbeat_at"] if keep_lock else None
            if keep_lock and token is not None:
                if type(lease_seconds) is not int or not 30 <= lease_seconds <= 3600:
                    raise RouterConfigError("invalid_lease")
                lease_expires_at, heartbeat_at = now + lease_seconds, now
            issue_id = (issue or {}).get("id")
            issue_url = (issue or {}).get("url")
            db.execute(
                "UPDATE router_requests SET state=?,target_runtime_id=COALESCE(?,target_runtime_id),"
                "target_model=COALESCE(?,target_model),issue_id=COALESCE(?,issue_id),"
                "target_model_rule_id=COALESCE(?,target_model_rule_id),"
                "target_model_source=COALESCE(?,target_model_source),"
                "target_model_reason=COALESCE(?,target_model_reason),"
                "issue_url=COALESCE(?,issue_url),resolution_json=COALESCE(?,resolution_json),"
                "last_error_code=?,lease_owner=?,lease_token=?,lease_expires_at=?,heartbeat_at=?,"
                "cancel_source_state=CASE WHEN ? IN ('queued','done','failed','cancelled') "
                "THEN NULL ELSE cancel_source_state END,"
                "reconcile_source_state=CASE WHEN ?='reconciling' AND reconcile_source_state IS NULL "
                "THEN CASE WHEN state='cancelling' THEN COALESCE(cancel_source_state,state) ELSE state END "
                "WHEN ? IN ('queued','waiting','done','failed','cancelled') THEN NULL "
                "ELSE reconcile_source_state END,updated_at=? "
                "WHERE request_id=?",
                (
                    state,
                    runtime_id,
                    model,
                    issue_id,
                    (resolution or {}).get("model_rule_id"),
                    (resolution or {}).get("model_source"),
                    (resolution or {}).get("model_reason"),
                    issue_url,
                    _encode(resolution) if resolution else None,
                    error,
                    lease_owner,
                    lease_token,
                    lease_expires_at,
                    heartbeat_at,
                    state,
                    state,
                    state,
                    now,
                    request_id,
                ),
            )
            self.event(
                db,
                request_id,
                state,
                agent_id=current["agent_id"],
                issue_id=issue_id,
                runtime_id=runtime_id,
                error_code=error,
            )
            db.commit()
            return True

    def cancel(self, request_id: str) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,agent_id,cancel_source_state,reconcile_source_state,last_error_code "
                "FROM router_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise RouterConfigError("request_not_found")
            current = row["state"]
            if current in TERMINAL_STATES:
                db.commit()
                return current
            if current in {"queued", "blocked"}:
                next_state = "cancelled"
                cancel_source = None
            elif current == "reconciling":
                # Keep the agent lock until the worker has checked for an issue
                # accepted by Multica but not yet visible in the read API.
                next_state = "reconciling"
                cancel_source = (
                    row["cancel_source_state"]
                    or row["reconcile_source_state"]
                    or "reconciling"
                )
            elif current in {"switching", "creating", "waiting", "cancelling"}:
                next_state = "cancelling"
                cancel_source = row["cancel_source_state"] or current
            else:
                raise RouterConfigError("request_cannot_be_cancelled")
            if next_state != current and next_state not in _TRANSITIONS.get(
                current, set()
            ):
                raise RouterConfigError("request_cannot_be_cancelled")
            db.execute(
                "UPDATE router_requests SET state=?,cancel_source_state=?,"
                "last_error_code=CASE WHEN ?='cancelled' THEN NULL ELSE last_error_code END,updated_at=? "
                "WHERE request_id=?",
                (next_state, cancel_source, next_state, _now(), request_id),
            )
            self.event(
                db,
                request_id,
                "cancel_requested" if next_state == current else next_state,
                agent_id=row["agent_id"],
                error_code=row["last_error_code"],
            )
            db.commit()
            return next_state

    def requeue_blocked(self, request_id: str) -> bool:
        """Requeue a pre-creation policy block after an operator fixes its cause."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,issue_id,agent_id,instance_id FROM router_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise RouterConfigError("request_not_found")
            if row["state"] != "blocked" or row["issue_id"]:
                db.rollback()
                return False
            now = _now()
            db.execute(
                "UPDATE router_requests SET state='queued',last_error_code=NULL,updated_at=? "
                "WHERE request_id=? AND state='blocked' AND issue_id IS NULL",
                (now, request_id),
            )
            self.event(db, request_id, "requeued", agent_id=row["agent_id"])
            db.commit()
            return True

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM router_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            return dict(row) if row else None

    def request_for_issue(self, issue_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM router_requests WHERE issue_id=?", (issue_id,)
            ).fetchone()
            return dict(row) if row else None

    def active_attachment_paths(self) -> set[str]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload_json FROM router_requests WHERE state NOT IN ('done','failed','cancelled')"
            ).fetchall()
        paths: set[str] = set()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (ValueError, TypeError, RecursionError):
                raise RouterConfigError("router_database_payload_invalid") from None
            attachments = (
                payload.get("attachments", []) if isinstance(payload, dict) else None
            )
            if not isinstance(attachments, list):
                raise RouterConfigError("router_database_payload_invalid")
            for item in attachments:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    raise RouterConfigError("router_database_payload_invalid")
                paths.add(item["path"])
        return paths

    def queue_position(self, request_id: str) -> int:
        with self.connect() as db:
            row = db.execute(
                "SELECT priority,created_at,request_id,instance_id,agent_id FROM router_requests "
                "WHERE request_id=? AND state='queued'",
                (request_id,),
            ).fetchone()
            if row is None:
                return 0
            ahead = db.execute(
                "SELECT COUNT(*) FROM router_requests WHERE state='queued' AND instance_id=? AND agent_id=? AND "
                "(priority>? OR (priority=? AND created_at<?) OR "
                "(priority=? AND created_at=? AND request_id<=?))",
                (
                    row["instance_id"],
                    row["agent_id"],
                    row["priority"],
                    row["priority"],
                    row["created_at"],
                    row["priority"],
                    row["created_at"],
                    request_id,
                ),
            ).fetchone()[0]
            return int(ahead)

    def list_queue(self, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT request_id,state,priority,instance_id,agent_id,route_id,issue_id,last_error_code,created_at,updated_at "
                    "FROM router_requests ORDER BY created_at DESC,request_id DESC LIMIT ?",
                    (limit,),
                )
            ]

    def list_requests_for_principal(
        self, principal_id: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT request_id,instance_id,agent_id,route_id,project_id,target_runtime_id,state,issue_id,"
                    "last_error_code,created_at,updated_at FROM router_requests WHERE principal_id=? "
                    "ORDER BY created_at DESC,request_id DESC LIMIT ?",
                    (principal_id, limit),
                )
            ]

    def identity(
        self, connector_id: str, platform_user_id: str
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT i.*,p.status AS principal_status,p.display_name FROM principal_identities i "
                "JOIN principals p USING(principal_id) WHERE i.connector_id=? AND i.platform_user_id=?",
                (connector_id, platform_user_id),
            ).fetchone()
            if (
                not row
                or row["status"] != "active"
                or row["principal_status"] != "active"
            ):
                return None
            return dict(row)

    def binding(self, principal_id: str, instance_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM runtime_bindings WHERE principal_id=? AND instance_id=?",
                (principal_id, instance_id),
            ).fetchone()
            return dict(row) if row else None

    def exceptions(self, binding_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM runtime_exceptions WHERE binding_id=? AND enabled=1",
                (binding_id,),
            ).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            try:
                value["selectors"] = json.loads(value.pop("selectors_json"))
            except (ValueError, TypeError, RecursionError):
                raise RouterConfigError("router_database_policy_invalid") from None
            result.append(value)
        return result

    def request_context(self, request_id: str) -> dict[str, Any] | None:
        return self.get(request_id)

    def active(
        self, limit: int = 8, *, after_request_id: str | None = None
    ) -> list[dict[str, Any]]:
        if (
            type(limit) is not int
            or not 1 <= limit <= 100
            or after_request_id is not None
            and (
                not isinstance(after_request_id, str)
                or not after_request_id
                or len(after_request_id) > 128
            )
        ):
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            if after_request_id is None:
                rows = db.execute(
                    "SELECT * FROM router_requests WHERE state IN (?,?,?,?,?) "
                    "ORDER BY request_id LIMIT ?",
                    (*ACTIVE_STATES, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM router_requests WHERE state IN (?,?,?,?,?) "
                    "AND request_id>? ORDER BY request_id LIMIT ?",
                    (*ACTIVE_STATES, after_request_id, limit),
                ).fetchall()
                if len(rows) < limit:
                    wrapped = db.execute(
                        "SELECT * FROM router_requests WHERE state IN (?,?,?,?,?) "
                        "AND request_id<=? ORDER BY request_id LIMIT ?",
                        (*ACTIVE_STATES, after_request_id, limit - len(rows)),
                    ).fetchall()
                    rows.extend(wrapped)
            return [dict(row) for row in rows]

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise RouterConfigError("invalid_arguments")
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT event_id,request_id,event_type,actor,rule_id,runtime_id,agent_id,issue_id,error_code,created_at "
                    "FROM router_events ORDER BY created_at DESC,event_id DESC LIMIT ?",
                    (limit,),
                )
            ]
