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
from .wake import verify_webhook_policy

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
WAKE_SCHEMA_V2 = {
    "wake_subscriptions": """subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id),
        profile TEXT NOT NULL CHECK(profile IN ('default','om73')), route TEXT NOT NULL UNIQUE,
        statuses_json TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        enabled_since REAL, disabled_reason TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL, updated_at REAL NOT NULL""",
    "wake_jobs": """id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL REFERENCES wake_subscriptions(subscription_id),
        event_key TEXT NOT NULL, issue_id TEXT NOT NULL, issue_key TEXT NOT NULL,
        transition_seq INTEGER NOT NULL, payload_json TEXT,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','delivery_unknown','dead','cancelled')),
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL, lease_until REAL, lease_token TEXT,
        last_error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        UNIQUE(subscription_id,event_key)""",
}
WAKE_SCHEMA = {
    "wake_subscriptions": """subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id),
        profile TEXT NOT NULL CHECK(profile IN ('default','om73')), route TEXT NOT NULL UNIQUE,
        statuses_json TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        enabled_since REAL, disabled_reason TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL, updated_at REAL NOT NULL,
        completion_filter TEXT NOT NULL DEFAULT 'any'""",
    "wake_jobs": WAKE_SCHEMA_V2["wake_jobs"],
}
APPROVAL_SCHEMA_V4 = {
    "approval_mappings": """mapping_id TEXT PRIMARY KEY,
        connection_id TEXT NOT NULL, workspace_id TEXT NOT NULL, workspace_key TEXT NOT NULL REFERENCES workspaces(id),
        source_profile TEXT NOT NULL CHECK(source_profile IN ('default','om73')),
        parent_issue_id TEXT NOT NULL, wakeup_id TEXT NOT NULL, route_id TEXT NOT NULL,
        subscription_id TEXT NOT NULL REFERENCES subscriptions(id), instruction TEXT NOT NULL,
        expires_at REAL, child_ids_json TEXT NOT NULL, tree_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','ready','delivered','delivery_unknown','blocked')),
        last_run_id TEXT, delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK(delivery_status IN ('pending','delivered','delivery_unknown','dead','blocked')),
        detail TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        UNIQUE(connection_id,workspace_id,source_profile,parent_issue_id),
        UNIQUE(connection_id,workspace_id,source_profile,wakeup_id)""",
    "approval_jobs": """id TEXT PRIMARY KEY, mapping_id TEXT NOT NULL REFERENCES approval_mappings(mapping_id),
        event_key TEXT NOT NULL, run_id TEXT NOT NULL, payload_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','delivered','dead','delivery_unknown')),
        attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, lease_token TEXT,
        last_error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        UNIQUE(mapping_id,event_key), UNIQUE(mapping_id,run_id)""",
}
APPROVAL_SCHEMA = {
    "approval_mappings": """mapping_id TEXT PRIMARY KEY,
        connection_id TEXT NOT NULL, workspace_id TEXT NOT NULL, workspace_key TEXT NOT NULL REFERENCES workspaces(id),
        source_profile TEXT NOT NULL CHECK(source_profile IN ('default','om73')),
        parent_issue_id TEXT NOT NULL, wakeup_id TEXT NOT NULL, route_id TEXT NOT NULL,
        subscription_id TEXT NOT NULL REFERENCES subscriptions(id), instruction TEXT NOT NULL,
        expires_at REAL, child_ids_json TEXT NOT NULL, tree_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','ready','delivered','delivery_unknown','blocked')),
        last_run_id TEXT, delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK(delivery_status IN ('pending','delivered','delivery_unknown','dead','blocked')),
        detail TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        agent_id TEXT NOT NULL DEFAULT '', project_id TEXT NOT NULL DEFAULT '', next_check_at REAL,
        UNIQUE(connection_id,workspace_id,source_profile,parent_issue_id),
        UNIQUE(connection_id,workspace_id,source_profile,wakeup_id)""",
    "approval_jobs": """id TEXT PRIMARY KEY, mapping_id TEXT NOT NULL REFERENCES approval_mappings(mapping_id),
        event_key TEXT NOT NULL, run_id TEXT NOT NULL, payload_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','delivered','dead','delivery_unknown')),
        attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, lease_token TEXT,
        last_error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        next_check_at REAL,
        UNIQUE(mapping_id,event_key), UNIQUE(mapping_id,run_id)""",
}
INDEXES_V1 = {
    "due": "CREATE INDEX due ON notifications(status,next_attempt_at)",
    "subscription_workspace": "CREATE INDEX subscription_workspace ON subscriptions(workspace_id,enabled)",
    "pending_hint_workspace": "CREATE INDEX pending_hint_workspace ON hints(workspace_id,status)",
}
WAKE_INDEXES = {
    "wake_due": "CREATE INDEX wake_due ON wake_jobs(status,next_attempt_at)",
    "wake_subscription_created": "CREATE INDEX wake_subscription_created ON wake_jobs(subscription_id,created_at)",
}
APPROVAL_INDEXES_V4 = {
    "approval_due": "CREATE INDEX approval_due ON approval_jobs(status,created_at)",
    "approval_workspace": "CREATE INDEX approval_workspace ON approval_mappings(workspace_key,status,updated_at)",
}
APPROVAL_INDEXES = {
    "approval_due": "CREATE INDEX approval_due ON approval_jobs(status,next_check_at,created_at)",
    "approval_workspace": "CREATE INDEX approval_workspace ON approval_mappings(workspace_key,status,next_check_at)",
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
            accepted_schemas = {
                1: SCHEMA,
                2: SCHEMA | WAKE_SCHEMA_V2,
                3: SCHEMA | WAKE_SCHEMA,
                4: SCHEMA | WAKE_SCHEMA | APPROVAL_SCHEMA_V4,
                5: SCHEMA | WAKE_SCHEMA | APPROVAL_SCHEMA,
            }
            require(
                (not tables and version == 0 and create)
                or (version in accepted_schemas and tables == set(accepted_schemas[version])),
                "notify_migration_failed",
            )
            if tables:
                schema = accepted_schemas[version]
                expected_indexes = (
                    INDEXES_V1 if version == 1 else
                    INDEXES_V1 | WAKE_INDEXES if version in {2, 3} else
                    INDEXES_V1 | WAKE_INDEXES | (APPROVAL_INDEXES_V4 if version == 4 else APPROVAL_INDEXES)
                )
                reference = sqlite3.connect(":memory:")
                try:
                    for table, columns in schema.items():
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
                    current_indexes = {
                        row["name"]: row["sql"]
                        for row in self.db.execute(
                            "SELECT name,sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
                        )
                    }
                    require(set(current_indexes) == set(expected_indexes), "notify_migration_failed")
                    for index, statement in expected_indexes.items():
                        reference.execute(statement)
                        reference_sql = reference.execute(
                            "SELECT sql FROM sqlite_master WHERE name=?", (index,)
                        ).fetchone()[0]
                        require(
                            " ".join(current_indexes[index].split())
                            == " ".join(reference_sql.split()),
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
                    for table, columns in (SCHEMA | WAKE_SCHEMA | APPROVAL_SCHEMA).items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    for statement in (INDEXES_V1 | WAKE_INDEXES | APPROVAL_INDEXES).values():
                        self.db.execute(statement)
                    self.db.execute("PRAGMA user_version=5")
            elif version == 1:
                # Accept only the exact shipped 0.4.0 schema, then apply the
                # known wake and approval additions atomically.
                with self.transaction():
                    for table, columns in WAKE_SCHEMA_V2.items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    for statement in WAKE_INDEXES.values():
                        self.db.execute(statement)
                    self.db.execute(
                        "ALTER TABLE wake_subscriptions ADD COLUMN completion_filter TEXT NOT NULL DEFAULT 'any'"
                    )
                    for table, columns in APPROVAL_SCHEMA.items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    for statement in APPROVAL_INDEXES.values():
                        self.db.execute(statement)
                    self.db.execute("PRAGMA user_version=5")
            elif version == 2:
                # Upgrade the exact shipped 0.5.0 wake schema without replacing rows.
                with self.transaction():
                    self.db.execute(
                        "ALTER TABLE wake_subscriptions ADD COLUMN completion_filter TEXT NOT NULL DEFAULT 'any'"
                    )
                    for table, columns in APPROVAL_SCHEMA.items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    for statement in APPROVAL_INDEXES.values():
                        self.db.execute(statement)
                    self.db.execute("PRAGMA user_version=5")
            elif version == 3:
                # Add only approval mapping/outbox storage; existing notify rows remain untouched.
                with self.transaction():
                    for table, columns in APPROVAL_SCHEMA.items():
                        self.db.execute(f"CREATE TABLE {table} ({columns})")
                    for statement in APPROVAL_INDEXES.values():
                        self.db.execute(statement)
                    self.db.execute("PRAGMA user_version=5")
            elif version == 4:
                # Preserve v4 approval receipts but block mappings that lack the
                # agent/project identity required for a safe read-only correlation.
                with self.transaction():
                    self.db.execute("DROP INDEX approval_due")
                    self.db.execute("DROP INDEX approval_workspace")
                    self.db.execute("ALTER TABLE approval_mappings ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")
                    self.db.execute("ALTER TABLE approval_mappings ADD COLUMN project_id TEXT NOT NULL DEFAULT ''")
                    self.db.execute("ALTER TABLE approval_mappings ADD COLUMN next_check_at REAL")
                    self.db.execute("ALTER TABLE approval_jobs ADD COLUMN next_check_at REAL")
                    self.db.execute(
                        "UPDATE approval_mappings SET status='blocked',delivery_status='blocked',"
                        "detail='approval_mapping_legacy_unverified',updated_at=? WHERE status IN ('pending','ready')",
                        (time.time(),),
                    )
                    self.db.execute(
                        "UPDATE approval_jobs SET status='dead',last_error='approval_mapping_legacy_unverified',updated_at=? "
                        "WHERE status='pending' AND mapping_id IN (SELECT mapping_id FROM approval_mappings WHERE status='blocked')",
                        (time.time(),),
                    )
                    for statement in APPROVAL_INDEXES.values():
                        self.db.execute(statement)
                    self.db.execute("PRAGMA user_version=5")
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

    @staticmethod
    def _cancel_wake(db, sid: str, reason: str) -> None:
        now = time.time()
        db.execute(
            "UPDATE wake_subscriptions SET enabled=0,disabled_reason=?,updated_at=? WHERE subscription_id=?",
            (reason, now, sid),
        )
        db.execute(
            "UPDATE wake_jobs SET status='cancelled',last_error=?,updated_at=? WHERE subscription_id=? AND status='pending'",
            (reason, now, sid),
        )

    def toggle(self, sid: str, enabled: bool) -> None:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM subscriptions WHERE id=?", (sid,)
            ).fetchone()
            require(row is not None, "notify_subscription_invalid")
            if not enabled:
                self._disable(db, sid, "subscription_disabled")
                self._cancel_wake(db, sid, "subscription_disabled")
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

    def project_wake_routes(self, routes: dict[str, dict]) -> None:
        by_route = {value["route"]: value for value in routes.values()}
        with self.transaction() as db:
            rows = db.execute(
                """SELECT ws.subscription_id,ws.route,ws.profile,ws.completion_filter,
                s.enabled AS source_enabled,
                a.configured AS account_configured,w.configured AS workspace_configured,
                w.enabled AS workspace_enabled FROM wake_subscriptions ws
                JOIN subscriptions s ON s.id=ws.subscription_id
                JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id"""
            ).fetchall()
            for row in rows:
                route = by_route.get(row["route"])
                reason = ""
                if route is None:
                    reason = "wake_route_removed"
                elif route["profile"] != row["profile"]:
                    reason = "wake_route_profile_mismatch"
                elif route.get("completion_filter", "any") != row["completion_filter"]:
                    reason = "wake_completion_filter_changed"
                elif not row["source_enabled"]:
                    reason = "subscription_disabled"
                elif not row["account_configured"] or not row["workspace_configured"] or not row["workspace_enabled"]:
                    reason = "orphaned_subscription"
                if reason:
                    self._cancel_wake(db, row["subscription_id"], reason)

    @staticmethod
    def _wake_metric(db, key: str, amount: int = 1) -> None:
        if amount:
            db.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+excluded.value",
                ("metric:" + key, str(amount)),
            )

    def add_wake_subscription(
        self, subscription_id: str, route_config: dict, *, enabled: bool = False, now: float | None = None
    ) -> str:
        now = now or time.time()
        profile, route = route_config.get("profile"), route_config.get("route")
        completion_filter = route_config.get("completion_filter", "any")
        require(profile in {"default", "om73"} and isinstance(route, str), "wake_subscription_invalid")
        require(completion_filter in {"any", "root_only", "explicit_issues"}, "wake_subscription_invalid")
        try:
            with self.transaction() as db:
                source = db.execute(
                    """SELECT s.*,a.platform AS account_platform,a.configured AS account_configured,
                    w.configured AS workspace_configured,w.enabled AS workspace_enabled
                    FROM subscriptions s JOIN accounts a ON a.name=s.account
                    JOIN workspaces w ON w.id=s.workspace_id WHERE s.id=?""",
                    (subscription_id,),
                ).fetchone()
                require(source is not None, "wake_subscription_invalid")
                require(
                    source["enabled"] == 1
                    and source["account_configured"] == 1
                    and source["workspace_configured"] == 1
                    and source["workspace_enabled"] == 1
                    and source["project_id"]
                    and source["platform"] == source["account_platform"],
                    "wake_subscription_invalid",
                )
                require(
                    (source["platform"] == "telegram" and source["chat_type"] == "thread" and bool(source["thread_id"]))
                    or (source["platform"] == "max" and source["chat_type"] in {"group", "dm"} and not source["thread_id"]),
                    "wake_destination_invalid",
                )
                existing = db.execute(
                    "SELECT profile,route,enabled,completion_filter FROM wake_subscriptions WHERE subscription_id=?",
                    (subscription_id,),
                ).fetchone()
                if existing:
                    require(
                        existing["profile"] == profile
                        and existing["route"] == route
                        and existing["completion_filter"] == completion_filter,
                        "wake_subscription_conflict",
                    )
                    if enabled and not existing["enabled"]:
                        db.execute(
                            "UPDATE wake_subscriptions SET enabled=1,enabled_since=?,disabled_reason='',updated_at=? WHERE subscription_id=?",
                            (now, now, subscription_id),
                        )
                        db.execute(
                            "UPDATE wake_jobs SET status='cancelled',last_error='wake_reenabled',updated_at=? WHERE subscription_id=? AND status='pending'",
                            (now, subscription_id),
                        )
                    return subscription_id
                db.execute(
                    """INSERT INTO wake_subscriptions
                    (subscription_id,profile,route,statuses_json,enabled,enabled_since,created_at,updated_at,completion_filter)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        subscription_id,
                        profile,
                        route,
                        encoded(["done"]),
                        int(enabled),
                        now if enabled else None,
                        now,
                        now,
                        completion_filter,
                    ),
                )
                db.execute(
                    "UPDATE notifications SET status='cancelled',payload_json=NULL,last_error='wake_subscription_registered',updated_at=? WHERE subscription_id=? AND status IN ('pending','retry')",
                    (now, subscription_id),
                )
                self._wake_metric(db, "wake_registered")
        except sqlite3.IntegrityError:
            raise NotifyError("wake_subscription_conflict") from None
        return subscription_id

    def set_wake_enabled(
        self, subscription_id: str, enabled: bool, routes: dict[str, dict], *, now: float | None = None
    ) -> None:
        now = now or time.time()
        with self.transaction() as db:
            row = db.execute(
                """SELECT ws.*,s.enabled AS source_enabled,s.account,s.workspace_id,
                a.configured AS account_configured,w.configured AS workspace_configured,
                w.enabled AS workspace_enabled FROM wake_subscriptions ws
                JOIN subscriptions s ON s.id=ws.subscription_id JOIN accounts a ON a.name=s.account
                JOIN workspaces w ON w.id=s.workspace_id WHERE ws.subscription_id=?""",
                (subscription_id,),
            ).fetchone()
            require(row is not None, "wake_subscription_invalid")
            if not enabled:
                self._cancel_wake(db, subscription_id, "wake_disabled")
                return
            route = next((r for r in routes.values() if r["route"] == row["route"]), None)
            require(
                route is not None
                and route["profile"] == row["profile"]
                and row["source_enabled"] == 1
                and row["account_configured"] == 1
                and row["workspace_configured"] == 1
                and row["workspace_enabled"] == 1,
                "wake_route_unavailable",
            )
            if row["enabled"]:
                return
            db.execute(
                "UPDATE wake_jobs SET status='cancelled',last_error='wake_reenabled',updated_at=? WHERE subscription_id=? AND status='pending'",
                (now, subscription_id),
            )
            db.execute(
                "UPDATE wake_subscriptions SET enabled=1,enabled_since=?,disabled_reason='',updated_at=? WHERE subscription_id=?",
                (now, now, subscription_id),
            )

    def wake_subscriptions(self) -> list[dict]:
        return self.rows(
            """SELECT ws.subscription_id,ws.profile,ws.route,ws.statuses_json,ws.enabled,
            ws.completion_filter,
            ws.enabled_since,ws.disabled_reason,ws.created_at,ws.updated_at,s.label,s.workspace_id
            FROM wake_subscriptions ws JOIN subscriptions s ON s.id=ws.subscription_id
            ORDER BY ws.created_at"""
        )

    def wake_binding(self, subscription_id: str) -> dict:
        rows = self.rows(
            """SELECT ws.profile,ws.route,ws.completion_filter,s.platform,s.chat_id,s.thread_id,s.chat_type,
            s.workspace_id,s.project_id,s.enabled FROM wake_subscriptions ws
            JOIN subscriptions s ON s.id=ws.subscription_id WHERE ws.subscription_id=?""",
            (subscription_id,),
        )
        require(bool(rows), "wake_subscription_invalid")
        return rows[0]

    def subscription_destination(self, subscription_id: str) -> dict:
        rows = self.rows(
            """SELECT platform,chat_id,thread_id,chat_type,workspace_id,project_id,enabled
            FROM subscriptions WHERE id=?""",
            (subscription_id,),
        )
        require(bool(rows), "wake_subscription_invalid")
        return rows[0]

    def wake_due(self, now: float, limit: int = 100) -> list[dict]:
        return self.rows(
            """SELECT j.id,j.subscription_id,j.event_key,j.issue_id,j.issue_key,j.transition_seq,
            ws.profile,ws.route,
            j.payload_json,j.attempts,j.next_attempt_at FROM wake_jobs j
            JOIN wake_subscriptions ws ON ws.subscription_id=j.subscription_id
            JOIN subscriptions s ON s.id=ws.subscription_id
            JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
            WHERE j.status='pending' AND COALESCE(j.next_attempt_at,0)<=?
            AND ws.enabled=1 AND ws.enabled_since IS NOT NULL AND s.enabled=1
            AND a.configured=1 AND w.configured=1 AND w.enabled=1
            ORDER BY j.created_at LIMIT ?""",
            (now, min(max(1, limit), 100)),
        )

    def wake_defer_unclaimed(self, job_id: str, code: str, delay: int = 30) -> None:
        now = time.time()
        with self.transaction() as db:
            db.execute(
                "UPDATE wake_jobs SET next_attempt_at=?,last_error=?,updated_at=? WHERE id=? AND status='pending'",
                (now + min(max(1, delay), 300), code, now, job_id),
            )

    def wake_claim(
        self,
        job_id: str,
        now: float,
        lease_seconds: int,
        routes: dict[str, dict],
        webhook_policy: dict[tuple[str, str], dict],
    ) -> dict | None:
        by_route = {row["route"]: row for row in routes.values()}
        with self.transaction() as db:
            row = db.execute(
                """SELECT j.*,ws.profile,ws.route,ws.enabled AS wake_enabled,ws.enabled_since,
                s.platform AS source_platform,s.account AS source_account,s.chat_id AS source_chat_id,
                s.thread_id AS source_thread_id,s.chat_type AS source_chat_type,s.workspace_id AS source_workspace,
                s.project_id AS source_project,s.enabled AS source_enabled,a.platform AS account_platform,
                a.configured AS account_configured,w.configured AS workspace_configured,w.enabled AS workspace_enabled
                FROM wake_jobs j JOIN wake_subscriptions ws ON ws.subscription_id=j.subscription_id
                JOIN subscriptions s ON s.id=ws.subscription_id JOIN accounts a ON a.name=s.account
                JOIN workspaces w ON w.id=s.workspace_id WHERE j.id=?""",
                (job_id,),
            ).fetchone()
            if row is None or row["status"] != "pending" or row["payload_json"] is None:
                return None
            route = by_route.get(row["route"])
            if not (
                route
                and route["profile"] == row["profile"]
                and row["wake_enabled"] == 1
                and row["enabled_since"] is not None
                and row["source_enabled"] == 1
                and row["account_configured"] == 1
                and row["workspace_configured"] == 1
                and row["workspace_enabled"] == 1
                and row["source_platform"] == row["account_platform"]
            ):
                return None
            try:
                verify_webhook_policy(
                    webhook_policy,
                    row["profile"],
                    row["route"],
                    {
                        "platform": row["source_platform"],
                        "chat_id": row["source_chat_id"],
                        "thread_id": row["source_thread_id"],
                        "chat_type": row["source_chat_type"],
                    },
                )
            except NotifyError as exc:
                db.execute(
                    "UPDATE wake_jobs SET status='dead',last_error=?,updated_at=? WHERE id=? AND status='pending'",
                    (exc.code, now, job_id),
                )
                self._wake_metric(db, "wake_dead")
                self._wake_metric(db, exc.code)
                return None
            token = str(uuid.uuid4())
            changed = db.execute(
                """UPDATE wake_jobs SET status='sending',attempts=attempts+1,
                lease_until=?,lease_token=?,next_attempt_at=NULL,last_error='',updated_at=?
                WHERE id=? AND status='pending' AND attempts=0""",
                (now + lease_seconds, token, now, job_id),
            )
            if changed.rowcount != 1:
                return None
            return dict(row) | {
                "attempts": row["attempts"] + 1,
                "lease_token": token,
                "payload_json": row["payload_json"],
            }

    def wake_finish(
        self, claim: dict, status: str, error_code: str = "", *, now: float | None = None
    ) -> bool:
        require(status in {"sent", "dead", "delivery_unknown"}, "wake_result_invalid")
        now = now or time.time()
        with self.transaction() as db:
            payload = None if status == "sent" else claim.get("payload_json")
            changed = db.execute(
                """UPDATE wake_jobs SET status=?,payload_json=?,last_error=?,lease_until=NULL,
                lease_token=NULL,updated_at=? WHERE id=? AND status='sending' AND lease_token=? AND attempts=?""",
                (status, payload, error_code, now, claim["id"], claim["lease_token"], claim["attempts"]),
            )
            if changed.rowcount:
                metric = {
                    "sent": "wake_sent",
                    "dead": "wake_dead",
                    "delivery_unknown": "wake_unknown",
                }[status]
                self._wake_metric(db, metric)
                if error_code == "wake_route_ignored":
                    self._wake_metric(db, "wake_route_ignored")
            return changed.rowcount == 1

    def wake_expire(self, now: float) -> int:
        with self.transaction() as db:
            changed = db.execute(
                """UPDATE wake_jobs SET status='delivery_unknown',last_error='wake_sender_lease_expired',
                lease_until=NULL,lease_token=NULL,updated_at=? WHERE status='sending' AND lease_until<=?""",
                (now, now),
            ).rowcount
            self._wake_metric(db, "wake_unknown", changed)
            return changed

    def wake_replay(
        self, job_id: str, retention_days: int, routes: dict[str, dict], *, now: float | None = None
    ) -> bool:
        now = now or time.time()
        by_route = {row["route"]: row for row in routes.values()}
        with self.transaction() as db:
            row = db.execute(
                """SELECT j.*,ws.enabled AS wake_enabled,ws.route,ws.profile,s.enabled AS source_enabled,
                a.configured AS account_configured,w.configured AS workspace_configured,w.enabled AS workspace_enabled
                FROM wake_jobs j JOIN wake_subscriptions ws ON ws.subscription_id=j.subscription_id
                JOIN subscriptions s ON s.id=ws.subscription_id JOIN accounts a ON a.name=s.account
                JOIN workspaces w ON w.id=s.workspace_id WHERE j.id=?""",
                (job_id,),
            ).fetchone()
            require(
                row is not None
                and row["status"] in {"dead", "delivery_unknown"}
                and row["payload_json"]
                and now - row["updated_at"] <= retention_days * 86400
                and row["wake_enabled"] == 1
                and row["source_enabled"] == 1
                and row["account_configured"] == 1
                and row["workspace_configured"] == 1
                and row["workspace_enabled"] == 1
                and (route := by_route.get(row["route"])) is not None
                and route["profile"] == row["profile"],
                "wake_replay_unavailable",
            )
            try:
                payload = json.loads(row["payload_json"])
            except (ValueError, TypeError):
                raise NotifyError("wake_replay_unavailable") from None
            require(
                isinstance(payload, dict)
                and payload.get("wake_id") == row["id"]
                and payload.get("event_type") == "task.completed"
                and isinstance(payload.get("snapshot"), dict),
                "wake_replay_unavailable",
            )
            changed = db.execute(
                """UPDATE wake_jobs SET status='pending',attempts=0,next_attempt_at=NULL,
                lease_until=NULL,lease_token=NULL,last_error='',updated_at=? WHERE id=? AND status IN ('dead','delivery_unknown')""",
                (now, job_id),
            )
            if changed.rowcount:
                self._wake_metric(db, "wake_replayed")
            return changed.rowcount == 1

    def wake_status(self) -> dict:
        return {
            "subscriptions": self.rows(
                "SELECT enabled,COUNT(*) AS count FROM wake_subscriptions GROUP BY enabled"
            ),
            "jobs": self.rows(
                "SELECT status,COUNT(*) AS count,MIN(created_at) AS oldest FROM wake_jobs GROUP BY status"
            ),
            "metrics": self.rows(
                "SELECT key,value FROM metadata WHERE key LIKE 'metric:wake_%' ORDER BY key"
            ),
        }

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
            wake_registered = db.execute(
                "SELECT 1 FROM wake_subscriptions WHERE subscription_id=?",
                (row["subscription_id"],),
            ).fetchone()
            if wake_registered:
                # A live attempt may finish, but neither retries nor lease takeovers
                # may restart ordinary delivery after the wake cutover.
                if row["status"] in {"pending", "retry"} or (
                    row["status"] == "sending" and (row["lease_until"] or 0) <= now
                ):
                    db.execute(
                        "UPDATE notifications SET status='cancelled',last_error='wake_subscription_registered',updated_at=? WHERE id=?",
                        (now, nid),
                    )
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
            elif db.execute(
                "SELECT 1 FROM wake_subscriptions WHERE subscription_id=?",
                (row["subscription_id"],),
            ).fetchone():
                status, detail = "cancelled", "wake_subscription_registered"
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

    def prune_wake(self, now: float | None = None) -> None:
        now = now or time.time()
        with self.transaction() as db:
            # Terminal receipts remain for the life of their subscription; only the
            # replayable request body is removed after the operator replay window.
            db.execute(
                """UPDATE wake_jobs SET payload_json=NULL WHERE status IN ('dead','delivery_unknown','cancelled')
                AND payload_json IS NOT NULL AND updated_at<?""",
                (now - 30 * 86400,),
            )

    def approval_route(self, profile: str, route: str) -> dict | None:
        rows = self.rows(
            """SELECT ws.subscription_id,ws.profile,ws.route,ws.enabled AS wake_enabled,
                s.*,w.id AS workspace_key,w.origin,w.workspace_id AS external_workspace_id,w.data_json AS workspace_data,
                w.configured AS workspace_configured,w.enabled AS workspace_enabled,
                a.configured AS account_configured,a.platform AS account_platform
                FROM wake_subscriptions ws JOIN subscriptions s ON s.id=ws.subscription_id
                JOIN workspaces w ON w.id=s.workspace_id JOIN accounts a ON a.name=s.account
                WHERE ws.profile=? AND ws.route=? LIMIT 2""",
            (profile, route),
        )
        return rows[0] if len(rows) == 1 else None

    def approval_mapping(
        self, connection_id: str, workspace_id: str, profile: str, parent_issue_id: str,
    ) -> dict | None:
        rows = self.rows(
            """SELECT * FROM approval_mappings WHERE connection_id=? AND workspace_id=?
            AND source_profile=? AND parent_issue_id=?""",
            (connection_id, workspace_id, profile, parent_issue_id),
        )
        return rows[0] if len(rows) == 1 else None

    def put_approval_mapping(self, mapping: dict[str, Any]) -> tuple[str, bool]:
        """Insert an immutable, instance-namespaced approval mapping."""
        identity = (
            mapping["connection_id"], mapping["workspace_id"], mapping["source_profile"],
            mapping["parent_issue_id"],
        )
        immutable = (
            mapping["wakeup_id"], mapping["route_id"], mapping["subscription_id"],
            mapping["instruction"], mapping["agent_id"], mapping["project_id"],
            mapping.get("expires_at"), mapping["child_ids_json"], mapping["tree_fingerprint"],
        )
        mapping_id = hashlib.sha256("\0".join(identity).encode("utf-8")).hexdigest()
        now = time.time()
        with self.transaction() as db:
            row = db.execute(
                """SELECT * FROM approval_mappings WHERE connection_id=? AND workspace_id=?
                AND source_profile=? AND parent_issue_id=?""",
                identity,
            ).fetchone()
            if row is not None:
                current = (
                    row["wakeup_id"], row["route_id"], row["subscription_id"], row["instruction"],
                    row["agent_id"], row["project_id"], row["expires_at"],
                    row["child_ids_json"], row["tree_fingerprint"],
                )
                require(current == immutable, "approval_mapping_conflict")
                return row["mapping_id"], False
            conflict = db.execute(
                """SELECT mapping_id FROM approval_mappings WHERE connection_id=? AND workspace_id=?
                AND source_profile=? AND wakeup_id=?""",
                (identity[0], identity[1], identity[2], mapping["wakeup_id"]),
            ).fetchone()
            require(conflict is None, "approval_mapping_conflict")
            db.execute(
                """INSERT INTO approval_mappings(
                    mapping_id,connection_id,workspace_id,workspace_key,source_profile,parent_issue_id,
                    wakeup_id,route_id,subscription_id,instruction,expires_at,child_ids_json,tree_fingerprint,
                    agent_id,project_id,
                    status,delivery_status,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending','pending',?,?)""",
                (mapping_id, mapping["connection_id"], mapping["workspace_id"], mapping["workspace_key"],
                 mapping["source_profile"], mapping["parent_issue_id"], mapping["wakeup_id"],
                 mapping["route_id"], mapping["subscription_id"], mapping["instruction"],
                 mapping.get("expires_at"), mapping["child_ids_json"], mapping["tree_fingerprint"],
                 mapping["agent_id"], mapping["project_id"], now, now),
            )
        return mapping_id, True

    def approval_mappings(
        self, now: float, *, workspace_key: str | None = None, limit: int = 20,
    ) -> list[dict]:
        require(type(limit) is int and 1 <= limit <= 100, "approval_mapping_invalid")
        sql = "SELECT * FROM approval_mappings WHERE status='pending' AND (next_check_at IS NULL OR next_check_at<=?)"
        params: list[Any] = [now]
        if workspace_key is not None:
            sql += " AND workspace_key=?"
            params.append(workspace_key)
        sql += " ORDER BY COALESCE(next_check_at,created_at),created_at LIMIT ?"
        params.append(limit)
        return self.rows(sql, tuple(params))

    def approval_defer_mapping(self, mapping_id: str, code: str, delay: int = 15) -> None:
        safe_code = (
            code
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "")
            else "approval_source_unavailable"
        )
        require(type(delay) is int and 1 <= delay <= 300, "approval_mapping_invalid")
        now = time.time()
        with self.transaction() as db:
            db.execute(
                "UPDATE approval_mappings SET next_check_at=?,detail=?,updated_at=? WHERE mapping_id=? AND status='pending'",
                (now + delay, safe_code, now, mapping_id),
            )

    def approval_block(self, mapping_id: str, code: str) -> None:
        safe_code = code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "") else "approval_blocked"
        with self.transaction() as db:
            db.execute(
                "UPDATE approval_mappings SET status='blocked',delivery_status='blocked',detail=?,updated_at=? WHERE mapping_id=? AND status='pending'",
                (safe_code, time.time(), mapping_id),
            )

    def approval_defer_unclaimed(self, job_id: str, code: str, delay: int = 15) -> None:
        safe_code = (
            code
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "")
            else "approval_delivery_unavailable"
        )
        require(type(delay) is int and 1 <= delay <= 300, "approval_mapping_invalid")
        now = time.time()
        with self.transaction() as db:
            db.execute(
                "UPDATE approval_jobs SET next_check_at=?,last_error=?,updated_at=? WHERE id=? AND status='pending' AND attempts=0",
                (now + delay, safe_code, now, job_id),
            )

    def approval_reject_unclaimed(self, job_id: str, code: str) -> None:
        safe_code = (
            code
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "")
            else "approval_delivery_rejected"
        )
        now = time.time()
        with self.transaction() as db:
            row = db.execute(
                "SELECT mapping_id FROM approval_jobs WHERE id=? AND status='pending' AND attempts=0",
                (job_id,),
            ).fetchone()
            if row is None:
                return
            db.execute(
                "UPDATE approval_jobs SET status='dead',last_error=?,payload_json='',updated_at=? WHERE id=? AND status='pending' AND attempts=0",
                (safe_code, now, job_id),
            )
            db.execute(
                "UPDATE approval_mappings SET status='blocked',delivery_status='dead',detail=?,updated_at=? WHERE mapping_id=? AND status='ready'",
                (safe_code, now, row["mapping_id"]),
            )

    def approval_enqueue(
        self, mapping_id: str, run_id: str, text: str, child_statuses: list[str],
    ) -> str | None:
        if not isinstance(text, str) or not text.strip() or len(text) > 3500:
            raise NotifyError("approval_payload_invalid")
        if (not isinstance(child_statuses, list) or not child_statuses or len(child_statuses) > 500
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value)
                       for value in child_statuses)):
            raise NotifyError("approval_payload_invalid")
        now = time.time()
        with self.transaction() as db:
            mapping = db.execute("SELECT * FROM approval_mappings WHERE mapping_id=?", (mapping_id,)).fetchone()
            if not mapping or mapping["status"] != "pending":
                return None
            existing = db.execute(
                "SELECT id FROM approval_jobs WHERE mapping_id=? AND run_id=?",
                (mapping_id, run_id),
            ).fetchone()
            if existing:
                return existing["id"]
            destination = db.execute(
                """SELECT s.*,a.configured AS account_configured,w.configured AS workspace_configured,
                    w.enabled AS workspace_enabled FROM subscriptions s
                    JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
                    JOIN wake_subscriptions ws ON ws.subscription_id=s.id
                    WHERE s.id=? AND ws.profile=? AND ws.route=? AND ws.enabled=1""",
                (mapping["subscription_id"], mapping["source_profile"], mapping["route_id"]),
            ).fetchone()
            require(
                destination is not None and destination["enabled"] and destination["account_configured"]
                and destination["workspace_configured"] and destination["workspace_enabled"],
                "approval_ready_destination_unverified",
            )
            payload = {
                key: destination[key]
                for key in ("platform", "account", "chat_id", "thread_id", "chat_type", "anchor_message_id")
            }
            payload.update(text=text.strip(), event_type="task.ready_for_approval")
            payload["approval_audit"] = {
                "parent_issue_id": mapping["parent_issue_id"],
                "wakeup_id": mapping["wakeup_id"],
                "run_id": run_id,
                "route_id": mapping["route_id"],
                "child_statuses": list(child_statuses),
            }
            payload_json = encoded(payload)
            require(len(payload_json.encode("utf-8")) <= 16 * 1024, "approval_payload_invalid")
            job_id = str(uuid.uuid4())
            event_key = f"approval:{mapping['wakeup_id']}:{run_id}"
            db.execute(
                """INSERT INTO approval_jobs(id,mapping_id,event_key,run_id,payload_json,status,created_at,updated_at)
                VALUES(?,?,?,?,?,'pending',?,?)""",
                (job_id, mapping_id, event_key, run_id, payload_json, now, now),
            )
            db.execute(
                "UPDATE approval_mappings SET status='ready',last_run_id=?,delivery_status='pending',updated_at=? WHERE mapping_id=? AND status='pending'",
                (run_id, now, mapping_id),
            )
            return job_id

    def approval_due(self, now: float) -> list[dict]:
        with self.transaction() as db:
            stale = db.execute(
                """SELECT mapping_id FROM approval_jobs WHERE status='sending' AND lease_until<=?""",
                (now,),
            ).fetchall()
            db.execute(
                """UPDATE approval_jobs SET status='delivery_unknown',last_error='process_interrupted',updated_at=?
                WHERE status='sending' AND lease_until<=?""",
                (now, now),
            )
            for row in stale:
                db.execute(
                    "UPDATE approval_mappings SET status='delivery_unknown',delivery_status='delivery_unknown',detail='process_interrupted',updated_at=? WHERE mapping_id=? AND status='ready'",
                    (now, row["mapping_id"]),
                )
            return [dict(row) for row in db.execute(
                """SELECT j.*,m.route_id,m.source_profile,m.subscription_id FROM approval_jobs j
                JOIN approval_mappings m ON m.mapping_id=j.mapping_id
                JOIN subscriptions s ON s.id=m.subscription_id
                JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
                JOIN wake_subscriptions ws ON ws.subscription_id=s.id
                WHERE j.status='pending' AND (j.next_check_at IS NULL OR j.next_check_at<=?)
                AND m.status='ready' AND s.enabled=1 AND a.configured=1
                AND w.configured=1 AND w.enabled=1 AND ws.enabled=1
                AND ws.route=m.route_id AND ws.profile=m.source_profile
                ORDER BY j.created_at LIMIT 100""",
                (now,),
            )]

    def approval_claim(self, job_id: str, now: float, lease: int = 300) -> dict | None:
        with self.transaction() as db:
            row = db.execute(
                """SELECT j.*,m.status AS mapping_status,m.route_id,m.source_profile,m.subscription_id
                FROM approval_jobs j JOIN approval_mappings m ON m.mapping_id=j.mapping_id
                JOIN subscriptions s ON s.id=m.subscription_id
                JOIN accounts a ON a.name=s.account JOIN workspaces w ON w.id=s.workspace_id
                JOIN wake_subscriptions ws ON ws.subscription_id=s.id
                WHERE j.id=? AND j.status='pending' AND j.attempts=0
                AND (j.next_check_at IS NULL OR j.next_check_at<=?)
                AND m.status='ready' AND ws.enabled=1
                AND ws.route=m.route_id AND ws.profile=m.source_profile
                AND s.enabled=1 AND a.configured=1 AND w.configured=1 AND w.enabled=1""",
                (job_id, now),
            ).fetchone()
            if row is None:
                return None
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError, RecursionError):
                db.execute(
                    "UPDATE approval_jobs SET status='dead',last_error='approval_payload_invalid',updated_at=? WHERE id=? AND status='pending'",
                    (now, job_id),
                )
                db.execute(
                    "UPDATE approval_mappings SET status='blocked',delivery_status='dead',detail='approval_payload_invalid',updated_at=? WHERE mapping_id=? AND status='ready'",
                    (now, row["mapping_id"]),
                )
                return None
            if not isinstance(payload, dict) or payload.get("event_type") != "task.ready_for_approval":
                db.execute(
                    "UPDATE approval_jobs SET status='dead',last_error='approval_payload_invalid',updated_at=? WHERE id=? AND status='pending'",
                    (now, job_id),
                )
                db.execute(
                    "UPDATE approval_mappings SET status='blocked',delivery_status='dead',detail='approval_payload_invalid',updated_at=? WHERE mapping_id=? AND status='ready'",
                    (now, row["mapping_id"]),
                )
                return None
            destination = db.execute("SELECT * FROM subscriptions WHERE id=?", (row["subscription_id"],)).fetchone()
            keys = ("platform", "account", "chat_id", "thread_id", "chat_type", "anchor_message_id")
            if any(payload.get(key) != destination[key] for key in keys):
                db.execute(
                    "UPDATE approval_jobs SET status='dead',last_error='approval_destination_changed',updated_at=? WHERE id=?",
                    (now, job_id),
                )
                db.execute(
                    "UPDATE approval_mappings SET status='blocked',delivery_status='dead',detail='approval_destination_changed',updated_at=? WHERE mapping_id=?",
                    (now, row["mapping_id"]),
                )
                return None
            lease_token = str(uuid.uuid4())
            db.execute(
                "UPDATE approval_jobs SET status='sending',attempts=attempts+1,lease_token=?,lease_until=?,next_check_at=NULL,updated_at=? WHERE id=? AND status='pending' AND attempts=0",
                (lease_token, now + lease, now, job_id),
            )
            return dict(db.execute("SELECT * FROM approval_jobs WHERE id=?", (job_id,)).fetchone())

    def approval_finish(self, claim: dict, outcome: str, detail: str) -> bool:
        if outcome not in {"delivered", "dead", "delivery_unknown"}:
            raise ValueError("invalid approval delivery outcome")
        now = time.time()
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE approval_jobs SET status=?,payload_json=CASE WHEN ?='delivered' THEN '' ELSE payload_json END,last_error=?,lease_token=NULL,lease_until=NULL,updated_at=? WHERE id=? AND status='sending' AND lease_token=? AND attempts=?",
                (outcome, outcome, detail[:128], now, claim["id"], claim["lease_token"], claim["attempts"]),
            )
            if cursor.rowcount != 1:
                return False
            mapping_state = "delivered" if outcome == "delivered" else "delivery_unknown" if outcome == "delivery_unknown" else "blocked"
            db.execute(
                "UPDATE approval_mappings SET status=?,delivery_status=?,detail=?,updated_at=? WHERE mapping_id=? AND status='ready'",
                (mapping_state, outcome, detail[:128], now, claim["mapping_id"]),
            )
            return True

    def approval_status(self) -> dict[str, int]:
        result = {
            row["status"]: row["count"]
            for row in self.rows("SELECT status,COUNT(*) AS count FROM approval_jobs GROUP BY status")
        }
        result["mappings_pending"] = self.rows(
            "SELECT COUNT(*) AS count FROM approval_mappings WHERE status='pending'"
        )[0]["count"]
        return result

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
