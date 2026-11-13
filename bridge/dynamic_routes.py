"""Profile-owned dynamic Workspace route records (no credentials or source payloads)."""

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

_SCHEMA_VERSION = 1
_TABLES = {"dynamic_routes", "route_audit"}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class DynamicRouteStore:
    """Small independent store. Static grants and credentials are never copied here."""

    def __init__(self, path: str | Path):
        requested = Path(path)
        try:
            requested.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory = requested.parent.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode)
                    or directory.st_uid != os.geteuid() or directory.st_mode & 0o077):
                raise BridgeError("dynamic_route_state_untrusted", "Dynamic route storage has unsafe permissions.")
            fd = os.open(requested, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077):
                    raise BridgeError("dynamic_route_state_untrusted", "Dynamic route database has unsafe permissions.")
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        except OSError as exc:
            raise BridgeError("dynamic_route_state_unavailable", "Dynamic route storage is unavailable.") from exc
        self.path = requested
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _initialize(self) -> None:
        self._preflight_schema()
        db = self._connect()
        try:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            objects = {(row[0], row[1]) for row in db.execute(
                "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )}
            if version == 0 and not objects:
                db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE dynamic_routes (
                        route_id TEXT PRIMARY KEY,
                        profile TEXT NOT NULL,
                        workspace_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        name_normalized TEXT NOT NULL,
                        create_key TEXT NOT NULL UNIQUE,
                        policy_hash TEXT NOT NULL,
                        policy_json TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('pending','active','disabled','revoked')),
                        created_by_profile TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        revision INTEGER NOT NULL DEFAULT 1,
                        UNIQUE(profile, workspace_id, name_normalized)
                    );
                    CREATE TABLE route_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        route_id TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        action TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    PRAGMA user_version=1;
                    COMMIT;
                """)
                objects = {("table", name) for name in _TABLES}
                version = _SCHEMA_VERSION
            expected_objects = {("table", name) for name in _TABLES}
            if version != _SCHEMA_VERSION or objects != expected_objects:
                raise BridgeError("dynamic_route_state_unsupported", "Dynamic route database schema is unsupported.")
            route_columns = {r[1] for r in db.execute("PRAGMA table_info(dynamic_routes)")}
            expected = {"route_id", "profile", "workspace_id", "name", "name_normalized", "create_key",
                        "policy_hash", "policy_json", "status", "created_by_profile", "created_at",
                        "updated_at", "revision"}
            audit_columns = {r[1] for r in db.execute("PRAGMA table_info(route_audit)")}
            if route_columns != expected or audit_columns != {"id", "route_id", "profile", "action", "created_at"}:
                raise BridgeError("dynamic_route_state_unsupported", "Dynamic route database schema is unsupported.")
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("dynamic_route_state_unavailable", "Dynamic route database could not be opened safely.") from exc
        finally:
            db.close()

    def _preflight_schema(self) -> None:
        """Reject unknown stores through a read-only connection before enabling WAL."""
        expected_route_columns = {
            "route_id", "profile", "workspace_id", "name", "name_normalized", "create_key",
            "policy_hash", "policy_json", "status", "created_by_profile", "created_at",
            "updated_at", "revision",
        }
        expected_audit_columns = {"id", "route_id", "profile", "action", "created_at"}
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
            version = db.execute("PRAGMA user_version").fetchone()[0]
            objects = {(row[0], row[1]) for row in db.execute(
                "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )}
            if version == 0 and not objects:
                return
            expected_objects = {("table", name) for name in _TABLES}
            if version != _SCHEMA_VERSION or objects != expected_objects:
                raise BridgeError("dynamic_route_state_unsupported", "Dynamic route database schema is unsupported.")
            route_columns = {row[1] for row in db.execute("PRAGMA table_info(dynamic_routes)")}
            audit_columns = {row[1] for row in db.execute("PRAGMA table_info(route_audit)")}
            if route_columns != expected_route_columns or audit_columns != expected_audit_columns:
                raise BridgeError("dynamic_route_state_unsupported", "Dynamic route database schema is unsupported.")
        except BridgeError:
            raise
        except sqlite3.Error as exc:
            raise BridgeError("dynamic_route_state_unavailable", "Dynamic route database could not be checked safely.") from exc
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(row["policy_json"])
        value["dynamic_status"] = row["status"]
        value["enabled"] = row["status"] == "active"
        return value

    def list(self, profile: str) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            rows = db.execute("SELECT * FROM dynamic_routes WHERE profile=? ORDER BY created_at,route_id", (profile,)).fetchall()
            return [self._record(row) for row in rows]
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise BridgeError("dynamic_route_state_unavailable", "Dynamic routes could not be read.") from exc
        finally:
            db.close()

    def list_all(self) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            rows = db.execute("SELECT * FROM dynamic_routes ORDER BY profile,created_at,route_id").fetchall()
            return [self._record(row) for row in rows]
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise BridgeError("dynamic_route_state_unavailable", "Dynamic routes could not be read.") from exc
        finally:
            db.close()

    def get(self, route_id: str) -> dict[str, Any]:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM dynamic_routes WHERE route_id=?", (route_id,)).fetchone()
            if row is None:
                raise BridgeError("route_not_found", "The dynamic route does not exist.")
            return self._record(row)
        except BridgeError:
            raise
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise BridgeError("dynamic_route_state_unavailable", "The dynamic route could not be read.") from exc
        finally:
            db.close()

    def create(self, *, profile: str, workspace_id: str, name: str, create_key: str,
               policy: dict[str, Any], status: str, max_routes: int) -> tuple[dict[str, Any], bool]:
        if status not in {"pending", "active"}:
            raise ValueError("invalid initial route state")
        policy_json = _json(policy)
        identity = dict(policy)
        identity.pop("route_id", None)
        identity.pop("enabled", None)
        identity.pop("dynamic_status", None)
        policy_hash = hashlib.sha256(_json(identity).encode()).hexdigest()
        now = time.time()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM dynamic_routes WHERE create_key=?", (create_key,)).fetchone()
            if existing:
                if existing["policy_hash"] != policy_hash or existing["profile"] != profile:
                    db.rollback()
                    raise BridgeError("route_conflict", "This source message already created a different route.")
                db.commit()
                return self._record(existing), False
            name_conflict = db.execute(
                "SELECT 1 FROM dynamic_routes WHERE profile=? AND workspace_id=? AND name_normalized=?",
                (profile, workspace_id, name.strip().casefold()),
            ).fetchone()
            if name_conflict:
                db.rollback()
                raise BridgeError("route_conflict", "A route with this name already exists in this workspace.")
            count = db.execute(
                "SELECT COUNT(*) FROM dynamic_routes WHERE profile=? AND workspace_id=? AND status!='revoked'",
                (profile, workspace_id),
            ).fetchone()[0]
            if count >= max_routes:
                db.rollback()
                raise BridgeError("route_limit_exceeded", "The grant route limit has been reached.")
            db.execute(
                """INSERT INTO dynamic_routes(route_id,profile,workspace_id,name,name_normalized,create_key,
                policy_hash,policy_json,status,created_by_profile,created_at,updated_at,revision)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (policy["route_id"], profile, workspace_id, name, name.strip().casefold(), create_key,
                 policy_hash, policy_json, status, profile, now, now),
            )
            db.execute("INSERT INTO route_audit(route_id,profile,action,created_at) VALUES(?,?,?,?)",
                       (policy["route_id"], profile, "created_" + status, now))
            db.commit()
            result = dict(policy)
            result["dynamic_status"] = status
            result["enabled"] = status == "active"
            return result, True
        except BridgeError:
            raise
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise BridgeError("route_conflict", "The dynamic route conflicts with existing route state.") from exc
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("dynamic_route_state_unavailable", "The dynamic route was not saved.") from exc
        finally:
            db.close()

    def set_status(self, route_id: str, profile: str, status: str) -> dict[str, Any]:
        if status not in {"active", "disabled", "revoked"}:
            raise BridgeError("invalid_arguments", "The requested route status is invalid.")
        now = time.time()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM dynamic_routes WHERE route_id=? AND profile=?", (route_id, profile)).fetchone()
            if row is None:
                db.rollback()
                raise BridgeError("route_not_found", "The dynamic route does not exist in this profile.")
            if row["status"] == "revoked" and status != "revoked":
                db.rollback()
                raise BridgeError("route_immutable", "A revoked dynamic route cannot be reactivated.")
            db.execute("UPDATE dynamic_routes SET status=?,updated_at=?,revision=revision+1 WHERE route_id=?",
                       (status, now, route_id))
            db.execute("INSERT INTO route_audit(route_id,profile,action,created_at) VALUES(?,?,?,?)",
                       (route_id, profile, "status_" + status, now))
            db.commit()
            result = self._record(row)
            result["dynamic_status"] = status
            result["enabled"] = status == "active"
            return result
        except BridgeError:
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise BridgeError("dynamic_route_state_unavailable", "The dynamic route status was not saved.") from exc
        finally:
            db.close()
