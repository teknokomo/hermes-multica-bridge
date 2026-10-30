"""SQLite delivery ledger shared by Standard and Isolated transports."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import BridgeError
from .identifiers import uuid7
from .validation import idempotency_key

RESULT_COMMENT_RESERVATION_SECONDS = 300
RATE_LIMIT_RETENTION_SECONDS = 3600


@dataclass(frozen=True)
class Attempt:
    key: str
    number: int
    attempt_id: str
    request_id: str


@dataclass(frozen=True)
class DeliveryRecord:
    connection_key: str
    route_id: str | None
    connection_id: str | None
    workspace_key: str | None
    workspace_id: str | None
    multica_origin: str | None
    autopilot_id: str | None
    trigger_id: str | None
    security_mode: str | None
    route_policy_fingerprint: str | None
    request_id: str
    source_board: str
    source_task_id: str
    idempotency_key: str
    request_sha256: str
    delivery_status: str
    execution_status: str
    delivery_id: str | None
    run_id: str | None
    target_issue_id: str | None
    target_task_id: str | None
    result_status: str | None
    result_sha256: str | None
    result_source_revision: int | None
    result_comment_sha256: str | None


@dataclass(frozen=True)
class DeliverySnapshot:
    route_id: str
    connection_id: str
    workspace_key: str
    workspace_id: str
    multica_origin: str
    autopilot_id: str
    trigger_id: str
    security_mode: str
    route_policy_fingerprint: str


@dataclass(frozen=True)
class ResultUpdate:
    accepted: bool
    changed: bool


_TERMINAL_RESULT_STATUSES = frozenset({"succeeded", "failed", "skipped"})


def _result_transition_allowed(current: str | None, incoming: str) -> bool:
    """Reject stale result snapshots that would move one run backwards."""
    if current is None or current == incoming:
        return True
    if current in _TERMINAL_RESULT_STATUSES:
        return False
    if incoming in _TERMINAL_RESULT_STATUSES:
        return True
    if current == "unknown":
        return incoming in {"pending", "running"}
    if current == "pending":
        return incoming == "running"
    return False


def _result_snapshot_allowed(
    *,
    current_status: str | None,
    current_sha256: str | None,
    current_source_revision: int | None,
    incoming_status: str,
    incoming_sha256: str,
    incoming_source_revision: int | None,
    allow_revisionless_change: bool = False,
) -> bool:
    """Order same-status snapshots by Multica's monotonic Issue revision."""
    if (
        current_source_revision is not None
        and incoming_source_revision is not None
        and incoming_source_revision < current_source_revision
    ):
        return False
    if (
        current_source_revision is not None
        and incoming_source_revision is None
        and current_sha256 != incoming_sha256
    ):
        return False
    if current_status != incoming_status:
        return _result_transition_allowed(current_status, incoming_status)
    if current_sha256 == incoming_sha256:
        return True
    if current_status is None:
        return True
    if current_source_revision is None:
        return incoming_source_revision is not None or allow_revisionless_change
    if incoming_source_revision is None:
        return False
    # A local poll generation orders concurrent reads, but it cannot make a
    # changed snapshot authoritative when the source revision is unchanged.
    return incoming_source_revision > current_source_revision


def _resolve_state_directory(
    directory: Path,
    *,
    public_root: Path = Path("/var/lib"),
    private_root: Path = Path("/var/lib/private"),
) -> Path:
    """Resolve systemd DynamicUser's known StateDirectory symlink, rejecting other links."""
    try:
        info = directory.lstat()
    except OSError as exc:
        raise BridgeError("state_unavailable", "The bridge state directory is unavailable.") from exc

    if stat.S_ISLNK(info.st_mode):
        expected_public = public_root / directory.name
        expected_private = private_root / directory.name
        try:
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise BridgeError("state_unavailable", "The bridge state directory link is invalid.") from exc
        if directory != expected_public or resolved != expected_private:
            raise BridgeError("state_untrusted", "The bridge state directory uses an unexpected symbolic link.")
        try:
            target_info = resolved.lstat()
        except OSError as exc:
            raise BridgeError("state_unavailable", "The systemd-managed state directory is unavailable.") from exc
        if (
            not stat.S_ISDIR(target_info.st_mode)
            or target_info.st_uid != os.geteuid()
            or target_info.st_mode & 0o077
        ):
            raise BridgeError("state_untrusted", "The systemd-managed state target has unsafe ownership or permissions.")
        return resolved

    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise BridgeError("state_untrusted", "The bridge state directory has unsafe ownership or permissions.")
    return directory


def _resolve_profile_state_directory(directory: Path) -> Path:
    """Prepare a profile-owned plugin data directory without following a symlink."""
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
    except OSError as exc:
        raise BridgeError("state_unavailable", "The profile state directory is unavailable.") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise BridgeError("state_untrusted", "The profile state directory has unsafe ownership or permissions.")
    return directory


class DeliveryStore:
    def __init__(self, path: str | Path, *, systemd_state: bool = False):
        requested = Path(path)
        directory = requested.parent
        if systemd_state:
            directory = _resolve_state_directory(directory)
        else:
            directory = _resolve_profile_state_directory(directory)
        self.path = directory / requested.name
        self._ensure_database_file()
        self._initialize()

    def _ensure_database_file(self) -> None:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise BridgeError("state_unavailable", "The bridge state database is unavailable.") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise BridgeError("state_untrusted", "The bridge state database has unsafe permissions.")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 3000")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._create_schema(conn)
            self._validate_schema(conn)
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge state database could not be initialized.") from exc
        finally:
            conn.close()

    @staticmethod
    def _create_schema(conn: sqlite3.Connection) -> None:
        """Create the current schema without implicitly ending the caller's transaction."""
        conn.execute(
            """CREATE TABLE IF NOT EXISTS deliveries (
                connection_key TEXT NOT NULL,
                route_id TEXT,
                connection_id TEXT,
                workspace_key TEXT,
                workspace_id TEXT,
                multica_origin TEXT,
                autopilot_id TEXT,
                trigger_id TEXT,
                security_mode TEXT,
                route_policy_fingerprint TEXT,
                request_id TEXT NOT NULL,
                source_board TEXT NOT NULL,
                source_task_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_attempt REAL NOT NULL,
                attempts INTEGER NOT NULL,
                delivery_status TEXT NOT NULL,
                execution_status TEXT NOT NULL,
                delivery_id TEXT,
                run_id TEXT,
                http_status INTEGER,
                target_issue_id TEXT,
                target_task_id TEXT,
                result_status TEXT,
                result_sha256 TEXT,
                result_source_revision INTEGER,
                result_poll_generation INTEGER NOT NULL DEFAULT 0,
                result_applied_poll_generation INTEGER NOT NULL DEFAULT 0,
                result_comment_sha256 TEXT,
                result_checked_at REAL,
                PRIMARY KEY (connection_key, request_id),
                UNIQUE (connection_key, source_board, source_task_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                connection_key TEXT NOT NULL,
                request_id TEXT NOT NULL,
                attempted_at REAL NOT NULL,
                outcome TEXT NOT NULL,
                FOREIGN KEY (connection_key, request_id)
                    REFERENCES deliveries(connection_key, request_id)
            )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS attempts_connection_time
                ON attempts(connection_key, attempted_at)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS result_comments (
                connection_key TEXT NOT NULL,
                request_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                reserved_at REAL NOT NULL,
                PRIMARY KEY (connection_key, request_id, fingerprint),
                FOREIGN KEY (connection_key, request_id)
                    REFERENCES deliveries(connection_key, request_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS connection_rate_events (
                event_id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                attempted_at REAL NOT NULL
            )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS connection_rate_events_key_time
                ON connection_rate_events(connection_id, attempted_at)"""
        )

    @staticmethod
    def _validate_schema(conn: sqlite3.Connection) -> None:
        """Reject stale development databases instead of silently mutating them."""
        expected = {
            "deliveries": {
                "connection_key",
                "route_id",
                "connection_id",
                "workspace_key",
                "workspace_id",
                "multica_origin",
                "autopilot_id",
                "trigger_id",
                "security_mode",
                "route_policy_fingerprint",
                "request_id",
                "source_board",
                "source_task_id",
                "idempotency_key",
                "request_sha256",
                "first_seen",
                "last_attempt",
                "attempts",
                "delivery_status",
                "execution_status",
                "delivery_id",
                "run_id",
                "http_status",
                "target_issue_id",
                "target_task_id",
                "result_status",
                "result_sha256",
                "result_source_revision",
                "result_poll_generation",
                "result_applied_poll_generation",
                "result_comment_sha256",
                "result_checked_at",
            },
            "attempts": {
                "attempt_id",
                "connection_key",
                "request_id",
                "attempted_at",
                "outcome",
            },
            "result_comments": {
                "connection_key",
                "request_id",
                "fingerprint",
                "status",
                "reserved_at",
            },
            "connection_rate_events": {
                "event_id",
                "connection_id",
                "attempted_at",
            },
        }
        for table, columns in expected.items():
            actual = {
                entry[1] for entry in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if actual != columns:
                raise sqlite3.DatabaseError(f"incompatible {table} schema")

    @staticmethod
    def _delivery_from_row(row: sqlite3.Row) -> DeliveryRecord:
        return DeliveryRecord(
            connection_key=row["connection_key"],
            route_id=row["route_id"],
            connection_id=row["connection_id"],
            workspace_key=row["workspace_key"],
            workspace_id=row["workspace_id"],
            multica_origin=row["multica_origin"],
            autopilot_id=row["autopilot_id"],
            trigger_id=row["trigger_id"],
            security_mode=row["security_mode"],
            route_policy_fingerprint=row["route_policy_fingerprint"],
            request_id=row["request_id"],
            source_board=row["source_board"],
            source_task_id=row["source_task_id"],
            idempotency_key=row["idempotency_key"],
            request_sha256=row["request_sha256"],
            delivery_status=row["delivery_status"],
            execution_status=row["execution_status"],
            delivery_id=row["delivery_id"],
            run_id=row["run_id"],
            target_issue_id=row["target_issue_id"],
            target_task_id=row["target_task_id"],
            result_status=row["result_status"],
            result_sha256=row["result_sha256"],
            result_source_revision=row["result_source_revision"],
            result_comment_sha256=row["result_comment_sha256"],
        )

    def get_delivery(
        self, *, connection_key: str, source_board: str, source_task_id: str
    ) -> DeliveryRecord | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT * FROM deliveries
                   WHERE connection_key = ? AND source_task_id = ?
                     AND (source_board = ? OR source_board = '')
                   ORDER BY CASE WHEN source_board = ? THEN 0 ELSE 1 END
                   LIMIT 1""",
                (connection_key, source_task_id, source_board, source_board),
            ).fetchone()
            return self._delivery_from_row(row) if row else None
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge delivery state could not be read.") from exc
        finally:
            conn.close()

    def latest_delivery(self, *, connection_key: str) -> DeliveryRecord | None:
        """Return the most recently attempted delivery for safe status surfaces."""
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT * FROM deliveries
                   WHERE connection_key = ?
                   ORDER BY last_attempt DESC, request_id DESC
                   LIMIT 1""",
                (connection_key,),
            ).fetchone()
            return self._delivery_from_row(row) if row else None
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge delivery state could not be read.") from exc
        finally:
            conn.close()

    def route_has_deliveries(self, route_id: str) -> bool:
        """Return whether a Route already owns immutable delivery history."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM deliveries WHERE COALESCE(route_id, connection_key) = ? LIMIT 1",
                (route_id,),
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge delivery state could not be inspected.") from exc
        finally:
            conn.close()

    def route_ids_with_deliveries(self) -> frozenset[str]:
        """Return every Route partition represented in this ledger."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT DISTINCT COALESCE(route_id, connection_key) AS route_key FROM deliveries"
            ).fetchall()
            return frozenset(str(row["route_key"]) for row in rows if row["route_key"])
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge delivery state could not be inspected.") from exc
        finally:
            conn.close()

    def reserve_connection_request(
        self,
        *,
        connection_id: str,
        max_requests: int,
        window_seconds: int,
        now: float | None = None,
    ) -> None:
        """Atomically reserve one profile-wide request against a Connection rate limit."""
        timestamp = time.time() if now is None else now
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM connection_rate_events WHERE attempted_at < ?",
                (timestamp - RATE_LIMIT_RETENTION_SECONDS,),
            )
            recent = conn.execute(
                """SELECT COUNT(*) FROM connection_rate_events
                   WHERE connection_id = ? AND attempted_at >= ?""",
                (connection_id, timestamp - window_seconds),
            ).fetchone()[0]
            if recent >= max_requests:
                raise BridgeError(
                    "rate_limited",
                    "The connection request limit has been reached.",
                    retryable=True,
                )
            conn.execute(
                """INSERT INTO connection_rate_events (event_id, connection_id, attempted_at)
                   VALUES (?, ?, ?)""",
                (uuid7(), connection_id, timestamp),
            )
            conn.commit()
        except BridgeError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The connection rate limit state could not be saved.") from exc
        finally:
            conn.close()

    def begin_attempt(
        self,
        *,
        connection_key: str,
        source_board: str,
        source_task_id: str,
        fingerprint: str,
        now: float | None = None,
        max_requests: int,
        window_seconds: int,
        max_attempts: int,
        snapshot: DeliverySnapshot | None = None,
    ) -> Attempt:
        timestamp = time.time() if now is None else now
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    """SELECT * FROM deliveries
                       WHERE connection_key = ? AND source_task_id = ?
                         AND (source_board = ? OR source_board = '')
                       ORDER BY CASE WHEN source_board = ? THEN 0 ELSE 1 END LIMIT 1""",
                    (connection_key, source_task_id, source_board, source_board),
                ).fetchone()
                if existing is not None and existing["request_sha256"] != fingerprint:
                    raise BridgeError("request_conflict", "This source task is already bound to different request data.")
                if existing is not None and snapshot is not None:
                    pairs = (
                        ("route_id", snapshot.route_id),
                        ("connection_id", snapshot.connection_id),
                        ("workspace_key", snapshot.workspace_key),
                        ("workspace_id", snapshot.workspace_id),
                        ("multica_origin", snapshot.multica_origin),
                        ("autopilot_id", snapshot.autopilot_id),
                        ("trigger_id", snapshot.trigger_id),
                        ("security_mode", snapshot.security_mode),
                        ("route_policy_fingerprint", snapshot.route_policy_fingerprint),
                    )
                    for column, incoming in pairs:
                        stored = existing[column]
                        if stored is not None and stored != incoming:
                            raise BridgeError(
                                "route_snapshot_conflict",
                                "The recorded Multica destination does not match the selected Route.",
                            )
                    if any(existing[column] is None for column, _incoming in pairs):
                        conn.execute(
                            """UPDATE deliveries SET
                                route_id = COALESCE(route_id, ?),
                                connection_id = COALESCE(connection_id, ?),
                                workspace_key = COALESCE(workspace_key, ?),
                                workspace_id = COALESCE(workspace_id, ?),
                                multica_origin = COALESCE(multica_origin, ?),
                                autopilot_id = COALESCE(autopilot_id, ?),
                                trigger_id = COALESCE(trigger_id, ?),
                                security_mode = COALESCE(security_mode, ?),
                                route_policy_fingerprint = COALESCE(route_policy_fingerprint, ?)
                               WHERE connection_key = ? AND request_id = ?""",
                            (
                                snapshot.route_id,
                                snapshot.connection_id,
                                snapshot.workspace_key,
                                snapshot.workspace_id,
                                snapshot.multica_origin,
                                snapshot.autopilot_id,
                                snapshot.trigger_id,
                                snapshot.security_mode,
                                snapshot.route_policy_fingerprint,
                                connection_key,
                                existing["request_id"],
                            ),
                        )
                if existing is not None and not existing["source_board"]:
                    conn.execute(
                        "UPDATE deliveries SET source_board = ? WHERE connection_key = ? AND request_id = ?",
                        (source_board, connection_key, existing["request_id"]),
                    )
                request_id = existing["request_id"] if existing is not None else uuid7()
                key = idempotency_key(connection_key, request_id)

                recent = conn.execute(
                    "SELECT COUNT(*) FROM attempts WHERE connection_key = ? AND attempted_at >= ?",
                    (connection_key, timestamp - window_seconds),
                ).fetchone()[0]
                if recent >= max_requests:
                    raise BridgeError("rate_limited", "The connection request limit has been reached.", retryable=True)
                previous_attempts = 0 if existing is None else int(existing["attempts"])
                if previous_attempts >= max_attempts:
                    raise BridgeError("retry_limit_reached", "This request has reached its controlled retry limit.")

                attempt_number = previous_attempts + 1
                attempt_id = uuid7()
                if existing is None:
                    snap = snapshot
                    conn.execute(
                        """INSERT INTO deliveries (
                            connection_key, route_id, connection_id, workspace_key, workspace_id,
                            multica_origin, autopilot_id, trigger_id, security_mode, route_policy_fingerprint,
                            request_id, source_board, source_task_id, idempotency_key,
                            request_sha256, first_seen, last_attempt, attempts,
                            delivery_status, execution_status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'unknown')""",
                        (
                            connection_key,
                            snap.route_id if snap else None,
                            snap.connection_id if snap else None,
                            snap.workspace_key if snap else None,
                            snap.workspace_id if snap else None,
                            snap.multica_origin if snap else None,
                            snap.autopilot_id if snap else None,
                            snap.trigger_id if snap else None,
                            snap.security_mode if snap else None,
                            snap.route_policy_fingerprint if snap else None,
                            request_id, source_board, source_task_id, key,
                            fingerprint, timestamp, timestamp, attempt_number,
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE deliveries SET last_attempt = ?, attempts = ? WHERE connection_key = ? AND request_id = ?",
                        (timestamp, attempt_number, connection_key, request_id),
                    )
                conn.execute(
                    "INSERT INTO attempts (attempt_id, connection_key, request_id, attempted_at, outcome) VALUES (?, ?, ?, ?, 'pending')",
                    (attempt_id, connection_key, request_id, timestamp),
                )
                conn.commit()
                return Attempt(key=key, number=attempt_number, attempt_id=attempt_id, request_id=request_id)
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        except BridgeError:
            raise
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge could not reserve a delivery attempt.") from exc

    def routes_for_task(self, *, source_board: str, source_task_id: str) -> tuple[str, ...]:
        """Return route ids with a recorded delivery for one Hermes task."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT DISTINCT COALESCE(route_id, connection_key) AS route_key
                     FROM deliveries
                    WHERE source_task_id = ? AND (source_board = ? OR source_board = '')
                    ORDER BY route_key""",
                (source_task_id, source_board),
            ).fetchall()
            return tuple(str(row["route_key"]) for row in rows if row["route_key"])
        except sqlite3.Error as exc:
            raise BridgeError("state_unavailable", "The bridge delivery routes could not be read.") from exc
        finally:
            conn.close()

    def finish_attempt(
        self,
        *,
        connection_key: str,
        request_id: str,
        attempt_number: int,
        attempt_id: str,
        delivery_status: str,
        execution_status: str,
        delivery_id: str | None,
        run_id: str | None,
        http_status: int | None,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """UPDATE attempts SET outcome = ?
                    WHERE attempt_id = ? AND connection_key = ? AND request_id = ? AND outcome = 'pending'""",
                (delivery_status, attempt_id, connection_key, request_id),
            )
            if cursor.rowcount != 1:
                raise BridgeError("state_unavailable", "The bridge could not find the reserved attempt.")
            current = conn.execute(
                """SELECT attempts, delivery_status, delivery_id, run_id
                     FROM deliveries WHERE connection_key = ? AND request_id = ?""",
                (connection_key, request_id),
            ).fetchone()
            if current is None or attempt_number > int(current["attempts"]):
                raise BridgeError("state_unavailable", "The bridge delivery state changed before the result was saved.")

            admitted_statuses = {"accepted", "duplicate"}
            new_admitted = delivery_status in admitted_statuses and run_id is not None
            current_admitted = (
                current["delivery_status"] in admitted_statuses and current["run_id"] is not None
            )
            if current_admitted and new_admitted:
                if current["run_id"] != run_id or (
                    current["delivery_id"] is not None
                    and delivery_id is not None
                    and current["delivery_id"] != delivery_id
                ):
                    raise BridgeError(
                        "state_unavailable",
                        "The bridge received conflicting identities for one idempotent delivery.",
                    )
            elif not current_admitted and (
                attempt_number == int(current["attempts"]) or new_admitted
            ):
                conn.execute(
                    """UPDATE deliveries SET delivery_status = ?, execution_status = ?,
                        delivery_id = COALESCE(?, delivery_id), run_id = COALESCE(?, run_id), http_status = ?
                        WHERE connection_key = ? AND request_id = ?""",
                    (
                        delivery_status,
                        execution_status,
                        delivery_id,
                        run_id,
                        http_status,
                        connection_key,
                        request_id,
                    ),
                )
            conn.commit()
        except BridgeError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge could not save the delivery result.") from exc
        finally:
            conn.close()

    def record_result(
        self,
        *,
        connection_key: str,
        request_id: str,
        execution_status: str,
        target_issue_id: str | None,
        target_task_id: str | None,
        result_sha256: str,
        source_revision: int | None = None,
        poll_generation: int | None = None,
        checked_at: float | None = None,
    ) -> ResultUpdate:
        """Persist a non-regressing result snapshot and report whether it changed state."""
        timestamp = time.time() if checked_at is None else checked_at
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT result_status, result_sha256, result_source_revision,
                          result_poll_generation, result_applied_poll_generation
                   FROM deliveries WHERE connection_key = ? AND request_id = ?""",
                (connection_key, request_id),
            ).fetchone()
            if row is None:
                raise BridgeError("state_unavailable", "The delivery record no longer exists.")
            if poll_generation is not None:
                if type(poll_generation) is not int or poll_generation <= 0:
                    raise BridgeError("invalid_arguments", "The result poll generation is invalid.")
                if poll_generation != int(row["result_poll_generation"]):
                    conn.rollback()
                    return ResultUpdate(accepted=False, changed=False)
            if row["result_sha256"] != result_sha256:
                pending = conn.execute(
                    """SELECT 1 FROM result_comments
                       WHERE connection_key = ? AND request_id = ? AND status = 'pending'
                         AND reserved_at > ? LIMIT 1""",
                    (
                        connection_key,
                        request_id,
                        timestamp - RESULT_COMMENT_RESERVATION_SECONDS,
                    ),
                ).fetchone()
                if pending is not None:
                    conn.rollback()
                    return ResultUpdate(accepted=False, changed=False)
            if not _result_snapshot_allowed(
                current_status=row["result_status"],
                current_sha256=row["result_sha256"],
                current_source_revision=row["result_source_revision"],
                incoming_status=execution_status,
                incoming_sha256=result_sha256,
                incoming_source_revision=source_revision,
                allow_revisionless_change=(
                    poll_generation is not None
                    and poll_generation > int(row["result_applied_poll_generation"])
                ),
            ):
                conn.rollback()
                return ResultUpdate(accepted=False, changed=False)
            changed = row["result_status"] != execution_status or row["result_sha256"] != result_sha256
            conn.execute(
                """UPDATE deliveries SET execution_status = ?, target_issue_id = COALESCE(?, target_issue_id),
                    target_task_id = COALESCE(?, target_task_id), result_status = ?, result_sha256 = ?,
                    result_source_revision = COALESCE(?, result_source_revision),
                    result_applied_poll_generation = CASE
                        WHEN ? IS NULL THEN result_applied_poll_generation
                        ELSE MAX(result_applied_poll_generation, ?)
                    END,
                    result_checked_at = ?
                    WHERE connection_key = ? AND request_id = ?""",
                (
                    execution_status, target_issue_id, target_task_id, execution_status,
                    result_sha256, source_revision, poll_generation, poll_generation,
                    timestamp, connection_key, request_id,
                ),
            )
            conn.commit()
            return ResultUpdate(accepted=True, changed=changed)
        except BridgeError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge result state could not be saved.") from exc
        finally:
            conn.close()

    def begin_result_poll(self, *, connection_key: str, request_id: str) -> int:
        """Reserve a monotonic poll generation so stale concurrent API reads cannot win."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT result_poll_generation FROM deliveries
                   WHERE connection_key = ? AND request_id = ?""",
                (connection_key, request_id),
            ).fetchone()
            if row is None:
                raise BridgeError("state_unavailable", "The delivery record no longer exists.")
            generation = int(row["result_poll_generation"]) + 1
            conn.execute(
                """UPDATE deliveries SET result_poll_generation = ?
                   WHERE connection_key = ? AND request_id = ?""",
                (generation, connection_key, request_id),
            )
            conn.commit()
            return generation
        except BridgeError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge result poll could not be reserved.") from exc
        finally:
            conn.close()

    def reserve_result_comment(
        self,
        *,
        connection_key: str,
        request_id: str,
        comment_sha256: str,
        now: float | None = None,
        stale_after_seconds: int = RESULT_COMMENT_RESERVATION_SECONDS,
    ) -> bool:
        """Reserve one comment fingerprint so concurrent result checks cannot duplicate it."""
        timestamp = time.time() if now is None else now
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            delivery = conn.execute(
                """SELECT result_sha256 FROM deliveries
                   WHERE connection_key = ? AND request_id = ?""",
                (connection_key, request_id),
            ).fetchone()
            if delivery is None:
                raise BridgeError("state_unavailable", "The delivery record no longer exists.")
            if delivery["result_sha256"] != comment_sha256:
                conn.rollback()
                return False
            row = conn.execute(
                """SELECT status, reserved_at FROM result_comments
                   WHERE connection_key = ? AND request_id = ? AND fingerprint = ?""",
                (connection_key, request_id, comment_sha256),
            ).fetchone()
            if row is not None and row["status"] == "published":
                conn.rollback()
                return False
            if row is not None and float(row["reserved_at"]) > timestamp - stale_after_seconds:
                conn.rollback()
                return False
            if row is None:
                conn.execute(
                    """INSERT INTO result_comments
                       (connection_key, request_id, fingerprint, status, reserved_at)
                       VALUES (?, ?, ?, 'pending', ?)""",
                    (connection_key, request_id, comment_sha256, timestamp),
                )
            else:
                conn.execute(
                    """UPDATE result_comments SET status = 'pending', reserved_at = ?
                       WHERE connection_key = ? AND request_id = ? AND fingerprint = ?""",
                    (timestamp, connection_key, request_id, comment_sha256),
                )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge result comment could not be reserved.") from exc
        finally:
            conn.close()

    def finish_result_comment(
        self,
        *,
        connection_key: str,
        request_id: str,
        comment_sha256: str,
        published: bool,
    ) -> None:
        """Commit a successful comment publication or release the reservation for retry."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if published:
                cursor = conn.execute(
                    """UPDATE result_comments SET status = 'published'
                       WHERE connection_key = ? AND request_id = ? AND fingerprint = ? AND status = 'pending'""",
                    (connection_key, request_id, comment_sha256),
                )
                if cursor.rowcount != 1:
                    raise BridgeError("state_unavailable", "The result comment reservation no longer exists.")
                conn.execute(
                    """UPDATE deliveries SET result_comment_sha256 = ?
                       WHERE connection_key = ? AND request_id = ? AND result_sha256 = ?""",
                    (comment_sha256, connection_key, request_id, comment_sha256),
                )
            else:
                conn.execute(
                    """DELETE FROM result_comments
                       WHERE connection_key = ? AND request_id = ? AND fingerprint = ? AND status = 'pending'""",
                    (connection_key, request_id, comment_sha256),
                )
            conn.commit()
        except BridgeError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise BridgeError("state_unavailable", "The bridge result comment reservation could not be updated.") from exc
        finally:
            conn.close()
