from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from bridge.dynamic_routes import DynamicRouteStore
from bridge.errors import BridgeError
from bridge.registry import new_id


def policy(*, route_id: str | None = None, name: str = "Canary", grant_id: str | None = None) -> dict:
    return {
        "route_id": route_id or new_id(), "name": name, "scope_kind": "project",
        "grant_id": grant_id or new_id(),
    }


def test_dynamic_store_initializes_private_independent_schema(tmp_path):
    path = tmp_path / "profile" / "dynamic-routes.sqlite3"
    DynamicRouteStore(path)
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"dynamic_routes", "route_audit"} <= tables
        columns = {row[1] for row in db.execute("PRAGMA table_info(dynamic_routes)")}
        assert not any("token" in field or "secret" in field or "pat" in field for field in columns)
    finally:
        db.close()


def test_create_is_idempotent_and_name_conflicts_do_not_partially_write(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    first = policy()
    created, inserted = store.create(profile="default", workspace_id="workspace-a", name="Canary",
                                     grant_id=first["grant_id"], create_key="same-source",
                                     policy=first, status="pending", max_routes=2)
    retry, inserted_again = store.create(profile="default", workspace_id="workspace-a", name="Canary",
                                         grant_id=first["grant_id"], create_key="same-source",
                                         policy=policy(grant_id=first["grant_id"]), status="active", max_routes=2)
    assert inserted is True
    assert inserted_again is False
    assert retry["route_id"] == created["route_id"]
    assert retry["dynamic_status"] == "pending"
    with pytest.raises(BridgeError, match="different route"):
        store.create(profile="default", workspace_id="workspace-a", name="Changed",
                     grant_id=first["grant_id"], create_key="same-source",
                     policy=policy(name="Changed", grant_id=first["grant_id"]),
                     status="pending", max_routes=2)
    assert len(store.list("default")) == 1


def test_route_quota_is_enforced_inside_create_transaction(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    first = policy(name="First")
    store.create(profile="default", workspace_id="workspace-a", grant_id=first["grant_id"], name="First",
                 create_key="one", policy=first, status="active", max_routes=1)
    second = policy(name="Second", grant_id=first["grant_id"])
    with pytest.raises(BridgeError) as raised:
        store.create(profile="default", workspace_id="workspace-a", grant_id=first["grant_id"], name="Second",
                     create_key="two", policy=second, status="pending", max_routes=1)
    assert raised.value.code == "route_limit_exceeded"
    assert len(store.list("default")) == 1


def test_route_quota_is_scoped_to_the_issuing_grant(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    first = policy(name="Grant A")
    second = policy(name="Grant B")
    store.create(profile="default", workspace_id="workspace-a", grant_id=first["grant_id"],
                 name="Grant A", create_key="grant-a", policy=first, status="active", max_routes=1)
    store.create(profile="default", workspace_id="workspace-a", grant_id=second["grant_id"],
                 name="Grant B", create_key="grant-b", policy=second, status="active", max_routes=1)
    with pytest.raises(BridgeError) as raised:
        third = policy(name="Grant A second", grant_id=first["grant_id"])
        store.create(profile="default", workspace_id="workspace-a", grant_id=first["grant_id"],
                     name="Grant A second", create_key="grant-a-second", policy=third,
                     status="pending", max_routes=1)
    assert raised.value.code == "route_limit_exceeded"
    assert {row["grant_id"] for row in store.list("default")} == {first["grant_id"], second["grant_id"]}


def test_registry_validation_failure_does_not_insert_dynamic_route(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    route = policy()

    def reject(_existing, _candidate):
        raise BridgeError("configuration_invalid", "registry size limit")

    with pytest.raises(BridgeError) as raised:
        store.create(profile="default", workspace_id="workspace-a", grant_id=route["grant_id"],
                     name="Canary", create_key="one", policy=route, status="pending",
                     max_routes=2, validate_registry=reject)
    assert raised.value.code == "configuration_invalid"
    assert store.list("default") == []


def test_approval_disable_and_revocation_are_audited_and_fenced(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    row, _ = store.create(profile="default", workspace_id="workspace-a", name="Canary",
                          grant_id=(route_policy := policy())["grant_id"], create_key="one",
                          policy=route_policy, status="pending", max_routes=2)
    assert row["enabled"] is False
    assert store.set_status(row["route_id"], "default", "active")["enabled"] is True
    assert store.set_status(row["route_id"], "default", "disabled")["enabled"] is False
    store.set_status(row["route_id"], "default", "revoked")
    assert store.list("default") == []
    assert store.list_all() == []
    assert store.get(row["route_id"])["dynamic_status"] == "revoked"
    with pytest.raises(BridgeError) as raised:
        store.set_status(row["route_id"], "default", "active")
    assert raised.value.code == "route_immutable"
    db = sqlite3.connect(store.path)
    try:
        actions = [r[0] for r in db.execute("SELECT action FROM route_audit ORDER BY id")]
    finally:
        db.close()
    assert actions == ["created_pending", "status_active", "status_disabled", "status_revoked"]


def test_unknown_database_schema_is_rejected_without_rewriting_it(tmp_path):
    path = tmp_path / "profile" / "routes.db"
    path.parent.mkdir(mode=0o700)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE foreign_table(value TEXT)")
    db.execute("PRAGMA user_version=77")
    db.commit()
    db.close()
    path.chmod(0o600)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(BridgeError) as raised:
        DynamicRouteStore(path)
    assert raised.value.code == "dynamic_route_state_unsupported"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 77
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("foreign_table",)]
    finally:
        db.close()


def test_unversioned_view_is_rejected_without_rewriting_it(tmp_path):
    path = tmp_path / "profile" / "routes.db"
    path.parent.mkdir(mode=0o700)
    db = sqlite3.connect(path)
    db.execute("CREATE VIEW unexpected_view AS SELECT 1 AS value")
    db.commit()
    db.close()
    path.chmod(0o600)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(BridgeError) as raised:
        DynamicRouteStore(path)
    assert raised.value.code == "dynamic_route_state_unsupported"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_schema_v1_migrates_grant_identity_from_policy_atomically(tmp_path):
    path = tmp_path / "profile" / "routes.db"
    path.parent.mkdir(mode=0o700)
    route = policy()
    db = sqlite3.connect(path)
    db.executescript("""
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
    """)
    db.execute(
        """INSERT INTO dynamic_routes(route_id,profile,workspace_id,name,name_normalized,create_key,
        policy_hash,policy_json,status,created_by_profile,created_at,updated_at,revision)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
        (route["route_id"], "default", "workspace-a", "Canary", "canary", "source",
         "hash", json.dumps(route), "pending", "default", 1.0, 1.0),
    )
    db.commit()
    db.close()
    path.chmod(0o600)

    store = DynamicRouteStore(path)

    assert store.list("default")[0]["grant_id"] == route["grant_id"]
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert "grant_id" in {row[1] for row in db.execute("PRAGMA table_info(dynamic_routes)")}
    finally:
        db.close()
