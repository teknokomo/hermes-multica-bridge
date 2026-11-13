from __future__ import annotations

import hashlib
import sqlite3

import pytest

from bridge.dynamic_routes import DynamicRouteStore
from bridge.errors import BridgeError
from bridge.registry import new_id


def policy(*, route_id: str | None = None, name: str = "Canary") -> dict:
    return {"route_id": route_id or new_id(), "name": name, "scope_kind": "project"}


def test_dynamic_store_initializes_private_independent_schema(tmp_path):
    path = tmp_path / "profile" / "dynamic-routes.sqlite3"
    DynamicRouteStore(path)
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
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
                                     create_key="same-source", policy=first, status="pending", max_routes=2)
    retry, inserted_again = store.create(profile="default", workspace_id="workspace-a", name="Canary",
                                         create_key="same-source", policy=policy(), status="active", max_routes=2)
    assert inserted is True
    assert inserted_again is False
    assert retry["route_id"] == created["route_id"]
    assert retry["dynamic_status"] == "pending"
    with pytest.raises(BridgeError, match="different route"):
        store.create(profile="default", workspace_id="workspace-a", name="Changed",
                     create_key="same-source", policy=policy(name="Changed"), status="pending", max_routes=2)
    assert len(store.list("default")) == 1


def test_route_quota_is_enforced_inside_create_transaction(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    store.create(profile="default", workspace_id="workspace-a", name="First",
                 create_key="one", policy=policy(name="First"), status="active", max_routes=1)
    with pytest.raises(BridgeError) as raised:
        store.create(profile="default", workspace_id="workspace-a", name="Second",
                     create_key="two", policy=policy(name="Second"), status="pending", max_routes=1)
    assert raised.value.code == "route_limit_exceeded"
    assert len(store.list("default")) == 1


def test_approval_disable_and_revocation_are_audited_and_fenced(tmp_path):
    store = DynamicRouteStore(tmp_path / "profile" / "routes.db")
    row, _ = store.create(profile="default", workspace_id="workspace-a", name="Canary",
                          create_key="one", policy=policy(), status="pending", max_routes=2)
    assert row["enabled"] is False
    assert store.set_status(row["route_id"], "default", "active")["enabled"] is True
    assert store.set_status(row["route_id"], "default", "disabled")["enabled"] is False
    store.set_status(row["route_id"], "default", "revoked")
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
