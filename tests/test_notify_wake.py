"""Completion wake contracts; all transports use local fakes."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest_plugins = ("tests.test_notify",)

from notify.cli import execute
from notify.config import NotifyError, parse_config
from notify.service import Service
from notify.state import INDEXES_V1, SCHEMA, State
from notify.wake import (
    MAX_BODY_BYTES,
    MAX_SNAPSHOT_BYTES,
    WakeSender,
    build_payload,
    classify_admission,
    load_webhook_policy,
    verify_configured_route,
    verify_webhook_policy,
)
from tests.test_notify import PROJECT, add, comment, issue, run

ROUTE = {
    "default-test": {"profile": "default", "route": "default-test", "test": True}
}
WEBHOOK_POLICY = {
    ("default", "default-test"): {
        "deliver": "telegram",
        "deliver_extra": {"chat_id": "100", "thread_id": "999"},
    }
}


def exported_route(**changes):
    return {
        "profile": "default",
        "route": "default-test",
        "events": ["task.completed"],
        "deliver": "telegram",
        "deliver_extra": {"chat_id": "100", "thread_id": "999"},
        "deliver_only": False,
        "cron_job": False,
        "mirror_to_session": False,
        "script_configured": False,
        "skills": [],
        "coalesce_enabled": False,
        "toolsets": ["web"],
        "hmac_configured": True,
        "prompt_policy": "snapshot_only_final",
    } | changes


def configure_wake(ctx):
    ctx.config = parse_config(
        ctx.raw
        | {
            "wake": {
                "enabled": True,
                "base_url": "http://127.0.0.1:8644",
                "secret_credential": "fake-wake",
                "routes": ROUTE,
            }
        }
    )
    sid = add(
        ctx,
        chat_type="thread",
        thread_id="999",
        project_id=PROJECT,
        label="test-thread",
    )
    ctx.state.add_wake_subscription(
        sid, ctx.config.wake["routes"]["default-test"], enabled=True, now=ctx.now
    )
    return sid


def create_done(ctx, *, revision=2, at=None, description="Description", comments=None):
    run(ctx, issue(ctx, "todo", 1, at=ctx.now))
    return run(
        ctx,
        issue(
            ctx,
            "done",
            revision,
            at=at or ctx.now + 1,
            title="Completed test issue",
            description=description,
        ),
        comments=comments or [],
    )


def test_wake_config_is_loopback_only_and_route_names_are_gateway_safe(ctx):
    base = ctx.raw | {"wake": {"enabled": True, "routes": ROUTE}}
    assert parse_config(base).wake["enabled"]
    for url in (
        "https://127.0.0.1:8644",
        "http://localhost:8644",
        "http://127.0.0.1:8644/path",
        "http://127.0.0.1:99999",
    ):
        with pytest.raises(NotifyError):
            parse_config(base | {"wake": {"enabled": True, "base_url": url, "routes": ROUTE}})
    with pytest.raises(NotifyError):
        parse_config(
            base
            | {
                "wake": {
                    "enabled": True,
                    "routes": {"UPPER_CASE": {"profile": "default", "route": "bad_route"}},
                }
            }
        )
    accepted_route = parse_config(
        ctx.raw
        | {
            "wake": {
                "enabled": True,
                "routes": {
                    "wake-route": {
                        "profile": "default",
                        "route": "wake.route_v1",
                    }
                },
            }
        }
    )
    assert accepted_route.wake["routes"]["wake-route"]["route"] == "wake.route_v1"


def test_new_done_transition_creates_one_wake_and_suppresses_all_regular_notices(ctx):
    sid = configure_wake(ctx)
    assert create_done(ctx, comments=[comment(ctx, text="QUESTION: do not send separately")]) == 0
    assert ctx.state.rows("SELECT * FROM notifications") == []
    jobs = ctx.state.rows("SELECT * FROM wake_jobs")
    assert len(jobs) == 1
    body = json.loads(jobs[0]["payload_json"])
    assert body["event"] == body["event_type"] == body["type"] == "task.completed"
    assert body["wake_id"] == jobs[0]["id"]
    assert body["profile"] == "default"
    assert body["origin"] == {
        "platform": "telegram",
        "chat_id": "100",
        "thread_id": "999",
        "chat_type": "thread",
    }
    assert body["snapshot"]["description"] == "Description"
    assert ctx.state.rows("SELECT enabled FROM wake_subscriptions WHERE subscription_id=?", (sid,))[0]["enabled"]
    run(ctx, issue(ctx, "done", 3, at=ctx.now + 2, description="changed later"))
    assert len(ctx.state.rows("SELECT * FROM wake_jobs")) == 1
    assert not ctx.state.rows("SELECT * FROM notifications")


def test_baseline_and_enabled_since_suppress_historical_done(ctx):
    configure_wake(ctx)
    run(ctx, issue(ctx, "done", at=ctx.now))
    assert not ctx.state.rows("SELECT * FROM wake_jobs")

    ctx.state.db.execute("DELETE FROM issues")
    ctx.state.db.execute("DELETE FROM events")
    # Re-arm the same subscription after the fixture's historical baseline.
    sid = ctx.state.wake_subscriptions()[0]["subscription_id"]
    ctx.state.set_wake_enabled(sid, False, ctx.config.wake["routes"])
    ctx.state.set_wake_enabled(sid, True, ctx.config.wake["routes"], now=ctx.now + 10)
    run(ctx, issue(ctx, "todo", at=ctx.now))
    run(ctx, issue(ctx, "done", 2, at=ctx.now + 5))
    assert not ctx.state.rows("SELECT * FROM wake_jobs")


def test_reopen_then_done_creates_new_wake_and_disable_cancels_pending(ctx):
    sid = configure_wake(ctx)
    create_done(ctx)
    run(ctx, issue(ctx, "todo", 3, at=ctx.now + 2))
    run(ctx, issue(ctx, "done", 4, at=ctx.now + 3, title="Second completion"))
    assert len(ctx.state.rows("SELECT * FROM wake_jobs")) == 2
    ctx.state.set_wake_enabled(sid, False, ctx.config.wake["routes"])
    assert {row["status"] for row in ctx.state.rows("SELECT status FROM wake_jobs")} == {"cancelled"}
    assert len(ctx.state.wake_subscriptions()) == 1
    run(ctx, issue(ctx, "todo", 5, at=ctx.now + 4))
    run(ctx, issue(ctx, "done", 6, at=ctx.now + 5))
    assert len(ctx.state.rows("SELECT * FROM notifications")) == 0


def test_wake_requires_exact_project_and_supported_destination(ctx):
    route = parse_config(ctx.raw | {"wake": {"enabled": True, "routes": ROUTE}}).wake["routes"]["default-test"]
    sid = add(ctx, project_id="")
    with pytest.raises(NotifyError):
        ctx.state.add_wake_subscription(sid, route)
    sid2 = add(ctx, chat_type="group", thread_id="", project_id=PROJECT)
    with pytest.raises(NotifyError):
        ctx.state.add_wake_subscription(sid2, route)


@pytest.mark.parametrize(
    ("status", "body", "expected", "code"),
    [
        (200, b'{"status":"accepted"}', "sent", ""),
        (202, b'{"status":"queued"}', "sent", ""),
        (200, b'{"status":"duplicate"}', "sent", ""),
        (409, b'{"status":"duplicate"}', "sent", ""),
        (200, b'{"status":"ignored"}', "dead", "wake_route_ignored"),
        (401, b'{"status":"ignored"}', "dead", "wake_http_401"),
        (409, b'{"status":"conflict"}', "dead", "wake_http_409"),
        (503, b'{"status":"error"}', "delivery_unknown", "wake_http_503"),
        (200, b"", "delivery_unknown", "wake_response_uncertain"),
        (200, b'{"status":"mystery"}', "delivery_unknown", "wake_response_uncertain"),
        (200, b'{"status":[]}', "delivery_unknown", "wake_response_uncertain"),
        (200, b'{"status":{}}', "delivery_unknown", "wake_response_uncertain"),
        (200, b'{"status":17}', "delivery_unknown", "wake_response_uncertain"),
        (201, b'{"status":"accepted"}', "delivery_unknown", "wake_response_uncertain"),
        (200, b"{" + b'"x":' * 2000 + b'0' + b'}' * 2000, "delivery_unknown", "wake_response_uncertain"),
    ],
)
def test_webhook_admission_requires_matching_http_and_body(status, body, expected, code):
    result = classify_admission(status, body)
    assert (result.status, result.error_code) == (expected, code)


def test_wake_sender_signs_exact_bytes_and_uses_fixed_route():
    wake_id = "6b2d7c11-90bd-4e2d-a9ce-48079b92ff53"
    body = b'{"event":"task.completed","event_type":"task.completed","type":"task.completed"}'
    expected_body = body

    class Response:
        status = 200

        def read(self, count):
            return b'{"status":"accepted"}'

    class Connection:
        def __init__(self, host, port, timeout):
            assert host == "127.0.0.1" and port == 8644 and timeout == 3
            self.status = 200

        def request(self, method, path, *, body, headers):
            assert (method, path) == ("POST", "/p/om73/webhooks/test-route")
            assert body is expected_body
            timestamp = headers["X-Webhook-Timestamp"]
            expected = hmac.new(
                b"secret", timestamp.encode("ascii") + b"." + body, hashlib.sha256
            ).hexdigest()
            assert headers["X-Webhook-Signature-V2"] == expected
            assert headers["X-Request-ID"] == wake_id

        def getresponse(self):
            return Response()

        def close(self):
            pass

    with patch("notify.wake.http.client.HTTPConnection", Connection):
        result = WakeSender("http://127.0.0.1:8644", 3).send(
            body,
            profile="om73",
            route="test-route",
            wake_id=wake_id,
            secret="secret",
        )
    assert result.status == "sent"


def test_wake_sender_rejects_non_loopback_and_non_root_urls():
    for base_url in (
        "http://localhost:8644",
        "http://127.0.0.1:8644/outside",
        "http://127.0.0.1:8644?target=elsewhere",
        "http://user@127.0.0.1:8644",
        "http://127.0.0.1:99999",
    ):
        with pytest.raises(NotifyError, match="wake_config_invalid"):
            WakeSender(base_url)


def test_webhook_policy_export_is_strict_and_pins_profile_event_and_destination(ctx):
    path = ctx.root / "webhook-policy.json"
    path.write_text(json.dumps({"routes": [exported_route()]}))
    path.chmod(0o600)
    policy = load_webhook_policy(path)
    verify_webhook_policy(
        policy,
        "default",
        "default-test",
        {
            "platform": "telegram",
            "chat_id": "100",
            "thread_id": "999",
            "chat_type": "thread",
        },
    )
    with pytest.raises(NotifyError, match="wake_route_profile_mismatch"):
        verify_webhook_policy(
            policy,
            "om73",
            "default-test",
            {
                "platform": "telegram",
                "chat_id": "100",
                "thread_id": "999",
                "chat_type": "thread",
            },
        )
    with pytest.raises(NotifyError, match="wake_route_policy_mismatch"):
        verify_webhook_policy(
            policy,
            "default",
            "default-test",
            {
                "platform": "telegram",
                "chat_id": "100",
                "thread_id": "998",
                "chat_type": "thread",
            },
        )
    for bad in (
        exported_route(events=["task.updated"]),
        exported_route(deliver_only=True),
        exported_route(script_configured=True),
        exported_route(skills=["review-skill"]),
        exported_route(coalesce_enabled=True),
        exported_route(toolsets=["plugins", "web"]),
        exported_route(hmac_configured=False),
        exported_route(extra_secret="must-not-be-exported"),
    ):
        path.write_text(json.dumps({"routes": [bad]}))
        with pytest.raises(NotifyError, match="wake_webhook_policy_invalid"):
            load_webhook_policy(path)


def test_configured_wake_route_must_exist_once_and_match_profile():
    configured = {
        "route-alias": {"route": "wake.route_v1", "profile": "default"}
    }
    assert verify_configured_route(configured, "default", "wake.route_v1") == next(
        iter(configured.values())
    )
    with pytest.raises(NotifyError, match="wake_route_profile_mismatch"):
        verify_configured_route(configured, "om73", "wake.route_v1")
    with pytest.raises(NotifyError, match="wake_route_unavailable"):
        verify_configured_route(configured, "default", "removed-route")


def test_doctor_rejects_a_persisted_wake_profile_missing_from_current_config(
    ctx, monkeypatch
):
    configure_wake(ctx)
    path = ctx.root / "webhook-policy.json"
    path.write_text(json.dumps({"routes": [exported_route()]}))
    path.chmod(0o600)
    ctx.config = parse_config(
        ctx.raw
        | {
            "wake": {
                "enabled": True,
                "webhook_policy_file": str(path),
                "routes": {
                    "default-test": {
                        "profile": "om73",
                        "route": "default-test",
                        "test": True,
                    }
                },
            }
        }
    )
    ctx.state.db.close()
    monkeypatch.setattr("notify.cli.load_config", lambda _path: ctx.config)
    monkeypatch.setattr("notify.cli.State", State)

    with pytest.raises(NotifyError, match="wake_route_profile_mismatch"):
        execute(
            SimpleNamespace(
                command="doctor",
                config=ctx.root / "unused.toml",
                offline=True,
            )
        )


def test_snapshot_is_utf8_bounded_and_truncates_old_comments():
    sub = {"platform": "max", "chat_id": "-10", "thread_id": "", "chat_type": "group"}
    issue_row = {
        "id": "issue-a",
        "identifier": "TEST-1",
        "title": "Finished",
        "status": "done",
        "description": "x" * 2000,
        "project_id": PROJECT,
    }
    comments = [
        {
            "id": f"comment-{i:03d}",
            "author_type": "agent",
            "content": ("old" if i < 10 else "😀") * (500 if i < 10 else 200),
            "created_at": datetime.fromtimestamp(1_800_000_000 + i, UTC).isoformat(),
        }
        for i in range(60)
    ]
    raw = build_payload(
        wake_id="6b2d7c11-90bd-4e2d-a9ce-48079b92ff53",
        profile="default",
        subscription=sub,
        issue=issue_row,
        comments=comments,
        issue_url="https://multica.example.invalid/test/issues/TEST-1",
        workspace_id="workspace-test",
        transition_seq=2,
    )
    body = json.loads(raw)
    assert len(raw) <= MAX_BODY_BYTES
    assert len(json.dumps(body["snapshot"], ensure_ascii=False).encode()) <= MAX_SNAPSHOT_BYTES
    assert body["snapshot"]["comments_truncated"] is True
    assert (body["event"], body["event_type"], body["type"]) == (
        "task.completed",
        "task.completed",
        "task.completed",
    )
    assert len(body["snapshot"]["comments"]) < 50
    assert "old" not in "".join(c["content"] for c in body["snapshot"]["comments"])


def test_snapshot_accepts_empty_multica_description_and_missing_author_type():
    raw = build_payload(
        wake_id="6b2d7c11-90bd-4e2d-a9ce-48079b92ff53",
        profile="default",
        subscription={
            "platform": "max",
            "chat_id": "-10",
            "thread_id": "",
            "chat_type": "group",
        },
        issue={
            "id": "issue-a",
            "identifier": "TEST-1",
            "title": "Finished",
            "status": "done",
            "description": None,
            "project_id": PROJECT,
        },
        comments=[
            {
                "id": "comment-1",
                "content": "Done",
                "created_at": datetime.fromtimestamp(1_800_000_000, UTC).isoformat(),
            }
        ],
        issue_url="https://multica.example.invalid/test/issues/TEST-1",
        workspace_id="workspace-test",
        transition_seq=1,
    )
    body = json.loads(raw)
    assert body["snapshot"]["description"] == ""
    assert body["snapshot"]["comments"][0]["author_type"] == "unknown"


def test_schema_v1_migration_preserves_rows_and_unknown_schema_is_untouched(ctx):
    legacy = ctx.root / "legacy.db"
    db = sqlite3.connect(legacy)
    for table, columns in SCHEMA.items():
        db.execute(f"CREATE TABLE {table} ({columns})")
    for statement in INDEXES_V1.values():
        db.execute(statement)
    db.execute("INSERT INTO metadata VALUES('sentinel','retained')")
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    legacy.chmod(0o600)
    migrated = State(legacy)
    assert migrated.db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert migrated.rows("SELECT value FROM metadata WHERE key='sentinel'")[0]["value"] == "retained"
    assert {r["name"] for r in migrated.db.execute("SELECT name FROM sqlite_master WHERE type='table'")} >= {"wake_jobs", "wake_subscriptions"}
    migrated.db.close()

    broken = ctx.root / "broken.db"
    db = sqlite3.connect(broken)
    for table, columns in SCHEMA.items():
        db.execute(f"CREATE TABLE {table} ({columns})")
    for statement in INDEXES_V1.values():
        db.execute(statement)
    db.execute("ALTER TABLE metadata ADD COLUMN unexpected TEXT")
    db.execute("PRAGMA user_version=1")
    db.commit()
    before = db.execute("PRAGMA user_version").fetchone()[0]
    db.close()
    broken.chmod(0o600)
    with pytest.raises(NotifyError, match="migration"):
        State(broken)
    verify = sqlite3.connect(broken)
    assert verify.execute("PRAGMA user_version").fetchone()[0] == before
    assert "wake_jobs" not in {r[0] for r in verify.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    verify.close()


def test_schema_migration_rolls_back_partial_wake_schema(ctx, monkeypatch):
    legacy = ctx.root / "rollback.db"
    db = sqlite3.connect(legacy)
    for table, columns in SCHEMA.items():
        db.execute(f"CREATE TABLE {table} ({columns})")
    for statement in INDEXES_V1.values():
        db.execute(statement)
    db.execute("INSERT INTO metadata VALUES('sentinel','retained')")
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    legacy.chmod(0o600)

    monkeypatch.setattr(
        "notify.state.WAKE_INDEXES",
        {"wake_due": "CREATE INDEX malformed migration index"},
    )
    with pytest.raises(NotifyError, match="migration"):
        State(legacy)

    verify = sqlite3.connect(legacy)
    assert verify.execute("PRAGMA user_version").fetchone()[0] == 1
    assert verify.execute(
        "SELECT value FROM metadata WHERE key='sentinel'"
    ).fetchone()[0] == "retained"
    assert "wake_subscriptions" not in {
        row[0]
        for row in verify.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    verify.close()


def test_wake_claim_fencing_unknown_and_explicit_replay(ctx):
    configure_wake(ctx)
    create_done(ctx)
    row = ctx.state.wake_due(time.time())[0]
    claim = ctx.state.wake_claim(
        row["id"], time.time(), 30, ctx.config.wake["routes"], WEBHOOK_POLICY
    )
    assert claim and claim["attempts"] == 1
    assert (
        ctx.state.wake_claim(
            row["id"], time.time(), 30, ctx.config.wake["routes"], WEBHOOK_POLICY
        )
        is None
    )
    stale = dict(claim, attempts=0)
    assert not ctx.state.wake_finish(stale, "sent")
    assert ctx.state.wake_finish(claim, "delivery_unknown", "wake_transport_uncertain")
    assert not ctx.state.wake_due(time.time())
    assert ctx.state.wake_replay(row["id"], 30, ctx.config.wake["routes"])
    replayed = ctx.state.wake_due(time.time())[0]
    assert replayed["id"] == row["id"] and replayed["attempts"] == 0
    claim2 = ctx.state.wake_claim(
        row["id"], time.time(), 30, ctx.config.wake["routes"], WEBHOOK_POLICY
    )
    assert claim2 and claim2["attempts"] == 1
    assert ctx.state.wake_finish(claim2, "sent")
    assert ctx.state.rows("SELECT payload_json,status FROM wake_jobs")[0]["payload_json"] is None


def test_wake_claim_rejects_a_route_export_with_a_changed_recipient(ctx):
    configure_wake(ctx)
    create_done(ctx)
    row = ctx.state.wake_due(time.time())[0]
    altered = {
        ("default", "default-test"): {
            "deliver": "telegram",
            "deliver_extra": {"chat_id": "100", "thread_id": "different"},
        }
    }
    assert (
        ctx.state.wake_claim(
            row["id"], time.time(), 30, ctx.config.wake["routes"], altered
        )
        is None
    )
    saved = ctx.state.rows("SELECT status,last_error,attempts FROM wake_jobs")[0]
    assert (saved["status"], saved["last_error"], saved["attempts"]) == (
        "dead",
        "wake_route_policy_mismatch",
        0,
    )


def test_service_sends_one_admitted_wake_and_clears_its_payload(ctx, monkeypatch):
    configure_wake(ctx)
    create_done(ctx)
    path = ctx.root / "webhook-policy.json"
    path.write_text(json.dumps({"routes": [exported_route()]}))
    path.chmod(0o600)
    ctx.config = parse_config(
        ctx.raw
        | {
            "wake": {
                "enabled": True,
                "webhook_policy_file": str(path),
                "routes": ROUTE,
            }
        }
    )
    row = ctx.state.wake_due(time.time())[0]
    sent = []

    class FakeSender:
        def __init__(self, base_url, timeout):
            assert base_url == "http://127.0.0.1:8644"
            assert timeout == 10

        def send(self, body, **kwargs):
            sent.append((body, kwargs))
            return SimpleNamespace(status="sent", error_code="")

    monkeypatch.setattr("notify.service.credential", lambda _name: "fake-secret")
    monkeypatch.setattr("notify.service.WakeSender", FakeSender)
    service = SimpleNamespace(
        config=ctx.config,
        state=ctx.state,
        wake_slots=asyncio.Semaphore(1),
        wake_scheduled={row["id"]},
    )
    asyncio.run(Service.deliver_wake(service, row))
    saved = ctx.state.rows("SELECT status,attempts,payload_json FROM wake_jobs")[0]
    assert (saved["status"], saved["attempts"], saved["payload_json"]) == (
        "sent",
        1,
        None,
    )
    assert len(sent) == 1
    assert json.loads(sent[0][0])["event_type"] == "task.completed"
    assert sent[0][1]["wake_id"] == row["id"]
    assert not ctx.state.wake_due(time.time())
    assert not service.wake_scheduled


def test_expired_sending_becomes_unknown_without_automatic_retry(ctx):
    configure_wake(ctx)
    create_done(ctx)
    row = ctx.state.wake_due(time.time())[0]
    ctx.state.wake_claim(
        row["id"], time.time() - 100, 10, ctx.config.wake["routes"], WEBHOOK_POLICY
    )
    assert ctx.state.wake_expire(time.time()) == 1
    assert ctx.state.rows("SELECT status FROM wake_jobs")[0]["status"] == "delivery_unknown"
    assert not ctx.state.wake_due(time.time())
