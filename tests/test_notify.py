"""Offline central notification contracts: no production credentials or writes."""

from __future__ import annotations

import copy
import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from notify.api import Multica
from notify.cli import main
from notify.config import (
    NotifyError,
    append_workspace,
    atomic_private,
    load_config,
    parse_config,
)
from notify.delivery import response
from notify.importer import import_issues
from notify.policy import classify, reconcile
from notify.state import State, encoded, subscription

WID = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
SQUAD = "33333333-3333-4333-8333-333333333333"


def iso(at):
    return datetime.fromtimestamp(at, UTC).isoformat()


@pytest.fixture
def ctx(tmp_path):
    tmp_path.chmod(0o700)
    raw = {
        "service": {
            "db_path": str(tmp_path / "state.db"),
            "runtime_dir": str(tmp_path / "run"),
        },
        "accounts": {
            "tg": {"platform": "telegram", "token_credential": "fake-tg"},
            "max": {"platform": "max", "token_credential": "fake-max"},
        },
        "workspaces": {
            "test": {
                "origin": "https://multica.example.invalid",
                "workspace_id": WID,
                "cli_profile": "test-cli",
                "pat_credential": "fake-pat",
            }
        },
    }
    config = parse_config(raw)
    state = State(tmp_path / "state.db", create=True)
    state.project(config)
    value = SimpleNamespace(
        root=tmp_path, config=config, state=state, raw=raw, now=time.time() - 100
    )
    yield value
    state.db.close()


def add(ctx, **changes):
    row = {
        "platform": "telegram",
        "account": "tg",
        "chat_id": "100",
        "chat_type": "group",
        "workspace_id": "test",
        "since": 0,
    } | changes
    return ctx.state.add_subscription(subscription(row, ctx.config, time.time()))


def issue(ctx, status="todo", revision=1, at=None, **extra):
    return {
        "id": "issue-a",
        "identifier": "TEST-1",
        "workspace_id": WID,
        "project_id": PROJECT,
        "status": status,
        "revision": revision,
        "updated_at": iso(at or ctx.now),
        "labels": [],
    } | extra


def comment(ctx, cid="c1", text="QUESTION: help", at=None):
    return {"id": cid, "content": text, "created_at": iso(at or ctx.now)}


def run(ctx, obj=None, comments=None, runs=None, **kw):
    return reconcile(
        ctx.state,
        ctx.config,
        "test",
        obj or issue(ctx),
        comments or [],
        runs or [],
        "https://multica.example.invalid/test/issues/TEST-1",
        **kw,
    )


def notifications(ctx):
    return ctx.state.rows("SELECT * FROM notifications")


@pytest.mark.parametrize(
    "changes",
    [
        {"thread_id": "2"},
        {"chat_type": "thread", "thread_id": ""},
        {"platform": "max", "account": "max", "chat_type": "thread", "thread_id": "2"},
        {"events": []},
        {"squad_id": "invalid"},
        {"mode": "invalid"},
        {"platform": "max"},
        {"labels": ["a", "a"]},
    ],
)
def test_subscription_validation(ctx, changes):
    with pytest.raises(NotifyError):
        add(ctx, **changes)


def test_subscription_uniqueness_and_empty_thread(ctx):
    add(ctx)
    with pytest.raises(NotifyError, match="duplicate"):
        add(ctx)
    assert ctx.state.rows("SELECT thread_id FROM subscriptions")[0]["thread_id"] == ""


def test_one_event_fans_out_and_global_seen_does_not_suppress(ctx):
    add(ctx)
    add(ctx, chat_id="101")
    assert run(ctx, comments=[comment(ctx)]) == 2
    assert run(ctx, comments=[comment(ctx)]) == 0
    assert len(ctx.state.rows("SELECT * FROM seen_comments")) == 1


def test_fanout_and_snapshot_rollback_together(ctx):
    add(ctx)
    add(ctx, chat_id="101")
    from notify.policy import render

    calls = []

    def fail_second(*args):
        calls.append(1)
        if len(calls) == 2:
            raise NotifyError("injected")
        return render(*args)

    with (
        patch("notify.policy.render", side_effect=fail_second),
        pytest.raises(NotifyError),
    ):
        run(ctx, comments=[comment(ctx)])
    for table in ("notifications", "processed_keys", "issues", "seen_comments"):
        assert not ctx.state.rows(f"SELECT * FROM {table}")


@pytest.mark.parametrize("mode", ["quiet", "verbose"])
def test_report_never_sent_separately(ctx, mode):
    add(ctx, mode=mode)
    run(ctx, comments=[comment(ctx, text=" REPORT: result ")])
    assert all(
        json.loads(n["payload_json"])["event_type"] != "report"
        for n in notifications(ctx)
    )


def test_verbose_plain_comments_and_progress(ctx):
    add(ctx, mode="verbose")
    assert run(ctx, comments=[comment(ctx, text="ordinary")]) == 2
    assert run(ctx, issue(ctx, "in_progress", 2)) == 1


def test_quiet_suppresses_plain_and_progress(ctx):
    add(ctx)
    assert run(ctx, comments=[comment(ctx, text="ordinary")]) == 0
    assert run(ctx, issue(ctx, "in_progress", 2)) == 0


@pytest.mark.parametrize("kind", ["blocked", "done", "in_review"])
def test_quiet_status_classes(ctx, kind):
    add(ctx)
    run(ctx)
    assert run(ctx, issue(ctx, kind, 2)) == 1
    assert run(ctx, issue(ctx, kind, 3)) == 0


@pytest.mark.parametrize("enabled", [False, True])
def test_cancelled_is_opt_in(ctx, enabled):
    add(ctx, events=["cancelled"] if enabled else ["final"])
    run(ctx)
    assert run(ctx, issue(ctx, "cancelled", 2)) == int(enabled)


def test_failed_requires_confirmed_task_scope(ctx):
    add(ctx)
    task = {
        "id": "task-a",
        "issue_id": "issue-a",
        "status": "failed",
        "completed_at": iso(ctx.now),
    }
    assert run(ctx, runs=[task]) == 1
    assert run(ctx, runs=[task]) == 0
    task["issue_id"] = "foreign"
    with pytest.raises(NotifyError):
        run(ctx, runs=[task])


@pytest.mark.parametrize("status", ["done", "blocked"])
def test_repeated_status_uses_durable_transition_sequence(ctx, status):
    add(ctx)
    run(ctx, issue(ctx, status, 1))
    run(ctx, issue(ctx, "todo", 2))
    run(ctx, issue(ctx, status, 3))
    assert len(notifications(ctx)) == 2
    assert len({n["event_key"] for n in notifications(ctx)}) == 2
    reopened = State(ctx.root / "state.db")
    assert reopened.rows("SELECT transition_seq FROM issues")[0]["transition_seq"] == 3
    reopened.db.close()
    assert run(ctx, issue(ctx, status, 4)) == 0


def test_history_id_has_priority(ctx):
    add(ctx)
    run(ctx, issue(ctx, "done", history_id="history-a"))
    assert "history-a" in notifications(ctx)[0]["event_key"]


def test_report_seen_then_long_pause_then_final_same_cycle(ctx):
    add(ctx)
    start = ctx.now - 10000
    run(ctx, issue(ctx, "done", 1, at=start), now=start)
    run(ctx, issue(ctx, "todo", 2, at=start + 1), now=start + 1)
    report = comment(ctx, text="REPORT: current-cycle", at=start + 2)
    run(
        ctx,
        issue(ctx, "in_progress", 3, at=start + 3),
        comments=[report],
        now=start + 3,
    )
    run(
        ctx,
        issue(ctx, "in_progress", 4, at=start + 4),
        comments=[report],
        now=start + 4,
    )
    run(ctx, issue(ctx, "done", 5), comments=[report], now=ctx.now)
    assert "current-cycle" in json.loads(notifications(ctx)[-1]["payload_json"])["text"]


def test_quick_reopen_excludes_previous_report(ctx):
    add(ctx)
    old = comment(ctx, text="REPORT: previous-cycle", at=ctx.now - 2)
    run(ctx, issue(ctx, "done", 1, at=ctx.now - 1), comments=[old], now=ctx.now)
    run(ctx, issue(ctx, "todo", 2, at=ctx.now + 1), now=ctx.now + 1)
    run(ctx, issue(ctx, "done", 3, at=ctx.now + 2), comments=[old], now=ctx.now + 2)
    assert (
        "previous-cycle"
        not in json.loads(notifications(ctx)[-1]["payload_json"])["text"]
    )


def test_unknown_cycle_uses_lookback(ctx):
    add(ctx)
    old = comment(ctx, text="REPORT: stale", at=ctx.now - 1000)
    run(ctx, issue(ctx, "done"), comments=[old], now=ctx.now)
    assert "stale" not in json.loads(notifications(ctx)[0]["payload_json"])["text"]


def test_late_revision_does_not_rollback_snapshot(ctx):
    add(ctx)
    run(ctx, issue(ctx, "done", 5))
    assert run(ctx, issue(ctx, "todo", 4)) == 0
    assert ctx.state.rows("SELECT status FROM issues")[0]["status"] == "done"


@pytest.mark.parametrize("assignee_type", ["member", "agent", None])
def test_squad_does_not_expand_members(ctx, assignee_type):
    add(ctx, squad_id=SQUAD)
    assert (
        run(ctx, issue(ctx, "done", assignee_type=assignee_type, assignee_id=SQUAD))
        == 0
    )


def test_exact_squad_and_labels_all(ctx):
    add(ctx, squad_id=SQUAD, labels=["a", "b"])
    assert (
        run(
            ctx,
            issue(
                ctx,
                "done",
                assignee_type="squad",
                assignee_id=SQUAD,
                labels=[{"name": "a"}],
            ),
        )
        == 0
    )
    assert (
        run(
            ctx,
            issue(
                ctx,
                "todo",
                2,
                assignee_type="squad",
                assignee_id=SQUAD,
                labels=["a", "b"],
            ),
        )
        == 0
    )
    assert (
        run(
            ctx,
            issue(
                ctx,
                "done",
                3,
                assignee_type="squad",
                assignee_id=SQUAD,
                labels=["a", "b"],
            ),
        )
        == 1
    )


def test_question_prefix_and_mention_priority(ctx):
    p = ctx.config.policy
    assert classify("  вОпРоС: help", "todo", p) == "question"
    assert classify("REPORT: @operator, help", "blocked", p) == "report"
    assert classify("a@example.invalid", "blocked", p) == "plain"


def test_shadow_subscription_keeps_own_destination(ctx):
    add(ctx, chat_id="123", shadow=True)
    run(ctx, comments=[comment(ctx)])
    payload = json.loads(notifications(ctx)[0]["payload_json"])
    assert payload["chat_id"] == "123"
    assert ctx.state.rows("SELECT shadow FROM subscriptions")[0]["shadow"] == 1


def test_disable_and_reenable_do_not_resurrect_queue(ctx):
    sid = add(ctx)
    run(ctx, comments=[comment(ctx)])
    ctx.state.toggle(sid, False)
    assert notifications(ctx)[0]["status"] == "cancelled"
    assert not ctx.state.due(time.time())
    before = time.time()
    ctx.state.toggle(sid, True)
    assert ctx.state.rows("SELECT since FROM subscriptions")[0]["since"] >= before
    assert notifications(ctx)[0]["status"] == "cancelled"
    assert run(ctx, comments=[comment(ctx, "c2")]) == 0


def make_claim(ctx, maximum=5):
    add(ctx)
    run(ctx, comments=[comment(ctx)])
    return ctx.state.claim(notifications(ctx)[0]["id"], time.time(), maximum, 300)


@pytest.mark.parametrize(
    "outcome,expected", [("delivered", "delivered"), ("retry", "cancelled")]
)
def test_inflight_finish_after_disable(ctx, outcome, expected):
    claim = make_claim(ctx)
    ctx.state.toggle(claim["subscription_id"], False)
    ctx.state.finish(claim, outcome, "test", 5)
    assert notifications(ctx)[0]["status"] == expected
    assert not ctx.state.claim(claim["id"], time.time() + 1000, 5, 300)


def test_lease_takeover_fences_late_worker(ctx):
    first = make_claim(ctx)
    second = ctx.state.claim(first["id"], time.time() + 301, 5, 300)
    assert second["attempts"] == 2 and second["lease_token"] != first["lease_token"]
    assert not ctx.state.finish(first, "delivered", "accepted", 5)
    assert ctx.state.finish(second, "delivered", "accepted", 5)
    assert notifications(ctx)[0]["payload_json"] is None


@pytest.mark.parametrize("budget", [1, 5, 10])
def test_retry_budget_and_cap(ctx, budget):
    claim = make_claim(ctx, budget)
    for attempt in range(1, budget + 1):
        assert claim["attempts"] == attempt
        ctx.state.finish(claim, "retry", "http_429", budget, 10000)
        row = notifications(ctx)[0]
        if attempt < budget:
            assert (
                row["status"] == "retry"
                and row["next_attempt_at"] - row["updated_at"] <= 600
            )
            claim = ctx.state.claim(row["id"], row["next_attempt_at"] + 1, budget, 300)
    assert row["status"] == "dead" and row["last_error"] == f"retry_exhausted:{budget}"


def test_replay_terminal_only_and_idempotent(ctx):
    claim = make_claim(ctx, 1)
    ctx.state.finish(claim, "retry", "uncertain", 1)
    original = notifications(ctx)[0]
    assert ctx.state.replay(claim["id"], 30)
    assert not ctx.state.replay(claim["id"], 30)
    assert notifications(ctx)[0]["payload_json"] == original["payload_json"]
    assert notifications(ctx)[0]["event_key"] == original["event_key"]


def test_confirmed_anchor_fallback_consumes_attempt_and_keeps_thread(ctx):
    sid = add(ctx, chat_type="thread", thread_id="77", anchor_message_id="11")
    run(ctx, comments=[comment(ctx)])
    row = notifications(ctx)[0]
    first = ctx.state.claim(row["id"], time.time(), 5, 300)
    ctx.state.finish(first, "anchor", "anchor_invalid", 5)
    second = ctx.state.claim(row["id"], time.time(), 5, 300)
    payload = json.loads(second["payload_json"])
    assert (
        second["attempts"] == 2
        and payload["anchor_message_id"] is None
        and payload["thread_id"] == "77"
    )
    assert second["subscription_id"] == sid


def test_budget_one_does_not_allow_extra_anchor_post(ctx):
    claim = make_claim(ctx, 1)
    ctx.state.finish(claim, "anchor", "anchor_invalid", 1)
    assert notifications(ctx)[0]["status"] == "dead"


def test_rate_limits_share_chat_across_threads(ctx):
    p = {"platform": "telegram", "chat_id": "100", "account": "tg"}
    assert ctx.state.reserve(p, 1000) == 1000
    assert ctx.state.reserve(p, 1000) == 1000.5
    assert ctx.state.reserve(p | {"chat_id": "101"}, 1000) >= 1000.55


def test_restart_retains_frozen_payload_without_source(ctx):
    make_claim(ctx)
    row = notifications(ctx)[0]
    other = State(ctx.root / "state.db")
    assert (
        other.rows("SELECT payload_json FROM notifications")[0]["payload_json"]
        == row["payload_json"]
    )
    other.db.close()


def test_retention_keeps_receipts_and_pending_hints(ctx):
    claim = make_claim(ctx)
    ctx.state.finish(claim, "delivered", "accepted", 5)
    ctx.state.hint(
        "test", {"type": "issue:updated", "payload": {"issue": {"id": "issue-a"}}}
    )
    ctx.state.prune(ctx.config, time.time() + 40 * 86400)
    assert not notifications(ctx)
    assert ctx.state.rows("SELECT * FROM processed_keys")
    assert ctx.state.rows("SELECT * FROM hints")
    assert run(ctx, comments=[comment(ctx)]) == 0


def test_payload_limits_and_no_source_secrets(ctx):
    add(ctx)
    run(
        ctx,
        issue(ctx, description="private-source-sentinel"),
        comments=[comment(ctx, text="QUESTION: " + "😀" * 20000)],
    )
    payload = notifications(ctx)[0]["payload_json"]
    assert len(payload.encode()) <= 16384 and len(json.loads(payload)["text"]) <= 3500
    assert "TEST-1" in payload and "https://" in payload
    assert (
        "private-source-sentinel"
        not in ctx.state.rows("SELECT data_json FROM issues")[0]["data_json"]
    )


def test_schema_unknown_rejected_without_changes(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE unknown(value TEXT)")
    db.commit()
    db.close()
    path.chmod(0o600)
    old = path.read_bytes()
    with pytest.raises(NotifyError):
        State(path)
    assert path.read_bytes() == old


def test_reload_projection_keeps_references_and_orphans(ctx):
    sid = add(ctx)
    run(ctx, comments=[comment(ctx)])
    ctx.state.project(ctx.config)
    raw = copy.deepcopy(ctx.raw)
    raw["accounts"] = {}
    ctx.state.project(parse_config(raw))
    row = ctx.state.rows("SELECT * FROM subscriptions")[0]
    assert (
        row["id"] == sid
        and not row["enabled"]
        and row["disabled_reason"] == "orphaned_subscription"
    )
    assert notifications(ctx)[0]["status"] == "cancelled"


def test_reload_identity_change_rolls_back(ctx):
    add(ctx)
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["test"]["origin"] = "https://other.example.invalid"
    with pytest.raises(NotifyError):
        ctx.state.project(parse_config(raw))
    assert (
        ctx.state.rows("SELECT origin FROM workspaces")[0]["origin"]
        == "https://multica.example.invalid"
    )


def test_append_workspace_preserves_comments_and_rejects_invalid(ctx):
    path = ctx.root / "notify.toml"
    atomic_private(path, b"# original comment\n[service]\n# keep me\n")
    row = ctx.raw["workspaces"]["test"]
    assert append_workspace(path, "test", row)
    content = path.read_text()
    assert "# original comment" in content and "# keep me" in content
    with pytest.raises(NotifyError):
        append_workspace(path, "bad", row | {"origin": "http://invalid"})
    assert path.read_text() == content


def test_cli_init_and_offline_doctor(tmp_path, capsys):
    tmp_path.chmod(0o700)
    path = tmp_path / "notify.toml"
    assert (
        main(
            [
                "init",
                "--config",
                str(path),
                "--db-path",
                str(tmp_path / "db"),
                "--runtime-dir",
                str(tmp_path / "run"),
            ]
        )
        == 0
    )
    assert load_config(path).accounts == {}
    assert main(["doctor", "--config", str(path), "--offline"]) == 0
    assert '"ok":true' in capsys.readouterr().out


def test_credentials_and_isolated_cli_home(ctx, monkeypatch):
    creds = ctx.root / "credentials"
    creds.mkdir(mode=0o700)
    atomic_private(creds / "fake-pat", b"fake-pat-sentinel")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.setenv("MULTICA_TOKEN", "must-not-be-inherited")
    api = Multica(ctx.config, "test")
    assert "MULTICA_TOKEN" not in api.env
    assert api.env["HOME"] != str(Path.home())
    assert (
        "fake-pat-sentinel"
        in (api.home / ".multica/profiles/test-cli/config.json").read_text()
    )
    captured = []

    def invoke(argv, env, timeout):
        captured.extend(argv)
        if "--version" in argv:
            return b"multica version 0.8.2"
        assert "fake-pat-sentinel" not in encoded(argv)
        return b"--updated-since --updated-until --offset --fields --sort"

    with patch("notify.api.run_cli", side_effect=invoke):
        api.check_cli()
    assert captured


def test_import_issues_is_baseline_only(ctx):
    sid = add(ctx)

    class Api:
        def issues(self, project):
            return [issue(ctx, "done")]

        def snapshot(self, iid):
            return (
                issue(ctx, "done"),
                [comment(ctx)],
                [],
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    assert import_issues(ctx.state, ctx.config, sid, Api(), dry_run=True) == 1
    assert not ctx.state.rows("SELECT * FROM issues")
    assert import_issues(ctx.state, ctx.config, sid, Api()) == 1
    assert not notifications(ctx)
    assert import_issues(ctx.state, ctx.config, sid, Api()) == 0


@pytest.mark.parametrize(
    "status,data,expected",
    [
        (200, {"ok": True}, "delivered"),
        (429, {"parameters": {"retry_after": 900}}, "retry"),
        (500, {}, "retry"),
        (403, {}, "terminal"),
        (
            400,
            {"description": "Bad Request: message to be replied not found"},
            "anchor",
        ),
    ],
)
def test_platform_outcomes(status, data, expected):
    result = response(status, data, True)
    assert result.outcome == expected and result.retry_after <= 600


def test_status_has_no_chat_token_or_payload(ctx):
    add(ctx, chat_id="123456789")
    run(ctx, comments=[comment(ctx, text="QUESTION: secret-message-sentinel")])
    value = encoded(ctx.state.status())
    assert "123456789" not in value and "secret-message-sentinel" not in value


def test_load_1000_events_100_subscriptions(ctx):
    for i in range(100):
        add(ctx, chat_id=str(1000 + i))
    rows = [comment(ctx, f"c{i}") for i in range(1000)]
    assert run(ctx, comments=rows) == 100000
    assert run(ctx, comments=rows) == 0
