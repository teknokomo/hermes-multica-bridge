"""Regressions for confirmed central-service review findings."""

from __future__ import annotations

import asyncio
import copy
import io
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bridge.errors import BridgeError
from notify.api import Multica, run_cli
from notify.config import NotifyError, atomic_private, parse_config
from notify.delivery import Result, Sender, response
from notify.policy import reconcile as policy_reconcile
from notify.service import Service
from tests.test_notify import WID, add, comment, issue, notifications, run
from tests.test_notify import ctx as ctx  # noqa: PLC0414 - pytest fixture re-export


@pytest.mark.parametrize("code", ["result_not_found", "api_forbidden"])
def test_unreadable_hint_does_not_starve_healthy_issue(ctx, code):
    add(ctx)
    ctx.state.hint(
        "test", {"type": "issue:updated", "payload": {"issue": {"id": "aaa"}}}
    )
    service = Service.__new__(Service)
    service.state, service.config = ctx.state, ctx.config
    seen = []

    class Api:
        limited = True

        def issues(self, *args):
            return [issue(ctx)]

        def snapshot(self, iid):
            seen.append(iid)
            if iid == "aaa":
                raise BridgeError(code, "fake unavailable issue")
            return (
                issue(ctx),
                [comment(ctx)],
                [],
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    service.scan("test", Api(), True)
    assert seen == ["aaa", "issue-a"]
    assert len(notifications(ctx)) == 1
    assert ctx.state.rows("SELECT status FROM hints")[0]["status"] == "rejected"
    assert ctx.state.rows("SELECT poll_until FROM cursors")[0]["poll_until"]


def test_existing_invalid_workspace_keeps_identity_and_disables(ctx):
    add(ctx)
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["test"]["workspace_id"] = "malformed"
    raw["workspaces"]["healthy"] = dict(
        ctx.raw["workspaces"]["test"],
        workspace_id="44444444-4444-4444-8444-444444444444",
    )
    candidate = parse_config(raw)
    ctx.state.project(candidate)
    rows = {r["id"]: r for r in ctx.state.rows("SELECT * FROM workspaces")}
    assert rows["test"]["workspace_id"] == ctx.raw["workspaces"]["test"]["workspace_id"]
    assert not rows["test"]["enabled"]
    assert rows["healthy"]["enabled"]
    assert ctx.state.rows("SELECT enabled FROM subscriptions")[0]["enabled"]


def test_cli_stdout_closed_but_process_running_is_recoverable():
    start = time.monotonic()
    with pytest.raises(NotifyError, match="notify_workspace_unavailable"):
        run_cli(
            [sys.executable, "-c", "import os,time; os.close(1); time.sleep(30)"],
            {},
            0.1,
        )
    assert time.monotonic() - start < 3


@pytest.mark.parametrize(
    "field,value", [("delivery_workers", 6), ("request_timeout_seconds", 20)]
)
def test_reload_rejects_restart_only_delivery_settings(ctx, field, value):
    async def check():
        path = ctx.root / "notify.toml"
        atomic_private(path, b"[service]\n")
        with patch("notify.service.load_config", return_value=ctx.config):
            service = Service(path)
        service.state = ctx.state
        old = service.config
        raw = copy.deepcopy(ctx.raw)
        raw["service"][field] = value
        with patch("notify.service.load_config", return_value=parse_config(raw)):
            await service.reload()
        assert service.config is old
        assert not service.collectors

    asyncio.run(check())


def test_invalid_readiness_policy_keeps_reload_projection_and_ipc_unchanged(ctx):
    async def check():
        socket_path = "/run/hermes-multica-notify-readiness/readiness.sock"
        raw = copy.deepcopy(ctx.raw)
        raw["wake"] = {
            "enabled": True,
            "routes": {"canary": {"profile": "default", "route": "canary-wake"}},
        }
        raw["readiness_ipc"] = {
            "enabled": True,
            "socket_path": socket_path,
            "peers": [{"uid": os.getuid(), "profiles": ["default"]}],
        }
        candidate = parse_config(raw)
        projection_calls = []
        state = SimpleNamespace(
            project=lambda config: projection_calls.append(("project", config)),
            project_wake_routes=lambda routes: projection_calls.append(("wake", routes)),
        )
        ipc = SimpleNamespace(path=Path(socket_path), config=ctx.config, _policy={("default", "old"): {}})
        service = Service.__new__(Service)
        service.path, service.config, service.state = ctx.root / "notify.toml", ctx.config, state
        service.readiness_ipc, service.locks, service.collectors = ipc, {}, []
        old_config = service.config
        with patch("notify.service.load_config", return_value=candidate), patch(
            "notify.service.load_webhook_policy", side_effect=NotifyError("wake_webhook_policy_invalid")
        ):
            await service.reload()
        assert service.config is old_config
        assert service.readiness_ipc is ipc
        assert ipc.config is ctx.config
        assert ipc._policy == {("default", "old"): {}}
        assert projection_calls == []

    asyncio.run(check())


def test_completed_pacing_floor_survives_overdue_slot(ctx):
    payload = {
        "platform": "telegram",
        "chat_id": "100",
        "chat_type": "thread",
        "account": "tg",
    }
    assert ctx.state.reserve(payload, 0) == 0
    assert ctx.state.reserve(payload, 10, completed=True) == 10
    assert ctx.state.reserve(payload, 10) == 13


def test_cli_response_recursion_is_event_invalid(ctx):
    api = Multica.__new__(Multica)
    api.config, api.workspace, api.env = ctx.config, ctx.config.workspaces["test"], {}

    def recurse(*args):
        raise RecursionError("nested")

    with (
        patch("notify.api.run_cli", return_value=b"{}"),
        patch("notify.api.strict_json_loads", side_effect=recurse),
        pytest.raises(NotifyError, match="notify_event_invalid"),
    ):
        list(api.issues(""))


def test_actual_dispatch_pacing_after_delayed_first_request(ctx):
    add(ctx)
    run(ctx, comments=[comment(ctx, "c1"), comment(ctx, "c2")])
    rows = notifications(ctx)
    starts = []

    class SlowSender:
        def send(self, *args):
            starts.append(time.monotonic())
            time.sleep(0.06)
            return Result("delivered", "accepted")

    async def check():
        path = ctx.root / "notify.toml"
        atomic_private(path, b"[service]\n")
        with patch("notify.service.load_config", return_value=ctx.config):
            service = Service(path, sender=SlowSender())
        service.state = ctx.state
        service.scheduled = {r["id"] for r in rows}
        with patch("notify.service.credential", return_value="fake"):
            await asyncio.gather(*(service.deliver(r) for r in rows))
        assert all(r["status"] == "delivered" for r in notifications(ctx))

    asyncio.run(check())
    assert len(starts) == 2
    assert starts[1] - starts[0] >= 3.0


@pytest.mark.parametrize("failure_point", ["snapshot", "reconcile"])
def test_invalid_issue_does_not_block_scan_and_keeps_cursor_for_retry(
    ctx, failure_point
):
    add(ctx, since=0)
    old_cursor = ctx.now - 30
    ctx.state.cursor("test", poll_until=old_cursor)
    ctx.state.hint(
        "test",
        {"type": "issue:updated", "payload": {"issue": {"id": "bad-issue"}}},
    )
    service = Service.__new__(Service)
    service.state, service.config = ctx.state, ctx.config
    seen = []
    fail_bad_issue = True
    bad_issue = issue(ctx)
    bad_issue.update(id="bad-issue", identifier="TEST-2")

    class Api:
        limited = False

        def issues(self, *args):
            return [{"id": "issue-a"}]

        def snapshot(self, iid):
            nonlocal fail_bad_issue
            seen.append(iid)
            if failure_point == "snapshot" and iid == "bad-issue" and fail_bad_issue:
                raise NotifyError("notify_event_invalid")
            current = bad_issue if iid == "bad-issue" else issue(ctx)
            return (
                current,
                [comment(ctx, f"question-{iid}")],
                [],
                f"https://multica.example.invalid/test/issues/{current['identifier']}",
            )

    def reconcile_issue(*args, **kwargs):
        if (
            failure_point == "reconcile"
            and args[3]["id"] == "bad-issue"
            and fail_bad_issue
        ):
            raise NotifyError("notify_event_invalid")
        return policy_reconcile(*args, **kwargs)

    api = Api()
    with patch("notify.service.reconcile", side_effect=reconcile_issue):
        service.scan("test", api, False)
    cursor = ctx.state.rows("SELECT * FROM cursors WHERE workspace_id='test'")[0]
    assert seen == ["bad-issue", "issue-a"]
    assert cursor["poll_until"] == old_cursor
    assert cursor["last_error"] == "notify_event_invalid"
    assert ctx.state.rows("SELECT status FROM hints")[0]["status"] == "pending"
    assert len(notifications(ctx)) == 1

    fail_bad_issue = False
    with patch("notify.service.reconcile", side_effect=reconcile_issue):
        service.scan("test", api, False)
    cursor = ctx.state.rows("SELECT * FROM cursors WHERE workspace_id='test'")[0]
    assert seen == ["bad-issue", "issue-a", "bad-issue", "issue-a"]
    assert cursor["poll_until"] > old_cursor
    assert cursor["last_error"] == ""
    assert len(notifications(ctx)) == 2


def test_pending_hint_backlog_is_bounded_and_historical_scan_recovers(ctx, monkeypatch):
    monkeypatch.setattr("notify.state.MAX_PENDING_HINTS_PER_WORKSPACE", 1)
    first = {
        "type": "issue:updated",
        "payload": {"issue": {"id": "issue-a", "revision": 1}},
    }
    assert ctx.state.hint("test", first)
    assert ctx.state.hint(
        "test",
        {
            "type": "issue:updated",
            "payload": {"issue": {"id": "issue-a", "revision": 2}},
        },
    )
    assert not ctx.state.hint(
        "test", {"type": "issue:updated", "payload": {"issue": {"id": "issue-b"}}}
    )
    assert len(ctx.state.rows("SELECT * FROM hints WHERE status='pending'")) == 1
    cursor = ctx.state.rows("SELECT * FROM cursors WHERE workspace_id='test'")[0]
    assert cursor["last_error"] == "notify_hint_backlog_full"
    assert cursor["source_history_limited"] == 1
    assert (
        ctx.state.rows(
            "SELECT value FROM metadata WHERE key='metric:pending_hints_rejected'"
        )[0]["value"]
        == "1"
    )

    class NoSubscriptionsApi:
        def issues(self, *args):
            raise AssertionError("scan without subscriptions must preserve pending hints")

    service = Service.__new__(Service)
    service.state, service.config = ctx.state, ctx.config
    service.scan("test", NoSubscriptionsApi(), False)
    assert len(ctx.state.rows("SELECT * FROM hints WHERE status='pending'")) == 1

    ctx.state.cursor("test", last_full=time.time())
    add(ctx, since=ctx.now - 3600)
    assert (
        ctx.state.rows("SELECT last_full FROM cursors WHERE workspace_id='test'")[0][
            "last_full"
        ]
        is None
    )
    historical = [issue(ctx), issue(ctx)]
    historical[1].update(id="issue-b", identifier="TEST-2")
    comments = {
        row["id"]: [comment(ctx, f"question-{row['id']}")]
        for row in historical
    }

    class HistoricalApi:
        limited = True

        def issues(self, *args):
            return [{"id": row["id"]} for row in historical]

        def snapshot(self, iid):
            row = next(row for row in historical if row["id"] == iid)
            return (
                row,
                comments[iid],
                [],
                f"https://multica.example.invalid/test/issues/{row['identifier']}",
            )

    service.scan("test", HistoricalApi(), True)
    assert len(notifications(ctx)) == 2
    assert not ctx.state.rows("SELECT * FROM hints WHERE status='pending'")


def test_failed_hints_keep_each_task_id_but_coalesce_duplicates(ctx):
    def failed(task_id):
        return {
            "type": "task:failed",
            "payload": {"task": {"id": task_id, "issue_id": "issue-a"}},
        }

    assert ctx.state.hint("test", failed("run-a"))
    assert ctx.state.hint("test", failed("run-a"))
    assert ctx.state.hint("test", failed("run-b"))
    rows = ctx.state.rows("SELECT task_id FROM hints WHERE status='pending' ORDER BY task_id")
    assert [row["task_id"] for row in rows] == ["run-a", "run-b"]


def test_http_408_is_retryable():
    assert response(408, {}, False) == Result("retry", "http_408")


def test_deeply_nested_response_is_uncertain_retry():
    class NestedResponse(io.BytesIO):
        def __init__(self, body):
            super().__init__(body)
            self.status = 200
            self.headers = {}

    class Opener:
        def open(self, *args, **kwargs):
            return NestedResponse(b"[" * 1200 + b"0" + b"]" * 1200)

    sender = Sender()
    sender.opener = Opener()
    payload = {
        "platform": "telegram",
        "account": "tg",
        "chat_id": "100",
        "chat_type": "dm",
        "thread_id": "",
        "text": "test",
        "anchor_message_id": None,
    }
    with (
        patch(
            "notify.delivery._response_body_complete",
            side_effect=lambda result: result.tell() == len(result.getvalue()),
        ),
        patch("notify.delivery._set_response_timeout", return_value=True),
    ):
        assert sender.send(payload, "fake-token") == Result(
            "retry", "response_uncertain"
        )


@pytest.mark.parametrize("missing", ["--direction", "--project"])
def test_cli_contract_requires_every_used_list_flag(missing):
    api = Multica.__new__(Multica)
    api.config = SimpleNamespace(service={"cli_binary": "multica"})
    api.env = {}
    flags = b"--updated-since --updated-until --offset --fields --sort --direction --project"
    help_text = b" ".join(flag for flag in flags.split() if flag.decode() != missing)

    def invoke(argv, env, timeout):
        return b"multica version 0.8.2" if "--version" in argv else help_text

    with (
        patch("notify.api.run_cli", side_effect=invoke),
        pytest.raises(NotifyError, match="notify_cli_contract_unavailable"),
    ):
        api.check_cli()


def test_duplicate_json_response_is_not_delivered():
    class Response(io.BytesIO):
        status = 200
        headers = None

    class Opener:
        def open(self, *args, **kw):
            result = Response(b'{"ok":false,"ok":true}')
            result.headers = {}
            return result

    sender = Sender()
    sender.opener = Opener()
    payload = {
        "platform": "telegram",
        "chat_id": "100",
        "thread_id": "",
        "text": "test",
        "anchor_message_id": None,
    }
    with (
        patch(
            "notify.delivery._response_body_complete",
            side_effect=lambda r: r.tell() == len(r.getvalue()),
        ),
        patch("notify.delivery._set_response_timeout", return_value=True),
    ):
        assert sender.send(payload, "fake").outcome == "retry"


def test_status_marks_stale_runtime_and_reports_cursor_lag(ctx):
    ctx.state.cursor(
        "test",
        poll_until=time.time() - 120,
        ws_connected=1,
        history_gap_seconds=360,
        recovery_mode=1,
    )
    result = ctx.state.status()
    assert not result["ready"]
    assert result["workspaces"][0]["degraded"]
    assert not result["workspaces"][0]["ws_connected"]
    assert result["workspaces"][0]["cursor_lag_seconds"] >= 120
    assert result["workspaces"][0]["history_gap_seconds"] == 360
    with ctx.state.transaction() as db:
        db.execute("INSERT INTO metadata VALUES('heartbeat',?)", (str(time.time()),))
    assert ctx.state.status()["ready"]


def test_full_reconcile_limit_cannot_exceed_two(ctx):
    raw = copy.deepcopy(ctx.raw)
    raw["service"]["full_reconcile_parallelism"] = 3
    with pytest.raises(NotifyError, match="notify_config_invalid"):
        parse_config(raw)


def test_transport_error_logs_no_credentials_or_source_text(ctx, caplog):
    add(ctx)
    run(ctx, comments=[comment(ctx, text="QUESTION: secret-text-sentinel")])

    class BrokenSender:
        def send(self, *args):
            raise OSError("fake-secret-token-sentinel secret-text-sentinel")

    async def check():
        path = ctx.root / "notify.toml"
        atomic_private(path, b"[service]\n")
        with patch("notify.service.load_config", return_value=ctx.config):
            service = Service(path, sender=BrokenSender())
        service.state = ctx.state
        with patch(
            "notify.service.credential", return_value="fake-secret-token-sentinel"
        ):
            await service.deliver(notifications(ctx)[0])

    with caplog.at_level("INFO", logger="hermes_multica_notify"):
        asyncio.run(check())
    assert "notify_delivery_unavailable" in caplog.text
    assert "secret-text-sentinel" not in caplog.text
    assert "fake-secret-token-sentinel" not in caplog.text


def test_report_written_after_reopen_before_poll_is_retained(ctx):
    import json

    add(ctx)
    run(ctx, issue(ctx, "done", 1), now=ctx.now)
    report = comment(ctx, text="REPORT: between reopen and poll", at=ctx.now + 5)
    run(
        ctx, issue(ctx, "todo", 2, at=ctx.now + 30), comments=[report], now=ctx.now + 30
    )
    run(
        ctx, issue(ctx, "done", 3, at=ctx.now + 60), comments=[report], now=ctx.now + 60
    )
    assert (
        "between reopen and poll"
        in json.loads(notifications(ctx)[-1]["payload_json"])["text"]
    )


@pytest.mark.parametrize(
    "outcome,expected",
    [("delivered", "delivered"), ("retry", "cancelled"), ("anchor", "cancelled")],
)
def test_disable_reenable_fences_inflight_retry(ctx, outcome, expected):
    from tests.test_notify import make_claim

    claim = make_claim(ctx)
    ctx.state.toggle(claim["subscription_id"], False)
    ctx.state.toggle(claim["subscription_id"], True)
    assert ctx.state.finish(claim, outcome, "fake-result", 5)
    assert notifications(ctx)[0]["status"] == expected
    assert not ctx.state.claim(claim["id"], time.time() + 301, 5, 300)


def test_disable_reenable_does_not_take_over_old_sending(ctx):
    from tests.test_notify import make_claim

    claim = make_claim(ctx)
    ctx.state.toggle(claim["subscription_id"], False)
    ctx.state.toggle(claim["subscription_id"], True)
    assert not ctx.state.due(time.time() + 301)
    assert notifications(ctx)[0]["status"] == "cancelled"
    assert ctx.state.replay(claim["id"], 30)
    assert ctx.state.claim(claim["id"], time.time() + 302, 5, 300)["attempts"] == 1


@pytest.mark.parametrize(
    "origin",
    ["https://MULTICA.example.invalid/", "https://multica.example.invalid:443"],
)
def test_physical_workspace_alias_is_not_a_second_collector(ctx, origin):
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["alias"] = dict(raw["workspaces"]["test"], origin=origin)
    with pytest.raises(NotifyError, match="notify_config_invalid"):
        parse_config(raw)


@pytest.mark.parametrize("chat_id", ["--100", "+100", "١٠٠", "-0", "100 "])
def test_rejects_malformed_chat_ids_before_persistence(ctx, chat_id):
    with pytest.raises(NotifyError, match="notify_subscription_invalid"):
        add(ctx, chat_id=chat_id)
    assert not ctx.state.rows("SELECT * FROM subscriptions")


@pytest.mark.parametrize(
    "field,value", [("thread_id", "١٢"), ("anchor_message_id", "١٢")]
)
def test_rejects_non_ascii_telegram_routing_numbers(ctx, field, value):
    values = {"chat_type": "thread", "thread_id": "12"} if field == "thread_id" else {}
    values[field] = value
    with pytest.raises(NotifyError):
        add(ctx, **values)
    assert not ctx.state.rows("SELECT * FROM subscriptions")


def test_snapshot_retries_across_status_transition_and_keeps_report(ctx):
    import json

    from notify.api import Multica

    base = ctx.now - 30
    report = comment(
        ctx, "cycle-report", "REPORT: created while reopening", at=base + 12
    )

    class Reader:
        def __init__(self):
            self.issues = [
                issue(ctx, "done", 1, at=base),
                issue(ctx, "todo", 2, at=base + 15),
                issue(ctx, "todo", 2, at=base + 15),
                issue(ctx, "todo", 2, at=base + 15),
            ]
            self.comment_reads = 0

        def get_issue(self, issue_id):
            return self.issues.pop(0)

        def _request(self, method, path):
            if path.endswith("/comments"):
                self.comment_reads += 1
                return json.dumps([report]).encode()
            return b"[]"

        def issue_link(self, identifier):
            return "https://multica.example.invalid/test/issues/" + identifier

    reader = Reader()
    api = Multica.__new__(Multica)
    api.reader, api.workspace, api.limited = reader, {"workspace_id": WID}, False
    current, comments, runs, _link = api.snapshot("issue-a")
    assert current["status"] == "todo" and current["revision"] == 2
    assert len(comments) == 1 and not runs and reader.comment_reads == 2

    add(ctx)
    run(ctx, current, comments, now=base + 16)
    assert not notifications(ctx)
    run(ctx, issue(ctx, "done", 3, at=base + 20), comments, now=base + 20)
    assert (
        "created while reopening"
        in json.loads(notifications(ctx)[0]["payload_json"])["text"]
    )


def test_snapshot_fails_closed_after_three_unstable_reads(ctx):
    from notify.api import Multica

    class Reader:
        n = 0

        def get_issue(self, issue_id):
            self.n += 1
            return issue(ctx, "done" if self.n % 2 else "todo", self.n)

        def _request(self, method, path):
            return b"[]"

    api = Multica.__new__(Multica)
    api.reader, api.workspace, api.limited = Reader(), {"workspace_id": WID}, False
    with pytest.raises(NotifyError, match="notify_snapshot_unstable"):
        api.snapshot("issue-a")
    assert api.reader.n == 6
