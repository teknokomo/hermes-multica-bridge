"""Regressions for confirmed central-service review findings."""

from __future__ import annotations

import asyncio
import copy
import io
import sys
import time
from unittest.mock import patch

import pytest

from bridge.errors import BridgeError
from notify.api import run_cli
from notify.config import NotifyError, atomic_private, parse_config
from notify.delivery import Result, Sender
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
    assert starts[1] - starts[0] >= 0.5


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
