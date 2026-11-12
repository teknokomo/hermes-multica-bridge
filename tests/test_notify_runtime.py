"""Offline central notification contracts: no production credentials or writes."""

from __future__ import annotations

import asyncio
import copy
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from notify.config import (
    NotifyError,
    append_workspace,
    atomic_private,
    load_config,
    parse_config,
)
from notify.delivery import Sender
from notify.state import encoded

WID = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
SQUAD = "33333333-3333-4333-8333-333333333333"


from tests.test_notify import add, comment, issue, make_claim, notifications, run
from tests.test_notify import ctx as ctx  # noqa: PLC0414 - pytest fixture re-export


def test_full_scan_jitter_and_limits(ctx):
    from notify.service import Service, full_delay

    class Rng:
        def uniform(self, a, b):
            return b

    assert full_delay(ctx.config, initial=True, rng=Rng()) == 30
    assert full_delay(ctx.config, rng=Rng()) == 330
    assert ctx.config.service["full_reconcile_parallelism"] == 2
    assert Service is not None


def test_poll_cursor_overlap_and_partial_failure(ctx):
    from notify.service import Service

    add(ctx)
    service = Service.__new__(Service)
    service.state, service.config = ctx.state, ctx.config
    calls = []

    class Api:
        limited = True

        def issues(self, project, since=None, until=None):
            calls.append((project, since, until))
            return [issue(ctx)]

        def snapshot(self, iid):
            return (
                issue(ctx),
                [comment(ctx)],
                [],
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    ctx.state.cursor("test", poll_until=ctx.now)
    service.scan("test", Api(), False)
    assert calls[0][1] == ctx.now - 300
    assert ctx.state.rows("SELECT poll_until FROM cursors")[0]["poll_until"] > ctx.now
    old = ctx.state.rows("SELECT poll_until FROM cursors")[0]["poll_until"]

    class Broken(Api):
        def snapshot(self, iid):
            raise NotifyError("notify_workspace_unavailable")

    with pytest.raises(NotifyError):
        service.scan("test", Broken(), False)
    assert ctx.state.rows("SELECT poll_until FROM cursors")[0]["poll_until"] == old


def test_history_gap_recovers_available_final_without_fake_transitions(ctx):
    from notify.service import Service

    add(ctx)
    run(ctx, issue(ctx, "todo"))
    ctx.state.cursor("test", poll_until=ctx.now - 1000)
    service = Service.__new__(Service)
    service.state, service.config = ctx.state, ctx.config

    class Api:
        limited = True

        def issues(self, *args):
            return [issue(ctx, "done", 3)]

        def snapshot(self, iid):
            return (
                issue(ctx, "done", 3),
                [],
                [],
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    service.scan("test", Api(), True)
    service.scan("test", Api(), True)
    assert len(notifications(ctx)) == 1
    cursor = ctx.state.rows("SELECT * FROM cursors")[0]
    assert cursor["source_history_limited"]
    assert cursor["last_full"]


def test_ws_hint_preserves_task_identity_and_survives_restart(ctx):
    event = {
        "type": "task:failed",
        "payload": {"task": {"id": "task-a", "issue_id": "issue-a"}},
    }
    ctx.state.hint("test", event)
    ctx.state.hint("test", event)
    assert len(ctx.state.rows("SELECT * FROM hints")) == 1
    assert ctx.state.rows("SELECT task_id FROM hints")[0]["task_id"] == "task-a"


def test_expired_disabled_lease_is_cancelled_without_takeover(ctx):
    first = make_claim(ctx)
    ctx.state.toggle(first["subscription_id"], False)
    assert not ctx.state.due(time.time() + 301)
    assert notifications(ctx)[0]["status"] == "cancelled"


def test_read_only_systemd_credentials_mode(ctx, monkeypatch):
    from notify.config import credential

    directory = ctx.root / "creds"
    directory.mkdir(mode=0o700)
    atomic_private(directory / "test", b"fake-credential")
    (directory / "test").chmod(0o400)
    directory.chmod(0o500)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    assert credential("test") == "fake-credential"
    directory.chmod(0o700)


def test_read_only_systemd_credentials_group_readable_mode(ctx, monkeypatch):
    from notify.config import credential

    directory = ctx.root / "group-readable-creds"
    directory.mkdir(mode=0o700)
    atomic_private(directory / "test", b"fake-credential")
    (directory / "test").chmod(0o440)
    directory.chmod(0o550)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    assert credential("test") == "fake-credential"
    directory.chmod(0o700)


def test_private_credential_rejects_group_readable_file_without_systemd_env(ctx, monkeypatch):
    from notify.config import credential

    directory = ctx.root / "private-creds"
    directory.mkdir(mode=0o700)
    atomic_private(directory / "test", b"fake-credential")
    (directory / "test").chmod(0o440)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(NotifyError) as exc:
        credential("test", directory)
    assert exc.value.code == "notify_credential_missing"


def test_append_workspace_concurrent_adds_preserve_both(ctx):
    import threading

    path = ctx.root / "notify.toml"
    atomic_private(path, b"# preserved\n[service]\n")
    errors = []

    def writer(key, wid):
        try:
            append_workspace(
                path, key, ctx.raw["workspaces"]["test"] | {"workspace_id": wid}
            )
        except (NotifyError, OSError, ValueError) as exc:
            errors.append(exc)

    a = threading.Thread(target=writer, args=("a", WID))
    b = threading.Thread(target=writer, args=("b", PROJECT))
    a.start()
    b.start()
    a.join()
    b.join()
    assert not errors
    assert set(load_config(path).workspaces) == {"a", "b"}
    assert "# preserved" in path.read_text()


def test_sender_telegram_thread_and_max_dm_payload(ctx):
    import urllib.error

    class Opener:
        def __init__(self):
            self.request = None

        def open(self, request, timeout):
            self.request = request
            raise urllib.error.URLError("fake secret-bearing transport error")

    sender = Sender()
    opener = Opener()
    sender.opener = opener
    payload = {
        "text": "hello",
        "platform": "telegram",
        "chat_id": "-100",
        "chat_type": "thread",
        "thread_id": "77",
        "anchor_message_id": "3",
        "account": "tg",
    }
    assert sender.send(payload, "fake-token").outcome == "retry"
    body = json.loads(opener.request.data)
    assert (
        body["message_thread_id"] == 77 and body["reply_parameters"]["message_id"] == 3
    )
    sender.send(
        payload
        | {
            "platform": "max",
            "chat_id": "123",
            "chat_type": "dm",
            "thread_id": "",
            "anchor_message_id": None,
        },
        "fake-token",
    )
    assert "botapi.max.ru/messages?user_id=123" in opener.request.full_url
    assert "link" not in json.loads(opener.request.data)


def watcher_files(ctx, *, groups=True):
    watcher = ctx.root / "watcher.toml"
    watcher.write_text(f'''[watcher]
socket_path = "/REPLACE/watcher.sock"
socket_gid = 1234
[profiles.test]
state_path = "/REPLACE/watcher.sqlite3"
multica_pat_credential = "fake-pat"
max_token_credential = "fake-max"
telegram_token_credential = "fake-tg"
own_multica_user_id = "self"
allowed_peer_uids = [1000]
[[profiles.test.routes]]
route_id = "route-a"
name = "Test"
multica_origin = "https://multica.example.invalid"
workspace_id = "{WID}"
project_id = "{PROJECT}"
source_platforms = ["telegram", "max"]
allowed_user_ids = ["1"]
allowed_chat_ids = ["100", "101"]
allow_groups = {str(groups).lower()}
allowed_statuses = ["todo", "done"]
''')
    binding = ctx.root / "bindings.toml"
    atomic_private(
        binding,
        b"""[[bindings]]
route_id = "route-a"
platform = "telegram"
account = "tg"
chat_id = "100"
chat_type = "group"
mode = "quiet"
""",
    )
    return watcher, binding


def test_import_watcher_disabled_idempotent_without_mappings(ctx):
    from notify.importer import import_watcher, watcher_plan

    watcher, binding = watcher_files(ctx)
    rows = watcher_plan(ctx.config, watcher, binding)
    assert import_watcher(ctx.state, rows) == 1
    assert import_watcher(ctx.state, rows) == 0
    assert not ctx.state.rows("SELECT enabled FROM subscriptions")[0]["enabled"]
    assert not Path("/REPLACE/watcher.sqlite3").exists()


@pytest.mark.parametrize(
    "change,code",
    [
        (("100", "999"), "binding_not_allowed"),
        (("route-a", "unknown"), "binding_unknown_route"),
        (('chat_type = "group"', 'chat_type = "thread"\nthread_id = "1"'), "ok"),
    ],
)
def test_import_binding_validation(ctx, change, code):
    from notify.importer import watcher_plan

    watcher, binding = watcher_files(ctx)
    atomic_private(binding, binding.read_text().replace(*change).encode())
    if code == "ok":
        assert watcher_plan(ctx.config, watcher, binding)[0]["thread_id"] == "1"
    else:
        with pytest.raises(NotifyError, match=code):
            watcher_plan(ctx.config, watcher, binding)


def test_import_requires_every_route_and_rejects_duplicate(ctx):
    from notify.importer import watcher_plan

    watcher, binding = watcher_files(ctx)
    original = binding.read_bytes()
    atomic_private(binding, b"bindings = []\n")
    with pytest.raises(NotifyError, match="binding_required"):
        watcher_plan(ctx.config, watcher, binding)
    atomic_private(binding, original + original)
    with pytest.raises(NotifyError, match="binding_duplicate"):
        watcher_plan(ctx.config, watcher, binding)


def test_import_group_allowlist_and_multiple_recipients(ctx):
    from notify.importer import watcher_plan

    watcher, binding = watcher_files(ctx, groups=False)
    with pytest.raises(NotifyError, match="binding_not_allowed"):
        watcher_plan(ctx.config, watcher, binding)
    watcher, binding = watcher_files(ctx)
    atomic_private(
        binding, binding.read_bytes() + binding.read_bytes().replace(b'"100"', b'"101"')
    )
    assert len(watcher_plan(ctx.config, watcher, binding)) == 2


def test_import_plans_missing_infrastructure_without_writes(ctx):
    from notify.importer import watcher_bundle

    watcher, binding = watcher_files(ctx)
    empty = parse_config({"service": ctx.config.service})
    before = binding.read_bytes()
    rows, accounts, workspaces = watcher_bundle(empty, watcher, binding)
    assert accounts and workspaces and rows[0]["enabled"] is False
    assert binding.read_bytes() == before
    assert not ctx.state.rows("SELECT * FROM subscriptions")


def test_import_dm_requires_allowed_user(ctx):
    from notify.importer import watcher_plan

    watcher, binding = watcher_files(ctx)
    atomic_private(
        binding,
        binding.read_text().replace('"group"', '"dm"').replace('"100"', '"1"').encode(),
    )
    assert watcher_plan(ctx.config, watcher, binding)[0]["chat_id"] == "1"


def test_delivery_waits_before_claim_and_disable_prevents_send(ctx):
    from notify.service import Service

    sid = add(ctx)
    run(ctx, comments=[comment(ctx)])
    row = notifications(ctx)[0]

    async def check():
        service = Service.__new__(Service)
        service.state, service.config = ctx.state, ctx.config
        service.stop = asyncio.Event()
        service.scheduled = {row["id"]}
        service.delivery_slots = asyncio.Semaphore(1)
        service.dispatch_lock = asyncio.Lock()

        class SenderStub:
            def send(self, *args):
                pytest.fail("disabled subscription was sent")

        service.sender = SenderStub()

        async def pause(delay):
            assert notifications(ctx)[0]["attempts"] == 0
            ctx.state.toggle(sid, False)

        service.pause = pause
        with patch("notify.service.credential", return_value="fake"):
            await service.deliver(row)

    asyncio.run(check())
    assert notifications(ctx)[0]["status"] == "cancelled"


def test_ws_auth_and_durable_normalized_hints(ctx):
    from notify.service import Service

    async def check():
        service = Service.__new__(Service)
        service.state, service.config = ctx.state, ctx.config
        service.stop = asyncio.Event()
        service.wakes = {"test": asyncio.Event()}
        auth = []

        class Conn:
            async def send(self, raw):
                auth.append(json.loads(raw))

            async def recv(self):
                return '{"type":"auth_ack"}'

            def __aiter__(self):
                return self

            async def __anext__(self):
                if service.stop.is_set():
                    raise StopAsyncIteration
                service.stop.set()
                return encoded(
                    {
                        "type": "task:failed",
                        "payload": {"task": {"id": "task-a", "issue_id": "issue-a"}},
                    }
                )

        class Connection:
            async def __aenter__(self):
                return Conn()

            async def __aexit__(self, *args):
                return False

        with (
            patch("notify.service.credential", return_value="fake"),
            patch("websockets.asyncio.client.connect", return_value=Connection()),
        ):
            await service.websocket("test")
        assert auth == [{"type": "auth", "payload": {"token": "fake"}}]

    asyncio.run(check())
    assert ctx.state.rows("SELECT task_id FROM hints")[0]["task_id"] == "task-a"


def test_invalid_reload_keeps_previous_projection(ctx):
    from notify.service import Service

    path = ctx.root / "bad.toml"
    atomic_private(path, b"not valid = [")

    async def check():
        service = Service.__new__(Service)
        service.state, service.config, service.path = ctx.state, ctx.config, path
        service.locks = {}
        service.collectors = []
        await service.reload()
        assert service.config is ctx.config

    asyncio.run(check())
    assert (
        ctx.state.rows("SELECT origin FROM workspaces")[0]["origin"]
        == ctx.raw["workspaces"]["test"]["origin"]
    )


def test_bad_workspace_isolated_at_startup(ctx):
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["broken"] = raw["workspaces"]["test"] | {
        "origin": "http://invalid"
    }
    config = parse_config(raw)
    assert "broken" in config.workspace_errors
    assert config.workspaces["broken"]["enabled"] is False
    assert config.workspaces["test"]["workspace_id"] == WID


def test_shutdown_waits_for_inflight_thread_before_unlock():
    from notify.service import blocking

    completed = []

    def network_work():
        time.sleep(0.03)
        completed.append(True)

    async def check():
        task = asyncio.create_task(blocking(network_work))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert completed

    asyncio.run(check())


def test_full_scans_bound_actual_collectors_and_serialize_workspace(ctx):
    import threading

    from notify.service import Service

    raw = copy.deepcopy(ctx.raw)
    for key, wid in [("two", PROJECT), ("three", SQUAD)]:
        raw["workspaces"][key] = raw["workspaces"]["test"] | {"workspace_id": wid}
    config = parse_config(raw)
    ctx.state.project(config)
    guard = threading.Lock()
    active = {}
    peak = [0]
    completed = []
    finished = threading.Event()

    def scan(key, api, full):
        assert full
        with guard:
            active[key] = active.get(key, 0) + 1
            assert active[key] == 1
            peak[0] = max(peak[0], sum(active.values()))
        time.sleep(0.03)
        with guard:
            active[key] -= 1
            completed.append(key)
            if len(completed) == 4:
                finished.set()

    class Api:
        limited = True

        def check_cli(self):
            return None

    async def check():
        service = Service.__new__(Service)
        service.config, service.state = config, ctx.state
        service.stop = asyncio.Event()
        service.locks = {key: asyncio.Lock() for key in config.workspaces}
        service.wakes = {key: asyncio.Event() for key in config.workspaces}
        service.full_slots = asyncio.Semaphore(2)
        service.api_factory = lambda *_: Api()
        service.scan = scan
        starts = []

        async def pause(delay):
            starts.append(delay)
            await asyncio.sleep(0)

        service.pause = pause
        tasks = [
            asyncio.create_task(service.collect(key))
            for key in ("test", "two", "three", "test")
        ]
        assert await asyncio.to_thread(finished.wait, 3)
        service.stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert len(starts) == 4 and all(0 <= value <= 30 for value in starts)

    asyncio.run(check())
    assert peak[0] == 2 and len(completed) == 4


def test_import_dry_run_does_not_create_db_or_rewrite_config(ctx, capsys):
    from notify.cli import main

    watcher, binding = watcher_files(ctx)
    config = ctx.root / "dry.toml"
    absent = ctx.root / "absent.db"
    atomic_private(
        config, ("[service]\ndb_path = " + json.dumps(str(absent)) + "\n").encode()
    )
    before = config.read_bytes()
    assert (
        main(
            [
                "--config",
                str(config),
                "import-watcher",
                "--watcher-config",
                str(watcher),
                "--bindings",
                str(binding),
                "--dry-run",
            ]
        )
        == 0
    )
    assert not absent.exists() and config.read_bytes() == before
    assert '"dry_run":true' in capsys.readouterr().out


def test_hint_retention_distinguishes_pending_processed_rejected(ctx):
    now = time.time()
    with ctx.state.transaction() as db:
        for key, status, age in [
            ("pending", "pending", 100 * 86400),
            ("processed", "processed", 2 * 86400),
            ("rejected", "rejected", 8 * 86400),
        ]:
            db.execute(
                "INSERT INTO hints VALUES(?,?,?,?,?,?,?,?)",
                (
                    key,
                    "test",
                    "issue-a",
                    None,
                    "issue:updated",
                    status,
                    now - age,
                    now - age,
                ),
            )
    ctx.state.prune(ctx.config, now)
    assert [row["id"] for row in ctx.state.rows("SELECT * FROM hints")] == ["pending"]


def test_sender_absolute_deadline_is_retry_not_unhandled():
    from bridge.webhook import _AbsoluteDeadlineExceeded

    sender = Sender()

    class Opener:
        def open(self, *args, **kwargs):
            raise _AbsoluteDeadlineExceeded()

    sender.opener = Opener()
    payload = {
        "platform": "telegram",
        "account": "tg",
        "chat_id": "1",
        "chat_type": "dm",
        "thread_id": "",
        "anchor_message_id": None,
        "text": "test",
    }
    assert sender.send(payload, "fake").outcome == "retry"


def test_unconfirmed_failed_hint_remains_pending(ctx):
    from notify.service import Service

    add(ctx)
    ctx.state.hint(
        "test",
        {
            "type": "task:failed",
            "payload": {"task": {"id": "task-a", "issue_id": "issue-a"}},
        },
    )
    service = Service.__new__(Service)
    service.config, service.state = ctx.config, ctx.state

    class Api:
        limited = True

        def __init__(self):
            self.runs = []

        def issues(self, *args):
            return []

        def snapshot(self, iid):
            return (
                issue(ctx),
                [],
                self.runs,
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    api = Api()
    service.scan("test", api, True)
    assert ctx.state.rows("SELECT status FROM hints")[0]["status"] == "pending"
    api.runs = [
        {
            "id": "task-a",
            "issue_id": "issue-a",
            "status": "failed",
            "created_at": comment(ctx)["created_at"],
        }
    ]
    service.scan("test", api, True)
    assert ctx.state.rows("SELECT status FROM hints")[0]["status"] == "processed"
    assert len(notifications(ctx)) == 1


def test_unused_workspace_can_be_repaired(ctx):
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["test"]["origin"] = "https://repaired.example.invalid"
    ctx.state.project(parse_config(raw))
    assert (
        ctx.state.rows("SELECT origin FROM workspaces")[0]["origin"]
        == "https://repaired.example.invalid"
    )


def test_suppressed_plain_comment_is_not_reclassified_after_status_change(ctx):
    add(ctx)
    ordinary = comment(ctx, text="hello @operator")
    assert run(ctx, comments=[ordinary]) == 0
    run(ctx, issue(ctx, "blocked", 2), comments=[ordinary])
    assert len(notifications(ctx)) == 1
    assert json.loads(notifications(ctx)[0]["payload_json"])["event_type"] == "blocked"


def test_baseline_marks_selected_subscription_without_starving_others(ctx):
    from notify.importer import import_issues

    first = add(ctx)
    second = add(ctx, chat_id="101")

    class Api:
        def issues(self, *args):
            return [issue(ctx, "done")]

        def snapshot(self, *args):
            return (
                issue(ctx, "done"),
                [comment(ctx)],
                [],
                "https://multica.example.invalid/test/issues/TEST-1",
            )

    assert import_issues(ctx.state, ctx.config, first, Api()) == 1
    assert not notifications(ctx)
    run(ctx, issue(ctx, "done"), comments=[comment(ctx)])
    rows = notifications(ctx)
    assert len(rows) == 2 and all(row["subscription_id"] == second for row in rows)
    assert import_issues(ctx.state, ctx.config, first, Api()) == 0


@pytest.mark.parametrize("mode", ["quiet", "verbose"])
def test_report_mention_on_blocked_is_not_delivered_as_question(ctx, mode):
    add(ctx, mode=mode)
    run(
        ctx,
        issue(ctx, "blocked"),
        comments=[comment(ctx, text="REPORT: investigation @operator")],
    )
    assert len(notifications(ctx)) == 1
    assert json.loads(notifications(ctx)[0]["payload_json"])["event_type"] == "blocked"


def test_append_quotes_dotted_account_and_workspace_names(ctx):
    from notify.config import append_tables

    path = ctx.root / "dotted.toml"
    atomic_private(path, b"# comment preserved\n[service]\n")
    append_tables(
        path,
        {"team.account": ctx.raw["accounts"]["tg"]},
        {"team.workspace": ctx.raw["workspaces"]["test"]},
    )
    config = load_config(path)
    assert "team.workspace" in config.workspaces and "team.account" in config.accounts
    assert "# comment preserved" in path.read_text()


def test_private_read_rejects_symlink_and_open_permissions(ctx):
    from notify.config import private_read

    target = ctx.root / "private"
    atomic_private(target, b"fake")
    link = ctx.root / "link"
    link.symlink_to(target)
    with pytest.raises(NotifyError):
        private_read(link)
    target.chmod(0o644)
    with pytest.raises(NotifyError):
        private_read(target)


def test_missing_credentials_are_explicit_and_unclaimed_delivery_is_deferred(ctx):
    from notify.config import credential

    with (
        patch.dict("os.environ", {"CREDENTIALS_DIRECTORY": str(ctx.root / "absent")}),
        pytest.raises(NotifyError, match="notify_credential_missing"),
    ):
        credential("fake")
    add(ctx)
    run(ctx, comments=[comment(ctx)])
    row = notifications(ctx)[0]
    ctx.state.defer_unclaimed(row["id"], "notify_credential_missing")
    assert not ctx.state.due(time.time()) and notifications(ctx)[0]["attempts"] == 0


def test_private_cli_runtime_directory_is_0700(ctx, monkeypatch):
    from notify.api import Multica

    directory = ctx.root / "credentials"
    directory.mkdir(mode=0o700)
    atomic_private(directory / "fake-pat", b"fake")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    Multica(ctx.config, "test")
    import stat

    assert stat.S_IMODE(Path(ctx.config.service["runtime_dir"]).stat().st_mode) == 0o700
