"""Approval-ready mapping and delivery remain offline and at-most-once."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import socket
import struct
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bridge.errors import BridgeError
from notify.approval import reconcile_mapping
from notify.approval_ipc import ApprovalMappingServer
from notify.config import NotifyError, parse_config
from notify.delivery import Result
from notify.service import Service
from notify.state import State, encoded
from tests.test_notify import PROJECT, WID, add
from tests.test_notify import ctx as ctx  # noqa: PLC0414 - pytest fixture re-export

CONNECTION_ID = "44444444-4444-4444-8444-444444444444"
AGENT_ID = "33333333-3333-4333-8333-333333333333"
WAKEUP_ID = "55555555-5555-4555-8555-555555555555"
PARENT_ID = "parent-1"
RUN_ID = "run-1"
CHILD_ID = "child-1"


def approval_context(ctx):
    raw = copy.deepcopy(ctx.raw)
    raw["workspaces"]["test"]["connection_id"] = CONNECTION_ID
    raw["wake"] = {
        "enabled": True,
        "base_url": "http://127.0.0.1:8644",
        "secret_credential": "fake-wake",
        "routes": {"approval": {"profile": "default", "route": "approval-route"}},
    }
    raw["approval_ipc"] = {
        "enabled": True,
        "native_delivery_suppressed": True,
        "peers": [{"uid": 1000, "profiles": ["default"]}],
    }
    config = parse_config(raw)
    ctx.config = config
    ctx.state.project(config)
    subscription_id = add(
        ctx,
        chat_type="thread",
        thread_id="999",
        project_id=PROJECT,
        label="approval-test",
    )
    ctx.state.add_wake_subscription(
        subscription_id,
        config.wake["routes"]["approval"],
        enabled=True,
        now=time.time(),
    )
    expiry = time.time() + 3600
    mapping = {
        "connection_id": CONNECTION_ID,
        "workspace_id": WID,
        "workspace_key": "test",
        "source_profile": "default",
        "parent_issue_id": PARENT_ID,
        "wakeup_id": WAKEUP_ID,
        "route_id": "approval-route",
        "subscription_id": subscription_id,
        "instruction": "Review completed stages.",
        "agent_id": AGENT_ID,
        "project_id": PROJECT,
        "expires_at": expiry,
        "child_ids_json": encoded([{"id": CHILD_ID, "stage": None}]),
        "tree_fingerprint": "a" * 64,
    }
    mapping_id, created = ctx.state.put_approval_mapping(mapping)
    assert created
    return config, mapping_id, mapping, expiry


class _Reader:
    def __init__(self, *, child_status="done", run_status="completed", run_id=RUN_ID):
        self.child_status = child_status
        self.run_status = run_status
        self.run_id = run_id
        self.calls = []

    def get_issue(self, issue_id):
        self.calls.append(("issue", issue_id))
        return {
            "id": PARENT_ID,
            "identifier": "CANARY-1",
            "workspace_id": WID,
            "project_id": PROJECT,
            "assignee_type": "agent",
            "assignee_id": AGENT_ID,
        }

    def list_issue_wakeups(self, issue_id):
        self.calls.append(("wakeups", issue_id))
        return [{
            "id": WAKEUP_ID,
            "issue_id": PARENT_ID,
            "agent_id": AGENT_ID,
            "kind": "event",
            "mode": "once",
            "instruction": "Review completed stages.",
            "condition": {"type": "children_done"},
            "enabled": False,
            "last_task_id": self.run_id,
            "expires_at": datetime.fromtimestamp(self.expiry, UTC).isoformat(),
            "timed_out_at": None,
        }]

    def list_issue_wakeup_runs(self, issue_id, wakeup_id):
        self.calls.append(("runs", issue_id, wakeup_id))
        return [{
            "id": self.run_id,
            "status": self.run_status,
            "completed_at": datetime.now(UTC).isoformat(),
        }]

    def list_issue_children(self, issue_id):
        self.calls.append(("children", issue_id))
        return [{
            "id": CHILD_ID,
            "workspace_id": WID,
            "project_id": PROJECT,
            "parent_issue_id": PARENT_ID,
            "status": self.child_status,
            "stage": None,
        }]

    def issue_link(self, identifier):
        return f"https://multica.example.invalid/test/issues/{identifier}"


class _Api:
    def __init__(self, reader):
        self.reader = reader


def _api_factory_for(reader):
    return lambda *_args: _Api(reader)


def _mapping(ctx, mapping_id):
    return ctx.state.rows("SELECT * FROM approval_mappings WHERE mapping_id=?", (mapping_id,))[0]


def _tree_fingerprint(child_ids=(CHILD_ID,), *, stages=None):
    stage_by_id = stages or {}
    immutable = [
        {"id": child_id, "stage": stage_by_id.get(child_id)}
        for child_id in sorted(child_ids)
    ]
    return hashlib.sha256(
        json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _ipc_request(
    *, parent_id=PARENT_ID, wakeup_id=WAKEUP_ID, expiry=None,
    child_ids=(CHILD_ID,), expected_stage_count=None, stages=None,
):
    ordered_ids = sorted(child_ids)
    return {
        "version": 1,
        "op": "approval_mapping.put",
        "parent_issue_id": parent_id,
        "wakeup_id": wakeup_id,
        "route_id": "approval-route",
        "bridge_route_id": "bridge-route",
        "source_profile": "default",
        "instruction": "Review the completed stages.",
        "expires_at": time.time() + 60 if expiry is None else expiry,
        "expected_stage_count": expected_stage_count,
        "registered_child_ids": ordered_ids,
        "registered_tree_fingerprint": _tree_fingerprint(ordered_ids, stages=stages),
    }


def test_approval_due_skips_disabled_wake_jobs_before_applying_limit(ctx):
    _config, active_mapping_id, active_mapping, _expiry = approval_context(ctx)
    disabled_subscription = add(
        ctx, chat_id="998", chat_type="thread", thread_id="998", project_id=PROJECT,
        label="disabled-wake",
    )
    ctx.state.add_wake_subscription(
        disabled_subscription, {"profile": "default", "route": "disabled-route"},
        enabled=False,
    )
    now = time.time()
    with ctx.state.transaction() as db:
        db.execute(
            "UPDATE approval_mappings SET status='ready' WHERE mapping_id=?",
            (active_mapping_id,),
        )
        db.execute(
            """INSERT INTO approval_jobs(
                id,mapping_id,event_key,run_id,payload_json,status,created_at,updated_at)
                VALUES('eligible-job',?,'eligible-event','eligible-run','{}','pending',?,?)""",
            (active_mapping_id, now, now),
        )
    for index in range(101):
        mapping = {
            **active_mapping,
            "parent_issue_id": f"disabled-parent-{index}",
            "wakeup_id": f"disabled-wakeup-{index}",
            "route_id": "disabled-route",
            "subscription_id": disabled_subscription,
        }
        mapping_id, created = ctx.state.put_approval_mapping(mapping)
        assert created
        created_at = now - 1000 + index
        with ctx.state.transaction() as db:
            db.execute(
                "UPDATE approval_mappings SET status='ready' WHERE mapping_id=?",
                (mapping_id,),
            )
            db.execute(
                """INSERT INTO approval_jobs(
                    id,mapping_id,event_key,run_id,payload_json,status,created_at,updated_at)
                    VALUES(?,?,?,'disabled-run','{}','pending',?,?)""",
                (
                    f"disabled-job-{index}", mapping_id,
                    f"disabled-event-{index}", created_at, created_at,
                ),
            )

    due = ctx.state.approval_due(now)
    assert [row["id"] for row in due] == ["eligible-job"]


@pytest.mark.parametrize("run_status,child_status,expected", [
    ("completed", "done", "ready"),
    ("running", "done", "pending"),
    ("failed", "done", "blocked"),
    ("succeeded", "done", "blocked"),
    ("completed", "in_review", "blocked"),
])
def test_approval_reconciliation_requires_scoped_completed_run_and_exact_done_children(
    ctx, run_status, child_status, expected,
):
    config, mapping_id, _saved, expiry = approval_context(ctx)
    reader = _Reader(run_status=run_status, child_status=child_status)
    reader.expiry = expiry
    with (
        patch("notify.approval.load_webhook_policy", return_value={}),
        patch("notify.approval.verify_webhook_policy"),
        patch("notify.approval.verify_configured_route"),
    ):
        result, job_id = reconcile_mapping(
            ctx.state,
            config,
            _mapping(ctx, mapping_id),
            api_factory=_api_factory_for(reader),
        )

    assert result == expected
    if expected == "ready":
        assert job_id
        rows = ctx.state.rows("SELECT * FROM approval_jobs")
        assert len(rows) == 1
        payload = json.loads(rows[0]["payload_json"])
        assert payload["event_type"] == "task.ready_for_approval"
        assert "CANARY-1" in payload["text"]
        assert "comments" not in payload
        assert reconcile_mapping(
            ctx.state,
            config,
            _mapping(ctx, mapping_id),
            api_factory=_api_factory_for(reader),
        ) == ("already_processed", None)
        assert len(ctx.state.rows("SELECT * FROM approval_jobs")) == 1
    elif expected == "pending":
        assert job_id is None
        assert ctx.state.rows("SELECT * FROM approval_jobs") == []
    else:
        assert job_id is None
        assert ctx.state.rows("SELECT * FROM approval_jobs") == []
        assert _mapping(ctx, mapping_id)["status"] == "blocked"


def test_approval_reconciliation_fails_closed_when_native_suppression_is_unverified(ctx):
    config, mapping_id, _saved, expiry = approval_context(ctx)
    config.approval_ipc["native_delivery_suppressed"] = False
    reader = _Reader()
    reader.expiry = expiry

    assert reconcile_mapping(
        ctx.state,
        config,
        _mapping(ctx, mapping_id),
        api_factory=_api_factory_for(reader),
    ) == ("disabled", None)
    assert reader.calls == []


def test_approval_mapping_backoff_is_durable_and_bounded(ctx):
    _config, mapping_id, _saved, _expiry = approval_context(ctx)
    now = time.time()
    assert len(ctx.state.approval_mappings(now, limit=20)) == 1
    ctx.state.approval_defer_mapping(mapping_id, "approval_run_pending", delay=15)
    assert ctx.state.approval_mappings(time.time(), limit=20) == []
    assert len(ctx.state.approval_mappings(time.time() + 16, limit=20)) == 1
    with pytest.raises(NotifyError):
        ctx.state.approval_defer_mapping(mapping_id, "pending", delay=301)


def test_approval_jobs_claim_once_and_unknown_never_retries(ctx):
    _config, mapping_id, _saved, _expiry = approval_context(ctx)
    job_id = ctx.state.approval_enqueue(mapping_id, RUN_ID, "Ready for review.", ["done"])
    assert job_id
    row = ctx.state.approval_due(time.time())[0]
    claim = ctx.state.approval_claim(job_id, time.time())
    assert claim and claim["attempts"] == 1
    assert ctx.state.approval_claim(job_id, time.time()) is None
    assert ctx.state.approval_finish(claim, "delivery_unknown", "approval_transport_uncertain")
    assert ctx.state.approval_due(time.time()) == []
    assert ctx.state.rows("SELECT attempts,status FROM approval_jobs WHERE id=?", (job_id,))[0] == {
        "attempts": 1,
        "status": "delivery_unknown",
    }
    assert row["id"] == job_id


def test_approval_success_clears_payload_and_uses_exact_sender_once(ctx):
    config, mapping_id, _saved, _expiry = approval_context(ctx)
    job_id = ctx.state.approval_enqueue(mapping_id, RUN_ID, "Ready for review.", ["done"])
    row = ctx.state.approval_due(time.time())[0]
    calls = []

    class Sender:
        def send(self, payload, token):
            calls.append((payload.copy(), token))
            return Result("delivered", "accepted")

    service = Service.__new__(Service)
    service.config = config
    service.state = ctx.state
    service.stop = asyncio.Event()
    service.approval_slots = asyncio.Semaphore(1)
    service.dispatch_lock = asyncio.Lock()
    service.approval_scheduled = {job_id}
    service.sender = Sender()
    service.pause = lambda _delay: asyncio.sleep(0)

    async def deliver():
        with (
            patch("notify.service.load_webhook_policy", return_value={}),
            patch("notify.service.verify_webhook_policy"),
            patch("notify.service.verify_configured_route"),
            patch("notify.service.credential", return_value="fake-token"),
        ):
            await service.deliver_approval(row)

    asyncio.run(deliver())
    assert len(calls) == 1
    assert calls[0][1] == "fake-token"
    assert calls[0][0]["event_type"] == "task.ready_for_approval"
    assert ctx.state.rows("SELECT status,payload_json,attempts FROM approval_jobs")[0] == {
        "status": "delivered",
        "payload_json": "",
        "attempts": 1,
    }
    assert ctx.state.approval_due(time.time()) == []


@pytest.mark.parametrize("sender_result", [None, SimpleNamespace(code="http_500")])
def test_approval_unexpected_sender_result_is_unknown_without_retry(ctx, sender_result):
    config, mapping_id, _saved, _expiry = approval_context(ctx)
    job_id = ctx.state.approval_enqueue(mapping_id, RUN_ID, "Ready for review.", ["done"])
    row = ctx.state.approval_due(time.time())[0]
    calls = []

    class Sender:
        def send(self, _payload, _token):
            calls.append("post")
            return sender_result

    service = Service.__new__(Service)
    service.config = config
    service.state = ctx.state
    service.stop = asyncio.Event()
    service.approval_slots = asyncio.Semaphore(1)
    service.dispatch_lock = asyncio.Lock()
    service.approval_scheduled = {job_id}
    service.sender = Sender()
    service.pause = lambda _delay: asyncio.sleep(0)

    async def deliver():
        with (
            patch("notify.service.load_webhook_policy", return_value={}),
            patch("notify.service.verify_webhook_policy"),
            patch("notify.service.verify_configured_route"),
            patch("notify.service.credential", return_value="fake-token"),
        ):
            await service.deliver_approval(row)

    asyncio.run(deliver())
    assert calls == ["post"]
    assert ctx.state.rows("SELECT status,attempts FROM approval_jobs WHERE id=?", (job_id,))[0] == {
        "status": "delivery_unknown",
        "attempts": 1,
    }
    assert ctx.state.approval_due(time.time()) == []


def test_approval_ipc_request_is_fixed_schema_and_rejects_boolean_expiry():
    base = _ipc_request()
    assert ApprovalMappingServer._valid_request(base)
    assert not ApprovalMappingServer._valid_request(base | {"extra": "rejected"})
    assert not ApprovalMappingServer._valid_request(base | {"expires_at": True})
    assert not ApprovalMappingServer._valid_request(base | {"source_profile": []})
    assert not ApprovalMappingServer._valid_request(base | {"expires_at": float("inf")})
    assert not ApprovalMappingServer._valid_request(base | {"expires_at": float("nan")})
    assert not ApprovalMappingServer._valid_request(base | {"expires_at": 10**400})


def test_approval_mapping_client_rejects_malformed_profile_and_expiry_before_connect(tmp_path):
    from bridge.approval_ipc import ApprovalMappingClient
    from bridge.errors import BridgeError

    client = ApprovalMappingClient(str(tmp_path / "missing.sock"))
    base = _ipc_request()
    for change in (
        {"source_profile": []},
        {"expires_at": None},
        {"expires_at": float("inf")},
        {"expires_at": 10**400},
        {"expected_stage_count": True},
        {"version": True},
    ):
        with pytest.raises(BridgeError, match="invalid"):
            client.put(base | change)


def test_approval_mapping_client_encodes_unicode_within_utf8_frame():
    from bridge.approval_ipc import MAX_FRAME, ApprovalMappingClient

    request = _ipc_request() | {"instruction": "🙂" * 2000}
    body = ApprovalMappingClient.encode_request(request)
    assert len(body) <= MAX_FRAME
    assert json.loads(body)["instruction"] == request["instruction"]

    long_children = tuple(f"child-{index:03d}-{'x' * 100}" for index in range(500))
    oversized = _ipc_request(child_ids=long_children)
    with pytest.raises(BridgeError) as caught:
        ApprovalMappingClient.encode_request(oversized)
    assert caught.value.code == "approval_mapping_too_large"


class _MappingReader:
    def __init__(
        self, parent_id, wakeup_id, expiry, *, child_id=CHILD_ID,
        last_task_id=None, stage=None, children=None,
    ):
        self.parent_id = parent_id
        self.wakeup_id = wakeup_id
        self.expiry = expiry
        self.child_id = child_id
        self.last_task_id = last_task_id
        self.stage = stage
        self.children = children
        self.calls = []

    def get_issue(self, issue_id):
        self.calls.append(("issue", issue_id))
        return {
            "id": self.parent_id,
            "workspace_id": WID,
            "project_id": PROJECT,
            "assignee_type": "agent",
            "assignee_id": AGENT_ID,
        }

    def list_issue_wakeups(self, issue_id):
        self.calls.append(("wakeups", issue_id))
        return [{
            "id": self.wakeup_id,
            "issue_id": self.parent_id,
            "agent_id": AGENT_ID,
            "kind": "event",
            "mode": "once",
            "instruction": "Review the completed stages.",
            "condition": ({"type": "children_done"} if self.stage is None else {
                "type": "children_done", "stage": self.stage,
            }),
            "enabled": self.last_task_id is None,
            "last_task_id": self.last_task_id,
            "expires_at": datetime.fromtimestamp(self.expiry, UTC).isoformat(),
            "timed_out_at": None,
        }]

    def list_issue_children(self, issue_id):
        self.calls.append(("children", issue_id))
        child_rows = self.children or [{"id": self.child_id, "stage": None}]
        return [
            {
                **row,
                "workspace_id": WID,
                "project_id": PROJECT,
                "parent_issue_id": self.parent_id,
                "status": "todo",
            }
            for row in child_rows
        ]


def test_approval_mapping_put_validates_route_and_is_idempotent(ctx):
    config, _old_mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    expiry = time.time() + 3600
    reader = _MappingReader(parent_id, wakeup_id, expiry)
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(parent_id=parent_id, wakeup_id=wakeup_id, expiry=expiry)

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
    ):
        assert server._put(request) == "accepted"
        assert server._put(request) == "duplicate"

    assert len(ctx.state.rows(
        "SELECT * FROM approval_mappings WHERE parent_issue_id=?", (parent_id,)
    )) == 1
    assert reader.calls.count(("issue", parent_id)) == 2


def test_approval_mapping_accepts_distinct_stage_count_below_maximum_ordinal(ctx):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    expiry = time.time() + 3600
    children = [
        {"id": "child-1", "stage": 1},
        {"id": "child-2", "stage": 3},
    ]
    stages = {row["id"]: row["stage"] for row in children}
    reader = _MappingReader(
        parent_id, wakeup_id, expiry, stage=3, children=children,
    )
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(
        parent_id=parent_id,
        wakeup_id=wakeup_id,
        expiry=expiry,
        child_ids=tuple(row["id"] for row in children),
        expected_stage_count=2,
        stages=stages,
    )

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
    ):
        assert server._put(request) == "accepted"

    stored = ctx.state.approval_mapping(CONNECTION_ID, WID, "default", parent_id)
    assert json.loads(stored["child_ids_json"]) == children


def test_approval_mapping_rejects_distinct_stage_count_above_maximum_ordinal(ctx):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    expiry = time.time() + 3600
    reader = _MappingReader(parent_id, wakeup_id, expiry, stage=3)
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(
        parent_id=parent_id,
        wakeup_id=wakeup_id,
        expiry=expiry,
        expected_stage_count=4,
    )

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
        pytest.raises(NotifyError, match="approval_mapping_invalid"),
    ):
        server._put(request)


def test_approval_mapping_put_rejects_changed_child_tree(ctx):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    expiry = time.time() + 3600
    reader = _MappingReader(parent_id, wakeup_id, expiry, child_id="replacement-child")
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(parent_id=parent_id, wakeup_id=wakeup_id, expiry=expiry)

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
        pytest.raises(NotifyError, match="approval_mapping_tree_changed"),
    ):
        server._put(request)

    assert ctx.state.approval_mapping(CONNECTION_ID, WID, "default", parent_id) is None


@pytest.mark.parametrize("last_task_id,expected", [(None, "rejected"), (RUN_ID, "accepted")])
def test_expired_wakeup_mapping_requires_evidence_wakeup_fired(ctx, last_task_id, expected):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    expiry = time.time() - 60
    reader = _MappingReader(parent_id, wakeup_id, expiry, last_task_id=last_task_id)
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(parent_id=parent_id, wakeup_id=wakeup_id, expiry=expiry)

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
    ):
        if expected == "rejected":
            with pytest.raises(NotifyError, match="approval_mapping_invalid"):
                server._put(request)
        else:
            assert server._put(request) == "accepted"
    mapping = ctx.state.approval_mapping(CONNECTION_ID, WID, "default", parent_id)
    assert (mapping is not None) is (expected == "accepted")


def test_approval_mapping_put_rejects_wakeup_with_different_expiry(ctx):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    requested_expiry = time.time() + 3600
    reader = _MappingReader(parent_id, wakeup_id, requested_expiry + 2)
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(parent_id=parent_id, wakeup_id=wakeup_id, expiry=requested_expiry)

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
        pytest.raises(NotifyError, match="approval_mapping_invalid"),
    ):
        server._put(request)

    assert ctx.state.approval_mapping(
        CONNECTION_ID, WID, "default", parent_id,
    ) is None


def test_approval_mapping_put_rejects_wakeup_with_different_saved_expiry(ctx):
    config, _mapping_id, _saved, _old_expiry = approval_context(ctx)
    parent_id = "66666666-6666-4666-8666-666666666666"
    wakeup_id = "77777777-7777-4777-8777-777777777777"
    requested_expiry = time.time() + 3600
    reader = _MappingReader(parent_id, wakeup_id, requested_expiry + 2)
    server = ApprovalMappingServer(
        config,
        ctx.state,
        api_factory=lambda *_args: SimpleNamespace(reader=reader),
    )
    request = _ipc_request(parent_id=parent_id, wakeup_id=wakeup_id, expiry=requested_expiry)

    with (
        patch("notify.approval_ipc.load_webhook_policy", return_value={}),
        patch("notify.approval_ipc.verify_webhook_policy"),
        pytest.raises(NotifyError, match="approval_mapping_invalid"),
    ):
        server._put(request)

    assert ctx.state.approval_mapping(
        CONNECTION_ID, WID, "default", parent_id,
    ) is None


def test_approval_mapping_put_fails_closed_without_native_suppression(ctx):
    config, _mapping_id, _saved, _expiry = approval_context(ctx)
    config.approval_ipc["native_delivery_suppressed"] = False
    server = ApprovalMappingServer(config, ctx.state)
    request = _ipc_request(
        parent_id="66666666-6666-4666-8666-666666666666",
        wakeup_id="77777777-7777-4777-8777-777777777777",
        expiry=time.time() + 3600,
    )

    with pytest.raises(NotifyError, match="approval_ready_delivery_unverified"):
        server._put(request)


def test_approval_ipc_peer_profile_is_checked_after_peer_credentials(ctx):
    config, _mapping_id, _saved, _expiry = approval_context(ctx)
    server = ApprovalMappingServer(config, ctx.state)

    class PeerSocket:
        def getsockopt(self, level, option, size):
            assert level == socket.SOL_SOCKET
            assert option == socket.SO_PEERCRED
            assert size == 12
            return struct.pack("3i", 123, 1000, 1000)

    class PeerWriter:
        def get_extra_info(self, name):
            assert name == "socket"
            return PeerSocket()

    assert server._peer(PeerWriter())
    assert server._peer(PeerWriter(), "default")
    assert not server._peer(PeerWriter(), "om73")


def test_approval_ipc_rejects_oversized_frames_before_json(ctx):
    config, _mapping_id, _saved, _expiry = approval_context(ctx)
    server = ApprovalMappingServer(config, ctx.state)

    async def read_frame():
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", 16 * 1024 + 1))
        reader.feed_eof()
        with pytest.raises(ValueError, match="frame size"):
            await server._read_frame(reader)

    asyncio.run(read_frame())


def test_approval_mapping_namespace_keeps_same_parent_per_instance(ctx):
    _config, _mapping_id, mapping, _expiry = approval_context(ctx)
    second = dict(
        mapping,
        connection_id="88888888-8888-4888-8888-888888888888",
        workspace_id="99999999-9999-4999-8999-999999999999",
        source_profile="om73",
        wakeup_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )

    mapping_id, created = ctx.state.put_approval_mapping(second)

    assert created
    assert mapping_id != _mapping_id
    assert ctx.state.rows(
        "SELECT source_profile FROM approval_mappings WHERE parent_issue_id=? ORDER BY source_profile",
        (mapping["parent_issue_id"],),
    ) == [{"source_profile": "default"}, {"source_profile": "om73"}]


def test_v4_database_upgrade_blocks_old_approval_and_adds_retry_columns(ctx):
    from notify.state import (
        APPROVAL_INDEXES_V4,
        APPROVAL_SCHEMA_V4,
        INDEXES_V1,
        SCHEMA,
        WAKE_INDEXES,
        WAKE_SCHEMA,
    )

    path = ctx.root / "approval-v4.db"
    db = __import__("sqlite3").connect(path)
    for table, columns in (SCHEMA | WAKE_SCHEMA | APPROVAL_SCHEMA_V4).items():
        db.execute(f"CREATE TABLE {table} ({columns})")
    for index in (INDEXES_V1 | WAKE_INDEXES | APPROVAL_INDEXES_V4).values():
        db.execute(index)
    db.execute("PRAGMA user_version=4")
    db.commit()
    db.close()
    path.chmod(0o600)
    migrated = State(path)
    assert {row[1] for row in migrated.db.execute("PRAGMA table_info(approval_jobs)")} >= {"next_check_at"}
    assert {row[1] for row in migrated.db.execute("PRAGMA table_info(approval_mappings)")} >= {
        "agent_id", "project_id", "next_check_at",
    }
    assert migrated.db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    migrated.db.close()
    reopened = State(path)
    reopened.db.close()
