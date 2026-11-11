from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from bridge.errors import BridgeError
from bridge.notification_policy import parse_notification_policy
from bridge.quiet_notifications import drain, reconcile
from bridge.watcher_delivery import DeliveryResult
from bridge.watcher_state import WatcherState
from tests.test_watcher import watcher_config


def mapping():
    return {"profile": "om73", "issue_id": "issue-1", "route_id": "route-1", "platform": "telegram",
                "user_id": "user-1", "chat_id": "chat-1", "thread_id": None, "message_id": "message-1", "chat_type": "dm"}


@pytest.mark.parametrize("text,status,kind", [
    ("  ВОПРОС: помощь", "done", "question"), ("question: help", "todo", "question"),
    ("REPORT: result", "done", "report"), ("contact a@host.example", "blocked", "plain"),
    ("help @operator", "blocked", "question"), ("help @operator", "done", "plain"),
])
def test_classification(text, status, kind):
    policy = parse_notification_policy({"mode": "quiet"}, ("blocked", "done", "in_review"))
    assert policy.classify(text, status) == kind


@pytest.mark.parametrize("raw,code", [
    ({"mode": "bad"}, "notification_policy_invalid"),
    ({"mode": "quiet", "final_statuses": []}, "notification_policy_invalid"),
    ({"events": ["unexpected"]}, "notification_event_unknown"),
    ({"mode": "quiet"}, "notification_policy_conflict"),
    ({"max_attempts": True}, "notification_policy_invalid"),
])
def test_policy_validation(raw, code):
    with pytest.raises(BridgeError) as exc:
        parse_notification_policy(raw, ("todo",))
    assert exc.value.code == code


def test_verbose_defaults_do_not_require_final_statuses():
    assert parse_notification_policy(None, ("todo",)).mode == "verbose"


@pytest.fixture
def state(tmp_path):
    s = WatcherState(tmp_path / "state" / "watcher.sqlite3")
    s.register_mapping(mapping())
    return s


def enqueue(state):
    payload = {"text": "frozen", "event_type": "question", "comment_ids": ["c1"],
               "route_id": "route-1", "mapping": state.mapping("issue-1")}
    assert state.enqueue_notification("key", mapping(), payload)
    return payload


def test_attempt_fencing_and_payload_survives_restart(state):
    payload = enqueue(state)
    first = state.claim_notification("key", 5, 60, now=1000)
    assert first == 1
    assert state.claim_notification("key", 5, 60, now=1001) is None
    restarted = WatcherState(state.path)
    assert json.loads(restarted.pending_notifications()[0]["payload_json"]) == payload
    second = restarted.claim_notification("key", 5, 60, now=1061)
    assert second == 2
    assert state.finish_notification("key", first, "delivered", "", 5) == "stale"
    assert restarted.finish_notification("key", second, "delivered", "", 5) == "delivered"
    assert state.pending_notifications() == []
    assert state.comment_seen("issue-1", "c1")


@pytest.mark.parametrize("budget", [1, 5, 10])
def test_bounded_retries_and_429(state, budget):
    enqueue(state)
    now = 1000
    for attempt in range(1, budget + 1):
        assert state.claim_notification("key", budget, 60, now=now) == attempt
        outcome = state.finish_notification("key", attempt, "not_sent", "http_429", budget, now=now)
        if attempt == budget:
            assert outcome == "retry_exhausted"
        else:
            assert outcome == "retry_scheduled"
            delay = (30, 60, 120, 300, 600)[min(attempt-1, 4)]
            assert state.claim_notification("key", budget, 60, now=now+delay-1) is None
            now += delay
    assert state.claim_notification("key", budget, 60, now=now+10000) is None
    assert state.comment_seen("issue-1", "c1")


def test_report_seen_before_pause_is_folded_into_final(state):
    cfg = watcher_config()
    route = replace(cfg.profiles[0].routes[0], notifications=parse_notification_policy(
        {"mode": "quiet", "final_statuses": ["done"]}, ("todo", "done")))
    profile = replace(cfg.profiles[0], routes=(route,))
    watcher = Mock(config=cfg, states={"om73": state})
    now = datetime.now(UTC)
    entered = (now-timedelta(hours=2)).isoformat()
    with state._connect() as db:
        db.execute("UPDATE mappings SET registered_at_ns=? WHERE issue_id='issue-1'",
                   (int((now-timedelta(hours=2)).timestamp()*1_000_000_000),))
    issue = {"id": "issue-1", "identifier": "TEST-1", "title": "Test", "status": "todo",
                 "revision": 1, "updated_at": entered}
    api = Mock()
    api.issue_link.return_value = "https://multica.example.org/test/issues/TEST-1"
    api.get_issue.return_value = issue
    api.list_comments.return_value = []
    watcher.apis = {("om73", "route-1"): api}
    reconcile(watcher, profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "report", "content": "REPORT: result", "author_id": "agent",
        "created_at": (now-timedelta(hours=1)).isoformat()}]
    reconcile(watcher, profile, route, "issue-1")
    assert state.comment_seen("issue-1", "report")
    assert not state.pending_notifications()
    issue.update(status="done", revision=3, updated_at=now.isoformat())
    reconcile(watcher, profile, route, "issue-1")
    pending = state.pending_notifications()
    assert len(pending) == 1
    assert "REPORT: result" in json.loads(pending[0]["payload_json"])["text"]
    reconcile(watcher, profile, route, "issue-1")
    assert len(state.pending_notifications()) == 1
    watcher.senders = {"om73": Mock()}
    watcher.senders["om73"].send.return_value = DeliveryResult("delivered", "")
    with patch("bridge.quiet_notifications.wait_for_rate_slot"):
        drain(watcher, profile, route)
    assert watcher.senders["om73"].send.call_count == 1


def test_migration_and_snapshot_rollback(tmp_path):
    from tests.fixtures.watcher_state_020 import WatcherState as OldState
    path = tmp_path / "old" / "state.sqlite3"
    old = OldState(path)
    old.register_mapping(mapping())
    backup = tmp_path / "backup.sqlite3"
    with sqlite3.connect(path) as source, sqlite3.connect(backup) as dest:
        source.backup(dest)
    migrated = WatcherState(path)
    assert migrated.mapping("issue-1") == old.mapping("issue-1")
    WatcherState(path)
    with sqlite3.connect(path) as target, sqlite3.connect(backup) as source:
        source.backup(target)
    restored = OldState(path)
    assert restored.mapping("issue-1") is not None


@pytest.mark.parametrize("kind", ["question", "blocked", "final", "failed", "cancelled"])
def test_each_quiet_class_uses_same_retry_budget(state, kind):
    payload = enqueue(state)
    with state._connect() as db:
        payload["event_type"] = kind
        db.execute("UPDATE deliveries SET event_type=?,payload_json=?", (kind, json.dumps(payload)))
    assert state.claim_notification("key", 1, 60) == 1
    assert state.finish_notification("key", 1, "delivery_unknown", "response_lost", 1) == "retry_exhausted"


def test_payload_limit_refuses_without_record(state):
    with pytest.raises(BridgeError):
        state.enqueue_notification("large", mapping(), {"text": "я"*16000, "event_type": "question"})
    assert state.pending_notifications() == []


def test_concurrent_claim_has_one_winner(state):
    from concurrent.futures import ThreadPoolExecutor
    enqueue(state)
    with ThreadPoolExecutor(max_workers=2) as workers:
        claims = list(workers.map(lambda _: state.claim_notification("key", 5, 300), range(2)))
    assert claims.count(1) == 1
    assert claims.count(None) == 1


def test_pending_notification_does_not_read_multica_and_waits_before_claim(state):
    payload = enqueue(state)
    cfg = watcher_config()
    route = replace(cfg.profiles[0].routes[0], notifications=parse_notification_policy(
        {"mode": "quiet", "final_statuses": ["done"]}, ("todo", "done")))
    profile = replace(cfg.profiles[0], routes=(route,))
    sender = Mock()
    sender.send.return_value = DeliveryResult("delivered", "")
    watcher = Mock(states={"om73": state}, senders={"om73": sender})
    original_claim = state.claim_notification
    waited = []
    def claim(*args, **kwargs):
        assert waited == [True]
        return original_claim(*args, **kwargs)
    with patch("bridge.quiet_notifications.wait_for_rate_slot", side_effect=lambda _: waited.append(True)), patch.object(state, "claim_notification", side_effect=claim):
        drain(watcher, profile, route)
    sender.send.assert_called_once_with(payload["mapping"], "frozen")
    watcher.apis.get.assert_not_called()


def test_cancelled_is_explicit_and_requires_allowed_status():
    assert "cancelled" not in parse_notification_policy(None, ()).events
    with pytest.raises(BridgeError) as exc:
        parse_notification_policy({"mode": "quiet", "events": ["cancelled"]}, ("done", "in_review"))
    assert exc.value.code == "notification_policy_conflict"
    policy = parse_notification_policy({"mode": "quiet", "events": ["cancelled"]}, ("done", "in_review", "cancelled"))
    assert policy.events == ("cancelled",)


def test_invalid_policy_disables_only_its_route():
    import dataclasses

    from bridge.watcher_config import parse_watcher_config
    cfg = watcher_config()
    route = dataclasses.asdict(cfg.profiles[0].routes[0])
    for k in ("policy_error", "policy_warnings"):
        route.pop(k)
    # A minimal real TOML-shaped configuration uses lists rather than dataclass tuples.
    import copy
    route = {k:list(v) if isinstance(v, tuple) else v for k,v in route.items()}
    route["notifications"] = {"mode": "quiet", "events": ["bad"]}
    other = copy.deepcopy(route)
    other["route_id"] = "route-2"
    other.pop("notifications")
    raw = {"watcher": {"socket_gid": 12345}, "profiles": {"om73": {
        "state_path": "/var/lib/test/state.sqlite3", "allowed_peer_uids": [1000],
        "multica_pat_credential": "fake-pat", "max_token_credential": "fake-max",
        "telegram_token_credential": "fake-telegram", "own_multica_user_id": "fake-own",
        "routes": [route, other],
    }}}
    parsed = parse_watcher_config(raw)
    assert parsed.profiles[0].routes[0].policy_error == "notification_event_unknown"
    assert parsed.profiles[0].routes[1].policy_error == ""


@pytest.fixture
def quiet_runtime(state):
    import threading

    from bridge.watcher import Watcher
    cfg = watcher_config()
    statuses = ("todo", "in_progress", "blocked", "done", "in_review", "cancelled")
    policy = parse_notification_policy({"mode": "quiet", "events": ["question", "blocked", "final", "failed", "cancelled"]}, statuses)
    route = replace(cfg.profiles[0].routes[0], allowed_statuses=statuses, notifications=policy)
    profile = replace(cfg.profiles[0], routes=(route,))
    runtime = object.__new__(Watcher)
    runtime.config = cfg
    runtime.states = {"om73": state}
    runtime._quiet_lock = threading.RLock()
    api = Mock()
    api.issue_link.return_value = "https://multica.example.org/test/issues/TEST-1"
    api.get_issue.return_value = {"id": "issue-1", "identifier": "TEST-1", "workspace_id": "workspace-1",
        "project_id": "project-1", "title": "Test", "status": "todo", "revision": 1,
        "updated_at": (datetime.now(UTC)-timedelta(hours=1)).isoformat()}
    api.list_comments.return_value = []
    runtime.apis = {("om73", "route-1"): api}
    sender = Mock()
    sender.send.return_value = DeliveryResult("delivered", "")
    runtime.senders = {"om73": sender}
    with patch("bridge.quiet_notifications.wait_for_rate_slot"):
        yield runtime, profile, route, api, sender


@pytest.mark.parametrize("status", ["blocked", "done", "in_review", "cancelled"])
def test_quiet_status_transition_not_revision_notifies(quiet_runtime, status):
    runtime, profile, route, api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 0
    api.get_issue.return_value.update(status=status, revision=2, updated_at=datetime.now(UTC).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 1
    api.get_issue.return_value["revision"] = 3
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 1


def test_reopen_then_done_notifies_again(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    for revision, status in enumerate(("todo", "done", "in_progress", "done"), 1):
        api.get_issue.return_value.update(status=status, revision=revision)
        runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 2


def test_failed_frame_survives_issue_reconcile(quiet_runtime):
    runtime, profile, route, _api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    runtime._reconcile(profile, route, "issue-1", event={"type": "task:failed"})
    runtime._reconcile(profile, route, "issue-1", event={"type": "task:failed"})
    assert sender.send.call_count == 1
    assert "task:failed" in sender.send.call_args.args[1]


def test_question_in_final_is_delivered_even_when_status_unchanged(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    api.get_issue.return_value["status"] = "done"
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "question", "content": "QUESTION: help", "author_id": "member",
                                     "created_at": datetime.now(UTC).isoformat()}]
    runtime._reconcile(profile, route, "issue-1")
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 1


def test_initial_recent_final_after_mapping_is_delivered(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    api.get_issue.return_value.update(status="done", updated_at=datetime.now(UTC).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 1


def test_enqueue_failure_rolls_back_snapshot_and_comment_markers(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    state = runtime.states["om73"]
    api.get_issue.return_value.update(status="done", revision=2)
    api.list_comments.return_value = [{"id": "plain", "content": "ordinary", "author_id": "member",
                                      "created_at": datetime.now(UTC).isoformat()}]
    with patch.object(state, "enqueue_notification", side_effect=BridgeError("watcher_state_unavailable", "fixture")):
        runtime._reconcile(profile, route, "issue-1")
    assert state.snapshot("issue-1")["status"] == "todo"
    assert not state.comment_seen("issue-1", "plain")
    assert sender.send.call_count == 0


def test_emoji_payload_is_bounded_and_keeps_required_fields(quiet_runtime):
    runtime, profile, route, api, _sender = quiet_runtime
    runtime.config = replace(runtime.config, max_message_chars=4000)
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "q", "content": "QUESTION: " + "😀"*4000,
                                      "author_id": "member", "created_at": datetime.now(UTC).isoformat()}]
    with patch("bridge.quiet_notifications.drain"):
        runtime._reconcile(profile, route, "issue-1")
    row = runtime.states["om73"].pending_notifications()[0]
    assert len(row["payload_json"].encode("utf-8")) <= 16384
    text = json.loads(row["payload_json"])["text"]
    assert "TEST-1" in text and "Статус:" in text and "https://" in text
    assert len(text) <= 4000


def test_expired_last_attempt_exhausts_once_without_another_send(state, caplog):
    enqueue(state)
    assert state.claim_notification("key", 1, 60, now=1000) == 1
    assert state.claim_notification("key", 1, 60, now=1061) is None
    assert state.claim_notification("key", 1, 60, now=2000) is None
    assert sum("retry_exhausted=1" in r.message for r in caplog.records) == 1
    assert state.comment_seen("issue-1", "c1")


def test_policy_ipc_and_readiness_do_not_expose_other_profiles(quiet_runtime):
    import asyncio
    import struct

    from bridge.watcher_ipc import decode_frame, encode_frame

    runtime, profile, route, _api, _sender = quiet_runtime
    hidden = replace(profile, name="hidden", allowed_peer_uids=(2000,),
                     routes=(replace(route, policy_error="notification_policy_invalid"),))
    runtime.config = replace(runtime.config, profiles=(profile, hidden))

    async def request(value):
        frame = encode_frame(value)
        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()
        writer = Mock()
        sock = Mock()
        sock.getsockopt.return_value = struct.pack("3i", 1234, 1000, 1000)
        writer.get_extra_info.return_value = sock
        async def done():
            return None
        writer.drain = done
        writer.wait_closed = done
        await runtime._serve_client(reader, writer)
        return decode_frame(writer.write.call_args.args[0])

    response = asyncio.run(request({"operation": "route_policies", "profile": "hidden", "route_id": route.route_id}))
    assert response == {"ok": False, "error_code": "watcher_peer_denied"}
    response = asyncio.run(request({"operation": "readiness"}))
    assert response == {"ok": True, "ready": True}
    response = asyncio.run(request({"operation": "route_policies", "profile": profile.name, "route_id": route.route_id}))
    assert response["notifications"]["mode"] == "quiet"


def test_workspace_link_uses_validated_slug_and_origin():
    from bridge.watcher_api import WatcherApiClient
    api = WatcherApiClient("https://multica.example.org", "fake-pat", "workspace-1", timeout=5)
    with patch.object(api, "_request", return_value={"id": "workspace-1", "slug": "team"}) as request:
        assert api.issue_link("TEST-1") == "https://multica.example.org/team/issues/TEST-1"
        api.issue_link("TEST-2")
        assert request.call_count == 1
    other = WatcherApiClient("https://multica.example.org", "fake-pat", "workspace-1", timeout=5)
    with patch.object(other, "_request", return_value={"id": "foreign", "slug": "team"}), pytest.raises(BridgeError):
        other.issue_link("TEST-1")


def test_revisionless_reopen_uses_new_durable_transition_key(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    api.get_issue.return_value.pop("revision", None)
    for status in ("todo", "done", "in_progress", "done"):
        api.get_issue.return_value["status"] = status
        runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 2
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 2


def test_late_discovered_historical_question_is_not_replayed(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "old-question", "content": "QUESTION: old",
        "author_id": "member", "created_at": (datetime.now(UTC)-timedelta(days=1)).isoformat()}]
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 0
    assert runtime.states["om73"].comment_seen("issue-1", "old-question")


def test_transient_outbox_database_error_does_not_stop_polling(quiet_runtime, caplog):
    runtime, profile, route, _api, sender = quiet_runtime
    with patch.object(runtime.states["om73"], "pending_notifications", side_effect=sqlite3.OperationalError("fixture")):
        drain(runtime, profile, route)
    assert sender.send.call_count == 0
    assert any("delivery_state_unavailable" in r.message for r in caplog.records)


def backdate_registration(runtime, seconds):
    state = runtime.states["om73"]
    with state._connect() as db:
        db.execute("UPDATE mappings SET registered_at_ns=? WHERE issue_id='issue-1'",
                   (int((datetime.now(UTC)-timedelta(seconds=seconds)).timestamp()*1_000_000_000),))


def test_quick_reopen_with_two_reports_uses_only_current_cycle(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    backdate_registration(runtime, 120)
    now = datetime.now(UTC)
    runtime._reconcile(profile, route, "issue-1")
    old = {"id": "old-report", "content": "REPORT: old cycle", "author_id": "agent",
           "created_at": (now-timedelta(seconds=90)).isoformat()}
    api.list_comments.return_value = [old]
    api.get_issue.return_value.update(status="done", revision=2, updated_at=(now-timedelta(seconds=80)).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    api.get_issue.return_value.update(status="in_progress", revision=3, updated_at=(now-timedelta(seconds=60)).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    new = {"id": "new-report", "content": "REPORT: new cycle", "author_id": "agent",
           "created_at": (now-timedelta(seconds=30)).isoformat()}
    api.list_comments.return_value = [old, new]
    api.get_issue.return_value.update(status="done", revision=4, updated_at=(now-timedelta(seconds=10)).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 2
    final = sender.send.call_args.args[1]
    assert "new cycle" in final and "old cycle" not in final


def test_report_before_intermediate_status_stays_in_same_cycle(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    backdate_registration(runtime, 7200)
    now = datetime.now(UTC)
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "report", "content": "REPORT: earlier in cycle", "author_id": "agent",
                                      "created_at": (now-timedelta(minutes=90)).isoformat()}]
    api.get_issue.return_value.update(status="in_progress", revision=2, updated_at=(now-timedelta(minutes=60)).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    api.get_issue.return_value.update(status="done", revision=3, updated_at=now.isoformat())
    runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 1
    assert "earlier in cycle" in sender.send.call_args.args[1]


def test_unknown_cycle_after_downtime_uses_lookback_only(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    backdate_registration(runtime, 7200)
    now = datetime.now(UTC)
    runtime._reconcile(profile, route, "issue-1")
    runtime._quiet_observed.clear()
    api.list_comments.return_value = [
        {"id": "old", "content": "REPORT: old", "author_id": "agent",
         "created_at": (now-timedelta(hours=1)).isoformat()},
        {"id": "recent", "content": "REPORT: recent", "author_id": "agent",
         "created_at": (now-timedelta(minutes=2)).isoformat()},
    ]
    api.get_issue.return_value.update(status="done", revision=2, updated_at=now.isoformat())
    runtime._reconcile(profile, route, "issue-1")
    assert runtime.states["om73"].snapshot("issue-1")["cycle_started_at"] is None
    assert "REPORT: recent" in sender.send.call_args.args[1]
    assert "REPORT: old" not in sender.send.call_args.args[1]


def test_quiet_status_outside_allowed_statuses_updates_cycle_snapshot(quiet_runtime):
    runtime, profile, route, api, _sender = quiet_runtime
    route = replace(route, allowed_statuses=("done", "in_review"))
    api.get_issue.return_value["status"] = "done"
    runtime._reconcile(profile, route, "issue-1")
    api.get_issue.return_value.update(status="in_progress", revision=2, updated_at=datetime.now(UTC).isoformat())
    runtime._reconcile(profile, route, "issue-1")
    snapshot = runtime.states["om73"].snapshot("issue-1")
    assert snapshot["status"] == "in_progress"
    assert snapshot["cycle_started_at"] is not None


def test_operator_mention_with_sentence_punctuation():
    policy = parse_notification_policy(
        {"mode": "quiet", "operator_mentions": ["@operator"]}, ("done", "in_review", "blocked"))
    assert policy.classify("Please help @operator.", "blocked") == "question"
    assert policy.classify("Mail user@operator.example.", "blocked") == "plain"


def test_quick_reopen_without_new_report_does_not_reuse_previous_result(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    backdate_registration(runtime, 120)
    now = datetime.now(UTC)
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "old-report", "content": "REPORT: previous result",
        "author_id": "agent", "created_at": (now-timedelta(seconds=90)).isoformat()}]
    for revision, status, age in ((2, "done", 80), (3, "in_progress", 60), (4, "done", 10)):
        api.get_issue.return_value.update(status=status, revision=revision,
                                         updated_at=(now-timedelta(seconds=age)).isoformat())
        runtime._reconcile(profile, route, "issue-1")
    assert sender.send.call_count == 2
    assert "previous result" not in sender.send.call_args.args[1]


def test_concurrent_question_reconcile_sends_once(quiet_runtime):
    from concurrent.futures import ThreadPoolExecutor

    runtime, profile, route, api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "concurrent-question", "content": "QUESTION: help",
        "author_id": "member", "created_at": datetime.now(UTC).isoformat()}]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: runtime._reconcile(profile, route, "issue-1"), range(2)))
    assert sender.send.call_count == 1


def test_report_pending_final_is_not_marked_seen_by_later_reconcile(quiet_runtime):
    runtime, profile, route, api, sender = quiet_runtime
    runtime._reconcile(profile, route, "issue-1")
    api.list_comments.return_value = [{"id": "report", "content": "REPORT: result", "author_id": "agent",
                                      "created_at": datetime.now(UTC).isoformat()}]
    api.get_issue.return_value.update(status="done", revision=2, updated_at=datetime.now(UTC).isoformat())
    sender.send.return_value = DeliveryResult("delivery_unknown", "response_lost")
    runtime._reconcile(profile, route, "issue-1")
    state = runtime.states["om73"]
    assert not state.comment_seen("issue-1", "report")
    runtime._reconcile(profile, route, "issue-1")
    assert not state.comment_seen("issue-1", "report")
    assert sender.send.call_count == 1


def test_event_removed_from_policy_is_not_delivered_from_outbox(state):
    enqueue(state)
    cfg = watcher_config()
    policy = parse_notification_policy({"mode": "quiet", "events": ["final"], "final_statuses": ["done"]}, ("done",))
    route = replace(cfg.profiles[0].routes[0], notifications=policy)
    profile = replace(cfg.profiles[0], routes=(route,))
    sender = Mock()
    runtime = Mock(states={"om73": state}, senders={"om73": sender})
    drain(runtime, profile, route)
    sender.send.assert_not_called()
    assert state.pending_notifications()[0]["attempts"] == 0


def test_outbox_cannot_cross_profiles_even_with_shared_state_path(state):
    enqueue(state)
    cfg = watcher_config()
    route = replace(cfg.profiles[0].routes[0], notifications=parse_notification_policy(
        {"mode": "quiet", "final_statuses": ["done"]}, ("done",)))
    foreign = replace(cfg.profiles[0], name="other-profile", routes=(route,))
    sender = Mock()
    runtime = Mock(states={"other-profile": state}, senders={"other-profile": sender})
    drain(runtime, foreign, route)
    sender.send.assert_not_called()
    assert state.pending_notifications()[0]["attempts"] == 0


def test_different_issues_are_not_serialized_by_one_global_lock(quiet_runtime):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    runtime, profile, route, _api, _sender = quiet_runtime
    first_started = threading.Event()
    second_started = threading.Event()
    release = threading.Event()
    def work(_runtime, _profile, _route, issue_id, _event):
        if issue_id == "first":
            first_started.set()
            release.wait(3)
        else:
            second_started.set()
    with patch("bridge.quiet_notifications.reconcile", side_effect=work), patch("bridge.quiet_notifications.drain"), ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(runtime._reconcile, profile, route, "first")
        assert first_started.wait(2)
        second = pool.submit(runtime._reconcile, profile, route, "second")
        try:
            assert second_started.wait(2)
        finally:
            release.set()
        first.result(timeout=2)
        second.result(timeout=2)
