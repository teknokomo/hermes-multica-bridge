from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from bridge.condition_wake import (
    ConditionWakeSpec,
    condition_wakeup_matches,
    parse_condition_wake,
    readiness_from_children,
    validate_child_tree,
)
from bridge.errors import BridgeError

PARENT = "11111111-1111-4111-8111-111111111111"
WORKSPACE = "22222222-2222-4222-8222-222222222222"
PROJECT = "33333333-3333-4333-8333-333333333333"
AGENT = "44444444-4444-4444-8444-444444444444"
CHILD_A = "55555555-5555-4555-8555-555555555555"
CHILD_B = "66666666-6666-4666-8666-666666666666"


def _spec(**extra):
    return parse_condition_wake({
        "enabled": True,
        "mode": "children_done",
        "instruction": "Check all stage tasks and request human approval.",
        "expires_in": "2h",
        **extra,
    })


def _child(issue_id: str, stage: int | None, status: str = "in_progress"):
    return {
        "id": issue_id,
        "workspace_id": WORKSPACE,
        "project_id": PROJECT,
        "parent_issue_id": PARENT,
        "status": status,
        "stage": stage,
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"stage": 2},
        {"expected_stage_count": 2},
        {"stage": 2, "expected_stage_count": 3},
        {"stage": None, "expected_stage_count": None},
    ],
)
def test_stage_requires_matching_stage_and_expected_count(fields):
    with pytest.raises(BridgeError, match="stage"):
        _spec(**fields)


def test_stage_count_is_bounded_by_the_maximum_child_tree():
    excessive = 1_000_000_000
    with pytest.raises(BridgeError, match="stage"):
        _spec(stage=excessive, expected_stage_count=excessive)

    saved = _spec().canonical()
    saved["stage"] = excessive
    saved["expected_stage_count"] = excessive
    with pytest.raises(BridgeError, match="stage"):
        ConditionWakeSpec.from_canonical(saved)

    malformed = replace(_spec(), stage=excessive, expected_stage_count=excessive)
    with pytest.raises(BridgeError, match="stage"):
        validate_child_tree(
            [_child(CHILD_A, 1)],
            parent_id=PARENT,
            workspace_id=WORKSPACE,
            project_id=PROJECT,
            spec=malformed,
        )


def test_unstaged_and_sequential_staged_child_sets_are_valid():
    unstaged = _spec()
    children, fingerprint = validate_child_tree(
        [_child(CHILD_A, None), _child(CHILD_B, None)],
        parent_id=PARENT,
        workspace_id=WORKSPACE,
        project_id=PROJECT,
        spec=unstaged,
    )
    assert len(children) == 2
    assert len(fingerprint) == 64

    staged = _spec(stage=2, expected_stage_count=2)
    children, _ = validate_child_tree(
        [_child(CHILD_A, 1), _child(CHILD_B, 2)],
        parent_id=PARENT,
        workspace_id=WORKSPACE,
        project_id=PROJECT,
        spec=staged,
    )
    assert {row["stage"] for row in children} == {1, 2}


def test_staged_child_groups_can_have_gaps_below_the_maximum_ordinal():
    staged = _spec(stage=3, expected_stage_count=2)
    children, _ = validate_child_tree(
        [_child(CHILD_A, 1), _child(CHILD_B, 3)],
        parent_id=PARENT,
        workspace_id=WORKSPACE,
        project_id=PROJECT,
        spec=staged,
    )
    assert {row["stage"] for row in children} == {1, 3}

    with pytest.raises(BridgeError, match="stage"):
        validate_child_tree(
            [_child(CHILD_A, 1), _child(CHILD_B, 2)],
            parent_id=PARENT,
            workspace_id=WORKSPACE,
            project_id=PROJECT,
            spec=staged,
        )


def test_condition_wakeup_payload_pins_kind_and_agent():
    payload = _spec().api_payload(agent_id=AGENT)
    assert payload["kind"] == "event"
    assert payload["agent_id"] == AGENT
    assert payload["condition"] == {"type": "children_done"}
    assert payload["mode"] == "once"
    assert payload["expires_in_seconds"] == 7200

    exact_expiry = 1_800_000_000.25
    exact_payload = _spec().api_payload(agent_id=AGENT, expires_at_override=exact_expiry)
    assert "expires_in_seconds" not in exact_payload
    assert datetime.fromisoformat(exact_payload["expires_at"]).timestamp() == pytest.approx(exact_expiry)

    with pytest.raises(BridgeError, match="agent"):
        _spec().api_payload(agent_id="not-an-agent-uuid")


def test_expired_condition_wake_requires_explicit_restore_context():
    expired = {
        "enabled": True,
        "mode": "children_done",
        "instruction": "Reconcile the registered wakeup.",
        "expires_at": int(datetime.now(UTC).timestamp()) - 60,
    }
    with pytest.raises(BridgeError, match="expires_at"):
        parse_condition_wake(expired)

    restored = parse_condition_wake(expired, allow_expired=True)
    with pytest.raises(BridgeError, match="expiry"):
        ConditionWakeSpec.from_canonical(restored.canonical())
    assert ConditionWakeSpec.from_canonical(
        restored.canonical(), allow_expired=True,
    ) == restored


def test_readiness_requires_every_saved_child_exactly_done():
    expected = [{"id": CHILD_A, "stage": None}, {"id": CHILD_B, "stage": None}]
    done = [_child(CHILD_A, None, "done"), _child(CHILD_B, None, "done")]
    assert readiness_from_children(
        expected, done, parent_id=PARENT, workspace_id=WORKSPACE, project_id=PROJECT
    ) == "ready"
    for status in ("failed", "cancelled", "blocked", "closed", "in_review"):
        current = [done[0], _child(CHILD_B, None, status)]
        assert readiness_from_children(
            expected, current, parent_id=PARENT, workspace_id=WORKSPACE, project_id=PROJECT
        ) == "approval_blocked"


def test_wakeup_match_requires_the_same_agent_parent_and_event_contract():
    spec = _spec()
    expected_expiry = 1_800_000_000.0
    wakeup = {
        "id": "77777777-7777-4777-8777-777777777777",
        "issue_id": PARENT,
        "agent_id": AGENT,
        "kind": "event",
        "mode": "once",
        "instruction": spec.instruction,
        "condition": {"type": "children_done"},
        "expires_at": datetime.fromtimestamp(expected_expiry, UTC).isoformat(),
    }
    assert condition_wakeup_matches(
        wakeup, PARENT, spec, agent_id=AGENT, expected_expires_at=expected_expiry,
    )
    assert not condition_wakeup_matches(
        wakeup, PARENT, spec, agent_id=CHILD_A, expected_expires_at=expected_expiry,
    )
    assert not condition_wakeup_matches(
        {**wakeup, "kind": "every"}, PARENT, spec, agent_id=AGENT,
        expected_expires_at=expected_expiry,
    )
    assert not condition_wakeup_matches(
        {**wakeup, "expires_at": datetime.fromtimestamp(expected_expiry + 120, UTC).isoformat()},
        PARENT, spec, agent_id=AGENT, expected_expires_at=expected_expiry,
    )
