"""Quiet reconciliation and durable delivery independent of Multica availability."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from datetime import UTC, datetime
from typing import Any

from .errors import BridgeError
from .watcher_delivery import wait_for_rate_slot

logger = logging.getLogger("hermes_multica_bridge.watcher")


def timestamp(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def reconcile(watcher: Any, profile: Any, route: Any, issue_id: str, event: dict[str, Any] | None = None) -> None:
    state = watcher.states[profile.name]
    mapping = state.mapping(issue_id)
    if not mapping or mapping["route_id"] != route.route_id:
        return
    api = watcher.apis[(profile.name, route.route_id)]
    issue = api.get_issue(issue_id)
    watcher._verify_issue(issue, route)
    comments = api.list_comments(issue_id)
    previous = state.snapshot(issue_id)
    policy = route.notifications
    status = str(issue.get("status") or "")
    now = time.time()
    registered = mapping["registered_at_ns"] / 1_000_000_000
    changed_at = timestamp(issue.get("updated_at"))
    initial_recent = (changed_at is not None and changed_at >= registered
                      and 0 <= now - changed_at <= policy.initial_lookback_minutes * 60)
    transition = (previous is not None and previous["status"] != status) or (previous is None and initial_recent)
    observed = watcher.__dict__.setdefault("_quiet_observed", set())
    observed_key = (profile.name, issue_id)
    cycle = previous.get("cycle_started_at") if previous else datetime.fromtimestamp(registered, UTC).isoformat()
    if previous is not None and observed_key not in observed and (
        state.issue_fingerprint(issue) != previous["content_hash"]
        or issue.get("revision") != previous["revision"]
        or str(issue.get("updated_at") or "") != previous["updated_at"]
    ):
        # Changes during downtime may contain an unobserved reopen cycle.
        cycle = None
    if previous and previous["status"] in policy.final_statuses and status not in policy.final_statuses:
        prior_phase = timestamp(previous.get("status_entered_at"))
        start = changed_at if changed_at is not None and (prior_phase is None or changed_at > prior_phase) else now
        cycle = datetime.fromtimestamp(start, UTC).isoformat()
    report_candidates = []
    notifications = []
    suppressed = []
    for comment in comments:
        cid = comment.get("id")
        content = comment.get("content")
        if not isinstance(cid, str) or not isinstance(content, str) or not content.strip():
            continue
        created = timestamp(comment.get("created_at"))
        if comment.get("author_id") == profile.own_multica_user_id:
            suppressed.append(cid)
            continue
        kind = policy.classify(content, status)
        if kind == "report":
            boundary = timestamp(cycle)
            if created is not None and created <= now and (
                (boundary is not None and created >= boundary)
                or (boundary is None and 0 <= now - created <= policy.initial_lookback_minutes * 60)
            ):
                report_candidates.append((created, cid, content.strip()))
        if state.comment_seen(issue_id, cid):
            continue
        if (created is not None and created < registered) or (previous is None and created is None):
            suppressed.append(cid)
            continue
        if kind == "question" and "question" in policy.events:
            author = str(comment.get("author_type") or "Multica")
            notifications.append(("question", f"comment:{cid}", f"Автор: {author}\n{content.strip()}", [cid]))
        else:
            suppressed.append(cid)
    kind = None
    if event and event.get("type") == "task:failed" and (previous is not None or initial_recent):
        kind = "failed"
    elif transition:
        if status in policy.final_statuses:
            kind = "final"
        elif status in ("blocked", "cancelled"):
            kind = status
    if kind in policy.events:
        detail = "Причина: событие task:failed от Multica." if kind == "failed" else ""
        report_ids = []
        if kind == "final" and report_candidates:
            _, cid, detail = max(report_candidates)
            report_ids = [cid]
        # The previous phase boundary survives restarts and distinguishes reopen cycles.
        phase = previous.get("status_entered_at", "") if previous else "initial"
        identity = str(issue.get("revision")) if kind == "failed" else f"{issue.get('revision')}:{phase}:{status}"
        notifications.append((kind, f"issue:{issue_id}:{identity}:{kind}", detail, report_ids))
    attached = {cid for _, _, _, ids in notifications for cid in ids}
    for pending in state.pending_notifications():
        if pending["issue_id"] == issue_id:
            attached.update(json.loads(pending["payload_json"]).get("comment_ids", []))
    suppressed = [cid for cid in suppressed if cid not in attached]
    identifier = str(issue.get("identifier") or issue_id)
    title = str(issue.get("title") or "Задача Multica")
    link = api.issue_link(identifier) if notifications else ""
    if not isinstance(link, str):
        raise BridgeError("invalid_api_response", "Multica issue link is unavailable.")
    db = state._connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        for kind, event_key, body, ids in notifications:
            key = hashlib.sha256(f"{profile.name}\0{route.route_id}\0{event_key}".encode()).hexdigest()
            heading = {"question": "❓ Вопрос", "blocked": "⛔ Блокировка", "final": "✅ Итог",
                       "failed": "⚠️ Ошибка", "cancelled": "Отмена"}[kind]
            footer = f"\nСтатус: {status}\n{link}"
            title_room = max(0, watcher.config.max_message_chars - len(footer) - len(heading) - len(identifier) - 8)
            prefix = f"{heading}: {identifier} «{title[:min(160, title_room)]}»\n"
            if len(prefix) + len(footer) > watcher.config.max_message_chars:
                raise BridgeError("watcher_message_invalid", "Required notification fields exceed the message limit.")
            room = max(0, watcher.config.max_message_chars - len(prefix) - len(footer))
            payload = {"text": prefix + body[:room] + footer, "mapping": mapping,
                       "parse_mode": None, "event_type": kind, "issue_id": issue_id,
                       "comment_ids": ids, "route_id": route.route_id}
            chunk = body[:room]
            size = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            while size > 16_384 and chunk:
                chunk = chunk[:max(0, len(chunk) - max(1, (size - 16_384) // 2))]
                payload["text"] = prefix + chunk + footer
                size = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            state.enqueue_notification(key, mapping, payload, _db=db)
        for cid in suppressed:
            state.mark_comment_seen(issue_id, cid, _db=db)
        state.save_snapshot(issue_id, issue, _db=db, _cycle_start=cycle)
        db.commit()
        observed.add(observed_key)
    finally:
        db.close()
    logger.info("route_id=%s delivered=0 suppressed=%d retried=0 retry_exhausted=0", route.route_id, len(suppressed))


def drain(watcher: Any, profile: Any, route: Any) -> None:
    if route.policy_error or route.notifications.mode != "quiet":
        return
    try:
        state = watcher.states[profile.name]
        policy = route.notifications
        for row in state.pending_notifications():
            payload = json.loads(row["payload_json"])
            if payload.get("route_id") != route.route_id or payload.get("event_type") not in policy.events:
                continue
            now = int(time.time())
            if row["next_retry_at"] is not None and row["next_retry_at"] > now:
                continue
            if row["status"] == "sending" and row["updated_at"] >= now - policy.sending_timeout_seconds:
                continue
            mapping = state.mapping(row["issue_id"])
            if mapping is None or mapping.get("profile") != profile.name or mapping != payload["mapping"]:
                continue
            try:
                watcher._authorize_mapping(profile, route, mapping, profile.allowed_peer_uids[0])
            except BridgeError:
                continue
            recipient = mapping["user_id"] if mapping["platform"] == "max" and mapping["chat_type"] == "dm" else mapping["chat_id"]
            delay = state.reserve_chat_slot(profile.name, mapping["platform"], recipient,
                                            interval_ms=510 if mapping["platform"] == "max" else 1100)
            wait_for_rate_slot(delay)
            attempt = state.claim_notification(row["delivery_key"], policy.max_attempts, policy.sending_timeout_seconds)
            if attempt is None:
                continue
            try:
                result = watcher.senders[profile.name].send(mapping, payload["text"])
                outcome = state.finish_notification(row["delivery_key"], attempt, result.status, result.detail, policy.max_attempts)
            except Exception:  # noqa: BLE001 -- any send exception has an uncertain outcome
                outcome = state.finish_notification(row["delivery_key"], attempt, "delivery_unknown",
                                                    "unexpected_delivery_error", policy.max_attempts)
            logger.log(logging.WARNING if outcome == "retry_exhausted" else logging.INFO,
                       "route_id=%s delivered=%d suppressed=0 retried=%d retry_exhausted=%d",
                       route.route_id, outcome == "delivered", attempt > 1, outcome == "retry_exhausted")
    except (BridgeError, sqlite3.Error):
        logger.warning("route_id=%s delivery_state_unavailable", route.route_id)
