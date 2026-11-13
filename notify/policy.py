"""Atomic source reconciliation and subscription fan-out."""

from __future__ import annotations

import json
import re
import time
import uuid

from .config import Config, NotifyError, require
from .state import State, encoded, epoch
from .wake import build_payload

MENTION = re.compile(r"(?<![\w@])@[\w](?:[\w.-]*[\w])?")


def classify(text: str, status: str, policy: dict) -> str:
    value = text.strip().casefold()
    mentions = {m.group().casefold() for m in MENTION.finditer(text)}
    operators = {m.casefold() for m in policy["operator_mentions"]}
    if any(value.startswith(v.casefold()) for v in policy["question_prefixes"]):
        return "question"
    if any(value.startswith(v.casefold()) for v in policy["report_prefixes"]):
        return "report"
    if status == "blocked" and mentions and (not operators or mentions & operators):
        return "question"
    return "plain"


def matches(sub: dict, issue: dict) -> bool:
    if sub["project_id"] and sub["project_id"] != issue.get("project_id"):
        return False
    if sub["squad_id"] and (
        issue.get("assignee_type") != "squad"
        or issue.get("assignee_id") != sub["squad_id"]
    ):
        return False
    labels = issue.get("labels", [])
    present = {
        v["name"] if isinstance(v, dict) else v
        for v in labels
        if isinstance(v, str)
        or (isinstance(v, dict) and isinstance(v.get("name"), str))
    }
    return set(json.loads(sub["labels_json"])) <= present


def render(sub: dict, issue: dict, kind: str, detail: str, link: str) -> dict:
    label = f"[{sub['label']}] " if sub["label"] else ""
    icon = {
        "question": "❓",
        "blocked": "⛔",
        "final": "✅",
        "failed": "⚠️",
        "cancelled": "⏹",
    }.get(kind, "•")
    title = str(issue.get("title", ""))[:128]
    required = (
        f"{icon} {label}{issue['identifier']} «{title}» — {issue['status']}\n{link}"
    )
    if kind == "final" and detail:
        detail = ("Итог: " if sub["locale"] == "ru" else "Result: ") + detail
    text = required + ("\n" + detail if detail else "")
    text = text[:3500]
    payload = {
        key: sub[key]
        for key in (
            "platform",
            "account",
            "chat_id",
            "thread_id",
            "chat_type",
            "anchor_message_id",
        )
    }
    payload |= {"text": text, "identifier": issue["identifier"], "event_type": kind}
    # Trim detail only; mandatory routing/footer text is retained even with multibyte UTF-8.
    while len(encoded(payload).encode()) > 16384 and len(payload["text"]) > len(
        required
    ):
        payload["text"] = (
            payload["text"][:-128]
            if len(payload["text"]) - 128 >= len(required)
            else required
        )
    require(
        len(required) <= 3500 and len(encoded(payload).encode()) <= 16384,
        "notify_event_invalid",
    )
    return payload


def reconcile(
    state: State,
    config: Config,
    workspace: str,
    issue: dict,
    comments: list[dict],
    runs: list[dict],
    link: str,
    *,
    baseline_subscription: str | None = None,
    recovery: bool = False,
    now: float | None = None,
) -> int:
    now = now or time.time()
    require(
        isinstance(issue, dict)
        and all(
            isinstance(issue.get(k), str) and issue[k]
            for k in ("id", "identifier", "status", "workspace_id")
        ),
        "notify_event_invalid",
    )
    require(
        issue["workspace_id"] == config.workspaces[workspace]["workspace_id"],
        "notify_event_invalid",
    )
    issue = {
        k: v
        for k, v in issue.items()
        if k
        in {
            "id",
            "identifier",
            "status",
            "workspace_id",
            "project_id",
            "revision",
            "updated_at",
            "created_at",
            "status_entered_at",
            "history_id",
            "assignee_type",
            "assignee_id",
            "labels",
            "title",
            "description",
        }
    }
    require(
        all(
            len(issue[k]) <= 128 for k in ("id", "identifier", "status", "workspace_id")
        ),
        "notify_event_invalid",
    )
    require(
        issue.get("history_id") is None or isinstance(issue["history_id"], str),
        "notify_event_invalid",
    )
    revision = issue.get("revision")
    require(
        revision is None or (type(revision) is int and revision >= 0),
        "notify_event_invalid",
    )
    require(isinstance(issue.get("labels", []), list), "notify_event_invalid")
    created = epoch(issue.get("updated_at"))
    require(created is not None, "notify_event_invalid")
    count, suppressed = 0, 0
    with state.transaction() as db:
        previous = db.execute(
            "SELECT * FROM issues WHERE workspace_id=? AND issue_id=?",
            (workspace, issue["id"]),
        ).fetchone()
        if (
            previous
            and previous["revision"] is not None
            and revision is not None
            and revision < previous["revision"]
        ):
            return 0
        if previous:
            prior_data = json.loads(previous["data_json"])
            prior_time = epoch(prior_data.get("updated_at"))
            if prior_time is not None and created < prior_time:
                return 0
        seq = previous["transition_seq"] if previous else 0
        cycle = previous["cycle_started_at"] if previous else None
        if recovery:
            cycle = None
        changed = (
            not previous
            or previous["status"] != issue["status"]
            or (
                issue.get("status_entered_at") is not None
                and issue.get("status_entered_at") != previous["status_entered_at"]
            )
        )
        if (
            previous
            and previous["status"] in config.policy["final_statuses"]
            and issue["status"] not in config.policy["final_statuses"]
        ):
            # Without a server transition time, the last confirmed final observation
            # is a conservative lower bound. The current poll time is an upper bound
            # and would discard reports written before this poll. Recovery cannot
            # establish that bound and keeps the documented unknown-cycle lookback.
            cycle = epoch(issue.get("status_entered_at"))
            if cycle is None and not recovery:
                cycle = previous["last_observed_at"]
        if changed:
            seq += 1
        candidates: list[tuple[str, str, str, float]] = []
        reports = []
        for comment in comments:
            require(isinstance(comment, dict), "notify_event_invalid")
            cid, body, at = (
                comment.get("id"),
                comment.get("content"),
                epoch(comment.get("created_at")),
            )
            require(
                isinstance(cid, str) and isinstance(body, str), "notify_event_invalid"
            )
            if at is None or at > now:
                continue
            kind = classify(body, issue["status"], config.policy)
            if kind == "report":
                if at >= (
                    cycle
                    if cycle is not None
                    else now - config.policy["lookback_minutes"] * 60
                ):
                    reports.append((at, cid, body.strip()))
            else:
                candidates.append(
                    (f"comment:{issue['id']}:{cid}", kind, body.strip(), at)
                )
        kind = (
            "final"
            if issue["status"] in config.policy["final_statuses"]
            else issue["status"]
        )
        issue = dict(issue)
        if changed:
            source = (
                issue.get("history_id") or issue.get("status_entered_at") or "unknown"
            )
            suffix = source if issue.get("history_id") else f"{source}:{seq}"
            issue["_transition_key"] = (
                f"status:{issue['id']}:{issue['status']}:{suffix}"
            )
            issue["_transition_at"] = epoch(issue.get("status_entered_at")) or created
        else:
            issue["_transition_key"] = prior_data["_transition_key"]
            issue["_transition_at"] = prior_data["_transition_at"]
        # Revisit the stable current transition for subscriptions not yet routed, including baselines.
        detail = max(reports)[2] if kind == "final" and reports else ""
        candidates.append(
            (issue["_transition_key"], kind, detail, issue["_transition_at"])
        )
        for run in runs:
            require(isinstance(run, dict), "notify_event_invalid")
            if run.get("status") != "failed":
                continue
            task_id = run.get("task_id") or run.get("id")
            require(
                isinstance(task_id, str) and run.get("issue_id") == issue["id"],
                "notify_event_invalid",
            )
            at = (
                epoch(run.get("completed_at"))
                or epoch(run.get("updated_at"))
                or epoch(run.get("created_at"))
            )
            if at is not None:
                candidates.append(
                    (
                        f"task:{issue['id']}:{task_id}:failed",
                        "failed",
                        "Multica: failed",
                        at,
                    )
                )
        db.execute(
            """INSERT OR REPLACE INTO issues VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                workspace,
                issue["id"],
                encoded({k: v for k, v in issue.items() if k != "description"}),
                issue["status"],
                revision,
                issue.get("status_entered_at"),
                cycle,
                seq,
                now,
            ),
        )
        subs = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM subscriptions WHERE (enabled=1 OR id=?) AND workspace_id=?",
                (baseline_subscription, workspace),
            )
        ]
        wake_registered = {
            row[0]
            for row in db.execute("SELECT subscription_id FROM wake_subscriptions")
        }
        for key, kind, detail, at in candidates:
            db.execute(
                "INSERT OR IGNORE INTO events(workspace_id,event_key,event_type,issue_id,created_at) VALUES(?,?,?,?,?)",
                (workspace, key, kind, issue["id"], at),
            )
            for sub in subs:
                if (
                    baseline_subscription is not None
                    and sub["id"] != baseline_subscription
                ):
                    continue
                if at < sub["since"] or not matches(sub, issue):
                    continue
                events = json.loads(sub["events_json"])
                allowed = kind in events if sub["mode"] == "quiet" else kind != "report"
                if kind == "cancelled":
                    allowed = "cancelled" in events
                receipt = db.execute(
                    "INSERT OR IGNORE INTO processed_keys VALUES(?,?)", (sub["id"], key)
                )
                if not receipt.rowcount:
                    continue
                if (
                    not allowed
                    or baseline_subscription is not None
                    or sub["id"] in wake_registered
                ):
                    suppressed += 1
                    continue
                payload = render(sub, issue, kind, detail, link) | {"event_key": key}
                require(len(encoded(payload).encode()) <= 16384, "notify_event_invalid")
                db.execute(
                    """INSERT INTO notifications(id,subscription_id,event_key,payload_json,status,created_at,updated_at)
                    VALUES(?,?,?,?,'pending',?,?)""",
                    (str(uuid.uuid4()), sub["id"], key, encoded(payload), now, now),
                )
                count += 1
        if (
            previous is not None
            and previous["status"] != "done"
            and issue["status"] == "done"
            and changed
            and baseline_subscription is None
            and config.wake.get("enabled", False)
        ):
            wake_rows = db.execute(
                """SELECT ws.subscription_id,ws.profile,ws.route,ws.enabled,ws.enabled_since,
                s.* FROM wake_subscriptions ws JOIN subscriptions s ON s.id=ws.subscription_id
                WHERE ws.enabled=1 AND s.enabled=1 AND s.workspace_id=?""",
                (workspace,),
            ).fetchall()
            route_by_name = {
                route["route"]: route for route in config.wake.get("routes", {}).values()
            }
            for wake_sub in wake_rows:
                route = route_by_name.get(wake_sub["route"])
                if (
                    not route
                    or route["profile"] != wake_sub["profile"]
                    or wake_sub["enabled_since"] is None
                    or issue["_transition_at"] < wake_sub["enabled_since"]
                    or not matches(dict(wake_sub), issue)
                ):
                    continue
                wake_id = str(uuid.uuid4())
                status, payload_raw, error_code = "pending", None, ""
                try:
                    payload_raw = build_payload(
                        wake_id=wake_id,
                        profile=wake_sub["profile"],
                        subscription=dict(wake_sub),
                        issue=issue,
                        comments=comments,
                        issue_url=link,
                        workspace_id=config.workspaces[workspace]["workspace_id"],
                        transition_seq=seq,
                    ).decode("utf-8")
                except NotifyError as exc:
                    if exc.code != "wake_snapshot_insufficient":
                        raise
                    status, error_code = "dead", "wake_snapshot_insufficient"
                inserted = db.execute(
                    """INSERT OR IGNORE INTO wake_jobs
                    (id,subscription_id,event_key,issue_id,issue_key,transition_seq,payload_json,
                    status,attempts,last_error,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?, ?,0,?,?,?)""",
                    (
                        wake_id,
                        wake_sub["subscription_id"],
                        issue["_transition_key"],
                        issue["id"],
                        issue["identifier"],
                        seq,
                        payload_raw,
                        status,
                        error_code,
                        now,
                        now,
                    ),
                )
                if inserted.rowcount:
                    state._wake_metric(db, "wake_created")
                    if error_code:
                        state._wake_metric(db, "wake_snapshot_insufficient")
                else:
                    state._wake_metric(db, "wake_duplicate_suppressed")
        if baseline_subscription is not None:
            db.execute(
                "INSERT OR IGNORE INTO processed_keys VALUES(?,?)",
                (baseline_subscription, "baseline:" + issue["id"]),
            )
        for metric, value in (
            ("notifications_created", count),
            ("suppressed", suppressed),
        ):
            if value:
                db.execute(
                    "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+excluded.value",
                    ("metric:" + metric, str(value)),
                )
        return count
