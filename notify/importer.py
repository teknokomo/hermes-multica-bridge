"""Explicit, default-disabled watcher bindings and read-only issue baselines."""

from __future__ import annotations

import hashlib
import time
import tomllib
from pathlib import Path

from bridge.watcher_config import parse_watcher_config

from .config import Config, name, parse_config, private_read, require
from .policy import matches, reconcile
from .state import State, subscription


def watcher_bundle(config: Config, watcher_path: Path, bindings_path: Path) -> tuple:
    # The watcher config is non-secret and may be root/group-readable.
    require(
        not watcher_path.is_symlink() and watcher_path.stat().st_size <= 1_048_576,
        "binding_invalid",
    )
    watcher = parse_watcher_config(tomllib.loads(watcher_path.read_text()))
    raw = tomllib.loads(private_read(bindings_path).decode())
    require(
        set(raw) == {"bindings"} and isinstance(raw["bindings"], list),
        "binding_invalid",
    )
    routes = {}
    for profile in watcher.profiles:
        for route in profile.routes:
            require(route.route_id not in routes, "binding_invalid")
            routes[route.route_id] = (profile, route)
    result, covered, seen = [], set(), set()
    accounts, workspaces = dict(config.accounts), dict(config.workspaces)
    new_accounts, new_workspaces = {}, {}
    for binding in raw["bindings"]:
        require(
            isinstance(binding, dict)
            and not set(binding)
            - {
                "route_id",
                "platform",
                "account",
                "chat_id",
                "chat_type",
                "thread_id",
                "anchor_message_id",
                "label",
                "mode",
            },
            "binding_invalid",
        )
        entry = routes.get(binding.get("route_id"))
        require(entry is not None, "binding_unknown_route")
        profile, route = entry
        require(
            {"route_id", "platform", "account", "chat_id", "chat_type"} <= set(binding),
            "binding_invalid",
        )
        account = name(binding["account"])
        if account not in accounts:
            token_name = (
                profile.telegram_token_credential
                if binding.get("platform") == "telegram"
                else profile.max_token_credential
            )
            require(bool(token_name), "binding_invalid")
            accounts[account] = new_accounts[account] = {
                "platform": binding.get("platform"),
                "token_credential": token_name,
            }
        require(
            binding.get("platform") in route.source_platforms, "binding_not_allowed"
        )
        dm = binding.get("chat_type") == "dm"
        require(
            binding.get("chat_id")
            in (route.allowed_user_ids if dm else route.allowed_chat_ids),
            "binding_not_allowed",
        )
        require(dm or route.allow_groups, "binding_not_allowed")
        workspace_keys = [
            key
            for key, row in workspaces.items()
            if row["origin"].rstrip("/") == route.multica_origin.rstrip("/")
            and row["workspace_id"] == route.workspace_id
        ]
        require(len(workspace_keys) <= 1, "binding_invalid")
        if not workspace_keys:
            key = (
                "watcher-"
                + hashlib.sha256(
                    (route.multica_origin + route.workspace_id).encode()
                ).hexdigest()[:16]
            )
            workspaces[key] = new_workspaces[key] = {
                "origin": route.multica_origin,
                "workspace_id": route.workspace_id,
                "cli_profile": key,
                "pat_credential": profile.multica_pat_credential,
            }
            workspace_keys = [key]
        row = {k: v for k, v in binding.items() if k != "route_id"}
        row |= {
            "workspace_id": workspace_keys[0],
            "project_id": route.project_id,
            "enabled": False,
            "mode": binding.get("mode", route.notifications.mode),
            "events": list(route.notifications.events),
        }
        candidate = parse_config(
            {
                "service": config.service,
                "policy": config.policy,
                "accounts": accounts,
                "workspaces": workspaces,
            }
        )
        row = subscription(row, candidate, time.time())
        key = tuple(
            row[k]
            for k in (
                "platform",
                "account",
                "chat_id",
                "thread_id",
                "workspace_id",
                "project_id",
                "squad_id",
            )
        )
        require(key not in seen, "binding_duplicate")
        seen.add(key)
        covered.add(route.route_id)
        result.append(row)
    require(set(routes) == covered, "binding_required")
    return result, new_accounts, new_workspaces


def watcher_plan(config: Config, watcher_path: Path, bindings_path: Path) -> list[dict]:
    return watcher_bundle(config, watcher_path, bindings_path)[0]


def import_watcher(state: State, rows: list[dict]) -> int:
    return len(state.add_subscriptions(rows, skip_existing=True))


def import_issues(
    state: State, config: Config, sid: str, api, *, dry_run: bool = False
) -> int:
    subs = state.rows("SELECT * FROM subscriptions WHERE id=?", (sid,))
    require(bool(subs), "notify_subscription_invalid")
    sub = subs[0]
    count = 0
    for candidate in api.issues(sub["project_id"]):
        issue, comments, runs, link = api.snapshot(candidate["id"])
        if not matches(sub, issue):
            continue
        if state.rows(
            "SELECT event_key FROM processed_keys WHERE subscription_id=? AND event_key=?",
            (sid, "baseline:" + issue["id"]),
        ):
            continue
        if not dry_run:
            reconcile(
                state,
                config,
                sub["workspace_id"],
                issue,
                comments,
                runs,
                link,
                baseline_subscription=sid,
            )
        count += 1
    return count
