"""Local-only administration for the central notification service."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from bridge.errors import BridgeError

from .api import Multica
from .config import (
    NotifyError,
    append_tables,
    append_workspace,
    atomic_private,
    credential,
    load_config,
    require,
)
from .importer import import_issues, import_watcher, watcher_bundle, watcher_plan
from .service import Service
from .state import State, encoded, subscription
from .wake import (
    load_webhook_policy,
    verify_configured_route,
    verify_webhook_policy,
)

DEFAULT_CONFIG = "/etc/hermes-multica-notify/notify.toml"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hermes-multica-notify")
    root.add_argument("--config", type=Path, default=Path(DEFAULT_CONFIG))
    commands = root.add_subparsers(dest="command", required=True)

    def command(parent, key):
        item = parent.add_parser(key)
        item.add_argument("--config", type=Path, default=argparse.SUPPRESS)
        return item

    init = command(commands, "init")
    init.add_argument(
        "--db-path", default="/var/lib/hermes-multica-notify/notify.sqlite3"
    )
    init.add_argument("--runtime-dir", default="/run/hermes-multica-notify")
    command(commands, "run")
    workspace = command(commands, "workspace").add_subparsers(
        dest="action", required=True
    )
    add = command(workspace, "add")
    for flag in ("name", "origin", "workspace-id", "cli-profile", "pat-credential"):
        add.add_argument("--" + flag, required=True)
    subscriptions = command(commands, "subscription").add_subparsers(
        dest="action", required=True
    )
    add = command(subscriptions, "add")
    for flag in ("platform", "account", "chat", "chat-type", "workspace"):
        add.add_argument("--" + flag, required=True)
    for flag in ("thread", "project", "squad", "label"):
        add.add_argument("--" + flag, default="")
    add.add_argument("--anchor")
    add.add_argument("--mode", choices=["quiet", "verbose"], default="quiet")
    add.add_argument("--locale", choices=["ru", "en"], default="ru")
    add.add_argument("--events", default="question,blocked,final,failed")
    add.add_argument("--labels", default="")
    add.add_argument("--since")
    add.add_argument("--shadow", action="store_true")
    add.add_argument("--disabled", action="store_true")
    listing = command(subscriptions, "list")
    listing.add_argument("--json", action="store_true")
    for action in ("enable", "disable"):
        command(subscriptions, action).add_argument("id")
    command(commands, "status").add_argument("--json", action="store_true")
    command(commands, "doctor").add_argument("--offline", action="store_true")
    dead = command(commands, "dead-letter").add_subparsers(dest="action", required=True)
    command(dead, "list").add_argument("--json", action="store_true")
    command(dead, "retry").add_argument("id")
    command(commands, "replay").add_argument("id")
    imported = command(commands, "import-watcher")
    imported.add_argument("--watcher-config", type=Path, required=True)
    imported.add_argument("--bindings", type=Path, required=True)
    imported.add_argument("--dry-run", action="store_true")
    issues = command(commands, "import-issues")
    issues.add_argument("--subscription", required=True)
    issues.add_argument("--dry-run", action="store_true")
    wake = command(commands, "wake").add_subparsers(dest="action", required=True)
    wake_add = command(wake, "add")
    wake_add.add_argument("--subscription", required=True)
    wake_add.add_argument("--profile", choices=["default", "om73"], required=True)
    wake_add.add_argument("--route", required=True)
    wake_add.add_argument("--status", choices=["done"], default="done")
    wake_add.add_argument("--enabled", action="store_true")
    command(wake, "list").add_argument("--json", action="store_true")
    command(wake, "status").add_argument("--json", action="store_true")
    for action in ("enable", "disable"):
        command(wake, action).add_argument("subscription")
    wake_replay = command(wake, "replay")
    wake_replay.add_argument("id")
    wake_replay.add_argument("--confirm", action="store_true")
    return root


def output(value) -> None:
    print(encoded(value))


def resolve_subscription(state: State, value: str) -> str:
    rows = state.rows(
        "SELECT id FROM subscriptions WHERE id=? OR label=? ORDER BY id LIMIT 2",
        (value, value),
    )
    require(len(rows) == 1, "wake_subscription_ambiguous")
    return rows[0]["id"]


def execute_wake(args, config, state: State) -> None:
    if args.action == "add":
        routes = [
            row
            for key, row in config.wake.get("routes", {}).items()
            if args.route in {key, row["route"]}
        ]
        require(len(routes) == 1, "wake_route_unavailable")
        route = routes[0]
        require(route["profile"] == args.profile, "wake_route_profile_mismatch")
        if args.enabled:
            require(config.wake.get("enabled", False), "wake_disabled")
        sid = resolve_subscription(state, args.subscription)
        policy = load_webhook_policy(Path(config.wake["webhook_policy_file"]))
        verify_webhook_policy(
            policy,
            route["profile"],
            route["route"],
            state.subscription_destination(sid),
        )
        state.add_wake_subscription(sid, route, enabled=args.enabled)
        output(
            {
                "ok": True,
                "subscription": sid,
                "profile": route["profile"],
                "route": route["route"],
                "enabled": bool(args.enabled),
            }
        )
    elif args.action == "list":
        output(state.wake_subscriptions())
    elif args.action == "status":
        output(state.wake_status())
    elif args.action in {"enable", "disable"}:
        sid = resolve_subscription(state, args.subscription)
        enabled = args.action == "enable"
        if enabled:
            require(config.wake.get("enabled", False), "wake_disabled")
            binding = state.wake_binding(sid)
            verify_configured_route(
                config.wake.get("routes", {}), binding["profile"], binding["route"]
            )
            policy = load_webhook_policy(Path(config.wake["webhook_policy_file"]))
            verify_webhook_policy(
                policy,
                binding["profile"],
                binding["route"],
                binding,
            )
        state.set_wake_enabled(sid, enabled, config.wake.get("routes", {}))
        output({"ok": True, "subscription": sid, "enabled": enabled})
    else:
        require(args.confirm, "wake_replay_confirmation_required")
        require(config.wake.get("enabled", False), "wake_disabled")
        job_rows = state.rows(
            "SELECT subscription_id FROM wake_jobs WHERE id=?", (args.id,)
        )
        require(bool(job_rows), "wake_replay_unavailable")
        binding = state.wake_binding(job_rows[0]["subscription_id"])
        verify_configured_route(
            config.wake.get("routes", {}), binding["profile"], binding["route"]
        )
        policy = load_webhook_policy(Path(config.wake["webhook_policy_file"]))
        verify_webhook_policy(
            policy,
            binding["profile"],
            binding["route"],
            binding,
        )
        require(
            state.wake_replay(
                args.id,
                config.service["replay_retention_days"],
                config.wake.get("routes", {}),
            ),
            "wake_replay_unavailable",
        )
        output({"ok": True, "id": args.id, "requeued": True})


def execute(args) -> None:
    if args.command == "init":
        require(not args.config.exists(), "notify_config_exists")
        text = "# Конфигурация центрального сервиса уведомлений\n[service]\n"
        text += (
            "db_path = "
            + json.dumps(args.db_path)
            + "\nruntime_dir = "
            + json.dumps(args.runtime_dir)
            + "\n"
        )
        atomic_private(args.config, text.encode())
        state = State(Path(args.db_path), create=True)
        state.db.close()
        output(
            {
                "ok": True,
                "next": "configure infrastructure, start run, then add subscriptions",
            }
        )
        return
    config = load_config(args.config)
    if args.command == "run":
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        asyncio.run(Service(args.config).run())
        return
    if args.command == "workspace":
        applied = append_workspace(
            args.config,
            args.name,
            {
                "origin": args.origin,
                "workspace_id": args.workspace_id,
                "cli_profile": args.cli_profile,
                "pat_credential": args.pat_credential,
            },
        )
        output({"ok": True, "reload_requested": applied})
        return
    if args.command == "import-watcher" and args.dry_run:
        rows = watcher_plan(config, args.watcher_config, args.bindings)
        output(
            {"ok": True, "subscriptions": len(rows), "enabled": False, "dry_run": True}
        )
        return
    state = State(Path(config.service["db_path"]))
    try:
        if args.command == "wake":
            execute_wake(args, config, state)
        elif args.command == "subscription":
            if args.action == "add":
                row = subscription(
                    {
                        "platform": args.platform,
                        "account": args.account,
                        "chat_id": args.chat,
                        "chat_type": args.chat_type,
                        "workspace_id": args.workspace,
                        "thread_id": args.thread,
                        "project_id": args.project,
                        "squad_id": args.squad,
                        "anchor_message_id": args.anchor,
                        "mode": args.mode,
                        "locale": args.locale,
                        "label": args.label,
                        "events": args.events.split(","),
                        "labels": args.labels.split(",") if args.labels else [],
                        "since": args.since or time.time(),
                        "enabled": not args.disabled,
                        "shadow": args.shadow,
                    },
                    config,
                    time.time(),
                )
                output({"ok": True, "id": state.add_subscription(row)})
            elif args.action == "list":
                output(
                    state.rows(
                        "SELECT id,workspace_id,account,label,mode,shadow,enabled,since,disabled_reason FROM subscriptions"
                    )
                )
            else:
                state.toggle(args.id, args.action == "enable")
                output({"ok": True})
        elif args.command == "status":
            result = state.status()
            result["wake"] = state.wake_status()
            output(result)
        elif args.command == "doctor":
            require(not config.workspace_errors, "notify_config_invalid")
            require(
                state.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
                "notify_migration_failed",
            )
            if not args.offline:
                for row in config.accounts.values():
                    credential(row["token_credential"])
                for key in config.workspaces:
                    Multica(config, key).check_cli()
            wake_rows = state.wake_subscriptions()
            active_wake = [row for row in wake_rows if row["enabled"]]
            if config.wake.get("enabled", False):
                webhook_policy = load_webhook_policy(
                    Path(config.wake["webhook_policy_file"])
                )
                for row in active_wake:
                    binding = state.wake_binding(row["subscription_id"])
                    verify_configured_route(
                        config.wake.get("routes", {}),
                        binding["profile"],
                        binding["route"],
                    )
                    verify_webhook_policy(
                        webhook_policy,
                        binding["profile"],
                        binding["route"],
                        binding,
                    )
                if not args.offline:
                    credential(config.wake["secret_credential"])
            output(
                {
                    "ok": True,
                    "offline": args.offline,
                    "wake": {
                        "enabled": bool(config.wake.get("enabled", False)),
                        "registered": len(wake_rows),
                        "active": len(active_wake),
                        "verified_routes": len(active_wake),
                    },
                }
            )
        elif args.command == "import-watcher":
            rows, accounts, workspaces = watcher_bundle(
                config, args.watcher_config, args.bindings
            )
            if accounts or workspaces:
                require(
                    append_tables(args.config, accounts, workspaces),
                    "notify_reload_pending",
                )
            deadline = time.monotonic() + 5
            while True:
                projected_accounts = {
                    r["name"]
                    for r in state.rows("SELECT name FROM accounts WHERE configured=1")
                }
                projected_workspaces = {
                    r["id"]
                    for r in state.rows("SELECT id FROM workspaces WHERE configured=1")
                }
                if all(
                    r["account"] in projected_accounts
                    and r["workspace_id"] in projected_workspaces
                    for r in rows
                ):
                    break
                require(time.monotonic() < deadline, "notify_reload_pending")
                time.sleep(0.05)
            output(
                {"ok": True, "created": import_watcher(state, rows), "enabled": False}
            )
        elif args.command == "import-issues":
            rows = state.rows(
                "SELECT workspace_id FROM subscriptions WHERE id=?",
                (args.subscription,),
            )
            require(bool(rows), "notify_subscription_invalid")
            api = Multica(config, rows[0]["workspace_id"])
            output(
                {
                    "ok": True,
                    "issues": import_issues(
                        state, config, args.subscription, api, dry_run=args.dry_run
                    ),
                    "dry_run": args.dry_run,
                }
            )
        elif args.command == "replay" or (
            args.command == "dead-letter" and args.action == "retry"
        ):
            output(
                {
                    "ok": True,
                    "requeued": state.replay(
                        args.id, config.service["replay_retention_days"]
                    ),
                }
            )
        elif args.command == "dead-letter":
            output(
                state.rows(
                    "SELECT id,subscription_id,event_key,status,attempts,last_error FROM notifications WHERE status='dead'"
                )
            )
    finally:
        state.db.close()


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    try:
        execute(parser().parse_args(argv))
        return 0
    except (NotifyError, BridgeError) as exc:
        output({"ok": False, "error_code": exc.code})
        return 1
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
        output({"ok": False, "error_code": "notify_operation_failed"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
