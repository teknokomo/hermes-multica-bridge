"""Operator CLI for the local deterministic runtime router."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bridge.registry import new_id

from .adapter import MulticaCliAdapter, MulticaCliError
from .config import (
    RouterConfig,
    RouterConfigError,
    read_private_json,
    service_cli_home,
)
from .state import RouterStore
from .worker import RouterWorker

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SELECTORS = {
    "platform",
    "chat_id",
    "thread_id",
    "agent_id",
    "workspace_id",
    "squad_id",
    "project_id",
    "instance_id",
}


def _load_cli_config(path: Path) -> tuple[dict[str, Any], RouterConfig, int]:
    value = read_private_json(path)
    if set(value) != {"runtime_router"}:
        raise RouterConfigError("operator_config_invalid")
    raw = value["runtime_router"]
    config = RouterConfig.parse(raw)
    info = path.stat(follow_symlinks=False)
    return dict(raw), config, info.st_uid


def _adapter(config: RouterConfig) -> MulticaCliAdapter:
    return MulticaCliAdapter(
        binary=config.cli_binary,
        home=str(service_cli_home(config)),
        timeout=config.cli_timeout_seconds,
        spool_root=config.state_path.parent / "runtime-router-spool",
    )


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise RouterConfigError("operator_config_directory_unsafe")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or stat.S_ISLNK(existing.st_mode)
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise RouterConfigError("operator_config_file_unsafe")
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    fd, temporary = tempfile.mkstemp(prefix=".router-config-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@contextmanager
def _exclusive_overlay_lock(path: Path):
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise RouterConfigError("operator_config_directory_unsafe")
    lock_path = path.with_name(path.name + ".lock")
    flags = (
        os.O_CREAT
        | os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RouterConfigError("operator_config_lock_unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _instance_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "cli_profile": args.cli_profile,
        "workspace_id": args.workspace_id,
        "base_url": args.base_url.rstrip("/"),
        "enabled": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-multica-router")
    parser.add_argument(
        "--config",
        default=os.environ.get("HERMES_MULTICA_ROUTER_CONFIG"),
        help="private JSON configuration file (0600)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("tick", help="run one deterministic worker cycle")
    commands.add_parser(
        "doctor", help="check local state and configured Multica profiles"
    )
    commands.add_parser("status", help="show queue and worker state")

    principal = commands.add_parser("principal", help="manage local principal records")
    principal_commands = principal.add_subparsers(dest="action", required=True)
    principal_add = principal_commands.add_parser("add")
    principal_add.add_argument("--principal-id", default=None)
    principal_add.add_argument("--display-name", required=True)
    principal_commands.add_parser("list")

    identity = commands.add_parser("identity", help="link trusted connector identities")
    identity_commands = identity.add_subparsers(dest="action", required=True)
    identity_link = identity_commands.add_parser("link")
    identity_link.add_argument("--principal-id", required=True)
    identity_link.add_argument("--connector-id", required=True)
    identity_link.add_argument("--platform-user-id", required=True)
    identity_list = identity_commands.add_parser("list")
    identity_list.add_argument("--principal-id")

    instance = commands.add_parser(
        "instance", help="inspect or add operator-owned instances"
    )
    instance_commands = instance.add_subparsers(dest="action", required=True)
    instance_add = instance_commands.add_parser("add")
    instance_add.add_argument("--instance-id", required=True)
    instance_add.add_argument("--cli-profile", required=True)
    instance_add.add_argument("--workspace-id", required=True)
    instance_add.add_argument("--base-url", required=True)
    instance_commands.add_parser("list")

    binding = commands.add_parser("binding", help="manage runtime bindings")
    binding_commands = binding.add_subparsers(dest="action", required=True)
    binding_list = binding_commands.add_parser("list")
    binding_list.add_argument("--principal-id")
    binding_set = binding_commands.add_parser("set")
    binding_set.add_argument("--principal-id", required=True)
    binding_set.add_argument("--instance-id", required=True)
    binding_set.add_argument("--runtime-id", required=True)
    binding_set.add_argument("--mode", choices=("strict", "exceptions"), required=True)
    binding_set.add_argument("--strict-until")

    exception = commands.add_parser("exception", help="manage runtime exceptions")
    exception_commands = exception.add_subparsers(dest="action", required=True)
    exception_add = exception_commands.add_parser("add")
    exception_add.add_argument("--binding-id", required=True)
    exception_add.add_argument("--name", required=True)
    exception_add.add_argument("--priority", type=int, required=True)
    exception_add.add_argument("--selectors-json", required=True)
    exception_add.add_argument("--runtime-id", required=True)
    exception_add.add_argument("--expires-at")
    exception_list = exception_commands.add_parser("list")
    exception_list.add_argument("--binding-id", required=True)
    exception_remove = exception_commands.add_parser("remove")
    exception_remove.add_argument("--binding-id", required=True)
    exception_remove.add_argument("--exception-id", required=True)
    return parser


def _check_runtime(
    config: RouterConfig,
    instance_id: str,
    runtime_id: str,
    principal_id: str,
    adapter: MulticaCliAdapter,
) -> bool:
    agent_matches = [
        agent
        for agent in config.agents
        if agent.instance_id == instance_id
        and principal_id in agent.allowed_principal_ids
        and runtime_id in agent.allowed_runtime_ids
    ]
    if not agent_matches:
        raise RouterConfigError("runtime_not_allowed")
    instance = config.instance(instance_id)
    catalog = {row["id"]: row for row in adapter.runtime_list(instance)}
    runtime = catalog.get(runtime_id)
    if runtime is None:
        raise RouterConfigError("runtime_not_available_in_instance")
    if runtime.get("accessible") is not True:
        raise RouterConfigError("runtime_not_accessible")
    if runtime.get("status") != "online":
        raise RouterConfigError("runtime_offline")
    return True


def _doctor(config: RouterConfig, adapter: MulticaCliAdapter) -> dict[str, Any]:
    state_exists = config.state_path.exists()
    state: dict[str, Any] | None = None
    if state_exists:
        state = RouterStore.inspect(config.state_path)
    instance_results = []
    for instance in config.instances:
        if not instance.enabled:
            instance_results.append(
                {"instance_id": instance.instance_id, "enabled": False}
            )
            continue
        workspaces = adapter.workspace_list(instance)
        workspace_ids = {row.get("id", row.get("workspace_id")) for row in workspaces}
        if instance.workspace_id not in workspace_ids:
            raise RouterConfigError("workspace_unavailable")
        runtimes = adapter.runtime_list(instance)
        runtime_map = {row["id"]: row for row in runtimes}
        agents = []
        for agent in config.agents:
            if agent.instance_id != instance.instance_id:
                continue
            record = adapter.agent_get(instance, agent.agent_id)
            if record.get("max_concurrent_tasks") != 1:
                raise RouterConfigError("agent_concurrency_invalid")
            runtime_id = record.get("runtime_id")
            if runtime_id not in agent.allowed_runtime_ids:
                raise RouterConfigError("runtime_not_allowed")
            runtime = runtime_map.get(runtime_id)
            if runtime is None:
                raise RouterConfigError("agent_runtime_mismatch")
            if runtime.get("accessible") is not True:
                raise RouterConfigError("runtime_not_accessible")
            if runtime.get("status") != "online":
                raise RouterConfigError("runtime_offline")
            model = record.get("model")
            configured_model = agent.model_by_runtime.get(runtime_id)
            models = runtime.get("models")
            if configured_model is not None:
                if (
                    model != configured_model
                    or not isinstance(models, list)
                    or configured_model not in models
                ):
                    raise RouterConfigError("model_unsupported")
            elif (
                not isinstance(model, str)
                or not isinstance(models, list)
                or model not in models
            ):
                raise RouterConfigError("runtime_default_model_unverified")
            agents.append(
                {
                    "agent_ref": agent.agent_ref,
                    "agent_id": agent.agent_id,
                    "runtime_id": runtime_id,
                    "model": model,
                    "max_concurrent_tasks": record["max_concurrent_tasks"],
                }
            )
        instance_results.append(
            {
                "instance_id": instance.instance_id,
                "workspace_access": True,
                "runtime_count": len(runtimes),
                "agents": agents,
            }
        )
    stale = []
    if state_exists and state is not None:
        now = int(time.time())
        stale = [
            {"request_id": row["request_id"], "state": row["state"]}
            for row in RouterStore.read_active(config.state_path)
            if row["state"] in {"switching", "creating"}
            and row["lease_expires_at"] is not None
            and row["lease_expires_at"] < now
        ]
    return {
        "ok": True,
        "feature_enabled": config.enabled,
        "state_initialized": state_exists,
        "state": state,
        "instances": instance_results,
        "expired_leases": stale,
    }


def _dispatch(
    args: argparse.Namespace,
    raw: dict[str, Any],
    config: RouterConfig,
    config_owner: int,
) -> dict[str, Any]:
    if os.geteuid() != config_owner:
        raise RouterConfigError("operator_config_owner_mismatch")
    adapter = _adapter(config)
    if args.command == "tick":
        return RouterWorker(config, adapter=adapter).tick()
    if args.command == "doctor":
        return _doctor(config, adapter)
    if args.command == "status":
        if not config.state_path.exists():
            return {"ok": True, "initialized": False, "queue_depth": 0, "active": []}
        return {"ok": True, **RouterStore.read_runtime_metrics(config.state_path)}

    store = RouterStore(config.state_path)
    if args.command == "principal":
        if args.action == "add":
            principal_id = args.principal_id or new_id()
            store.create_principal(principal_id, args.display_name)
            return {"ok": True, "principal_id": principal_id}
        return {"ok": True, "principals": store.list_principals()}
    if args.command == "identity":
        if args.action == "list":
            return {"ok": True, "identities": store.list_identities(args.principal_id)}
        connector = next(
            (
                item
                for item in config.connectors
                if item.connector_id == args.connector_id and item.enabled
            ),
            None,
        )
        if connector is None:
            raise RouterConfigError("connector_unresolved")
        store.link_identity(
            new_id(), args.principal_id, args.connector_id, args.platform_user_id
        )
        return {"ok": True, "linked": True}
    if args.command == "instance":
        if args.action == "list":
            return {
                "ok": True,
                "instances": [
                    {
                        "instance_id": item.instance_id,
                        "cli_profile": item.cli_profile,
                        "workspace_id": item.workspace_id,
                        "enabled": item.enabled,
                    }
                    for item in config.instances
                ],
            }
        if not _ID.fullmatch(args.instance_id):
            raise RouterConfigError("instance_id_invalid")
        parsed = urlsplit(args.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise RouterConfigError("instance_url_invalid")
        if config.operator_config_path is None:
            raise RouterConfigError("operator_config_path_required")
        candidate_value = _instance_args(args)
        with _exclusive_overlay_lock(config.operator_config_path):
            try:
                overlay = dict(read_private_json(config.operator_config_path))
            except RouterConfigError as exc:
                if str(exc) != "operator_config_unavailable":
                    raise
                overlay = {}
            if set(overlay) - {"instances"}:
                raise RouterConfigError("operator_config_invalid")
            instances = overlay.get("instances", {})
            if not isinstance(instances, dict) or args.instance_id in instances:
                raise RouterConfigError("instance_id_conflict")
            candidate_instances = {
                **raw.get("instances", {}),
                **instances,
                args.instance_id: candidate_value,
            }
            candidate_raw = {
                **raw,
                "operator_config_path": None,
                "instances": candidate_instances,
            }
            candidate = RouterConfig.parse(candidate_raw)
            instance = candidate.instance(args.instance_id)
            workspaces = adapter.workspace_list(instance)
            if args.workspace_id not in {
                row.get("id", row.get("workspace_id")) for row in workspaces
            }:
                raise RouterConfigError("workspace_unavailable")
            _atomic_private_json(
                config.operator_config_path,
                {"instances": {**instances, args.instance_id: candidate_value}},
            )
        return {"ok": True, "instance_id": args.instance_id, "workspace_access": True}
    if args.command == "binding":
        if args.action == "list":
            return {"ok": True, "bindings": store.list_bindings(args.principal_id)}
        binding_principal = next(
            (
                row
                for row in store.list_principals()
                if row["principal_id"] == args.principal_id
                and row["status"] == "active"
            ),
            None,
        )
        if binding_principal is None:
            raise RouterConfigError("principal_unresolved")
        _check_runtime(
            config, args.instance_id, args.runtime_id, args.principal_id, adapter
        )
        store.set_binding(
            new_id(),
            args.principal_id,
            args.instance_id,
            args.runtime_id,
            args.mode,
            args.strict_until,
            "local-operator",
        )
        return {
            "ok": True,
            "principal_id": args.principal_id,
            "instance_id": args.instance_id,
            "runtime_id": args.runtime_id,
            "mode": args.mode,
        }
    if args.command == "exception":
        if args.action == "list":
            return {"ok": True, "exceptions": store.list_exceptions(args.binding_id)}
        if args.action == "remove":
            return {
                "ok": True,
                "removed": store.remove_exception(args.binding_id, args.exception_id),
            }
        binding = next(
            (
                row
                for row in store.list_bindings()
                if row["binding_id"] == args.binding_id
            ),
            None,
        )
        if binding is None:
            raise RouterConfigError("runtime_unbound")
        try:
            selectors = json.loads(args.selectors_json)
        except (ValueError, RecursionError):
            raise RouterConfigError("invalid_arguments") from None
        if (
            not isinstance(selectors, dict)
            or not selectors
            or set(selectors) - _SELECTORS
            or any(
                not isinstance(value, str) or not value for value in selectors.values()
            )
        ):
            raise RouterConfigError("invalid_arguments")
        _check_runtime(
            config,
            binding["instance_id"],
            args.runtime_id,
            binding["principal_id"],
            adapter,
        )
        exception_id = new_id()
        store.add_exception(
            exception_id,
            args.binding_id,
            args.name,
            args.priority,
            selectors,
            args.runtime_id,
            args.expires_at,
        )
        return {"ok": True, "exception_id": exception_id}
    raise RouterConfigError("invalid_arguments")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.config:
        print(json.dumps({"ok": False, "error_code": "operator_config_required"}))
        return 2
    try:
        raw, config, owner = _load_cli_config(Path(args.config))
        result = _dispatch(args, raw, config, owner)
    except (RouterConfigError, MulticaCliError) as exc:
        code = exc.code if isinstance(exc, MulticaCliError) else str(exc)
        result = {"ok": False, "error_code": code}
    except (OSError, ValueError, TypeError):
        result = {"ok": False, "error_code": "router_operation_failed"}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover - exercised through the entry point
    sys.exit(main())
