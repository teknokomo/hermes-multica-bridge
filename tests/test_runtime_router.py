from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from bridge.registry import new_id, registry_from_mapping, route_policy_fingerprint
from runtime_router.adapter import MulticaCliAdapter, MulticaCliError
from runtime_router.cli import _check_runtime, _doctor
from runtime_router.config import RouterConfig, RouterConfigError, service_cli_home
from runtime_router.policy import (
    ResolutionError,
    resolve_runtime,
    route_request_policy_hash,
)
from runtime_router.spool import AttachmentSpool
from runtime_router.state import RouterStore
from runtime_router.tools import RuntimeRouterTools, register_tools
from runtime_router.worker import RouterWorker
from tests.test_registry import workspace_registry_payload

PRINCIPAL = "00000000-0000-4000-8000-000000000001"
AGENT = "00000000-0000-4000-8000-000000000002"
IDENTITY = "00000000-0000-4000-8000-000000000003"
ROUTE = "018f0000-0000-7000-8000-000000000004"
CONNECTOR = "telegram-main"
INSTANCE = "primary"
RUNTIME_A = "runtime-a"
RUNTIME_B = "runtime-b"
MODEL_A = "model-a"
MODEL_B = "model-b"


def router_settings(state_path: Path, *, enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "state_path": str(state_path),
        "worker_profile": "default",
        "tick_seconds": 30,
        "lease_seconds": 900,
        "unbound_policy": "reject",
        "connectors": {
            CONNECTOR: {"profile": "default", "platform": "telegram", "label": "Test"}
        },
        "instances": {
            INSTANCE: {
                "cli_profile": "fake-profile",
                "workspace_id": "workspace-1",
                "base_url": "https://multica.example",
            }
        },
        "agents": {
            "canonical": {
                "instance_id": INSTANCE,
                "agent_id": AGENT,
                "model_by_runtime": {RUNTIME_A: MODEL_A, RUNTIME_B: MODEL_B},
                "allowed_runtime_ids": [RUNTIME_A, RUNTIME_B],
                "allowed_principal_ids": [PRINCIPAL],
            }
        },
        "operators": [{"connector_id": CONNECTOR, "platform_user_id": "operator-1"}],
    }


def source_context(profile: str = "default") -> dict[str, str]:
    return {
        "profile": profile,
        "platform": "telegram",
        "user_id": "user-1",
        "chat_id": "chat-1",
        "thread_id": "thread-1",
        "message_id": "message-1",
    }


def workspace_router_registry() -> dict:
    registry = workspace_registry_payload()
    route = registry["routes"][0]
    route.update(
        {
            "route_id": ROUTE,
            "enabled": True,
            "instance_id": INSTANCE,
            "project_id": "project-1",
            "project_ids": ["project-1"],
            "default_project_id": "project-1",
            "allowed_user_ids": ["user-1"],
            "allowed_chat_ids": ["chat-1"],
            "allowed_thread_ids": ["thread-1"],
            "source_platforms": ["telegram"],
            "runtime_router": {"enabled": True, "agent_ref": "canonical"},
            "allowed_assignees": [{"id": AGENT, "type": "agent", "label": "Canonical"}],
            "default_assignee": {"id": AGENT, "type": "agent"},
        }
    )
    return registry


class FakeAdapter:
    def __init__(
        self, *, runs=None, issue_status="todo", switch_error=None, create_error=None
    ):
        self.runs = runs or []
        self.issue_status = issue_status
        self.switch_error = switch_error
        self.create_error = create_error
        self.created = []
        self.switched = []
        self.current_runtime = RUNTIME_A
        self.issue = None

    def runtime_list(self, _instance):
        return [
            {
                "id": RUNTIME_A,
                "status": "online",
                "accessible": True,
                "models": [MODEL_A],
            },
            {
                "id": RUNTIME_B,
                "status": "online",
                "accessible": True,
                "models": [MODEL_B],
            },
        ]

    def agent_get(self, _instance, agent_id):
        return {
            "id": agent_id,
            "runtime_id": self.current_runtime,
            "model": MODEL_A if self.current_runtime == RUNTIME_A else MODEL_B,
            "max_concurrent_tasks": 1,
        }

    def workspace_list(self, _instance):
        return [{"id": "workspace-1"}]

    def verify_agent_runtime(self, instance, agent_id, runtime_id, model):
        record = self.agent_get(instance, agent_id)
        if record["runtime_id"] != runtime_id or record["model"] != model:
            raise MulticaCliError("runtime_switch_failed", uncertain=True)
        return record

    def switch_runtime(self, _instance, _agent_id, runtime_id, _model):
        if self.switch_error:
            raise self.switch_error
        self.switched.append(runtime_id)
        self.current_runtime = runtime_id
        return self.agent_get(_instance, _agent_id)

    def agent_runs(self, _instance, _agent_id):
        return self.runs

    @staticmethod
    def active_runs(rows):
        return MulticaCliAdapter.active_runs(rows)

    def project_get(self, _instance, project_id):
        return {"id": project_id, "workspace_id": "workspace-1"}

    def find_request_issue(self, _instance, marker, _project_id):
        if self.issue and marker in self.issue["description"]:
            return dict(self.issue)
        return None

    def create_issue(
        self,
        _instance,
        *,
        request_id,
        agent_id,
        project_id,
        title,
        description,
        priority,
        parent_id,
        attachments,
        related_issue_ids,
    ):
        self.created.append(request_id)
        if self.create_error:
            raise self.create_error
        marker = f"<!-- router-request:{request_id} -->"
        self.issue = {
            "id": "issue-1",
            "identifier": "TEST-1",
            "project_id": project_id,
            "workspace_id": "workspace-1",
            "assignee_id": agent_id,
            "description": f"{description}\n{marker}",
            "status": self.issue_status,
            "url": "https://multica.example/issues/TEST-1",
        }
        return dict(self.issue)

    def issue_get(self, _instance, issue_id):
        if self.issue is None or self.issue["id"] != issue_id:
            raise MulticaCliError("issue_not_found")
        self.issue["status"] = self.issue_status
        return dict(self.issue)

    def cancel_issue(self, _instance, issue_id):
        self.issue_status = "cancelled"
        return self.issue_get(_instance, issue_id)


class RuntimeRouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "runtime-router.sqlite3"
        self.raw_config = router_settings(self.db_path)
        self.config = RouterConfig.parse(self.raw_config)

    def tearDown(self):
        self.temp.cleanup()

    def initialized_store(self) -> RouterStore:
        store = RouterStore(self.db_path)
        store.upsert_connector(CONNECTOR, "default", "telegram", "Test")
        store.create_principal(PRINCIPAL, "Example principal")
        store.link_identity(IDENTITY, PRINCIPAL, CONNECTOR, "user-1")
        store.set_binding(
            new_id(), PRINCIPAL, INSTANCE, RUNTIME_A, "strict", None, "operator"
        )
        return store

    def enqueue(
        self,
        store: RouterStore,
        *,
        request_id: str | None = None,
        key: str = "idem-1",
        instance_id: str = INSTANCE,
        agent_id: str = AGENT,
        profile: str = "default",
        route_id: str = ROUTE,
        priority: int = 2,
        runtime_id: str = RUNTIME_A,
        model: str = MODEL_A,
    ) -> tuple[dict, bool]:
        return store.enqueue(
            request_id=request_id or new_id(),
            key=key,
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=instance_id,
            agent_id=agent_id,
            agent_ref="canonical",
            route_id=route_id,
            project_id="project-1",
            payload={
                "source": source_context(profile),
                "title": "Test task",
                "description": "No real work.",
                "route_policy_hash": "a" * 64,
                "attachments": [],
            },
            priority=priority,
            runtime_id=runtime_id,
            model=model,
        )

    def publish_snapshot(self, registry: dict) -> None:
        profiles = self.db_path.parent / "profiles"
        profiles.mkdir(mode=0o700)
        envelope = {
            "profile": "default",
            "runtime_router": self.raw_config,
            "registry": registry,
            "updated_at": int(time.time()),
        }
        path = profiles / "default.json"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        path.chmod(0o600)

    def test_feature_flag_defaults_off_and_enabled_config_requires_topology(self):
        self.assertFalse(RouterConfig.parse({"state_path": str(self.db_path)}).enabled)
        with self.assertRaisesRegex(
            RouterConfigError, "must be shared across Hermes profiles"
        ):
            RouterConfig.parse({"enabled": True})
        with self.assertRaisesRegex(RouterConfigError, "requires connectors"):
            RouterConfig.parse({"enabled": True, "state_path": str(self.db_path)})
        with self.assertRaisesRegex(
            RouterConfigError, "kanban_mirror_projection_unavailable"
        ):
            RouterConfig.parse({"kanban_mirror": True, "state_path": str(self.db_path)})

    def test_invalid_reload_replaces_previous_enabled_profile_snapshot(self):
        valid = RouterConfig.parse(self.raw_config)
        data_root = Path(self.temp.name) / "hermes-plugin-data"
        data_root.mkdir(mode=0o700)
        storage_package = ModuleType("plugins")
        storage_package.__path__ = []
        storage_module = ModuleType("plugins.plugin_storage")
        storage_module.plugin_data_dir = lambda _plugin_name: data_root

        for raw_config in (
            {"enabled": "invalid"},
            None,
        ):
            with self.subTest(raw_config=raw_config):

                class Context:
                    profile_name = "default"

                    def __init__(inner_self):
                        inner_self.tools = {}

                    def get_config(
                        inner_self, key, default=None, _raw_config=raw_config
                    ):
                        if key == "runtime_router":
                            return _raw_config
                        if key == "registry":
                            return workspace_router_registry()
                        return default

                    def register_tool(inner_self, name, handler, **_kwargs):
                        inner_self.tools[name] = handler

                runtime = RuntimeRouterTools(Context())
                with patch.dict(
                    "sys.modules",
                    {
                        "plugins": storage_package,
                        "plugins.plugin_storage": storage_module,
                    },
                ):
                    runtime._snapshot_profile(
                        valid,
                        "default",
                        runtime_config_snapshot=self.raw_config,
                        registry_snapshot=workspace_router_registry(),
                    )
                    old_snapshot = self.db_path.parent / "profiles" / "default.json"
                    self.assertTrue(
                        json.loads(old_snapshot.read_text())["runtime_router"][
                            "enabled"
                        ]
                    )
                    register_tools(runtime.ctx)

                snapshot = json.loads(old_snapshot.read_text())
                self.assertEqual(
                    snapshot["runtime_router"], {"__invalid_configuration__": True}
                )
                self.assertEqual(snapshot["registry"]["routes"], [])
                with self.assertRaisesRegex(
                    RouterConfigError, "router_profile_snapshots_unavailable"
                ):
                    RouterWorker(valid)._profile_snapshots()

    def test_config_rejects_duplicate_canonical_agent_per_instance(self):
        duplicate = dict(self.raw_config)
        duplicate["agents"] = {
            "canonical": self.raw_config["agents"]["canonical"],
            "duplicate": self.raw_config["agents"]["canonical"],
        }
        with self.assertRaisesRegex(RouterConfigError, "registered only once"):
            RouterConfig.parse(duplicate)

    def test_config_rejects_non_https_instance_url(self):
        invalid = json.loads(json.dumps(self.raw_config))
        invalid["instances"][INSTANCE]["base_url"] = "http://multica.example"
        with self.assertRaisesRegex(RouterConfigError, "instance fields"):
            RouterConfig.parse(invalid)

    def test_multica_cli_uses_a_private_router_owned_home(self):
        home = service_cli_home(self.config)
        self.assertEqual(home, self.db_path.parent / "cli-home")
        self.assertEqual(home.stat().st_mode & 0o777, 0o700)
        home.rmdir()
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        home.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RouterConfigError, "router_cli_home_unsafe"):
            service_cli_home(self.config)

    def test_strict_binding_ignores_exception_and_explicit_runtime(self):
        result = resolve_runtime(
            identity={"principal_id": PRINCIPAL, "status": "active"},
            binding={
                "principal_id": PRINCIPAL,
                "instance_id": INSTANCE,
                "default_runtime_id": RUNTIME_A,
                "mode": "strict",
            },
            exceptions=[
                {
                    "exception_id": "rule",
                    "priority": 1,
                    "selectors": {"project_id": "project-1"},
                    "runtime_id": RUNTIME_B,
                }
            ],
            context={"project_id": "project-1"},
            allowed_runtime_ids={RUNTIME_A, RUNTIME_B},
            runtime_catalog={
                RUNTIME_A: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_A],
                },
                RUNTIME_B: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_B],
                },
            },
            model_by_runtime={RUNTIME_A: MODEL_A, RUNTIME_B: MODEL_B},
            explicit_runtime_id=RUNTIME_B,
        )
        self.assertEqual(result.runtime_id, RUNTIME_A)
        self.assertEqual(result.source, "binding")

    def test_exception_priority_then_specificity(self):
        result = resolve_runtime(
            identity={"principal_id": PRINCIPAL, "status": "active"},
            binding={
                "principal_id": PRINCIPAL,
                "instance_id": INSTANCE,
                "default_runtime_id": RUNTIME_A,
                "mode": "exceptions",
            },
            exceptions=[
                {
                    "exception_id": "broad",
                    "priority": 2,
                    "selectors": {"project_id": "project-1"},
                    "runtime_id": RUNTIME_A,
                },
                {
                    "exception_id": "specific",
                    "priority": 2,
                    "selectors": {"project_id": "project-1", "thread_id": "thread-1"},
                    "runtime_id": RUNTIME_B,
                },
            ],
            context={"project_id": "project-1", "thread_id": "thread-1"},
            allowed_runtime_ids={RUNTIME_A, RUNTIME_B},
            runtime_catalog={
                RUNTIME_A: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_A],
                },
                RUNTIME_B: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_B],
                },
            },
            model_by_runtime={RUNTIME_A: MODEL_A, RUNTIME_B: MODEL_B},
        )
        self.assertEqual(result.rule_id, "specific")
        self.assertEqual(result.runtime_id, RUNTIME_B)

    def test_equal_exception_rank_fails_closed(self):
        rules = [
            {
                "exception_id": f"rule-{runtime}",
                "priority": 1,
                "selectors": {"project_id": "project-1"},
                "runtime_id": runtime,
            }
            for runtime in (RUNTIME_A, RUNTIME_B)
        ]
        with self.assertRaisesRegex(ResolutionError, "rule_conflict"):
            resolve_runtime(
                identity={"principal_id": PRINCIPAL, "status": "active"},
                binding={
                    "principal_id": PRINCIPAL,
                    "instance_id": INSTANCE,
                    "default_runtime_id": RUNTIME_A,
                    "mode": "exceptions",
                },
                exceptions=rules,
                context={"project_id": "project-1"},
                allowed_runtime_ids={RUNTIME_A, RUNTIME_B},
                runtime_catalog={
                    RUNTIME_A: {
                        "status": "online",
                        "accessible": True,
                        "models": [MODEL_A],
                    },
                    RUNTIME_B: {
                        "status": "online",
                        "accessible": True,
                        "models": [MODEL_B],
                    },
                },
                model_by_runtime={RUNTIME_A: MODEL_A, RUNTIME_B: MODEL_B},
            )

    def test_unbound_offline_inaccessible_and_unsupported_model_reject(self):
        common = {
            "identity": {"principal_id": PRINCIPAL, "status": "active"},
            "binding": {
                "principal_id": PRINCIPAL,
                "instance_id": INSTANCE,
                "default_runtime_id": RUNTIME_A,
                "mode": "strict",
            },
            "exceptions": [],
            "context": {},
            "allowed_runtime_ids": {RUNTIME_A},
            "runtime_catalog": {
                RUNTIME_A: {"status": "online", "accessible": True, "models": [MODEL_A]}
            },
            "model_by_runtime": {RUNTIME_A: MODEL_A},
        }
        with self.assertRaisesRegex(ResolutionError, "runtime_unbound"):
            resolve_runtime(**{**common, "binding": None})
        for runtime in (
            {"status": "offline", "accessible": True, "models": [MODEL_A]},
            {"status": "online", "accessible": False, "models": [MODEL_A]},
            {"status": "online", "accessible": True, "models": [MODEL_B]},
            {"status": "online", "accessible": True},
        ):
            with self.subTest(runtime=runtime), self.assertRaises(ResolutionError):
                resolve_runtime(**{**common, "runtime_catalog": {RUNTIME_A: runtime}})

    def test_fresh_schema_integrity_and_private_modes(self):
        store = RouterStore(self.db_path)
        result = store.check()
        self.assertEqual(result["schema"], 3)
        self.assertEqual(result["journal_mode"].lower(), "wal")
        self.assertEqual(self.db_path.stat().st_mode & 0o777, 0o600)

    def test_additive_v1_migration_is_transactional_and_idempotent(self):
        RouterStore(self.db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("ALTER TABLE router_requests DROP COLUMN cancel_source_state")
            db.execute("ALTER TABLE router_requests DROP COLUMN reconcile_source_state")
            db.execute("DROP TABLE router_worker_state")
            db.execute("PRAGMA user_version=1")
        migrated = RouterStore(self.db_path)
        self.assertEqual(migrated.check()["schema"], 3)
        self.assertEqual(RouterStore(self.db_path).check()["schema"], 3)

    def test_additive_v2_migration_is_idempotent(self):
        RouterStore(self.db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("ALTER TABLE router_requests DROP COLUMN cancel_source_state")
            db.execute("ALTER TABLE router_requests DROP COLUMN reconcile_source_state")
            db.execute("PRAGMA user_version=2")
        migrated = RouterStore(self.db_path)
        self.assertEqual(migrated.check()["schema"], 3)
        columns = {
            row[1]
            for row in sqlite3.connect(self.db_path).execute(
                "PRAGMA table_info(router_requests)"
            )
        }
        self.assertIn("cancel_source_state", columns)
        self.assertIn("reconcile_source_state", columns)
        self.assertEqual(RouterStore(self.db_path).check()["schema"], 3)

    def test_unknown_schema_is_rejected_without_rewriting_file(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE unknown_schema(value TEXT)")
            db.execute("PRAGMA user_version=91")
        self.db_path.chmod(0o600)
        before = hashlib.sha256(self.db_path.read_bytes()).digest()
        with self.assertRaisesRegex(RouterConfigError, "schema_unsupported"):
            RouterStore(self.db_path)
        self.assertEqual(hashlib.sha256(self.db_path.read_bytes()).digest(), before)

    def test_principal_identity_uniqueness_and_binding_scope(self):
        store = self.initialized_store()
        store.create_principal(
            "00000000-0000-4000-8000-000000000005", "Other principal"
        )
        with self.assertRaisesRegex(RouterConfigError, "identity_conflict"):
            store.link_identity(
                new_id(), "00000000-0000-4000-8000-000000000005", CONNECTOR, "user-1"
            )
        binding = store.binding(PRINCIPAL, INSTANCE)
        self.assertEqual(binding["default_runtime_id"], RUNTIME_A)
        self.assertIsNone(store.binding(PRINCIPAL, "other-instance"))

    def test_exception_selectors_and_expiry_are_persisted(self):
        store = self.initialized_store()
        binding_id = store.binding(PRINCIPAL, INSTANCE)["binding_id"]
        store.add_exception(
            "exception-1",
            binding_id,
            "project rule",
            5,
            {"project_id": "project-1"},
            RUNTIME_B,
            "2027-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            store.exceptions(binding_id)[0]["selectors"], {"project_id": "project-1"}
        )
        store.set_binding(
            binding_id,
            PRINCIPAL,
            INSTANCE,
            RUNTIME_A,
            "exceptions",
            None,
            "operator",
        )
        rules = store.exceptions(binding_id)
        self.assertEqual(rules[0]["enabled"], 1)
        resolved = resolve_runtime(
            identity={"principal_id": PRINCIPAL, "status": "active"},
            binding=store.binding(PRINCIPAL, INSTANCE),
            exceptions=rules,
            context={"project_id": "project-1"},
            allowed_runtime_ids={RUNTIME_A, RUNTIME_B},
            runtime_catalog={
                RUNTIME_A: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_A],
                },
                RUNTIME_B: {
                    "status": "online",
                    "accessible": True,
                    "models": [MODEL_B],
                },
            },
            model_by_runtime={RUNTIME_A: MODEL_A, RUNTIME_B: MODEL_B},
        )
        self.assertEqual(resolved.runtime_id, RUNTIME_B)
        self.assertEqual(resolved.rule_id, "exception-1")
        with self.assertRaisesRegex(RouterConfigError, "exception_name_conflict"):
            store.add_exception(
                "exception-2",
                binding_id,
                "project rule",
                5,
                {"project_id": "project-2"},
                RUNTIME_B,
                None,
            )

    def test_enqueue_is_idempotent_and_payload_changes_conflict(self):
        store = self.initialized_store()
        first, created = self.enqueue(store)
        duplicate, duplicate_created = self.enqueue(store)
        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(first["request_id"], duplicate["request_id"])
        changed_payload = {
            "source": source_context(),
            "title": "Different",
            "description": "No real work.",
            "route_policy_hash": "a" * 64,
            "attachments": [],
        }
        with self.assertRaisesRegex(RouterConfigError, "request_conflict"):
            store.enqueue(
                request_id=new_id(),
                key="idem-1",
                principal_id=PRINCIPAL,
                connector_id=CONNECTOR,
                instance_id=INSTANCE,
                agent_id=AGENT,
                agent_ref="canonical",
                route_id=ROUTE,
                project_id="project-1",
                payload=changed_payload,
                runtime_id=RUNTIME_A,
                model=MODEL_A,
            )

    def test_agent_lock_fences_one_active_and_distinguishes_instances(self):
        store = self.initialized_store()
        first, _ = self.enqueue(store, key="first", priority=4)
        second, _ = self.enqueue(store, key="second", priority=3)
        other, _ = self.enqueue(
            store, key="other-instance", instance_id="secondary", priority=1
        )
        claimed = store.claim_next("worker-1", 900, {"default"})
        self.assertEqual(claimed["request_id"], first["request_id"])
        independent = store.claim_next("worker-2", 900, {"default"})
        self.assertEqual(independent["request_id"], other["request_id"])
        self.assertFalse(
            store.transition(
                first["request_id"], "creating", token="stale", expected={"switching"}
            )
        )
        self.assertEqual(store.get(second["request_id"])["state"], "queued")

    def test_claim_filter_does_not_starve_enabled_profile_after_500_rows(self):
        store = self.initialized_store()
        for index in range(505):
            payload = {
                "source": source_context("disabled-profile"),
                "title": "task",
                "description": "",
                "attachments": [],
            }
            store.enqueue(
                request_id=new_id(),
                key=f"disabled-{index}",
                principal_id=PRINCIPAL,
                connector_id=CONNECTOR,
                instance_id=INSTANCE,
                agent_id=f"agent-{index}",
                agent_ref="canonical",
                route_id=ROUTE,
                project_id="project-1",
                payload=payload,
                priority=1,
            )
        eligible, _ = self.enqueue(store, key="eligible", priority=2)
        claim = store.claim_next("worker", 900, {"default"})
        self.assertEqual(claim["request_id"], eligible["request_id"])

    def test_read_only_diagnostics_do_not_initialize_or_change_database(self):
        store = self.initialized_store()
        self.enqueue(store)
        before = hashlib.sha256(self.db_path.read_bytes()).digest()
        metrics = RouterStore.read_runtime_metrics(self.db_path)
        active = RouterStore.read_active(self.db_path)
        self.assertEqual(metrics["queue_depth"], 1)
        self.assertEqual(active, [])
        self.assertEqual(hashlib.sha256(self.db_path.read_bytes()).digest(), before)

    def test_cli_adapter_uses_fixed_argv_and_cleared_environment(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "agent": {
                            "id": AGENT,
                            "runtime_id": RUNTIME_A,
                            "model": MODEL_A,
                            "max_concurrent_tasks": 1,
                        }
                    }
                ),
            )

        adapter = MulticaCliAdapter(
            binary="/usr/local/bin/multica", home="/private/service-home", runner=runner
        )
        record = adapter.agent_get(self.config.instance(INSTANCE), AGENT)
        argv, options = calls[0]
        self.assertEqual(record["id"], AGENT)
        self.assertEqual(
            argv[:4],
            ["/usr/local/bin/multica", "--profile", "fake-profile", "--workspace-id"],
        )
        self.assertEqual(options["env"]["HOME"], "/private/service-home")
        self.assertNotIn("HTTP_PROXY", options["env"])
        self.assertNotIn("MULTICA_PAT", " ".join(argv))
        self.assertIsNone(options["input"])

    def test_cli_adapter_marks_create_timeout_uncertain(self):
        def runner(_argv, **_kwargs):
            raise __import__("subprocess").TimeoutExpired("multica", 1)

        adapter = MulticaCliAdapter(runner=runner)
        with self.assertRaises(MulticaCliError) as caught:
            adapter.create_issue(
                self.config.instance(INSTANCE),
                request_id=ROUTE,
                agent_id=AGENT,
                project_id="project-1",
                title="Test",
                description="Body",
            )
        self.assertTrue(caught.exception.uncertain)

    def test_cli_adapter_marks_unexpected_successful_create_body_uncertain(self):
        adapter = MulticaCliAdapter(
            runner=lambda _argv, **_kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps({"unexpected": {"id": "issue-1"}})
            )
        )
        adapter.find_request_issue = lambda *_args: None
        with self.assertRaisesRegex(MulticaCliError, "issue_create_unknown") as caught:
            adapter.create_issue(
                self.config.instance(INSTANCE),
                request_id=ROUTE,
                agent_id=AGENT,
                project_id="project-1",
                title="Test",
                description="Body",
            )
        self.assertTrue(caught.exception.uncertain)

    def test_cli_adapter_cancels_issue_without_starting_a_run(self):
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "issue": {
                            "id": "issue-1",
                            "status": "cancelled",
                        }
                    }
                ),
            )

        adapter = MulticaCliAdapter(runner=runner)
        adapter.cancel_issue(self.config.instance(INSTANCE), "issue-1")
        self.assertIn("--no-start", calls[0])
        self.assertTrue(
            any(
                calls[1][index : index + 3] == ["issue", "get", "issue-1"]
                for index in range(len(calls[1]) - 2)
            )
        )

    def test_cli_adapter_rejects_unverified_runtime_and_model_shapes(self):
        def runner(_argv, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {"runtimes": [{"id": RUNTIME_A, "status": "online"}]}
                ),
            )

        adapter = MulticaCliAdapter(runner=runner)
        with self.assertRaisesRegex(MulticaCliError, "invalid_response"):
            adapter.runtime_list(self.config.instance(INSTANCE))

    def test_cli_adapter_stops_child_when_incremental_output_exceeds_limit(self):
        import shlex

        script = self.root / "fake-multica"
        pid_path = self.root / "child.pid"
        child = (
            "import os,sys; "
            f"open({str(pid_path)!r}, 'w').write(str(os.getpid())); "
            "sys.stdout.write('x' * 2097152)"
        )
        script.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(sys.executable)
            + " -c "
            + shlex.quote(child)
            + "\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
        adapter = MulticaCliAdapter(binary=str(script), timeout=5)

        with self.assertRaisesRegex(MulticaCliError, "response_too_large") as caught:
            adapter._call(
                self.config.instance(INSTANCE),
                ["issue", "create"],
                uncertain_on_failure=True,
            )
        self.assertTrue(caught.exception.uncertain)
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_keep_current_unbound_resolution_uses_no_exception_rules(self):
        store = RouterStore(self.db_path)
        store.upsert_connector(CONNECTOR, "default", "telegram", "Test")
        store.create_principal(PRINCIPAL, "Example principal")
        store.link_identity(IDENTITY, PRINCIPAL, CONNECTOR, "user-1")
        store.exceptions = lambda _binding_id: self.fail(  # type: ignore[method-assign]
            "synthetic bindings must not query exceptions"
        )
        registry = registry_from_mapping(workspace_router_registry())
        route = registry.routes[0]
        payload = {
            "source": {"profile": "default", **source_context()},
            "route_policy_hash": route_request_policy_hash(
                route_policy_fingerprint(registry, route), "project-1"
            ),
        }
        request = {
            "connector_id": CONNECTOR,
            "principal_id": PRINCIPAL,
            "agent_ref": "canonical",
            "agent_id": AGENT,
            "instance_id": INSTANCE,
            "project_id": "project-1",
            "target_runtime_id": RUNTIME_A,
            "target_model": MODEL_A,
        }
        worker = RouterWorker(
            replace(self.config, unbound_policy="keep_current"),
            adapter=FakeAdapter(),
        )
        worker.store = store

        resolution = worker._resolution(
            worker.config, request, route, payload, registry
        )

        self.assertEqual(resolution.runtime_id, RUNTIME_A)
        self.assertEqual(resolution.model, MODEL_A)

    def test_create_accepts_keep_current_without_persisted_binding(self):
        store = RouterStore(self.db_path)
        store.upsert_connector(CONNECTOR, "default", "telegram", "Test")
        store.create_principal(PRINCIPAL, "Example principal")
        store.link_identity(IDENTITY, PRINCIPAL, CONNECTOR, "user-1")
        store.exceptions = lambda _binding_id: self.fail(  # type: ignore[method-assign]
            "synthetic bindings must not query exceptions"
        )
        raw_registry = workspace_router_registry()
        registry = registry_from_mapping(raw_registry)
        route = registry.routes[0]
        source = {
            **{key: value for key, value in source_context().items() if key != "profile"},
            "thread_id": "123",
            "chat_type": "thread",
        }
        config = replace(self.config, unbound_policy="keep_current")
        tools = RuntimeRouterTools(SimpleNamespace())
        tools._context = lambda _tool_context=None: (  # type: ignore[method-assign]
            source,
            "default",
            config,
            store,
        )

        with (
            patch("runtime_router.tools.WorkspaceRuntime._registry", return_value=registry),
            patch("runtime_router.tools.WorkspaceRuntime._route", return_value=route),
            patch("runtime_router.tools.MulticaCliAdapter", return_value=FakeAdapter()),
            patch(
                "runtime_router.tools._load_hermes_context",
                return_value=SimpleNamespace(source=source, attachments=[]),
            ),
        ):
            result = json.loads(
                tools.create({"route_id": ROUTE, "title": "Fixture task"})
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(store.get(result["request_id"])["state"], "queued")

    def test_spool_serializes_failed_rollback_against_shared_blob_store(self):
        spool = AttachmentSpool(self.root / "serialized-spool")
        content = b"shared fixture"
        valid = ("note.txt", "text/plain", hashlib.sha256(content).hexdigest(), content)
        invalid = ("broken.txt", "text/plain", "0" * 64, b"invalid")
        first_written = threading.Event()
        allow_failure = threading.Event()
        second_finished = threading.Event()
        results: list[list[dict[str, str | int]]] = []
        failures: list[str] = []

        def failing_attachments():
            yield valid
            first_written.set()
            if not allow_failure.wait(3):
                raise RuntimeError("test synchronization timed out")
            yield invalid

        def failing_store():
            try:
                spool.store(failing_attachments(), maximum_total=1024)
            except RouterConfigError as exc:
                failures.append(str(exc))

        def successful_store():
            results.append(spool.store([valid], maximum_total=1024))
            second_finished.set()

        first = threading.Thread(target=failing_store)
        second = threading.Thread(target=successful_store)
        first.start()
        self.assertTrue(first_written.wait(2))
        second.start()
        self.assertFalse(second_finished.wait(0.05))
        allow_failure.set()
        first.join(3)
        second.join(3)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, ["attachment_invalid"])
        self.assertTrue(second_finished.is_set())
        stored_path = Path(results[0][0]["path"])
        self.assertEqual(hashlib.sha256(stored_path.read_bytes()).hexdigest(), valid[2])

    def test_operator_runtime_selection_and_doctor_require_accessible_online_model(
        self,
    ):
        class InaccessibleAdapter(FakeAdapter):
            def runtime_list(self, instance):
                rows = super().runtime_list(instance)
                rows[0]["accessible"] = False
                return rows

        with self.assertRaisesRegex(RouterConfigError, "runtime_not_accessible"):
            _check_runtime(
                self.config,
                INSTANCE,
                RUNTIME_A,
                PRINCIPAL,
                InaccessibleAdapter(),
            )
        with self.assertRaisesRegex(RouterConfigError, "runtime_not_accessible"):
            _doctor(self.config, InaccessibleAdapter())

        result = _doctor(self.config, FakeAdapter())
        self.assertTrue(result["ok"])
        self.assertFalse(result["state_initialized"])
        self.assertEqual(result["instances"][0]["agents"][0]["model"], MODEL_A)

    def test_cancel_keeps_attachment_referenced_by_another_active_request(self):
        store = self.initialized_store()
        spool = AttachmentSpool(self.root / "runtime-router-spool")
        attachment = spool.store(
            [
                (
                    "note.txt",
                    "text/plain",
                    hashlib.sha256(b"private fixture").hexdigest(),
                    b"private fixture",
                )
            ],
            maximum_total=1024,
        )[0]
        requests = []
        for key in ("shared-attachment-a", "shared-attachment-b"):
            request, _ = store.enqueue(
                request_id=new_id(),
                key=key,
                principal_id=PRINCIPAL,
                connector_id=CONNECTOR,
                instance_id=INSTANCE,
                agent_id=AGENT,
                agent_ref="canonical",
                route_id=ROUTE,
                project_id="project-1",
                payload={
                    "source": source_context(),
                    "title": "Fixture",
                    "description": "No real work.",
                    "attachments": [attachment],
                },
                runtime_id=RUNTIME_A,
                model=MODEL_A,
            )
            requests.append(request)
        tools = RuntimeRouterTools(SimpleNamespace())
        tools._context = lambda _tool_context=None: (  # type: ignore[method-assign]
            source_context(),
            "default",
            self.config,
            store,
        )

        result = json.loads(tools.cancel({"request_id": requests[0]["request_id"]}))
        self.assertEqual(result["state"], "cancelled")
        self.assertTrue(Path(attachment["path"]).exists())
        second = json.loads(tools.cancel({"request_id": requests[1]["request_id"]}))
        self.assertEqual(second["state"], "cancelled")
        self.assertFalse(Path(attachment["path"]).exists())

    def test_worker_creates_once_then_releases_after_terminal_readback(self):
        store = self.initialized_store()
        registry = workspace_router_registry()
        parsed_registry = registry_from_mapping(registry)
        route = parsed_registry.routes[0]
        route_hash = route_request_policy_hash(
            route_policy_fingerprint(parsed_registry, route), "project-1"
        )
        payload = {
            "source": source_context(),
            "title": "No real work",
            "description": "Fixture request",
            "route_policy_hash": route_hash,
            "priority": "medium",
            "attachments": [],
            "related_issue_ids": [],
        }
        request, _ = store.enqueue(
            request_id=new_id(),
            key="worker-idem",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload=payload,
            runtime_id=RUNTIME_A,
            model=MODEL_A,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter()
        worker = RouterWorker(self.config, adapter=adapter, owner="test-worker")
        created = worker.tick()
        self.assertEqual(created["state"], "waiting")
        self.assertEqual(adapter.created, [request["request_id"]])
        self.assertEqual(store.get(request["request_id"])["state"], "waiting")
        adapter.issue_status = "done"
        completed = worker.tick()
        self.assertEqual(completed["processed"], 1)
        self.assertEqual(store.get(request["request_id"])["state"], "done")
        self.assertEqual(adapter.created, [request["request_id"]])

    def test_waiting_issue_canceled_status_is_terminal_and_cleans_attachments(self):
        store = self.initialized_store()
        spool = AttachmentSpool(self.root / "runtime-router-spool")
        attachment = spool.store(
            [
                (
                    "note.txt",
                    "text/plain",
                    hashlib.sha256(b"terminal fixture").hexdigest(),
                    b"terminal fixture",
                )
            ],
            maximum_total=1024,
        )[0]
        registry = workspace_router_registry()
        parsed_registry = registry_from_mapping(registry)
        route = parsed_registry.routes[0]
        payload = {
            "source": source_context(),
            "title": "No real work",
            "description": "Fixture request",
            "route_policy_hash": route_request_policy_hash(
                route_policy_fingerprint(parsed_registry, route), "project-1"
            ),
            "priority": "medium",
            "attachments": [attachment],
            "related_issue_ids": [],
        }
        request, _ = store.enqueue(
            request_id=new_id(),
            key="worker-canceled-status",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload=payload,
            runtime_id=RUNTIME_A,
            model=MODEL_A,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter()
        worker = RouterWorker(self.config, adapter=adapter, owner="test-worker")

        created = worker.tick()
        self.assertEqual(created["state"], "waiting")
        adapter.issue_status = "canceled"
        completed = worker.tick()

        self.assertEqual(completed["processed"], 1)
        self.assertEqual(store.get(request["request_id"])["state"], "cancelled")
        self.assertFalse(Path(attachment["path"]).exists())
        self.assertEqual(adapter.created, [request["request_id"]])

    def test_worker_does_not_switch_or_create_while_agent_has_active_run(self):
        store = self.initialized_store()
        registry = workspace_router_registry()
        parsed = registry_from_mapping(registry)
        payload = {
            "source": source_context(),
            "title": "Task",
            "description": "",
            "route_policy_hash": route_request_policy_hash(
                route_policy_fingerprint(parsed, parsed.routes[0]), "project-1"
            ),
            "attachments": [],
        }
        request, _ = store.enqueue(
            request_id=new_id(),
            key="busy",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload=payload,
            runtime_id=RUNTIME_A,
            model=MODEL_A,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter(runs=[{"status": "running"}])
        result = RouterWorker(self.config, adapter=adapter).tick()
        self.assertTrue(result["queued"])
        self.assertEqual(store.get(request["request_id"])["state"], "queued")
        self.assertEqual(adapter.created, [])
        self.assertEqual(adapter.switched, [])

    def test_worker_never_retries_uncertain_issue_creation(self):
        store = self.initialized_store()
        registry = workspace_router_registry()
        parsed = registry_from_mapping(registry)
        payload = {
            "source": source_context(),
            "title": "Task",
            "description": "",
            "route_policy_hash": route_request_policy_hash(
                route_policy_fingerprint(parsed, parsed.routes[0]), "project-1"
            ),
            "attachments": [],
        }
        request, _ = store.enqueue(
            request_id=new_id(),
            key="uncertain",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload=payload,
            runtime_id=RUNTIME_A,
            model=MODEL_A,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter(
            create_error=MulticaCliError("issue_create_unknown", uncertain=True)
        )
        worker = RouterWorker(self.config, adapter=adapter)
        first = worker.tick()
        self.assertEqual(first["state"], "reconciling")
        self.assertEqual(store.get(request["request_id"])["state"], "reconciling")
        worker.tick()
        self.assertEqual(adapter.created, [request["request_id"]])

    def test_disabled_feature_flag_does_not_reconcile_or_call_multica(self):
        store = self.initialized_store()
        request, _ = self.enqueue(store, key="disabled-waiting")
        claimed = store.claim_next("test-worker", 900, {"default"})
        self.assertIsNotNone(claimed)
        token = claimed["lease_token"]
        self.assertTrue(
            store.transition(
                request["request_id"],
                "creating",
                token=token,
                expected={"switching"},
            )
        )
        self.assertTrue(
            store.transition(
                request["request_id"],
                "waiting",
                token=token,
                expected={"creating"},
                issue={"id": "issue-1", "url": "https://multica.example/issues/1"},
            )
        )
        registry = workspace_router_registry()
        self.raw_config["enabled"] = False
        self.publish_snapshot(registry)
        adapter = FakeAdapter()
        adapter.issue_get = lambda *_args: self.fail(
            "disabled router must not read or mutate Multica"
        )
        adapter.agent_runs = lambda *_args: self.fail(
            "disabled router must not inspect Multica runs"
        )
        result = RouterWorker(self.config, adapter=adapter).tick()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["processed"], 0)
        self.assertEqual(store.get(request["request_id"])["state"], "waiting")
        self.assertEqual(adapter.created, [])

    def test_cancel_after_uncertain_create_keeps_lock_until_issue_reconciliation(self):
        store = self.initialized_store()
        registry = workspace_router_registry()
        parsed = registry_from_mapping(registry)
        request, _ = store.enqueue(
            request_id=new_id(),
            key="uncertain-cancel",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload={
                "source": source_context(),
                "title": "Task",
                "description": "",
                "route_policy_hash": route_request_policy_hash(
                    route_policy_fingerprint(parsed, parsed.routes[0]), "project-1"
                ),
                "attachments": [],
            },
            runtime_id=RUNTIME_A,
            model=MODEL_A,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter(
            create_error=MulticaCliError("issue_create_unknown", uncertain=True)
        )
        worker = RouterWorker(self.config, adapter=adapter)
        self.assertEqual(worker.tick()["state"], "reconciling")
        self.assertEqual(store.cancel(request["request_id"]), "reconciling")
        row = store.get(request["request_id"])
        self.assertEqual(row["cancel_source_state"], "creating")
        self.assertEqual(row["reconcile_source_state"], "creating")

        self.enqueue(store, key="behind-uncertain-create")
        worker.tick()
        self.assertEqual(store.get(request["request_id"])["state"], "reconciling")
        self.assertEqual(adapter.created, [request["request_id"]])
        marker = f"<!-- router-request:{request['request_id']} -->"
        adapter.issue = {
            "id": "issue-1",
            "identifier": "TEST-1",
            "project_id": "project-1",
            "workspace_id": "workspace-1",
            "assignee_id": AGENT,
            "description": marker,
            "status": "todo",
            "url": "https://multica.example/issues/TEST-1",
        }
        adapter.issue_status = "todo"
        worker.tick()
        self.assertEqual(store.get(request["request_id"])["state"], "cancelling")
        worker.tick()
        self.assertEqual(store.get(request["request_id"])["state"], "cancelled")
        self.assertEqual(adapter.created, [request["request_id"]])

    def test_uncertain_runtime_switch_reconciles_then_requeues_without_issue_duplicate(
        self,
    ):
        store = self.initialized_store()
        binding = store.binding(PRINCIPAL, INSTANCE)
        store.set_binding(
            binding["binding_id"],
            PRINCIPAL,
            INSTANCE,
            RUNTIME_B,
            "strict",
            None,
            "operator",
        )
        registry = workspace_router_registry()
        parsed = registry_from_mapping(registry)
        request, _ = store.enqueue(
            request_id=new_id(),
            key="uncertain-switch",
            principal_id=PRINCIPAL,
            connector_id=CONNECTOR,
            instance_id=INSTANCE,
            agent_id=AGENT,
            agent_ref="canonical",
            route_id=ROUTE,
            project_id="project-1",
            payload={
                "source": source_context(),
                "title": "Task",
                "description": "",
                "route_policy_hash": route_request_policy_hash(
                    route_policy_fingerprint(parsed, parsed.routes[0]), "project-1"
                ),
                "attachments": [],
            },
            runtime_id=RUNTIME_B,
            model=MODEL_B,
        )
        self.publish_snapshot(registry)
        adapter = FakeAdapter(
            switch_error=MulticaCliError("runtime_switch_unknown", uncertain=True)
        )

        def switch_then_lose_response(_instance, _agent_id, runtime_id, _model):
            adapter.current_runtime = runtime_id
            raise adapter.switch_error

        adapter.switch_runtime = switch_then_lose_response
        worker = RouterWorker(self.config, adapter=adapter)
        first = worker.tick()
        self.assertEqual(first["state"], "reconciling", first)
        self.assertEqual(
            store.get(request["request_id"])["reconcile_source_state"], "switching"
        )

        result = worker.tick()

        self.assertEqual(result["state"], "waiting")
        self.assertEqual(store.get(request["request_id"])["state"], "waiting")
        self.assertEqual(adapter.created, [request["request_id"]])
        self.assertEqual(adapter.current_runtime, RUNTIME_B)

    def test_legacy_cancelled_switch_reconciliation_keeps_agent_locked(self):
        store = self.initialized_store()
        request, _ = self.enqueue(store, key="legacy-switch-cancel")
        claimed = store.claim_next("worker", 900, {"default"})
        self.assertIsNotNone(claimed)
        self.assertTrue(
            store.transition(
                request["request_id"],
                "reconciling",
                token=claimed["lease_token"],
                expected={"switching"},
                error="lease_expired:switching",
            )
        )
        with store.connect() as db:
            db.execute(
                "UPDATE router_requests SET reconcile_source_state=NULL WHERE request_id=?",
                (request["request_id"],),
            )
        self.assertEqual(store.cancel(request["request_id"]), "reconciling")
        self.publish_snapshot(workspace_router_registry())

        worker = RouterWorker(self.config, adapter=FakeAdapter())
        worker.tick()

        row = store.get(request["request_id"])
        self.assertEqual(row["state"], "reconciling")
        self.assertEqual(row["cancel_source_state"], "reconciling")
        self.assertIsNotNone(row["lease_token"])


if __name__ == "__main__":
    unittest.main()
