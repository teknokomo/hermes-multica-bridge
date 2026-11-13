from __future__ import annotations

import concurrent.futures
import copy
import importlib.util
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from bridge.errors import BridgeError
from bridge.registry import new_id, registry_from_mapping, route_policy_fingerprint
from tests.helpers import isolated_bridge_config, standard_connection
from tests.test_registry import registry_payload, workspace_registry_payload


def _load_plugin_api():
    fake_fastapi = types.ModuleType("fastapi")

    class APIRouter:
        def get(self, *_args, **_kwargs):
            return lambda function: function

        def put(self, *_args, **_kwargs):
            return lambda function: function

        def post(self, *_args, **_kwargs):
            return lambda function: function

    class HTTPException(Exception):
        def __init__(self, *, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    fake_fastapi.APIRouter = APIRouter
    fake_fastapi.Body = lambda *args, **kwargs: None
    fake_fastapi.HTTPException = HTTPException

    path = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location(
        "test_dashboard_plugin_api_module", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"fastapi": fake_fastapi}):
        spec.loader.exec_module(module)
    return module


PLUGIN_API = _load_plugin_api()


class DashboardPluginApiTests(unittest.TestCase):
    def test_dynamic_route_approval_uses_profile_store_and_checks_credential_anchor(self) -> None:
        raw = workspace_registry_payload()
        anchor = raw["routes"][0]
        workspace = raw["workspaces"][0]
        connection = raw["connections"][0]
        grant_id = new_id()
        raw["route_grants"] = [{
            "grant_id": grant_id,
            "profile": "default",
            "connection_id": connection["connection_id"],
            "workspace_key": workspace["workspace_key"],
            "workspace_id": workspace["workspace_id"],
            "allowed_project_ids": ["project-1"],
            "allowed_squad_ids": [],
            "allow_all_projects": False,
            "allowed_source_platforms": ["telegram"],
            "allowed_chat_ids": ["chat-1"],
            "allowed_thread_ids": [],
            "allowed_user_ids": ["user-1"],
            "allowed_assignees": [
                {"id": item["id"], "type": item["type"]}
                for item in anchor["allowed_assignees"]
            ],
            "credential_route_id": anchor["route_id"],
            "max_routes": 2,
            "auto_approve": False,
            "expires_at": "2030-01-01T00:00:00Z",
            "enabled": True,
        }]
        dynamic = copy.deepcopy(anchor)
        dynamic_id = new_id()
        dynamic.update({
            "route_id": dynamic_id,
            "name": "Pending dynamic route",
            "enabled": False,
            "watcher_enabled": False,
            "wake_mode": "completion",
            "source_platforms": ["telegram"],
            "grant_id": grant_id,
            "credential_route_id": anchor["route_id"],
            "dynamic_status": "pending",
            "created_by_profile": "default",
        })
        store = Mock()
        store.get.return_value = dynamic
        store.list.return_value = [dynamic]
        anchor["enabled"] = False
        storage_path = Path("dashboard-plugin-data/deliveries.sqlite3")
        with (
            patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": raw}]),
            patch.object(PLUGIN_API, "_storage_path", return_value=storage_path),
            patch.object(PLUGIN_API, "DynamicRouteStore", return_value=store) as store_factory,
            patch.object(PLUGIN_API, "_route_secret_presence", return_value={"multica_pat": True}),
        ):
            secrets = Mock(multica_pat="fake-pat")
            api = Mock()
            with (
                patch.object(PLUGIN_API, "standard_route_secrets", return_value=secrets),
                patch.object(PLUGIN_API, "WorkspaceApiClient", return_value=api),
            ):
                api.get_project.return_value = {"workspace_id": "foreign-workspace"}
                with self.assertRaises(PLUGIN_API.HTTPException):
                    PLUGIN_API._review_dynamic_route(dynamic_id, approve=True)
                store.set_status.assert_not_called()
                api.get_project.side_effect = BridgeError("api_unavailable", "Unavailable")
                with self.assertRaises(PLUGIN_API.HTTPException):
                    PLUGIN_API._review_dynamic_route(dynamic_id, approve=True)
                store.set_status.assert_not_called()
                api.get_project.side_effect = None
                api.get_project.return_value = {"workspace_id": workspace["workspace_id"]}
                result = PLUGIN_API._review_dynamic_route(dynamic_id, approve=True)

        self.assertEqual(result, {"ok": True, "route_id": dynamic_id, "status": "active", "changed": True})
        self.assertEqual(store_factory.call_count, 3)
        store.set_status.assert_called_once_with(dynamic_id, "default", "active")

    def test_dynamic_route_approval_rejects_tombstoned_anchor(self) -> None:
        for field, value in (("tombstoned", True),):
            with self.subTest(field=field):
                raw = workspace_registry_payload()
                anchor = raw["routes"][0]
                anchor[field] = value
                if field == "tombstoned":
                    anchor["enabled"] = False
                workspace = raw["workspaces"][0]
                connection = raw["connections"][0]
                grant_id = new_id()
                raw["route_grants"] = [{
                    "grant_id": grant_id, "profile": "default",
                    "connection_id": connection["connection_id"],
                    "workspace_key": workspace["workspace_key"],
                    "workspace_id": workspace["workspace_id"],
                    "allowed_project_ids": ["project-1"], "allowed_squad_ids": [],
                    "allow_all_projects": False, "allowed_source_platforms": anchor["source_platforms"],
                    "allowed_chat_ids": anchor["allowed_chat_ids"],
                    "allowed_thread_ids": anchor.get("allowed_thread_ids", []),
                    "allowed_user_ids": anchor["allowed_user_ids"],
                    "allowed_assignees": [{"id": item["id"], "type": item["type"]}
                                           for item in anchor["allowed_assignees"]],
                    "credential_route_id": anchor["route_id"], "max_routes": 2,
                    "auto_approve": False, "expires_at": "2030-01-01T00:00:00Z", "enabled": True,
                }]
                dynamic = copy.deepcopy(anchor)
                dynamic_id = new_id()
                dynamic.update({
                    "route_id": dynamic_id, "name": "Pending dynamic", "enabled": False,
                    "tombstoned": False, "watcher_enabled": False, "wake_mode": "completion",
                    "grant_id": grant_id, "credential_route_id": anchor["route_id"],
                    "dynamic_status": "pending", "created_by_profile": "default",
                })
                store = Mock()
                store.get.return_value = dynamic
                store.list.return_value = [dynamic]
                with (
                    patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": raw}]),
                    patch.object(PLUGIN_API, "_storage_path", return_value=Path("fake/deliveries.sqlite3")),
                    patch.object(PLUGIN_API, "DynamicRouteStore", return_value=store),
                    patch.object(PLUGIN_API, "_route_secret_presence", return_value={"multica_pat": True}) as secret_check,
                    self.assertRaises(PLUGIN_API.HTTPException) as raised,
                ):
                    PLUGIN_API._review_dynamic_route(dynamic_id, approve=True)
                self.assertEqual(raised.exception.status_code, 400)
                self.assertIn("credential", raised.exception.detail)
                secret_check.assert_not_called()

    def test_reject_dynamic_route_succeeds_after_its_grant_was_removed(self) -> None:
        raw = workspace_registry_payload()
        dynamic = copy.deepcopy(raw["routes"][0])
        dynamic_id = new_id()
        dynamic.update({
            "route_id": dynamic_id,
            "name": "Orphaned dynamic route",
            "enabled": True,
            "watcher_enabled": False,
            "wake_mode": "completion",
            "grant_id": new_id(),
            "credential_route_id": raw["routes"][0]["route_id"],
            "dynamic_status": "active",
            "created_by_profile": "default",
        })
        store = Mock()
        store.get.return_value = dynamic
        with (
            patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": raw}]),
            patch.object(PLUGIN_API, "_storage_path", return_value=Path("fake/deliveries.sqlite3")),
            patch.object(PLUGIN_API, "DynamicRouteStore", return_value=store),
        ):
            result = PLUGIN_API._review_dynamic_route(dynamic_id, approve=False)

        self.assertEqual(result, {"ok": True, "route_id": dynamic_id, "status": "revoked", "changed": True})
        store.set_status.assert_called_once_with(dynamic_id, "default", "revoked")

    def test_completion_readiness_is_checked_in_ipc_sized_batches(self) -> None:
        raw = workspace_registry_payload()
        route = raw["routes"][0]
        project_ids = [f"project-{index}" for index in range(PLUGIN_API.MAX_PROJECTS + 1)]
        route.update({
            "scope_kind": "workspace",
            "project_selection": "allowlist",
            "project_ids": project_ids,
            "project_id": project_ids[0],
            "default_project_id": project_ids[0],
            "wake_mode": "completion",
            "watcher_enabled": False,
        })
        registry = registry_from_mapping(raw)
        client = Mock()
        client.check.side_effect = lambda profile, projects: [
            {"project_id": item["project_id"], "wake_ready": True, "reason": "ready", "wake_route_id": "wake"}
            for item in projects
        ]
        with (
            patch.object(PLUGIN_API, "NotifyReadinessClient", return_value=client),
            patch.object(PLUGIN_API, "_route_secret_presence", return_value={"multica_pat": True}),
        ):
            result = PLUGIN_API._route_status(registry, registry.routes[0])

        self.assertTrue(result["wake_ready"])
        self.assertEqual([len(call.args[1]) for call in client.check.call_args_list], [PLUGIN_API.MAX_PROJECTS, 1])
        self.assertEqual([item["project_id"] for item in result["projects_readiness"]], project_ids)

    def test_registry_update_rejects_grant_edits_that_orphan_existing_dynamic_routes(self) -> None:
        current = workspace_registry_payload()
        anchor = current["routes"][0]
        workspace = current["workspaces"][0]
        connection = current["connections"][0]
        grant_id = new_id()
        current["route_grants"] = [{
            "grant_id": grant_id, "profile": "default",
            "connection_id": connection["connection_id"],
            "workspace_key": workspace["workspace_key"], "workspace_id": workspace["workspace_id"],
            "allowed_project_ids": ["project-1"], "allowed_squad_ids": [],
            "allow_all_projects": False, "allowed_source_platforms": anchor["source_platforms"],
            "allowed_chat_ids": anchor["allowed_chat_ids"],
            "allowed_thread_ids": anchor.get("allowed_thread_ids", []),
            "allowed_user_ids": anchor["allowed_user_ids"],
            "allowed_assignees": [{"id": item["id"], "type": item["type"]}
                                   for item in anchor["allowed_assignees"]],
            "credential_route_id": anchor["route_id"], "max_routes": 2,
            "auto_approve": False, "expires_at": "2030-01-01T00:00:00Z", "enabled": True,
        }]
        dynamic = copy.deepcopy(anchor)
        dynamic.update({
            "route_id": new_id(), "name": "Existing dynamic", "enabled": True,
            "watcher_enabled": False, "wake_mode": "completion", "dynamic_status": "active",
            "grant_id": grant_id, "credential_route_id": anchor["route_id"],
            "created_by_profile": "default",
        })
        requested = copy.deepcopy(current)
        requested["route_grants"][0]["allowed_project_ids"] = []
        store = Mock()
        store.list_all.return_value = [dynamic]
        with tempfile.TemporaryDirectory() as temp:
            storage_dir = Path(temp) / "dashboard-plugin-data"
            storage_dir.mkdir(mode=0o700)
            storage = storage_dir / "deliveries.sqlite3"
            dynamic_store_path = storage_dir / "dynamic-routes.sqlite3"
            dynamic_store_path.touch(mode=0o600)
            dynamic_store_path.chmod(0o600)
            settings = Mock()

            with (
                patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": current}]),
                patch.object(PLUGIN_API, "_storage_path", return_value=storage),
                patch.object(PLUGIN_API, "DynamicRouteStore", return_value=store),
                patch.object(PLUGIN_API, "_settings_module", return_value=settings),
                patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
                self.assertRaises(PLUGIN_API.HTTPException) as raised,
            ):
                PLUGIN_API.update_registry({"registry": requested})

            self.assertEqual(raised.exception.status_code, 400)
            self.assertIn("Revoke or update", raised.exception.detail)
            settings.save_plugin_settings.assert_not_called()

    def test_status_does_not_create_dynamic_state_when_no_dynamic_routes_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            storage_path = Path(temp) / "never-created" / "deliveries.sqlite3"
            registry = {"connections": [], "workspaces": [], "routes": [], "operator_grants": [], "route_grants": []}
            with (
                patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": registry}]),
                patch.object(PLUGIN_API, "_storage_path", return_value=storage_path),
            ):
                result = PLUGIN_API.status()
            self.assertTrue(result["ok"])
            self.assertEqual(result["counts"]["dynamic_routes"], 0)
            self.assertFalse(storage_path.parent.exists())

    def test_disabled_but_complete_connection_can_be_pre_enable_ready(self) -> None:
        connection = standard_connection(enabled=False)
        errors = PLUGIN_API._enable_readiness(
            connection,
            {
                "webhook_url": True,
                "hmac_signing_secret": True,
                "multica_pat": True,
            },
        )
        self.assertNotIn("disabled", errors)
        self.assertEqual(errors, ())

    def test_route_status_uses_effective_connection_enablement(self) -> None:
        payload = registry_payload(route_count=1)
        payload["connections"][0]["enabled"] = False
        registry = registry_from_mapping(payload)
        route = registry.routes[0]
        with (
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={
                    "webhook_url": True,
                    "hmac_signing_secret": True,
                    "multica_pat": True,
                },
            ),
            patch.object(PLUGIN_API, "_latest_delivery", return_value=None),
        ):
            row = PLUGIN_API._route_status(registry, route)
        self.assertTrue(row["configured"])
        self.assertFalse(row["enabled"])

    def test_route_status_reports_route_enablement_with_shared_connection(self) -> None:
        payload = registry_payload(route_count=2)
        payload["routes"][1]["enabled"] = False
        registry = registry_from_mapping(payload)
        with (
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={
                    "webhook_url": True,
                    "hmac_signing_secret": True,
                    "multica_pat": True,
                },
            ),
            patch.object(PLUGIN_API, "_latest_delivery", return_value=None),
        ):
            enabled = PLUGIN_API._route_status(registry, registry.routes[0])
            disabled = PLUGIN_API._route_status(registry, registry.routes[1])

        self.assertTrue(enabled["enabled"])
        self.assertFalse(disabled["enabled"])

    def test_tombstoned_route_is_reported_as_effectively_disabled(self) -> None:
        payload = registry_payload(route_count=1)
        payload["routes"][0]["enabled"] = False
        payload["routes"][0]["tombstoned"] = True
        registry = registry_from_mapping(payload)
        with (
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={"webhook_url": True, "hmac_signing_secret": True, "multica_pat": True},
            ),
            patch.object(PLUGIN_API, "_latest_delivery", return_value=None),
        ):
            row = PLUGIN_API._route_status(registry, registry.routes[0])

        self.assertFalse(row["enabled"])
        self.assertTrue(row["tombstoned"])

    def test_workspace_missing_pat_is_not_reported_as_configured(self) -> None:
        registry = registry_from_mapping(workspace_registry_payload())
        secrets = types.SimpleNamespace(webhook_url="", hmac_signing_secret=None, multica_pat=None)
        with (
            patch.object(PLUGIN_API, "standard_route_secrets", return_value=secrets),
            patch("bridge.watcher_ipc.WatcherIpcClient") as watcher_client,
        ):
            watcher_client.return_value.readiness.return_value = {"ready": True}
            row = PLUGIN_API._route_status(registry, registry.routes[0])

        self.assertFalse(row["configured"])
        self.assertFalse(row["secrets"]["multica_pat"])
        self.assertIn("multica_pat", row["readiness_errors"])

    def test_workspace_status_reports_normalized_typed_assignees_and_legacy_warning(self) -> None:
        payload = workspace_registry_payload()
        payload["routes"][0]["allowed_assignees"] = [payload["routes"][0]["default_assignee"]["id"]]
        registry = registry_from_mapping(payload)
        with (
            patch.object(PLUGIN_API, "standard_route_secrets", return_value=types.SimpleNamespace(
                webhook_url="", hmac_signing_secret=None, multica_pat="fake-pat",
            )),
            patch("bridge.watcher_ipc.WatcherIpcClient") as watcher_client,
        ):
            watcher_client.return_value.readiness.return_value = {"ready": True}
            row = PLUGIN_API._route_status(registry, registry.routes[0])
        self.assertEqual(row["assignees"][0]["type"], "member")
        self.assertTrue(row["assignees"][0]["default"])
        self.assertTrue(row["require_assignee"])
        self.assertFalse(row["test"])
        self.assertEqual(row["warnings"], ["legacy_assignee_entry"])

    def test_registry_update_uses_workspace_readiness_contract(self) -> None:
        current = workspace_registry_payload()
        current["routes"][0]["enabled"] = False
        current["routes"][0]["destination_locked"] = False
        requested = copy.deepcopy(current)
        requested["routes"][0]["enabled"] = True
        fields = [{"key": "registry", "type": "json", "value": current}]
        settings = Mock()
        settings.save_plugin_settings.return_value = ["registry"]

        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={"webhook_url": False, "hmac_signing_secret": False, "multica_pat": True},
            ),
            patch("bridge.watcher_ipc.WatcherIpcClient") as watcher_client,
        ):
            watcher_client.return_value.readiness.return_value = {"ready": True}
            result = PLUGIN_API.update_registry({"registry": requested})

        self.assertTrue(result["ok"])
        self.assertTrue(result["registry"]["routes"][0]["enabled"])
        self.assertTrue(result["registry"]["routes"][0]["destination_locked"])
        self.assertEqual(
            result["registry"]["routes"][0]["allowed_assignees"],
            requested["routes"][0]["allowed_assignees"],
        )
        self.assertEqual(
            result["registry"]["routes"][0]["default_assignee"],
            requested["routes"][0]["default_assignee"],
        )

    def test_registry_update_rejects_workspace_route_when_workspace_readiness_fails(self) -> None:
        current = workspace_registry_payload()
        current["routes"][0]["enabled"] = False
        current["routes"][0]["destination_locked"] = False
        requested = copy.deepcopy(current)
        requested["routes"][0]["enabled"] = True
        fields = [{"key": "registry", "type": "json", "value": current}]
        settings = Mock()
        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={"webhook_url": False, "hmac_signing_secret": False, "multica_pat": False},
            ),
            patch("bridge.watcher_ipc.WatcherIpcClient") as watcher_client,
        ):
            watcher_client.return_value.readiness.return_value = {"ready": True}
            with self.assertRaises(PLUGIN_API.HTTPException) as raised:
                PLUGIN_API.update_registry({"registry": requested})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("multica_pat", raised.exception.detail)
        settings.save_plugin_settings.assert_not_called()

    def test_completion_readiness_failure_blocks_route_activation(self) -> None:
        current = workspace_registry_payload()
        current["routes"][0].update(enabled=False, destination_locked=False,
                                    wake_mode="completion", watcher_enabled=False)
        requested = copy.deepcopy(current)
        requested["routes"][0]["enabled"] = True
        settings = Mock()
        with (
            patch.object(PLUGIN_API, "_fields", return_value=[{"key": "registry", "value": current}]),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
            patch.object(PLUGIN_API, "_route_secret_presence", return_value={"multica_pat": True}),
            patch.object(PLUGIN_API.NotifyReadinessClient, "check",
                         side_effect=BridgeError("source_unavailable", "notify unavailable")),
            self.assertRaises(PLUGIN_API.HTTPException) as raised,
        ):
            PLUGIN_API.update_registry({"registry": requested})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("wake_readiness_unavailable", raised.exception.detail)
        settings.save_plugin_settings.assert_not_called()

    def test_isolated_sender_status_requires_live_matching_sender_policy(self) -> None:
        registry = registry_from_mapping(registry_payload(route_count=1, security_mode="isolated"))
        route = registry.routes[0]
        connection = registry.route_config(route)
        expected_route_policy = route_policy_fingerprint(registry, route)

        class ReadyClient:
            def __init__(self, socket_path: str, timeout: float):
                self.socket_path = socket_path
                self.timeout = timeout

            def readiness(self):
                return {
                    "ok": True,
                    "ready": True,
                    "policy_fingerprint": connection.policy_fingerprint,
                    "route_policy_fingerprint": expected_route_policy,
                }

        with (
            patch.object(PLUGIN_API, "_socket_available", return_value=True),
            patch.object(PLUGIN_API, "BridgeIpcClient", ReadyClient),
        ):
            status = PLUGIN_API._isolated_sender_status(connection, expected_route_policy)
        self.assertTrue(status["socket_available"])
        self.assertTrue(status["sender_ready"])
        self.assertIsNone(status["error_code"])

        class MismatchedClient(ReadyClient):
            def readiness(self):
                return {
                    "ok": True,
                    "ready": True,
                    "policy_fingerprint": "policy-other",
                    "route_policy_fingerprint": expected_route_policy,
                }

        with (
            patch.object(PLUGIN_API, "_socket_available", return_value=True),
            patch.object(PLUGIN_API, "BridgeIpcClient", MismatchedClient),
        ):
            mismatch = PLUGIN_API._isolated_sender_status(connection, expected_route_policy)
        self.assertFalse(mismatch["sender_ready"])
        self.assertEqual(mismatch["error_code"], "isolated_policy")

        class StaleRoutePolicyClient(ReadyClient):
            def readiness(self):
                return {
                    "ok": True,
                    "ready": True,
                    "policy_fingerprint": connection.policy_fingerprint,
                    "route_policy_fingerprint": "route-policy-stale",
                }

        with (
            patch.object(PLUGIN_API, "_socket_available", return_value=True),
            patch.object(PLUGIN_API, "BridgeIpcClient", StaleRoutePolicyClient),
        ):
            stale_route = PLUGIN_API._isolated_sender_status(connection, expected_route_policy)
            stale_route_status = PLUGIN_API._route_status(registry, route)
        self.assertFalse(stale_route["sender_ready"])
        self.assertEqual(stale_route["error_code"], "isolated_policy")
        self.assertFalse(stale_route_status["configured"])
        self.assertIn("isolated_policy", stale_route_status["readiness_errors"])

    def test_isolated_enable_readiness_does_not_treat_socket_presence_as_ready(
        self,
    ) -> None:
        connection = isolated_bridge_config().connection
        errors = PLUGIN_API._enable_readiness(
            connection,
            {},
            isolated_status={
                "socket_available": True,
                "sender_ready": False,
                "error_code": "credential_invalid",
            },
        )
        self.assertIn("credential_invalid", errors)

        missing_probe = PLUGIN_API._enable_readiness(connection, {})
        self.assertIn("isolated_policy", missing_probe)

    def test_isolated_instructions_include_complete_route_identity(self) -> None:
        raw = registry_payload(route_count=1, security_mode="isolated")
        raw["connections"][0].update(
            {
                "request_timeout_seconds": 27,
                "max_response_bytes": 32_768,
                "max_payload_bytes": 98_304,
                "max_requests_per_window": 11,
                "window_seconds": 900,
                "max_attempts_per_request": 4,
            }
        )
        route = registry_from_mapping(raw).routes[0]
        fields = [{"key": "registry", "type": "json", "value": raw}]
        with patch.object(PLUGIN_API, "_fields", return_value=fields):
            instructions = PLUGIN_API.isolated_instructions(route.route_id)

        command = instructions["setup_command"]
        self.assertIn(f"--instance {route.isolated_instance_id}", command)
        self.assertIn(f"--route-id {route.route_id}", command)
        self.assertIn(f"--connection-id {route.connection_id}", command)
        self.assertIn(f"--workspace-key {route.workspace_key}", command)
        self.assertIn("--route-policy-fingerprint route-policy-", command)
        self.assertIn(f"--event {route.event}", command)
        self.assertIn("--request-timeout-seconds 27", command)
        self.assertIn("--max-response-bytes 32768", command)
        self.assertIn("--max-payload-bytes 98304", command)
        self.assertIn("--max-requests-per-window 11", command)
        self.assertIn("--window-seconds 900", command)
        self.assertIn("--max-attempts-per-request 4", command)
        self.assertIn("--result-tracking", command)

    def test_used_route_destination_is_immutable_but_tombstone_is_allowed(self) -> None:
        raw = registry_payload(route_count=1)
        route_id = raw["routes"][0]["route_id"]
        old = registry_from_mapping(raw)

        changed = {**raw, "routes": [dict(raw["routes"][0])]}
        changed["routes"][0]["trigger_id"] = "trigger-replacement"
        with (
            patch.object(
                PLUGIN_API, "_used_route_ids", return_value=frozenset({route_id})
            ),
            self.assertRaises(BridgeError) as raised,
        ):
            PLUGIN_API._guard_registry_update(old, registry_from_mapping(changed))
        self.assertEqual(raised.exception.code, "route_immutable")

        changed_event = {**raw, "routes": [dict(raw["routes"][0])]}
        changed_event["routes"][0]["event"] = "hermes.task.replaced"
        with (
            patch.object(
                PLUGIN_API, "_used_route_ids", return_value=frozenset({route_id})
            ),
            self.assertRaises(BridgeError) as raised,
        ):
            PLUGIN_API._guard_registry_update(old, registry_from_mapping(changed_event))
        self.assertEqual(raised.exception.code, "route_immutable")

        tombstoned = {**raw, "routes": [dict(raw["routes"][0])]}
        tombstoned["routes"][0]["enabled"] = False
        tombstoned["routes"][0]["tombstoned"] = True
        with patch.object(
            PLUGIN_API, "_used_route_ids", return_value=frozenset({route_id})
        ):
            PLUGIN_API._guard_registry_update(old, registry_from_mapping(tombstoned))

    def test_deleted_route_id_with_delivery_history_cannot_be_reused(self) -> None:
        used_route_id = registry_payload(route_count=1)["routes"][0]["route_id"]
        old = registry_from_mapping(
            {"connections": [], "workspaces": [], "routes": [], "operator_grants": []}
        )
        replacement = registry_payload(route_count=1)
        replacement["routes"][0]["route_id"] = used_route_id

        with self.assertRaises(BridgeError) as raised:
            PLUGIN_API._guard_registry_update(
                old,
                registry_from_mapping(replacement),
                used_route_ids=frozenset({used_route_id}),
            )

        self.assertEqual(raised.exception.code, "route_immutable")

    def test_enabled_route_destination_is_immutable_before_first_delivery(self) -> None:
        raw = registry_payload(route_count=1)
        old = registry_from_mapping(raw)
        changed = copy.deepcopy(raw)
        changed["routes"][0]["trigger_id"] = "trigger-replacement"

        with self.assertRaises(BridgeError) as raised:
            PLUGIN_API._guard_registry_update(
                old,
                registry_from_mapping(changed),
                used_route_ids=frozenset(),
            )

        self.assertEqual(raised.exception.code, "route_immutable")

    def test_registry_update_fails_closed_when_delivery_storage_is_unavailable(self) -> None:
        raw = registry_payload(route_count=1)
        fields = [{"key": "registry", "type": "json", "value": raw}]
        settings = Mock()

        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(
                PLUGIN_API,
                "_storage_path",
                side_effect=PLUGIN_API.HTTPException(status_code=503, detail="storage unavailable"),
            ),
            self.assertRaises(PLUGIN_API.HTTPException) as raised,
        ):
            PLUGIN_API.update_registry({"registry": copy.deepcopy(raw)})

        self.assertEqual(raised.exception.status_code, 503)
        settings.save_plugin_settings.assert_not_called()

    def test_enabling_route_persists_destination_lock(self) -> None:
        current = registry_payload(route_count=1)
        current["routes"][0]["enabled"] = False
        current["routes"][0]["destination_locked"] = False
        requested = copy.deepcopy(current)
        requested["routes"][0]["enabled"] = True
        fields = [{"key": "registry", "type": "json", "value": current}]
        settings = Mock()
        settings.save_plugin_settings.return_value = ["registry"]

        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={"webhook_url": True, "hmac_signing_secret": True, "multica_pat": True},
            ),
        ):
            result = PLUGIN_API.update_registry({"registry": requested})

        self.assertTrue(result["registry"]["routes"][0]["destination_locked"])
        written = settings.save_plugin_settings.call_args.args[2]["registry"]
        self.assertTrue(written["routes"][0]["destination_locked"])

    def test_tombstoned_route_cannot_be_reactivated(self) -> None:
        raw = registry_payload(route_count=1)
        raw["routes"][0]["enabled"] = False
        raw["routes"][0]["tombstoned"] = True
        old = registry_from_mapping(raw)
        reactivated = {**raw, "routes": [dict(raw["routes"][0])]}
        reactivated["routes"][0]["tombstoned"] = False
        with self.assertRaises(BridgeError) as raised:
            PLUGIN_API._guard_registry_update(
                old,
                registry_from_mapping(reactivated),
                used_route_ids=frozenset(),
            )
        self.assertEqual(raised.exception.code, "route_immutable")

    def test_concurrent_registry_updates_cannot_reactivate_tombstoned_route(self) -> None:
        current = registry_payload(route_count=1)
        route_id = current["routes"][0]["route_id"]
        tombstoned = copy.deepcopy(current)
        tombstoned["routes"][0]["enabled"] = False
        tombstoned["routes"][0]["tombstoned"] = True
        stale = copy.deepcopy(current)

        state = {"registry": copy.deepcopy(current)}
        state_lock = threading.Lock()
        first_save_entered = threading.Event()
        allow_first_save = threading.Event()
        second_read = threading.Event()
        reads = 0
        def fields():
            nonlocal reads
            with state_lock:
                reads += 1
                if reads == 2:
                    second_read.set()
                registry = copy.deepcopy(state["registry"])
            return [{"key": "registry", "type": "json", "value": registry}]

        class Settings:
            def save_plugin_settings(self, _plugin_id, _plugin_root, values):
                candidate = copy.deepcopy(values["registry"])
                if candidate["routes"][0]["tombstoned"]:
                    first_save_entered.set()
                    if not allow_first_save.wait(timeout=2):
                        raise AssertionError("timed out waiting to release the first registry save")
                with state_lock:
                    state["registry"] = candidate
                return ["registry"]

        with (
            patch.object(PLUGIN_API, "_fields", side_effect=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=Settings()),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset({route_id})),
            patch.object(
                PLUGIN_API,
                "_route_secret_presence",
                return_value={"webhook_url": True, "hmac_signing_secret": True, "multica_pat": True},
            ),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(PLUGIN_API.update_registry, {"registry": tombstoned})
            self.assertTrue(first_save_entered.wait(timeout=2))
            second = executor.submit(PLUGIN_API.update_registry, {"registry": stale})
            self.assertFalse(second_read.wait(timeout=0.2))
            allow_first_save.set()
            first_result = first.result(timeout=2)
            with self.assertRaises(PLUGIN_API.HTTPException) as raised:
                second.result(timeout=2)

        self.assertTrue(first_result["ok"])
        self.assertEqual(raised.exception.status_code, 400)
        self.assertTrue(state["registry"]["routes"][0]["tombstoned"])
        self.assertFalse(state["registry"]["routes"][0]["enabled"])

    def test_disabled_isolated_route_cannot_clear_destination_lock(self) -> None:
        current = registry_payload(route_count=1, security_mode="isolated")
        current["routes"][0]["enabled"] = False
        current["routes"][0]["destination_locked"] = True
        requested = {**current, "routes": [dict(current["routes"][0])]}
        requested["routes"][0]["destination_locked"] = False

        fields = [{"key": "registry", "type": "json", "value": current}]
        settings = Mock()
        settings.save_plugin_settings.return_value = ["registry"]
        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
        ):
            result = PLUGIN_API.update_registry({"registry": requested})

        self.assertTrue(result["registry"]["routes"][0]["destination_locked"])
        written = settings.save_plugin_settings.call_args.args[2]["registry"]
        self.assertTrue(written["routes"][0]["destination_locked"])

    def test_route_readiness_is_reported_independently(self) -> None:
        registry = registry_from_mapping(registry_payload(route_count=2))
        first, second = registry.routes

        def secret_presence(route):
            if route.route_id == first.route_id:
                return {
                    "webhook_url": True,
                    "hmac_signing_secret": True,
                    "multica_pat": True,
                }
            return {
                "webhook_url": False,
                "hmac_signing_secret": True,
                "multica_pat": True,
            }

        with (
            patch.object(
                PLUGIN_API, "_route_secret_presence", side_effect=secret_presence
            ),
            patch.object(PLUGIN_API, "_latest_delivery", return_value=None),
        ):
            first_status = PLUGIN_API._route_status(registry, first)
            second_status = PLUGIN_API._route_status(registry, second)
        self.assertTrue(first_status["configured"])
        self.assertFalse(second_status["configured"])
        self.assertIn("webhook_url", second_status["readiness_errors"])

    def test_empty_registry_can_be_persisted_directly(self) -> None:
        empty_registry = {
            "connections": [],
            "workspaces": [],
            "routes": [],
            "operator_grants": [],
        }
        fields = [{"key": "registry", "type": "json", "value": empty_registry}]
        self.assertEqual(PLUGIN_API._effective_registry(fields), empty_registry)

        settings = Mock()
        settings.save_plugin_settings.return_value = ["registry"]
        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            patch.object(PLUGIN_API, "_used_route_ids", return_value=frozenset()),
        ):
            result = PLUGIN_API.update_registry({"registry": empty_registry})
        self.assertTrue(result["ok"])
        settings.save_plugin_settings.assert_called_once()
        saved = settings.save_plugin_settings.call_args.args[2]
        self.assertEqual(saved, {"registry": empty_registry})

    def test_missing_registry_returns_empty_registry(self) -> None:
        empty_registry = {
            "connections": [],
            "workspaces": [],
            "routes": [],
            "operator_grants": [],
        }
        self.assertEqual(PLUGIN_API._effective_registry([]), empty_registry)

    def test_registry_endpoint_rejects_unknown_fields_before_persistence(self) -> None:
        payload = registry_payload(route_count=1)
        payload["routes"][0]["credential_value"] = "fixture-marker"
        empty_registry = {
            "connections": [],
            "workspaces": [],
            "routes": [],
            "operator_grants": [],
        }
        fields = [{"key": "registry", "type": "json", "value": empty_registry}]
        settings = Mock()
        with (
            patch.object(PLUGIN_API, "_fields", return_value=fields),
            patch.object(PLUGIN_API, "_settings_module", return_value=settings),
            self.assertRaises(PLUGIN_API.HTTPException) as raised,
        ):
            PLUGIN_API.update_registry({"registry": payload})
        self.assertEqual(raised.exception.status_code, 400)
        settings.save_plugin_settings.assert_not_called()


if __name__ == "__main__":
    unittest.main()
