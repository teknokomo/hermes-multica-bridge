from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.registry import (
    TrustedRouteContext,
    new_id,
    registry_from_mapping,
    route_policy_fingerprint,
    route_secret_env_name,
    standard_route_secrets,
)
from tests.helpers import TEST_ORIGIN, TEST_WEBHOOK_URL


def registry_payload(*, route_count: int = 10, security_mode: str = "standard") -> dict:
    connection_id = new_id()
    workspace_ids = [new_id() for _ in range(3)]
    routes = []
    for index in range(route_count):
        routes.append(
            {
                "route_id": new_id(),
                "connection_id": connection_id,
                "workspace_key": workspace_ids[index % 3],
                "name": f"Route {index + 1}",
                "route_type": "autopilot",
                "autopilot_id": f"autopilot-{index + 1}",
                "trigger_id": f"trigger-{index + 1}",
                "event": "hermes.task.dispatched",
                "enabled": True,
                "tombstoned": False,
                "destination_locked": True,
                "source_boards": ["example-board"],
                "allowed_profiles": ["worker-a"],
                "allowed_assignees": ["worker-a"],
                "operator_grant_required": False,
                "result_tracking_enabled": True,
            }
        )
    return {
        "connections": [
            {
                "connection_id": connection_id,
                "name": "Primary",
                "multica_origin": TEST_ORIGIN,
                "security_mode": security_mode,
                "enabled": True,
                "hmac_enabled": True,
            }
        ],
        "workspaces": [
            {
                "workspace_key": workspace_key,
                "connection_id": connection_id,
                "name": f"Workspace {index + 1}",
                "workspace_id": f"workspace-{index + 1}",
            }
            for index, workspace_key in enumerate(workspace_ids)
        ],
        "routes": routes,
        "operator_grants": [],
    }


def workspace_registry_payload(*, allow_groups: bool = False, security_mode: str = "standard") -> dict:
    payload = registry_payload(route_count=0, security_mode=security_mode)
    payload["routes"].append({
        "route_id": new_id(),
        "connection_id": payload["connections"][0]["connection_id"],
        "workspace_key": payload["workspaces"][0]["workspace_key"],
        "name": "Workspace route",
        "route_type": "workspace",
        "project_id": "project-1",
        "enabled": True,
        "tombstoned": False,
        "destination_locked": True,
        "source_platforms": ["telegram", "max"],
        "allowed_user_ids": ["user-1"],
        "allowed_chat_ids": ["chat-1"],
        "allow_groups": allow_groups,
        "allowed_statuses": ["todo", "in_progress", "done"],
        "allowed_assignees": ["member-1"],
        "require_source_attachment": False,
        "max_attachments": 4,
        "max_attachment_bytes": 4_000_000,
        "allowed_mime_types": ["application/pdf"],
        "allowed_extensions": [".pdf"],
        "watcher_enabled": True,
    })
    return payload


class RegistryTests(unittest.TestCase):
    def test_negative_telegram_group_chat_id_requires_group_opt_in(self) -> None:
        payload = workspace_registry_payload(allow_groups=True)
        payload["routes"][0]["allowed_chat_ids"] = ["-1001234567890"]
        route = registry_from_mapping(payload).routes[0]
        self.assertEqual(route.allowed_chat_ids, ("-1001234567890",))

        payload["routes"][0]["allow_groups"] = False
        registry = registry_from_mapping(payload)
        context = {
            "platform": "telegram", "user_id": "user-1", "chat_id": "-1001234567890",
            "chat_type": "group", "message_id": "message-1",
        }
        self.assertEqual(registry.authorized_workspace_routes(context), ())

    def test_unhashable_route_type_is_reported_as_configuration_error(self) -> None:
        for invalid_type in ([], {}):
            with self.subTest(invalid_type=invalid_type):
                payload = workspace_registry_payload()
                payload["routes"][0]["route_type"] = invalid_type
                with self.assertRaises(BridgeError) as raised:
                    registry_from_mapping(payload)
                self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_redacted_registry_example_has_four_disabled_workspace_routes(self) -> None:
        path = Path(__file__).parents[1] / "config" / "registry.om73.example.json"
        registry = registry_from_mapping(json.loads(path.read_text(encoding="utf-8")))
        workspace_routes = [route for route in registry.routes if route.route_type == "workspace"]
        self.assertEqual(len(registry.workspaces), 4)
        self.assertEqual(len(workspace_routes), 4)
        self.assertTrue(all(not route.enabled and route.watcher_enabled for route in workspace_routes))
        self.assertTrue(all("REPLACE-" in workspace.workspace_id for workspace in registry.workspaces))

    def test_one_connection_three_workspaces_and_ten_routes_validate(self) -> None:
        registry = registry_from_mapping(registry_payload())
        self.assertEqual(len(registry.connections), 1)
        self.assertEqual(len(registry.workspaces), 3)
        self.assertEqual(len(registry.routes), 10)
        self.assertEqual(
            registry.routes[0].workspace_key, registry.routes[3].workspace_key
        )

    def test_non_string_security_mode_is_configuration_error(self) -> None:
        for mode in ([], {}, None, 1):
            with self.subTest(mode=mode):
                payload = registry_payload(route_count=1)
                payload["connections"][0]["security_mode"] = mode
                with self.assertRaises(BridgeError) as raised:
                    registry_from_mapping(payload)
                self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_workspace_route_requires_standard_connection_and_complete_policy(self) -> None:
        registry = registry_from_mapping(workspace_registry_payload())
        route = registry.routes[0]
        self.assertEqual(route.route_type, "workspace")
        self.assertEqual(route.project_id, "project-1")
        payload = workspace_registry_payload(security_mode="isolated")
        with self.assertRaises(BridgeError):
            registry_from_mapping(payload)
        payload = workspace_registry_payload()
        payload["routes"][0]["watcher_enabled"] = False
        with self.assertRaises(BridgeError):
            registry_from_mapping(payload)

    def test_workspace_source_policy_requires_exact_user_chat_and_group_opt_in(self) -> None:
        registry = registry_from_mapping(workspace_registry_payload())
        source = {
            "platform": "telegram", "user_id": "user-1", "chat_id": "chat-1",
            "chat_type": "dm",
        }
        self.assertEqual(len(registry.authorized_workspace_routes(source)), 1)
        self.assertEqual(registry.authorized_workspace_routes({**source, "user_id": "other"}), ())
        self.assertEqual(registry.authorized_workspace_routes({**source, "chat_id": "other"}), ())
        self.assertEqual(registry.authorized_workspace_routes({**source, "chat_type": "group"}), ())
        self.assertEqual(registry.authorized_workspace_routes({**source, "chat_type": "thread"}), ())
        group_registry = registry_from_mapping(workspace_registry_payload(allow_groups=True))
        self.assertEqual(len(group_registry.authorized_workspace_routes({**source, "chat_type": "thread"})), 1)

    def test_workspace_policy_fingerprint_covers_project_source_and_attachment_policy(self) -> None:
        payload = workspace_registry_payload()
        registry = registry_from_mapping(payload)
        route = registry.routes[0]
        before = route_policy_fingerprint(registry, route)
        payload["routes"][0]["project_id"] = "project-2"
        changed = registry_from_mapping(payload)
        self.assertNotEqual(before, route_policy_fingerprint(changed, changed.routes[0]))

    def test_two_connections_are_independent(self) -> None:
        payload = registry_payload(route_count=2)
        second_id = new_id()
        second_workspace = new_id()
        payload["connections"].append(
            {
                "connection_id": second_id,
                "name": "Secondary",
                "multica_origin": "https://other.example.org",
                "security_mode": "standard",
                "enabled": True,
                "hmac_enabled": True,
            }
        )
        payload["workspaces"].append(
            {
                "workspace_key": second_workspace,
                "connection_id": second_id,
                "name": "Other",
                "workspace_id": "workspace-other",
            }
        )
        route = dict(payload["routes"][1])
        route.update(
            {
                "route_id": new_id(),
                "connection_id": second_id,
                "workspace_key": second_workspace,
                "name": "Other route",
            }
        )
        payload["routes"].append(route)
        registry = registry_from_mapping(payload)
        self.assertEqual(len(registry.connections), 2)
        self.assertEqual(
            registry.route_config(registry.routes[-1]).multica_origin,
            "https://other.example.org",
        )

    def test_cross_connection_workspace_reference_is_rejected(self) -> None:
        payload = registry_payload(route_count=1)
        payload["routes"][0]["connection_id"] = new_id()
        with self.assertRaises(BridgeError) as raised:
            registry_from_mapping(payload)
        self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_registry_rejects_unknown_fields_instead_of_persisting_untrusted_values(
        self,
    ) -> None:
        original = registry_payload(route_count=1)
        cases = (
            (
                "registry",
                lambda payload: payload.update(unexpected_field="fixture-marker"),
            ),
            (
                "connection",
                lambda payload: payload["connections"][0].update(
                    unexpected_field="fixture-marker"
                ),
            ),
            (
                "workspace",
                lambda payload: payload["workspaces"][0].update(
                    unexpected_field="fixture-marker"
                ),
            ),
            (
                "route",
                lambda payload: payload["routes"][0].update(
                    unexpected_field="fixture-marker"
                ),
            ),
            (
                "operator grant",
                lambda payload: payload["operator_grants"].append(
                    {
                        "board": "example-board",
                        "task_id": "task-example",
                        "route_id": payload["routes"][0]["route_id"],
                        "unexpected_field": "fixture-marker",
                    }
                ),
            ),
        )
        for label, inject in cases:
            with self.subTest(label=label), self.assertRaises(BridgeError) as raised:
                payload = copy.deepcopy(original)
                inject(payload)
                registry_from_mapping(payload)
            self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_registry_rejects_version_field(self) -> None:
        payload = registry_payload(route_count=1)
        payload["version"] = 3
        with self.assertRaises(BridgeError) as raised:
            registry_from_mapping(payload)
        self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_authorization_checks_profile_assignee_and_exact_grant(self) -> None:
        payload = registry_payload(route_count=1)
        route_id = payload["routes"][0]["route_id"]
        payload["routes"][0]["operator_grant_required"] = True
        payload["operator_grants"] = [
            {"board": "example-board", "task_id": "task_12345678", "route_id": route_id}
        ]
        registry = registry_from_mapping(payload)
        trusted = TrustedRouteContext(
            board="example-board",
            task_id="task_12345678",
            run_id="12",
            profile="worker-a",
            assignee="worker-a",
            state="running",
        )
        self.assertEqual(
            [route.route_id for route in registry.authorized_routes(trusted)],
            [route_id],
        )
        self.assertEqual(
            registry.authorized_routes(
                TrustedRouteContext(
                    board=trusted.board,
                    task_id=trusted.task_id,
                    run_id=trusted.run_id,
                    profile="worker-b",
                    assignee=trusted.assignee,
                    state=trusted.state,
                )
            ),
            (),
        )

    def test_unlocked_route_is_not_authorized_even_when_enabled(self) -> None:
        payload = registry_payload(route_count=1)
        route_id = payload["routes"][0]["route_id"]
        payload["routes"][0]["destination_locked"] = False
        registry = registry_from_mapping(payload)
        trusted = TrustedRouteContext(
            board="example-board",
            task_id="task_12345678",
            run_id="12",
            profile="worker-a",
            assignee="worker-a",
            state="running",
        )

        self.assertEqual(registry.authorized_routes(trusted), ())
        self.assertEqual(registry.authorized_routes(trusted, include_disabled=True), ())
        self.assertEqual(registry.route(route_id).destination_locked, False)

    def test_standard_route_credentials_are_independently_scoped(self) -> None:
        registry = registry_from_mapping(registry_payload(route_count=2))
        first, second = registry.routes
        first_webhook = route_secret_env_name(first.route_id, "webhook")
        second_webhook = route_secret_env_name(second.route_id, "webhook")
        self.assertNotEqual(first_webhook, second_webhook)
        values = {
            first_webhook: TEST_WEBHOOK_URL,
            second_webhook: TEST_WEBHOOK_URL.replace("awt_", "awt_B"),
            route_secret_env_name(first.route_id, "hmac"): "first-secret",
            route_secret_env_name(second.route_id, "hmac"): "second-secret",
        }
        getter = lambda name, default="": values.get(name, default)
        first_secrets = standard_route_secrets(first, get_secret=getter)
        second_secrets = standard_route_secrets(second, get_secret=getter)
        self.assertEqual(first_secrets.hmac_signing_secret, "first-secret")
        self.assertEqual(second_secrets.hmac_signing_secret, "second-secret")

    def test_isolated_routes_get_independent_instance_ids(self) -> None:
        registry = registry_from_mapping(
            registry_payload(route_count=2, security_mode="isolated")
        )
        first = registry.route_config(registry.routes[0])
        second = registry.route_config(registry.routes[1])
        self.assertNotEqual(first.isolated_instance_id, second.isolated_instance_id)
        self.assertNotEqual(first.socket_path, second.socket_path)

if __name__ == "__main__":
    unittest.main()
