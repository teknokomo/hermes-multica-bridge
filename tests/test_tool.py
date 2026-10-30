from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.errors import BridgeError
from bridge.registry import TrustedRouteContext
from bridge.tool import (
    LIST_ROUTES_TOOL_SCHEMA,
    RESULT_TOOL_SCHEMA,
    SEND_TOOL_SCHEMA,
    PluginRuntime,
    register,
)
from bridge.validation import request_fingerprint
from tests.helpers import sample_request
from tests.test_registry import registry_payload, workspace_registry_payload


class FakeContext:
    def __init__(self, settings=None):
        self.settings = settings or {}
        self.tools = {}
        self.dispatch_calls = []

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def dispatch_tool(self, name, arguments):
        self.dispatch_calls.append((name, arguments))
        return "{}"


def isolated_settings():
    registry = registry_payload(route_count=1, security_mode="isolated")
    registry["routes"][0]["allowed_profiles"] = ["example"]
    registry["routes"][0]["allowed_assignees"] = ["example"]
    return {"registry": registry}


class ToolTests(unittest.TestCase):
    @staticmethod
    def current():
        return types.SimpleNamespace(
            request=sample_request(),
            trusted=TrustedRouteContext(
                board="example-board",
                task_id="task_12345678",
                run_id="12",
                profile="example",
                assignee="example",
                state="running",
            ),
        )

    def test_plugin_entrypoint_registers_autopilot_and_workspace_tools(self) -> None:
        root = Path(__file__).resolve().parents[1]
        name = "hermes_multica_bridge_plugin_test"
        spec = importlib.util.spec_from_file_location(
            name,
            root / "__init__.py",
            submodule_search_locations=[str(root)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            ctx = FakeContext()
            module.register(ctx)
            self.assertEqual(
                set(ctx.tools),
                {
                    "multica_list_routes", "multica_send_task", "multica_check_task_result",
                    "multica_workspace_send", "multica_workspace_get",
                    "multica_workspace_comment", "multica_workspace_update",
                },
            )
            self.assertNotIn("pass_context", ctx.tools["multica_list_routes"])
            for name in ("multica_workspace_send", "multica_workspace_get",
                         "multica_workspace_comment", "multica_workspace_update"):
                self.assertNotIn("pass_context", ctx.tools[name])
            self.assertFalse(ctx.tools["multica_send_task"].get("pass_context", False))
        finally:
            for loaded in list(sys.modules):
                if loaded == name or loaded.startswith(name + "."):
                    sys.modules.pop(loaded, None)

    def test_absent_registry_is_empty(self) -> None:
        registry = PluginRuntime(FakeContext())._registry()
        self.assertEqual(len(registry.connections), 0)
        self.assertEqual(len(registry.workspaces), 0)
        self.assertEqual(len(registry.routes), 0)

    def test_explicit_empty_registry_remains_empty(self) -> None:
        settings = {
            "registry": {
            "connections": [],
            "workspaces": [],
            "routes": [],
            "operator_grants": [],
            }
        }
        registry = PluginRuntime(FakeContext(settings))._registry()
        self.assertEqual(len(registry.routes), 0)

    def test_schemas_accept_only_optional_route_id_and_no_payload(self) -> None:
        self.assertEqual(LIST_ROUTES_TOOL_SCHEMA["parameters"]["properties"], {})
        for schema in (SEND_TOOL_SCHEMA, RESULT_TOOL_SCHEMA):
            self.assertEqual(set(schema["parameters"]["properties"]), {"route_id"})
            self.assertFalse(schema["parameters"]["additionalProperties"])

    def test_list_routes_includes_only_authorized_workspace_purpose_and_no_secrets(self) -> None:
        runtime = PluginRuntime(FakeContext({"registry": workspace_registry_payload()}))
        source = types.SimpleNamespace(platform="telegram", user_id="user-1", chat_id="chat-1",
                                       thread_id=None, message_id="message-1", chat_type="dm")
        with patch("bridge.tool.read_current_task_with_context",
                   side_effect=BridgeError("source_unavailable", "no kanban source")):
            result = json.loads(runtime.handle_list_routes({}, tool_context=source))
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["routes"]), 1)
        route = result["routes"][0]
        self.assertEqual(route["type"], "workspace")
        self.assertEqual(route["purpose"], "Create and track issues in the configured project.")
        self.assertNotIn("pat", json.dumps(result).lower())
        self.assertNotIn("credential", json.dumps(result).lower())

    def test_list_routes_uses_bound_session_source_without_tool_context(self) -> None:
        runtime = PluginRuntime(FakeContext({"registry": workspace_registry_payload()}))
        source = {
            "platform": "telegram", "user_id": "user-1", "chat_id": "chat-1",
            "thread_id": None, "message_id": "message-1", "chat_type": "dm",
        }
        with patch("bridge.tool.trusted_source", return_value=source) as resolve_source, patch(
            "bridge.tool.read_current_task_with_context",
            side_effect=BridgeError("source_unavailable", "no kanban source"),
        ):
            result = json.loads(runtime.handle_list_routes({}))
        resolve_source.assert_called_once_with(None)
        self.assertEqual([route["type"] for route in result["routes"]], ["workspace"])

    def test_model_route_selector_cannot_bypass_trusted_route_policy(self) -> None:
        raw = registry_payload(route_count=2)
        for route in raw["routes"]:
            route["allowed_profiles"] = ["example"]
            route["allowed_assignees"] = ["example"]
        denied_route_id = raw["routes"][1]["route_id"]
        raw["routes"][1]["source_boards"] = ["other-board"]
        runtime = PluginRuntime(FakeContext({"registry": raw}))

        with patch(
            "bridge.tool.read_current_task_with_context", return_value=self.current()
        ), patch.object(runtime, "_send") as send:
            result = json.loads(runtime.handle_send({"route_id": denied_route_id}))

        self.assertEqual(result["error_code"], "route_denied")
        send.assert_not_called()

    def test_isolated_send_reads_current_task_and_uses_configured_socket(self) -> None:
        captured = {}

        class Client:
            def __init__(self, socket_path, timeout):
                captured["socket_path"] = socket_path
                captured["timeout"] = timeout

            def send(self, request):
                captured["request"] = request
                return {"ok": True, "delivery_status": "accepted"}

        settings = isolated_settings()
        context = FakeContext(settings)
        runtime = PluginRuntime(context)
        registry = runtime._registry()
        expected_socket = registry.route_config(registry.routes[0]).socket_path
        with tempfile.TemporaryDirectory() as directory, patch(
            "bridge.tool._profile_state_path",
            return_value=Path(directory) / "deliveries.sqlite3",
        ), patch(
            "bridge.tool.read_current_task_with_context", return_value=self.current()
        ) as read, patch("bridge.tool.BridgeIpcClient", Client):
            result = json.loads(runtime.handle_send({}))
        self.assertTrue(result["ok"])
        self.assertEqual(captured["socket_path"], expected_socket)
        self.assertEqual(captured["request"], sample_request())
        self.assertIs(read.call_args.kwargs["dispatch_tool"].__self__, context)

    def test_connection_rate_limit_is_shared_by_multiple_routes(self) -> None:
        raw = registry_payload(route_count=2, security_mode="isolated")
        raw["connections"][0]["max_requests_per_window"] = 2
        for route in raw["routes"]:
            route["allowed_profiles"] = ["example"]
            route["allowed_assignees"] = ["example"]
        runtime = PluginRuntime(FakeContext({"registry": raw}))
        routes = runtime._registry().routes

        with tempfile.TemporaryDirectory() as directory, patch(
            "bridge.tool._profile_state_path",
            return_value=Path(directory) / "deliveries.sqlite3",
        ), patch(
            "bridge.tool.read_current_task_with_context", return_value=self.current()
        ), patch.object(
            runtime,
            "_isolated_client",
            return_value=types.SimpleNamespace(send=lambda _request: {"ok": True}),
        ):
            first = json.loads(runtime.handle_send({"route_id": routes[0].route_id}))
            second = json.loads(runtime.handle_send({"route_id": routes[1].route_id}))
            third = json.loads(runtime.handle_send({"route_id": routes[0].route_id}))

        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(third["error_code"], "rate_limited")

    def test_nonempty_model_arguments_are_rejected_before_task_read(self) -> None:
        context = FakeContext(isolated_settings())
        runtime = PluginRuntime(context)
        with patch("bridge.tool.read_current_task_with_context") as read:
            result = json.loads(runtime.handle_send({"url": "https://attacker.invalid"}))
        self.assertEqual(result["error_code"], "invalid_arguments")
        read.assert_not_called()

    def test_result_is_written_as_durable_comment_then_acknowledged(self) -> None:
        fingerprint = "a" * 64
        request_id = "123e4567-e89b-12d3-a456-426614174000"
        marker = f"<!-- hmb-result:{request_id}:{fingerprint} -->"
        calls = []

        class Client:
            def __init__(self, *_args, **_kwargs):
                pass

            def check_result(self, request):
                calls.append(("check", request))
                return {
                    "ok": True,
                    "request_id": request_id,
                    "delivery_status": "accepted",
                    "execution_status": "succeeded",
                    "comment_required": True,
                    "comment_fingerprint": fingerprint,
                    "comment_marker": marker,
                    "comment_text": f"[Hermes Multica Bridge]\nDone\n{marker}",
                }

            def finish_result_comment(self, request, request_id, fp, *, published):
                calls.append(("ack", request_id, fp, published))
                return {"ok": True, "acknowledged": True}

        context = FakeContext(isolated_settings())
        runtime = PluginRuntime(context)
        with patch("bridge.tool.read_current_task_with_context", return_value=self.current()), patch(
            "bridge.tool.BridgeIpcClient", Client
        ), patch("bridge.tool.add_current_task_comment", return_value=True) as add:
            result = json.loads(runtime.handle_check_result({}))
        self.assertTrue(result["ok"])
        self.assertTrue(result["comment_written"])
        add.assert_called_once()
        self.assertEqual(
            add.call_args.kwargs["expected_request_sha256"],
            request_fingerprint(sample_request()),
        )
        self.assertIs(add.call_args.kwargs["dispatch_tool"].__self__, context)
        self.assertEqual(calls[-1], ("ack", "123e4567-e89b-12d3-a456-426614174000", fingerprint, True))

    def test_comment_write_failure_releases_reservation(self) -> None:
        from bridge.errors import BridgeError

        fingerprint = "b" * 64
        request_id = "123e4567-e89b-12d3-a456-426614174000"
        marker = f"<!-- hmb-result:{request_id}:{fingerprint} -->"
        acks = []

        class Client:
            def __init__(self, *_args, **_kwargs):
                pass

            def check_result(self, _request):
                return {
                    "ok": True,
                    "request_id": request_id,
                    "comment_required": True,
                    "comment_fingerprint": fingerprint,
                    "comment_marker": marker,
                    "comment_text": f"Result\n{marker}",
                }

            def finish_result_comment(self, _request, _request_id, _fp, *, published):
                acks.append(published)
                return {"ok": True}

        runtime = PluginRuntime(FakeContext(isolated_settings()))
        with patch("bridge.tool.read_current_task_with_context", return_value=self.current()), patch(
            "bridge.tool.BridgeIpcClient", Client
        ), patch(
            "bridge.tool.add_current_task_comment",
            side_effect=BridgeError("hermes_write_failed", "failed"),
        ):
            result = json.loads(runtime.handle_check_result({}))
        self.assertEqual(result["error_code"], "hermes_write_failed")
        self.assertEqual(acks, [False])

    def test_register_binds_handlers_to_profile_context(self) -> None:
        ctx = FakeContext(isolated_settings())
        register(ctx)
        self.assertEqual(
            set(ctx.tools),
            {
                "multica_list_routes", "multica_send_task", "multica_check_task_result",
                "multica_workspace_send", "multica_workspace_get",
                "multica_workspace_comment", "multica_workspace_update",
            },
        )
        self.assertTrue(callable(ctx.tools["multica_send_task"]["handler"]))

    def test_result_lookup_allows_an_authorized_disabled_tombstoned_route(self) -> None:
        registry = registry_payload(route_count=1)
        route_id = registry["routes"][0]["route_id"]
        registry["routes"][0]["enabled"] = False
        registry["routes"][0]["tombstoned"] = True
        registry["routes"][0]["allowed_profiles"] = ["example"]
        registry["routes"][0]["allowed_assignees"] = ["example"]
        runtime = PluginRuntime(FakeContext({"registry": registry}))
        response = {
            "ok": True,
            "request_id": "018f0000-0000-7000-8000-000000000001",
            "delivery_status": "accepted",
            "execution_status": "succeeded",
            "comment_required": False,
        }
        with (
            patch("bridge.tool.read_current_task_with_context", return_value=self.current()),
            patch.object(runtime, "_check", return_value=(response, object())) as check,
        ):
            result = json.loads(runtime.handle_check_result({"route_id": route_id}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["route_id"], route_id)
        check.assert_called_once()

    def test_result_lookup_can_select_single_isolated_delivery_without_route_id(self) -> None:
        registry = registry_payload(route_count=2, security_mode="isolated")
        for route in registry["routes"]:
            route["allowed_profiles"] = ["example"]
            route["allowed_assignees"] = ["example"]
        expected_route = registry["routes"][1]["route_id"]
        runtime = PluginRuntime(FakeContext({"registry": registry}))
        response = {
            "ok": True,
            "request_id": "018f0000-0000-7000-8000-000000000001",
            "delivery_status": "accepted",
            "execution_status": "succeeded",
            "comment_required": False,
        }

        class Probe:
            def __init__(self, present: bool, *, result: dict | None = None):
                self.present = present
                self.result = result

            def has_delivery(self, _request):
                return {"ok": True, "has_delivery": self.present}

            def check_result(self, _request):
                assert self.result is not None
                return self.result

        class EmptyProfileStore:
            def __init__(self, _path):
                pass

            def routes_for_task(self, **_kwargs):
                return ()

        with (
            patch("bridge.tool.read_current_task_with_context", return_value=self.current()),
            patch("bridge.tool._profile_state_path", return_value=Path("/tmp/ignored-deliveries.sqlite3")),
            patch("bridge.tool.DeliveryStore", EmptyProfileStore),
            patch.object(
                runtime,
                "_isolated_client",
                side_effect=[Probe(False), Probe(True), Probe(True, result=response)],
            ),
        ):
            result = json.loads(runtime.handle_check_result({}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["route_id"], expected_route)


if __name__ == "__main__":
    unittest.main()
