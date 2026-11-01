from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from bridge.errors import BridgeError
from bridge.workspace_state import WorkspaceState
from bridge.workspace_tools import WORKSPACE_TOOLS, WorkspaceRuntime
from tests.test_registry import (
    AGENT_UUID,
    MEMBER_UUID,
    SQUAD_UUID,
    workspace_registry_payload,
)


class _Context:
    def __init__(self, config, source):
        self.config = config
        self.profile_name = "om73"
        self.source = source
        self.posted_messages = []

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def post_message(self, text):
        self.posted_messages.append(text)
        return {"ok": True, "message_id": f"notice-{len(self.posted_messages)}"}


class _Api:
    def __init__(self):
        self.create_calls = []
        self.comments = []
        self.updates = []
        self.uploads = []
        self.metadata = {}
        self.metadata_calls = []
        self.metadata_error = False
        self.readback_error = None
        self.readback_override = None
        self.issue = {"id": "issue-1", "workspace_id": "workspace-1", "project_id": "project-1",
                      "identifier": "73AN-7", "title": "Task", "description": "", "status": "todo",
                      "assignee_id": MEMBER_UUID, "assignee_type": "member", "revision": 1}
        self.parent = {"id": "parent-1", "workspace_id": "workspace-1", "project_id": "project-1"}

    def create_issue(self, **kwargs):
        self.create_calls.append(kwargs)
        self.issue.update({key: value for key, value in kwargs.items() if key != "project_id"})
        self.issue["project_id"] = kwargs["project_id"]
        return dict(self.issue)

    def get_issue(self, issue_id):
        if issue_id != "parent-1" and self.readback_error is not None:
            raise self.readback_error
        if issue_id != "parent-1" and self.readback_override is not None:
            return dict(self.readback_override)
        return self.parent if issue_id == "parent-1" else dict(self.issue)

    def list_comments(self, issue_id):
        return []

    def create_comment(self, issue_id, content):
        self.comments.append((issue_id, content))
        return {"id": "comment-1", "content": content, "created_at": "now"}

    def update_issue(self, issue_id, updates):
        normalized = dict(updates)
        if isinstance(normalized.get("title"), str):
            normalized["title"] = normalized["title"].strip()
        self.updates.append((issue_id, normalized))
        self.issue.update(normalized)
        return dict(self.issue)

    def upload_issue_attachment(self, issue_id, filename, media_type, data):
        self.uploads.append((issue_id, filename, media_type, data))
        return {"id": "attachment-1"}

    def set_issue_metadata(self, issue_id, key, value):
        self.metadata_calls.append(("set", issue_id, key, value))
        if self.metadata_error:
            raise BridgeError("api_unavailable", "metadata unavailable")
        self.metadata[key] = value
        return {"metadata": dict(self.metadata)}

    def delete_issue_metadata(self, issue_id, key):
        self.metadata_calls.append(("delete", issue_id, key))
        if self.metadata_error:
            raise BridgeError("api_unavailable", "metadata unavailable")
        self.metadata.pop(key, None)
        return {"metadata": dict(self.metadata)}


class WorkspaceToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.payload = workspace_registry_payload()
        route = self.payload["routes"][0]
        self.route_id = route["route_id"]
        self.source = SimpleNamespace(
            platform="telegram", user_id="user-1", chat_id="chat-1", thread_id=None,
            message_id="message-1", chat_type="dm", attachments=(),
        )
        self.ctx = _Context({"registry": self.payload}, self.source)
        self.runtime = WorkspaceRuntime(self.ctx)
        self.state = WorkspaceState(Path(self.temp.name) / "profile" / "workspace.sqlite3")
        self.api = _Api()
        self.runtime._state = lambda: self.state
        self.runtime._api = lambda registry, route: self.api
        self.secrets_patcher = patch(
            "bridge.workspace_tools.standard_route_secrets",
            return_value=SimpleNamespace(multica_pat="test-profile-multica-pat"),
        )
        self.secrets_patcher.start()

    def tearDown(self) -> None:
        self.secrets_patcher.stop()
        self.temp.cleanup()

    def _gateway_modules(self, source=None, *, attachments=(), bound=None, env=None):
        source = source or self.source
        names = {
            "platform": "HERMES_SESSION_PLATFORM",
            "user_id": "HERMES_SESSION_USER_ID",
            "chat_id": "HERMES_SESSION_CHAT_ID",
            "thread_id": "HERMES_SESSION_THREAD_ID",
            "message_id": "HERMES_SESSION_MESSAGE_ID",
            "chat_type": "HERMES_SESSION_CHAT_TYPE",
        }
        values = {name: getattr(source, key) or "" for key, name in names.items()}
        bound_values = values if bound is None else bound
        env_values = values if env is None else env
        package = ModuleType("gateway")
        package.__path__ = []
        module = ModuleType("gateway.session_context")
        module.get_bound_session_env = lambda name, default="": bound_values.get(name, default)
        module.get_session_env = lambda name, default="": env_values.get(name, default)
        module.get_current_attachments = lambda: attachments
        package.session_context = module
        return {"gateway": package, "gateway.session_context": module}

    def test_create_is_cached_by_profile_route_and_source(self) -> None:
        ipc = SimpleNamespace(register_issue=lambda mapping: {"ok": True})
        args = {"route_id": self.route_id, "title": "Task"}
        with patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc):
            first = json.loads(self.runtime.send(args, tool_context=self.source))
            second = json.loads(self.runtime.send(args, tool_context=self.source))
        self.assertTrue(first["ok"])
        self.assertEqual(second["issue"]["id"], "issue-1")
        self.assertEqual(len(self.api.create_calls), 1)
        self.assertEqual(self.state.issue_mapping("issue-1")["chat_id"], "chat-1")

    def test_session_context_fallback_works_without_tool_context(self) -> None:
        modules = self._gateway_modules()
        ipc = SimpleNamespace(register_issue=lambda mapping: {"ok": True})
        with patch.dict(sys.modules, modules), patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc):
            result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}))
        self.assertTrue(result["ok"])
        self.assertEqual(len(self.api.create_calls), 1)
        self.assertEqual(self.state.issue_mapping("issue-1")["message_id"], "message-1")

    def test_failed_watcher_registration_retries_from_persisted_source_on_get(self) -> None:
        ipc = SimpleNamespace(register_issue=Mock(side_effect=[
            BridgeError("watcher_ipc_unavailable", "unavailable"), {"ok": True},
        ]))
        other_source = SimpleNamespace(**{**vars(self.source), "message_id": "message-2"})
        with patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc), \
                patch("bridge.workspace_tools.time.monotonic", return_value=100):
            created = json.loads(self.runtime.send(
                {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
            ))
        with patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc), \
                patch("bridge.workspace_tools.time.monotonic", return_value=131):
            fetched = json.loads(self.runtime.get(
                {"route_id": self.route_id, "issue_id": "issue-1"}, tool_context=other_source,
            ))

        self.assertEqual(created["watcher_mapping"], "pending")
        self.assertTrue(fetched["ok"])
        self.assertEqual(ipc.register_issue.call_count, 2)
        self.assertEqual(ipc.register_issue.call_args.args[0]["message_id"], "message-1")
        self.assertEqual(ipc.register_issue.call_args.args[0]["chat_id"], "chat-1")

    def test_get_does_not_create_watcher_mapping_from_current_message(self) -> None:
        self.api.issue = {**self.api.issue, "id": "unmapped-issue"}
        ipc = SimpleNamespace(register_issue=Mock(return_value={"ok": True}))
        with patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc):
            result = json.loads(self.runtime.get(
                {"route_id": self.route_id, "issue_id": "unmapped-issue"}, tool_context=self.source,
            ))
        self.assertTrue(result["ok"])
        ipc.register_issue.assert_not_called()

    def test_session_context_fails_closed_when_no_bound_source_or_env_exists(self) -> None:
        empty = {name: "" for name in (
            "HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID", "HERMES_SESSION_CHAT_ID",
            "HERMES_SESSION_THREAD_ID", "HERMES_SESSION_MESSAGE_ID", "HERMES_SESSION_CHAT_TYPE",
        )}
        modules = self._gateway_modules(bound=empty, env=empty)
        with patch.dict(sys.modules, modules):
            result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}))
        self.assertEqual(result["error_code"], "source_unavailable")
        self.assertEqual(self.api.create_calls, [])

    def test_session_context_rejects_stale_process_env_fallback(self) -> None:
        empty = {name: "" for name in (
            "HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID", "HERMES_SESSION_CHAT_ID",
            "HERMES_SESSION_THREAD_ID", "HERMES_SESSION_MESSAGE_ID", "HERMES_SESSION_CHAT_TYPE",
        )}
        names = {
            "HERMES_SESSION_PLATFORM": "telegram", "HERMES_SESSION_USER_ID": "user-1",
            "HERMES_SESSION_CHAT_ID": "chat-1", "HERMES_SESSION_THREAD_ID": "",
            "HERMES_SESSION_MESSAGE_ID": "message-1", "HERMES_SESSION_CHAT_TYPE": "dm",
        }
        modules = self._gateway_modules(bound=empty, env=names)
        with patch.dict(sys.modules, modules):
            result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}))
        self.assertEqual(result["error_code"], "source_unavailable")
        self.assertEqual(self.api.create_calls, [])

    def test_runtime_reuses_state_without_resetting_a_live_operation(self) -> None:
        storage_package = ModuleType("plugins")
        storage_package.__path__ = []
        storage_module = ModuleType("plugins.plugin_storage")

        def plugin_data_dir(_plugin_name: str) -> Path:
            return Path(self.temp.name) / "runtime-profile"

        storage_module.plugin_data_dir = plugin_data_dir
        source = {
            "platform": self.source.platform, "user_id": self.source.user_id,
            "chat_id": self.source.chat_id, "thread_id": self.source.thread_id,
            "message_id": self.source.message_id, "chat_type": self.source.chat_type,
        }
        key = self.state.operation_key("om73", self.route_id, source, "create_issue")
        request_hash = self.state.payload_hash({"title": "live"})

        with patch.dict(sys.modules, {"plugins": storage_package, "plugins.plugin_storage": storage_module}):
            first_state = WorkspaceRuntime(self.ctx)._state()
            first_state.begin(
                key=key, route_id=self.route_id, operation="create_issue", request_hash=request_hash,
            )
            second_state = WorkspaceRuntime(self.ctx)._state()
            self.assertIs(first_state, second_state)
            second_state.finish(key, status="accepted", result={"id": "issue-live"})
            result = second_state.begin(
                key=key, route_id=self.route_id, operation="create_issue", request_hash=request_hash,
            )

        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.result, {"id": "issue-live"})

    def test_same_source_cannot_change_payload_or_spoof_context(self) -> None:
        ipc = SimpleNamespace(register_issue=lambda mapping: {"ok": True})
        with patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc):
            first = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}, tool_context=self.source))
            changed = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Different"}, tool_context=self.source))
        forged = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task", "chat_id": "other"},
                                              tool_context=self.source))
        self.assertTrue(first["ok"])
        self.assertEqual(changed["error_code"], "operation_conflict")
        self.assertEqual(forged["error_code"], "invalid_arguments")
        self.assertEqual(len(self.api.create_calls), 1)

    def test_unauthorized_source_and_cross_project_parent_do_not_write(self) -> None:
        unauthorized = SimpleNamespace(**{**vars(self.source), "user_id": "other-user"})
        denied = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}, tool_context=unauthorized))
        self.assertEqual(denied["error_code"], "route_denied")
        self.api.parent["project_id"] = "other-project"
        parent_denied = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Child", "parent_issue_id": "parent-1", "assignee_id": MEMBER_UUID},
            tool_context=self.source,
        ))
        self.assertEqual(parent_denied["error_code"], "route_denied")
        self.assertEqual(self.api.create_calls, [])

    def test_incomplete_telegram_thread_context_is_rejected_before_multica_write(self) -> None:
        for thread_id in (None, "0", "topic-nine"):
            with self.subTest(thread_id=thread_id):
                source = SimpleNamespace(**{
                    **vars(self.source), "chat_type": "thread", "thread_id": thread_id,
                })
                result = json.loads(self.runtime.send(
                    {"route_id": self.route_id, "title": "Task"}, tool_context=source,
                ))
                self.assertEqual(result["error_code"], "source_unavailable")
        self.assertEqual(self.api.create_calls, [])

    def test_foreign_attachment_is_rejected_before_issue_post(self) -> None:
        path = Path(self.temp.name) / "file.pdf"
        path.write_bytes(b"fake attachment bytes")
        descriptor = {
            "path": str(path), "media_type": "application/pdf", "message_id": "old-message",
            "platform": "telegram", "chat_type": "dm", "chat_id": "chat-1", "actor": "user-1",
        }
        source = SimpleNamespace(**{**vars(self.source), "attachments": (descriptor,)})
        result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}, tool_context=source))
        self.assertEqual(result["error_code"], "attachment_invalid")
        self.assertEqual(self.api.create_calls, [])

    def test_current_message_attachment_from_gateway_is_attached_automatically(self) -> None:
        content = b"fake attachment bytes"
        path = Path(self.temp.name) / "file.pdf"
        path.write_bytes(content)
        descriptor = {
            "path": str(path), "media_type": "application/pdf", "message_id": "message-1",
            "platform": "telegram", "chat_type": "dm", "chat_id": "chat-1", "actor": "user-1",
        }
        modules = self._gateway_modules(attachments=(descriptor,))
        ipc = SimpleNamespace(register_issue=lambda mapping: {"ok": True})
        with patch.dict(sys.modules, modules), patch("bridge.watcher_ipc.WatcherIpcClient", return_value=ipc):
            result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["attachments"][0]["status"], "attached")
        self.assertEqual(self.api.uploads, [("issue-1", "file.pdf", "application/pdf", content)])

    def test_symlinked_attachment_is_rejected_before_issue_post(self) -> None:
        target = Path(self.temp.name) / "original.pdf"
        target.write_bytes(b"fake attachment bytes")
        link = Path(self.temp.name) / "file.pdf"
        link.symlink_to(target)
        descriptor = {
            "path": str(link), "media_type": "application/pdf", "message_id": "message-1",
            "platform": "telegram", "chat_type": "dm", "chat_id": "chat-1", "actor": "user-1",
        }
        modules = self._gateway_modules(attachments=(descriptor,))
        with patch.dict(sys.modules, modules):
            result = json.loads(self.runtime.send({"route_id": self.route_id, "title": "Task"}))
        self.assertEqual(result["error_code"], "attachment_invalid")
        self.assertEqual(self.api.create_calls, [])

    def test_comment_and_update_are_route_checked_and_allowlisted(self) -> None:
        comment = json.loads(self.runtime.comment(
            {"route_id": self.route_id, "issue_id": "issue-1", "content": "hello"}, tool_context=self.source,
        ))
        update = json.loads(self.runtime.update(
            {"route_id": self.route_id, "issue_id": "issue-1", "status": "done",
             "assignee_id": MEMBER_UUID}, tool_context=self.source,
        ))
        self.assertTrue(comment["ok"])
        self.assertEqual(update["issue"]["status"], "done")
        self.assertEqual(self.api.comments, [("issue-1", "hello")])
        self.assertEqual(self.api.updates[0][1], {"status": "done", "assignee_id": MEMBER_UUID, "assignee_type": "member"})

    def test_update_title_is_normalized_before_readback_comparison(self) -> None:
        result = json.loads(self.runtime.update(
            {"route_id": self.route_id, "issue_id": "issue-1", "title": "  New title  "},
            tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(result["issue"]["title"], "New title")
        self.assertEqual(self.api.updates[-1][1], {"title": "New title"})

    def test_create_resolves_explicit_default_and_typed_assignments(self) -> None:
        for assignee_id, assignee_type in (
            (MEMBER_UUID, "member"), (AGENT_UUID, "agent"), (SQUAD_UUID, "squad"),
        ):
            with self.subTest(assignee_type=assignee_type):
                self.state = WorkspaceState(Path(self.temp.name) / assignee_type / "workspace.sqlite3")
                self.runtime._state = lambda: self.state
                self.api = _Api()
                self.runtime._api = lambda registry, route: self.api
                source = SimpleNamespace(**{**vars(self.source), "message_id": f"message-{assignee_type}"})
                result = json.loads(self.runtime.send(
                    {"route_id": self.route_id, "title": "Task",
                     "assignee_id": assignee_id, "assignee_type": assignee_type},
                    tool_context=source,
                ))
                self.assertTrue(result["ok"])
                self.assertEqual(self.api.create_calls[0]["assignee_id"], assignee_id)
                self.assertEqual(self.api.create_calls[0]["assignee_type"], assignee_type)
                self.assertEqual(result["issue"]["assignee_type"], assignee_type)

    def test_assignee_id_inference_and_ambiguity_fail_closed(self) -> None:
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID},
            tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(self.api.create_calls[0]["assignee_type"], "member")

        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["allowed_assignees"].append({"id": MEMBER_UUID, "type": "agent"})
        payload["routes"][0]["default_assignee"] = {"id": MEMBER_UUID, "type": "member"}
        self.ctx.config["registry"] = payload
        self.state = WorkspaceState(Path(self.temp.name) / "ambiguous" / "workspace.sqlite3")
        self.runtime._state = lambda: self.state
        self.api = _Api()
        self.runtime._api = lambda registry, route: self.api
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID},
            tool_context=self.source,
        ))
        self.assertEqual(result["error_code"], "assignee_type_required")
        self.assertEqual(self.api.create_calls, [])

    def test_same_assignee_id_resolves_only_with_explicit_type_when_ambiguous(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["allowed_assignees"].append({"id": MEMBER_UUID, "type": "agent"})
        self.ctx.config["registry"] = payload
        self.state = WorkspaceState(Path(self.temp.name) / "typed-duplicate" / "workspace.sqlite3")
        self.runtime._state = lambda: self.state
        self.api = _Api()
        self.runtime._api = lambda registry, route: self.api
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID, "assignee_type": "agent"},
            tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(self.api.create_calls[0]["assignee_type"], "agent")

    def test_missing_or_disallowed_assignee_fails_before_post(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["default_assignee"] = None
        self.ctx.config["registry"] = payload
        missing = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        denied = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": "00000000-0000-4000-8000-000000000099",
             "assignee_type": "member"}, tool_context=self.source,
        ))
        self.assertEqual(missing["error_code"], "assignee_required")
        self.assertEqual(denied["error_code"], "assignee_not_allowed")
        self.assertEqual(self.api.create_calls, [])

    def test_accepted_post_with_failed_readback_never_posts_twice(self) -> None:
        self.api.readback_error = BridgeError("api_unavailable", "readback offline", retryable=True)
        first = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertEqual(first["error_code"], "assignee_verification_failed")
        self.assertEqual(first["issue_id"], "issue-1")
        self.assertEqual(len(self.api.create_calls), 1)

        self.api.readback_error = None
        second = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertTrue(second["ok"])
        self.assertEqual(len(self.api.create_calls), 1)

    def test_assignment_readback_mismatch_is_recoverable_by_get_only(self) -> None:
        self.api.readback_override = {**self.api.issue, "assignee_type": "agent"}
        first = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID, "assignee_type": "member"},
            tool_context=self.source,
        ))
        self.assertEqual(first["error_code"], "assignee_verification_failed")
        self.api.readback_override = None
        second = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID, "assignee_type": "member"},
            tool_context=self.source,
        ))
        self.assertTrue(second["ok"])
        self.assertEqual(len(self.api.create_calls), 1)

    def test_unassigned_creation_is_not_successful_and_notice_is_attempted_once(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["default_assignee"] = None
        self.ctx.config["registry"] = payload
        args = {"route_id": self.route_id, "title": "Unassigned", "allow_unassigned": True}
        first = json.loads(self.runtime.send(args, tool_context=self.source))
        second = json.loads(self.runtime.send(args, tool_context=self.source))
        self.assertFalse(first["ok"])
        self.assertEqual(first["error_code"], "assignee_required")
        self.assertEqual(first["issue_id"], "issue-1")
        self.assertEqual(first["notification_status"], "delivered")
        self.assertFalse(second["ok"])
        self.assertEqual(len(self.api.create_calls), 1)
        self.assertEqual(len(self.ctx.posted_messages), 1)
        self.assertIn("73AN-7", self.ctx.posted_messages[0])

    def test_unassigned_notice_unknown_is_terminal(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["default_assignee"] = None
        self.ctx.config["registry"] = payload
        self.ctx.post_message = Mock(return_value={"ok": False, "error": "timeout"})
        args = {"route_id": self.route_id, "title": "Unassigned", "allow_unassigned": True}
        first = json.loads(self.runtime.send(args, tool_context=self.source))
        second = json.loads(self.runtime.send(args, tool_context=self.source))
        self.assertEqual(first["notification_status"], "delivery_unknown")
        self.assertEqual(second["notification_status"], "delivery_unknown")
        self.ctx.post_message.assert_called_once()

    def test_unassigned_creation_requires_public_post_message_before_multica_write(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["default_assignee"] = None
        ctx = SimpleNamespace(get_config=lambda key, default=None: {"registry": payload}.get(key, default),
                              profile_name="om73")
        runtime = WorkspaceRuntime(ctx)
        runtime._state = lambda: self.state
        runtime._api = lambda registry, route: self.api
        result = json.loads(runtime.send(
            {"route_id": self.route_id, "title": "Task", "allow_unassigned": True},
            tool_context=self.source,
        ))
        self.assertEqual(result["error_code"], "notification_unavailable")
        self.assertEqual(self.api.create_calls, [])

    def test_related_issue_metadata_is_compact_and_validated_before_post(self) -> None:
        related = ["73AN-8", "73FIN-3"]
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "related_issue_ids": related},
            tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertIn(("set", "issue-1", "related_issue_ids", '["73AN-8","73FIN-3"]'), self.api.metadata_calls)

        self.api = _Api()
        self.runtime._api = lambda registry, route: self.api
        invalid = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "related_issue_ids": ["73AN-8", "73AN-8"]},
            tool_context=SimpleNamespace(**{**vars(self.source), "message_id": "duplicate-message"}),
        ))
        self.assertEqual(invalid["error_code"], "invalid_arguments")
        self.assertEqual(self.api.create_calls, [])

    def test_test_route_metadata_is_pseudonymous_and_metadata_failure_warns_once(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["test"] = True
        self.ctx.config["registry"] = payload
        self.api.metadata_error = True
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(result["warnings"], ["metadata_incomplete"])
        metadata_values = json.dumps(self.api.metadata)
        self.assertNotIn("user-1", metadata_values)
        self.assertNotIn("chat-1", metadata_values)
        self.assertNotIn("message-1", metadata_values)
        self.assertIn(("set", "issue-1", "origin_test", True), self.api.metadata_calls)
        self.assertEqual(self.api.metadata, {})
        self.assertFalse(any("user-1" in str(call) for call in self.api.metadata_calls))

    def test_successful_metadata_contains_hashes_and_expected_origin_fields(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["test"] = True
        self.ctx.config["registry"] = payload
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(self.api.metadata["origin"], "telegram")
        self.assertEqual(self.api.metadata["origin_route"], self.route_id)
        self.assertEqual(self.api.metadata["created_by"], "hermes-multica-bridge")
        self.assertEqual(self.api.metadata["origin_test"], True)
        self.assertRegex(self.api.metadata["requester"], r"^[0-9a-f]{64}$")
        self.assertRegex(self.api.metadata["source_message_id"], r"^[0-9a-f]{64}$")
        plain_requester = hashlib.sha256(
            json.dumps(
                {"platform": "telegram", "user_id": "user-1", "route_id": self.route_id},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertNotEqual(self.api.metadata["requester"], plain_requester)
        serialized = json.dumps(self.api.metadata)
        for raw in ("user-1", "chat-1", "message-1"):
            self.assertNotIn(raw, serialized)

    def test_update_supports_agent_squad_type_change_and_null_pair(self) -> None:
        agent_update = json.loads(self.runtime.update(
            {"route_id": self.route_id, "issue_id": "issue-1", "assignee_id": AGENT_UUID, "assignee_type": "agent"},
            tool_context=self.source,
        ))
        self.assertTrue(agent_update["ok"])
        self.assertEqual(self.api.updates[-1][1], {"assignee_id": AGENT_UUID, "assignee_type": "agent"})

        squad_update = json.loads(self.runtime.update(
            {"route_id": self.route_id, "issue_id": "issue-1", "assignee_id": SQUAD_UUID, "assignee_type": "squad"},
            tool_context=SimpleNamespace(**{**vars(self.source), "message_id": "squad-update"}),
        ))
        self.assertTrue(squad_update["ok"])
        self.assertEqual(self.api.updates[-1][1], {"assignee_id": SQUAD_UUID, "assignee_type": "squad"})

        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["require_assignee"] = False
        self.ctx.config["registry"] = payload
        unassigned = json.loads(self.runtime.update(
            {"route_id": self.route_id, "issue_id": "issue-1", "assignee_id": None},
            tool_context=SimpleNamespace(**{**vars(self.source), "message_id": "unassign-message"}),
        ))
        self.assertTrue(unassigned["ok"])
        self.assertEqual(self.api.updates[-1][1], {"assignee_id": None, "assignee_type": None})

    def test_confirmed_update_with_failed_readback_retries_only_get(self) -> None:
        get_issue = self.api.get_issue
        self.api.get_issue = Mock(side_effect=[
            dict(self.api.issue),
            BridgeError("api_unavailable", "readback offline", retryable=True),
        ])
        args = {"route_id": self.route_id, "issue_id": "issue-1", "status": "done"}
        first = json.loads(self.runtime.update(args, tool_context=self.source))
        self.assertEqual(first["error_code"], "assignee_verification_failed")
        self.assertEqual(len(self.api.updates), 1)
        self.api.get_issue = get_issue
        second = json.loads(self.runtime.update(args, tool_context=self.source))
        self.assertTrue(second["ok"])
        self.assertEqual(len(self.api.updates), 1)

    def test_assignment_change_changes_operation_hash(self) -> None:
        first = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": MEMBER_UUID, "assignee_type": "member"},
            tool_context=self.source,
        ))
        second = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "assignee_id": AGENT_UUID, "assignee_type": "agent"},
            tool_context=self.source,
        ))
        self.assertTrue(first["ok"])
        self.assertEqual(second["error_code"], "operation_conflict")
        self.assertEqual(len(self.api.create_calls), 1)

    def test_default_assignee_change_conflicts_with_an_accepted_operation(self) -> None:
        first = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertTrue(first["ok"])
        payload = copy.deepcopy(self.payload)
        payload["routes"][0]["default_assignee"] = {"id": AGENT_UUID, "type": "agent"}
        self.ctx.config["registry"] = payload
        second = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task"}, tool_context=self.source,
        ))
        self.assertEqual(second["error_code"], "operation_conflict")
        self.assertEqual(len(self.api.create_calls), 1)

    def test_related_issue_identifier_limit_accepts_16_and_rejects_17_before_post(self) -> None:
        accepted = [f"73AN-{index}" for index in range(16)]
        result = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "related_issue_ids": accepted},
            tool_context=self.source,
        ))
        self.assertTrue(result["ok"])
        self.assertIn(("set", "issue-1", "related_issue_ids", json.dumps(accepted, separators=(",", ":"))),
                      self.api.metadata_calls)

        self.api = _Api()
        self.runtime._api = lambda registry, route: self.api
        rejected = json.loads(self.runtime.send(
            {"route_id": self.route_id, "title": "Task", "related_issue_ids": accepted + ["73AN-16"]},
            tool_context=SimpleNamespace(**{**vars(self.source), "message_id": "too-many-related"}),
        ))
        self.assertEqual(rejected["error_code"], "invalid_arguments")
        self.assertEqual(self.api.create_calls, [])

    def test_tool_schemas_expose_typed_assignment_and_related_issue_fields(self) -> None:
        schemas = {name: properties for name, _, properties, _, _ in WORKSPACE_TOOLS}
        self.assertEqual(schemas["multica_workspace_send"]["assignee_type"]["enum"], ["member", "agent", "squad"])
        self.assertEqual(schemas["multica_workspace_send"]["related_issue_ids"]["maxItems"], 16)
        self.assertEqual(schemas["multica_workspace_update"]["assignee_id"]["type"], ["string", "null"])


if __name__ == "__main__":
    unittest.main()
