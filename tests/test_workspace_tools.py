from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from bridge.workspace_state import WorkspaceState
from bridge.workspace_tools import WorkspaceRuntime
from tests.test_registry import workspace_registry_payload


class _Context:
    def __init__(self, config, source):
        self.config = config
        self.profile_name = "om73"
        self.source = source

    def get_config(self, key, default=None):
        return self.config.get(key, default)


class _Api:
    def __init__(self):
        self.create_calls = []
        self.comments = []
        self.updates = []
        self.uploads = []
        self.issue = {"id": "issue-1", "workspace_id": "workspace-1", "project_id": "project-1",
                      "title": "Task", "description": "", "status": "todo", "revision": 1}
        self.parent = {"id": "parent-1", "workspace_id": "workspace-1", "project_id": "project-1"}

    def create_issue(self, **kwargs):
        self.create_calls.append(kwargs)
        return dict(self.issue)

    def get_issue(self, issue_id):
        return self.parent if issue_id == "parent-1" else dict(self.issue)

    def list_comments(self, issue_id):
        return []

    def create_comment(self, issue_id, content):
        self.comments.append((issue_id, content))
        return {"id": "comment-1", "content": content, "created_at": "now"}

    def update_issue(self, issue_id, updates):
        self.updates.append((issue_id, updates))
        return {**self.issue, **updates}

    def upload_issue_attachment(self, issue_id, filename, media_type, data):
        self.uploads.append((issue_id, filename, media_type, data))
        return {"id": "attachment-1"}


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

    def tearDown(self) -> None:
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
            {"route_id": self.route_id, "title": "Child", "parent_issue_id": "parent-1", "assignee_id": "member-1"},
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
             "assignee_id": "member-1"}, tool_context=self.source,
        ))
        self.assertTrue(comment["ok"])
        self.assertEqual(update["issue"]["status"], "done")
        self.assertEqual(self.api.comments, [("issue-1", "hello")])
        self.assertEqual(self.api.updates[0][1], {"status": "done", "assignee_id": "member-1", "assignee_type": "member"})


if __name__ == "__main__":
    unittest.main()
