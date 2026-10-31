from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.dispatcher import (
    MAX_SERVICE_LIFETIME_SECONDS,
    SOCKET_IDLE_SECONDS,
    BridgeDispatcher,
    _activation_listener,
    _has_trusted_gateway_parent,
    _is_worker_scope_leader,
    _read_connection,
    _serve_connection,
    _service_accept_timeout,
    is_kanban_worker_process,
    is_kanban_worker_scope,
    is_trusted_gateway_process,
    linux_peer_pidfd,
    linux_pidfd_open,
    main,
    peer_pidfd_is_alive,
)
from bridge.errors import BridgeError
from bridge.multica_api import ResultSnapshot
from bridge.state import DeliveryStore
from bridge.validation import MAX_IPC_REQUEST_BYTES
from bridge.webhook import WebhookResult
from tests.helpers import (
    TEST_CONNECTION_ID,
    TEST_HMAC_SECRET,
    TEST_PAT,
    TEST_ROUTE_ID,
    TEST_ROUTE_POLICY_FINGERPRINT,
    TEST_WEBHOOK_URL,
    TEST_WORKSPACE_KEY,
    isolated_bridge_config,
    sample_request,
)


class FakeWebhook:
    def __init__(self, **_kwargs):
        pass

    def send(self, _url, **_kwargs):
        return WebhookResult(True, "accepted", "pending", "delivery-1", "run-1", 200)


class FakeApi:
    def __init__(self, *_args, **_kwargs):
        pass

    def snapshot(self, _autopilot_id, _run_id):
        return ResultSnapshot(
            "succeeded",
            "completed",
            "issue-1",
            "task-1",
            "Multica execution status: succeeded.",
            "a" * 64,
        )


class DispatcherTests(unittest.TestCase):
    def test_activation_idle_retirement_exceeds_normal_polling_cadence(self) -> None:
        self.assertGreaterEqual(SOCKET_IDLE_SECONDS, 90.0)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        state = root / "state"
        state.mkdir(mode=0o700)
        self.store = DeliveryStore(state / "deliveries.sqlite3")
        self.creds = root / "credentials"
        self.creds.mkdir(mode=0o700)
        (self.creds / "HMB_WEBHOOK_URL").write_text(TEST_WEBHOOK_URL, encoding="utf-8")
        (self.creds / "HMB_HMAC_SIGNING_SECRET").write_text(TEST_HMAC_SECRET, encoding="utf-8")
        (self.creds / "HMB_MULTICA_PAT").write_text(TEST_PAT, encoding="ascii")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_main_requires_route_specific_config_path(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(main(["--check-route-config"]), 1)

    def _dispatcher(self, config=None) -> BridgeDispatcher:
        return BridgeDispatcher(
            config or isolated_bridge_config(),
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: True,
            worker_process_check=lambda *_args: True,
            peer_process_alive_check=lambda _pidfd: True,
            webhook_client_factory=FakeWebhook,
            api_client_factory=FakeApi,
        )

    def test_socket_peer_pidfd_is_bound_to_live_original_process(self) -> None:
        left, right = socket.socketpair()
        peer_pidfd = None
        try:
            try:
                peer_pidfd = linux_peer_pidfd(left)
            except BridgeError:
                self.skipTest("kernel does not provide SO_PEERPIDFD")
            self.assertTrue(peer_pidfd_is_alive(peer_pidfd))
        finally:
            if peer_pidfd is not None:
                os.close(peer_pidfd)
            left.close()
            right.close()

    def test_linux_pidfd_open_uses_libc_fallback_without_python_wrapper(self) -> None:
        with patch.object(os, "pidfd_open", None, create=True), patch(
            "bridge.dispatcher._libc_pidfd_open",
            return_value=321,
        ) as libc_fallback:
            self.assertEqual(linux_pidfd_open(123), 321)
        libc_fallback.assert_called_once_with(123)

    def test_precheck_rejects_peer_that_exits_during_authorization(self) -> None:
        dispatcher = self._dispatcher()
        liveness = iter((True, False))
        dispatcher.peer_process_alive_check = lambda _pidfd: next(liveness)
        with self.assertRaises(BridgeError) as error:
            dispatcher.precheck_peer(peer_pid=200, peer_uid=12345, peer_pidfd=200)
        self.assertEqual(error.exception.code, "peer_auth_failed")

    def test_send_check_and_ack_operations_share_service_policy(self) -> None:
        dispatcher = self._dispatcher()
        before = dispatcher.handle(
            json.dumps({"operation": "has_delivery", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(before, {"ok": True, "has_delivery": False})
        raw = json.dumps({"operation": "send", "request": sample_request()}).encode()
        sent = dispatcher.handle(raw, peer_pid=200, peer_uid=12345, peer_pidfd=200)
        self.assertTrue(sent["ok"])
        record = self.store.get_delivery(
            connection_key=TEST_ROUTE_ID,
            source_board="example-board",
            source_task_id="task_12345678",
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.route_id, TEST_ROUTE_ID)
        self.assertEqual(record.connection_id, TEST_CONNECTION_ID)
        self.assertEqual(record.workspace_key, TEST_WORKSPACE_KEY)
        self.assertEqual(record.workspace_id, isolated_bridge_config().connection.workspace_id)
        self.assertEqual(record.multica_origin, isolated_bridge_config().connection.multica_origin)
        self.assertEqual(record.autopilot_id, isolated_bridge_config().connection.autopilot_id)
        self.assertEqual(record.trigger_id, isolated_bridge_config().connection.trigger_id)
        self.assertEqual(record.security_mode, "isolated")
        self.assertEqual(record.route_policy_fingerprint, TEST_ROUTE_POLICY_FINGERPRINT)
        after = dispatcher.handle(
            json.dumps({"operation": "has_delivery", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(after, {"ok": True, "has_delivery": True})
        check = dispatcher.handle(
            json.dumps({"operation": "check_result", "request": sample_request(run_id="13")}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertTrue(check["comment_required"])
        ack = dispatcher.handle(
            json.dumps(
                {
                    "operation": "finish_result_comment",
                    "request": sample_request(run_id="13"),
                    "request_id": sent["request_id"],
                    "fingerprint": check["comment_fingerprint"],
                    "published": True,
                }
            ).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(ack, {"ok": True, "acknowledged": True})

    def test_isolated_reconfiguration_cannot_retarget_existing_delivery(self) -> None:
        original = isolated_bridge_config()
        sent = self._dispatcher(original).handle(
            json.dumps({"operation": "send", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertTrue(sent["ok"])

        api_calls = []

        class CapturingApi:
            def __init__(self, origin, _pat, workspace_id, **_kwargs):
                api_calls.append(("init", origin, workspace_id))

            def snapshot(self, autopilot_id, run_id):
                api_calls.append(("snapshot", autopilot_id, run_id))
                return ResultSnapshot(
                    "succeeded",
                    "completed",
                    "issue-1",
                    "task-1",
                    "Multica execution status: succeeded.",
                    "d" * 64,
                )

        changed = isolated_bridge_config(
            workspace_id="workspace-replacement",
            autopilot_id="autopilot-replacement",
            trigger_id="trigger-replacement",
        )
        dispatcher = BridgeDispatcher(
            changed,
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: True,
            worker_process_check=lambda *_args: True,
            peer_process_alive_check=lambda _pidfd: True,
            webhook_client_factory=FakeWebhook,
            api_client_factory=CapturingApi,
        )
        visible = dispatcher.handle(
            json.dumps({"operation": "has_delivery", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(visible, {"ok": True, "has_delivery": True})

        result = dispatcher.handle(
            json.dumps({"operation": "check_result", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(api_calls[0], ("init", original.connection.multica_origin, original.connection.workspace_id))
        self.assertEqual(api_calls[1], ("snapshot", original.connection.autopilot_id, "run-1"))

        retry = dispatcher.handle(
            json.dumps({"operation": "send", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertFalse(retry["ok"])
        self.assertEqual(retry["error_code"], "route_snapshot_conflict")

    def test_gateway_readiness_validates_credentials_without_external_request(self) -> None:
        dispatcher = BridgeDispatcher(
            isolated_bridge_config(),
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: False,
            worker_process_check=lambda *_args: False,
            gateway_process_check=lambda *_args: True,
            peer_process_alive_check=lambda _pidfd: True,
            webhook_client_factory=FakeWebhook,
            api_client_factory=FakeApi,
        )
        result = dispatcher.handle(
            json.dumps({"operation": "readiness"}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(
            result,
            {
                "ok": True,
                "ready": True,
                "policy_fingerprint": isolated_bridge_config().connection.policy_fingerprint,
                "route_policy_fingerprint": TEST_ROUTE_POLICY_FINGERPRINT,
            },
        )

        (self.creds / "HMB_HMAC_SIGNING_SECRET").unlink()
        failed = dispatcher.handle(
            json.dumps({"operation": "readiness"}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertFalse(failed["ok"])
        self.assertEqual(failed["error_code"], "credential_invalid")

    def test_worker_cannot_use_gateway_only_readiness_operation(self) -> None:
        dispatcher = BridgeDispatcher(
            isolated_bridge_config(),
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: True,
            worker_process_check=lambda *_args: True,
            gateway_process_check=lambda *_args: False,
            peer_process_alive_check=lambda _pidfd: True,
        )
        result = dispatcher.handle(
            json.dumps({"operation": "readiness"}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(result["error_code"], "worker_context_invalid")

    def test_peer_uid_and_exact_worker_scope_fail_closed(self) -> None:
        denied = self._dispatcher().handle(
            json.dumps({"operation": "send", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=99999,
            peer_pidfd=200,
        )
        self.assertEqual(denied["error_code"], "permission_denied")

        dispatcher = BridgeDispatcher(
            isolated_bridge_config(),
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: False,
            worker_process_check=lambda *_args: True,
            peer_process_alive_check=lambda _pidfd: True,
        )
        denied = dispatcher.handle(
            json.dumps({"operation": "send", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(denied["error_code"], "worker_context_invalid")

    def test_unexpected_exception_is_redacted(self) -> None:
        class ExplodingFactory:
            def __init__(self, **_kwargs):
                raise RuntimeError("secret internal detail")

        dispatcher = BridgeDispatcher(
            isolated_bridge_config(),
            self.store,
            self.creds,
            worker_scope_check=lambda *_args: True,
            worker_process_check=lambda *_args: True,
            peer_process_alive_check=lambda _pidfd: True,
            webhook_client_factory=ExplodingFactory,
        )
        result = dispatcher.handle(
            json.dumps({"operation": "send", "request": sample_request()}).encode(),
            peer_pid=200,
            peer_uid=12345,
            peer_pidfd=200,
        )
        self.assertEqual(result["error_code"], "internal_error")
        self.assertNotIn("secret internal detail", repr(result))

    def test_connection_handler_prechecks_peer_before_read(self) -> None:
        class Unreadable:
            def __init__(self):
                self.read_attempted = False
                self.response = b""

            def recv(self, _size):
                self.read_attempted = True
                raise AssertionError("must not read")

            def sendall(self, data):
                self.response += data

            def shutdown(self, _how):
                pass

        connection = Unreadable()
        dispatcher = self._dispatcher()
        dispatcher.worker_process_check = lambda *_args: False
        with (
            patch("bridge.dispatcher.linux_peer_credentials", return_value=(200, 12345)),
            patch("bridge.dispatcher.linux_peer_pidfd", return_value=123456),
        ):
            _serve_connection(dispatcher, connection)
        self.assertFalse(connection.read_attempted)
        self.assertEqual(json.loads(connection.response)["error_code"], "worker_context_invalid")

    def test_read_connection_obeys_full_ipc_bound_and_one_message(self) -> None:
        def read(payload: bytes) -> bytes:
            sender, receiver = socket.socketpair()
            try:
                sender.sendall(payload)
                sender.shutdown(socket.SHUT_WR)
                return _read_connection(receiver)
            finally:
                sender.close()
                receiver.close()

        self.assertEqual(read(b'{"operation":"x"}\n'), b'{"operation":"x"}')
        with self.assertRaises(BridgeError) as multiple:
            read(b"{}\n{}\n")
        self.assertEqual(multiple.exception.code, "invalid_request")
        with self.assertRaises(BridgeError) as incomplete:
            read(b"{}")
        self.assertEqual(incomplete.exception.code, "request_too_large")
        with self.assertRaises(BridgeError) as oversized:
            read(b"x" * (MAX_IPC_REQUEST_BYTES + 1) + b"\n")
        self.assertEqual(oversized.exception.code, "request_too_large")

    def test_dynamic_gateway_unit_must_be_exact_direct_parent(self) -> None:
        def write_proc(root: Path, pid: int, ppid: int, cgroup: str) -> None:
            proc = root / str(pid)
            proc.mkdir()
            (proc / "stat").write_text(f"{pid} (worker) S {ppid} 0 0 0\n", encoding="ascii")
            (proc / "cgroup").write_text(f"0::{cgroup}\n", encoding="ascii")
            (proc / "cmdline").write_bytes(
                b"hermes\0--cli\0chat\0-q\0work kanban task task_12345678\0"
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup_root = root / "sys-fs-cgroup"
            cgroup_root.mkdir()
            (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
            scope = "hermes-worker-kanban-task_12345678-run-12.scope"
            scope_prefix = "/user.slice/user-12345.slice/user@12345.service/app.slice"
            scope_dir = (
                cgroup_root
                / "user.slice"
                / "user-12345.slice"
                / "user@12345.service"
                / "app.slice"
                / scope
            )
            scope_dir.mkdir(parents=True)
            # A wrapped PID can make a child numerically lower than its worker parent.
            (scope_dir / "cgroup.procs").write_text("5\n300\n", encoding="ascii")
            write_proc(
                root,
                300,
                200,
                f"{scope_prefix}/{scope}",
            )
            write_proc(root, 5, 300, f"{scope_prefix}/{scope}")
            write_proc(root, 200, 1, "/system.slice/custom-hermes-gateway.service")
            self.assertTrue(
                is_kanban_worker_scope(
                    300,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                    parent_pidfd_open=lambda _pid: linux_pidfd_open(os.getpid()),
                )
            )
            self.assertTrue(
                is_kanban_worker_process(
                    300,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                    parent_pidfd_open=lambda _pid: linux_pidfd_open(os.getpid()),
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    300,
                    12345,
                    "other-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            relocated_scope = "hermes-worker-kanban-relocated_task-run-88.scope"
            relocated_dir = (
                cgroup_root
                / "user.slice"
                / "user-12345.slice"
                / "user@12345.service"
                / "app.slice"
                / relocated_scope
            )
            relocated_dir.mkdir(parents=True)
            (relocated_dir / "cgroup.procs").write_text("600\n", encoding="ascii")
            write_proc(
                root,
                600,
                200,
                f"{scope_prefix}/{relocated_scope}",
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    600,
                    12345,
                    "relocated_task",
                    "88",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                    parent_pidfd_open=lambda _pid: linux_pidfd_open(os.getpid()),
                )
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    5,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    5,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            forged_dir = (
                cgroup_root
                / "user.slice"
                / "user-12345.slice"
                / "user@12345.service"
                / "app.slice"
                / "delegated.scope"
                / scope
            )
            forged_dir.mkdir(parents=True)
            (forged_dir / "cgroup.procs").write_text("400\n", encoding="ascii")
            write_proc(
                root,
                400,
                200,
                f"{scope_prefix}/delegated.scope/{scope}",
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    400,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    400,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            forged_scope = "hermes-worker-kanban-forged_task-run-77.scope"
            forged_scope_dir = (
                cgroup_root
                / "user.slice"
                / "user-12345.slice"
                / "user@12345.service"
                / "app.slice"
                / forged_scope
            )
            forged_scope_dir.mkdir(parents=True)
            (forged_scope_dir / "cgroup.procs").write_text("500\n", encoding="ascii")
            write_proc(
                root,
                500,
                300,
                f"{scope_prefix}/{forged_scope}",
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    500,
                    12345,
                    "forged_task",
                    "77",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    500,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

    def test_parent_pidfd_pins_the_observed_gateway_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_pid = os.getpid()
            parent = root / str(parent_pid)
            parent.mkdir()
            (parent / "cgroup").write_text(
                "0::/system.slice/custom-hermes-gateway.service\n",
                encoding="ascii",
            )
            with patch(
                "bridge.dispatcher._read_parent_pid",
                side_effect=[parent_pid, parent_pid, parent_pid],
            ), patch("bridge.dispatcher.linux_pidfd_open", wraps=linux_pidfd_open) as pidfd_open:
                trusted = _has_trusted_gateway_parent(
                    300,
                    "custom-hermes-gateway.service",
                    root,
                )
            self.assertTrue(trusted)
            pidfd_open.assert_called_once_with(parent_pid)

    def test_parent_pid_change_during_cgroup_check_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "200"
            parent.mkdir()
            (parent / "cgroup").write_text(
                "0::/system.slice/custom-hermes-gateway.service\n",
                encoding="ascii",
            )
            with patch(
                "bridge.dispatcher._read_parent_pid",
                side_effect=[200, 200, 201],
            ) as read_parent_pid:
                trusted = _has_trusted_gateway_parent(
                    300,
                    "custom-hermes-gateway.service",
                    root,
                    parent_pidfd_open=lambda _pid: linux_pidfd_open(os.getpid()),
                )
            self.assertFalse(trusted)
            self.assertEqual(read_parent_pid.call_count, 3)

    def test_gateway_process_requires_exact_configured_service_cgroup(self) -> None:
        def write_cgroup(root: Path, pid: int, cgroup: str) -> None:
            proc = root / str(pid)
            proc.mkdir()
            (proc / "cgroup").write_text(f"0::{cgroup}\n", encoding="ascii")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup_root = root / "sys-fs-cgroup"
            cgroup_root.mkdir()
            (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
            write_cgroup(root, 200, "/system.slice/custom-hermes-gateway.service")
            write_cgroup(root, 201, "/system.slice/other.service")
            self.assertTrue(
                is_trusted_gateway_process(
                    200,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_trusted_gateway_process(
                    201,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            (root / "200" / "cgroup").write_text(
                "0::/system.slice/custom-hermes-gateway.service\n2:cpu,cpuacct:/system.slice/gateway\n",
                encoding="ascii",
            )
            self.assertFalse(
                is_trusted_gateway_process(
                    200,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            (root / "200" / "cgroup").write_text(
                "2:cpu,cpuacct:/system.slice/custom-hermes-gateway.service\n",
                encoding="ascii",
            )
            self.assertFalse(
                is_trusted_gateway_process(
                    200,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            (root / "200" / "cgroup").write_text(
                "0::/system.slice/custom-hermes-gateway.service\n",
                encoding="ascii",
            )
            (cgroup_root / "cgroup.controllers").unlink()
            self.assertFalse(
                is_trusted_gateway_process(
                    200,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

    def test_reparented_scope_child_loses_gateway_ancestry(self) -> None:
        def write_proc(root: Path, pid: int, ppid: int, cgroup: str) -> None:
            proc = root / str(pid)
            proc.mkdir()
            (proc / "stat").write_text(f"{pid} (worker) S {ppid} 0 0 0\n", encoding="ascii")
            (proc / "cgroup").write_text(f"0::{cgroup}\n", encoding="ascii")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup_root = root / "sys-fs-cgroup"
            cgroup_root.mkdir()
            (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
            scope = "hermes-worker-kanban-task_12345678-run-12.scope"
            scope_prefix = "/user.slice/user-12345.slice/user@12345.service/app.slice"
            scope_path = f"{scope_prefix}/{scope}"
            scope_dir = (
                cgroup_root
                / "user.slice"
                / "user-12345.slice"
                / "user@12345.service"
                / "app.slice"
                / scope
            )
            scope_dir.mkdir(parents=True)
            (scope_dir / "cgroup.procs").write_text("5\n", encoding="ascii")
            write_proc(root, 5, 1, scope_path)
            write_proc(root, 1, 0, "/init.scope")

            self.assertFalse(
                is_kanban_worker_scope(
                    5,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    5,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            nested_scope = scope_dir / "nested"
            nested_scope.mkdir()
            (nested_scope / "cgroup.procs").write_text("301\n", encoding="ascii")
            write_proc(
                root,
                301,
                300,
                f"{scope_prefix}/{scope}/nested",
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    301,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    301,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

            (cgroup_root / "cgroup.controllers").unlink()
            self.assertFalse(
                is_kanban_worker_process(
                    300,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_scope(
                    5,
                    12345,
                    "task_12345678",
                    "12",
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )
            self.assertFalse(
                is_kanban_worker_process(
                    5,
                    12345,
                    "custom-hermes-gateway.service",
                    proc_root=root,
                    cgroup_root=cgroup_root,
                )
            )

    def test_worker_scope_rejects_hybrid_cgroup_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup_root = root / "sys-fs-cgroup"
            cgroup_root.mkdir()
            (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
            scope = "hermes-worker-kanban-task_12345678-run-12.scope"
            scope_path = "/user.slice/user-12345.slice/user@12345.service/app.slice/" + scope
            scope_dir = cgroup_root.joinpath(*Path(scope_path).parts[1:])
            scope_dir.mkdir(parents=True)
            (scope_dir / "cgroup.procs").write_text("300\n", encoding="ascii")
            proc = root / "300"
            proc.mkdir()
            (proc / "stat").write_text("300 (worker) S 200 0 0 0\n", encoding="ascii")
            (proc / "cgroup").write_text(
                f"0::{scope_path}\n2:cpu,cpuacct:/user.slice/worker\n",
                encoding="ascii",
            )
            self.assertFalse(_is_worker_scope_leader(300, root, cgroup_root))

    def test_activation_listener_requires_exact_instance_socket(self) -> None:
        class Listener:
            def __init__(self):
                self.closed = False
                self.timeout = None

            def getsockopt(self, *_args):
                return 1

            def getsockname(self):
                return "/run/hermes-multica-bridge/example.sock"

            def settimeout(self, timeout):
                self.timeout = timeout

            def close(self):
                self.closed = True

        listener = Listener()
        env = {"LISTEN_PID": "999", "LISTEN_FDS": "1"}
        with patch("bridge.dispatcher.os.getpid", return_value=999), patch(
            "bridge.dispatcher.socket.fromfd", return_value=listener
        ):
            self.assertIs(
                _activation_listener("/run/hermes-multica-bridge/example.sock", env),
                listener,
            )

        listener = Listener()
        with patch("bridge.dispatcher.os.getpid", return_value=999), patch(
            "bridge.dispatcher.socket.fromfd", return_value=listener
        ), self.assertRaises(BridgeError):
            _activation_listener("/run/hermes-multica-bridge/other.sock", env)
        self.assertTrue(listener.closed)

    def test_service_lifetime_bounds_accepts_and_drains_an_accepted_request(self) -> None:
        from types import SimpleNamespace

        class FakeClock:
            value = 100.0

            def __call__(self):
                return self.value

        class FakeConnection:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class FakeListener:
            def __init__(self):
                self.closed = False
                self.timeouts = []
                self.accept_calls = 0

            def settimeout(self, value):
                self.timeouts.append(value)

            def accept(self):
                self.accept_calls += 1
                return FakeConnection(), None

            def close(self):
                self.closed = True

        self.assertEqual(_service_accept_timeout(1_000.0, now=0.0), SOCKET_IDLE_SECONDS)
        self.assertEqual(_service_accept_timeout(25.0, now=10.0), 15.0)
        self.assertEqual(_service_accept_timeout(10.0, now=10.0), 0.0)

        clock = FakeClock()
        listener = FakeListener()
        config = SimpleNamespace(connection=SimpleNamespace(socket_path="/run/example.sock"))
        served = []

        def serve_one(_dispatcher, _connection):
            served.append(True)
            # Model a bounded request that finishes after the age limit. The
            # sender must finish it, then retire before accepting another one.
            clock.value += MAX_SERVICE_LIFETIME_SECONDS + 1

        with (
            patch.dict(
                os.environ,
                {"HMB_CONFIG": "/tmp/config.toml", "STATE_DIRECTORY": "/tmp/state"},
            ),
            patch("bridge.dispatcher.load_config", return_value=config),
            patch("bridge.dispatcher.DeliveryStore", return_value=object()),
            patch("bridge.dispatcher.BridgeDispatcher", return_value=object()),
            patch("bridge.dispatcher._activation_listener", return_value=listener),
            patch("bridge.dispatcher._serve_connection", side_effect=serve_one),
            patch("bridge.dispatcher.time.monotonic", side_effect=clock),
        ):
            self.assertEqual(main(["--activation"]), 0)

        self.assertEqual(served, [True])
        self.assertEqual(listener.accept_calls, 1)
        self.assertEqual(listener.timeouts, [SOCKET_IDLE_SECONDS])
        self.assertTrue(listener.closed)


if __name__ == "__main__":
    unittest.main()
