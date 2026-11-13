from __future__ import annotations

import asyncio
import json
import os
import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bridge.errors import BridgeError
from bridge.notify_readiness import MAX_FRAME, MAX_PROJECTS, NotifyReadinessClient
from notify.config import NotifyError, parse_config
from notify.readiness_ipc import ReadinessServer

WORKSPACE_ID = "11111111-1111-4111-8111-111111111111"
PROJECT_ID = "22222222-2222-4222-8222-222222222222"


class _State:
    def __init__(self):
        self.queries = []
        self.data = [{
            "profile": "default",
            "route": "canary-wake",
            "wake_enabled": 1,
            "subscription_enabled": 1,
            "platform": "telegram",
            "chat_id": "test-chat",
            "thread_id": "test-thread",
            "chat_type": "thread",
            "workspace_key": "internal-workspace",
            "project_id": PROJECT_ID,
            "data_json": json.dumps({"workspace_id": WORKSPACE_ID}),
            "workspace_configured": 1,
            "workspace_enabled": 1,
            "account_configured": 1,
        }]

    def rows(self, query, params=()):
        self.queries.append((query, params))
        return [row for row in self.data if row["project_id"] == params[0]]


def _config(path, *, uid=None, profiles=None):
    return SimpleNamespace(
        readiness_ipc={
            "enabled": True,
            "socket_path": str(path),
            "peers": [{"uid": os.getuid() if uid is None else uid,
                       "profiles": ("default",) if profiles is None else tuple(profiles)}],
        },
        wake={
            "enabled": True,
            "webhook_policy_file": "/unused/test-policy.json",
            "routes": {"canary-key": {"profile": "default", "route": "canary-wake"}},
        },
    )


async def _raw_request(path, body: bytes) -> dict:
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(struct.pack("!I", len(body)) + body)
    await writer.drain()
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    response = json.loads(await reader.readexactly(size))
    writer.close()
    await writer.wait_closed()
    return response


def test_readiness_ipc_returns_only_project_readiness_and_authenticates_peer(tmp_path):
    async def run():
        socket_path = tmp_path / "run" / "readiness.sock"
        socket_path.parent.mkdir(mode=0o700)
        state = _State()
        server = ReadinessServer(_config(socket_path), state)
        with (
            patch("notify.readiness_ipc.load_webhook_policy", return_value={"fixture": True}),
            patch("notify.readiness_ipc.verify_webhook_policy", return_value=None) as verify,
        ):
            await server.start()
            try:
                assert socket_path.parent.stat().st_mode & 0o777 == 0o711
                assert socket_path.stat().st_mode & 0o777 == 0o666
                client = NotifyReadinessClient(str(socket_path))
                result = await asyncio.to_thread(
                    client.check,
                    "default",
                    [{"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID}],
                )
                assert result == [{
                    "workspace_id": WORKSPACE_ID,
                    "project_id": PROJECT_ID,
                    "wake_ready": True,
                    "reason": "ready",
                    "wake_route_id": "canary-wake",
                }]
                verify.assert_called_once()
                assert len(state.queries) == 1
                assert "credential" not in repr(result).lower()
                assert "token" not in repr(result).lower()

                denied = await _raw_request(
                    str(socket_path),
                    b'{"profile":"om73","projects":[{"workspace_id":"'
                    + WORKSPACE_ID.encode()
                    + b'","project_id":"'
                    + PROJECT_ID.encode()
                    + b'"}]}',
                )
                assert denied == {"ok": False, "error_code": "ipc_peer_denied"}
                assert len(state.queries) == 1

                malformed_profile = await _raw_request(
                    str(socket_path),
                    json.dumps({"profile": [], "projects": [{
                        "workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID,
                    }]}).encode(),
                )
                assert malformed_profile == {"ok": False, "error_code": "ipc_request_invalid"}
                assert len(state.queries) == 1

                oversized = await _raw_request(str(socket_path), b" " * (MAX_FRAME + 1))
                assert oversized == {"ok": False, "error_code": "ipc_request_invalid"}
                assert len(state.queries) == 1
            finally:
                await server.close()

    asyncio.run(run())


def test_readiness_ipc_rejects_unallowlisted_uid_before_reading_request(tmp_path):
    async def run():
        socket_path = tmp_path / "run" / "readiness.sock"
        socket_path.parent.mkdir(mode=0o700)
        state = _State()
        server = ReadinessServer(_config(socket_path, uid=os.getuid() + 1), state)
        with patch("notify.readiness_ipc.load_webhook_policy", return_value={}):
            await server.start()
            try:
                denied = await _raw_request(str(socket_path), b"not-json")
                assert denied == {"ok": False, "error_code": "ipc_peer_denied"}
                assert state.queries == []
            finally:
                await server.close()

    asyncio.run(run())


def test_source_profile_can_check_a_wake_route_owned_by_default_profile(tmp_path):
    async def run():
        socket_path = tmp_path / "run" / "readiness.sock"
        socket_path.parent.mkdir(mode=0o700)
        state = _State()
        server = ReadinessServer(_config(socket_path, profiles=["om73"]), state)
        with (
            patch("notify.readiness_ipc.load_webhook_policy", return_value={("default", "canary-wake"): {}}),
            patch("notify.readiness_ipc.verify_webhook_policy", return_value=None) as verify,
        ):
            await server.start()
            try:
                result = await asyncio.to_thread(
                    NotifyReadinessClient(str(socket_path)).check,
                    "om73",
                    [{"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID}],
                )
                assert result[0]["wake_ready"] is True
                verify.assert_called_once()
                assert verify.call_args.args[:3] == ({("default", "canary-wake"): {}}, "default", "canary-wake")
            finally:
                await server.close()

    asyncio.run(run())


def test_readiness_ipc_returns_one_result_for_every_project(tmp_path):
    async def run():
        second_project_id = "33333333-3333-4333-8333-333333333333"
        socket_path = tmp_path / "run" / "readiness.sock"
        socket_path.parent.mkdir(mode=0o700)
        state = _State()
        state.data.append({
            **state.data[0],
            "route": "second-canary-wake",
            "project_id": second_project_id,
        })
        config = _config(socket_path)
        config.wake["routes"]["second-canary-key"] = {
            "profile": "default", "route": "second-canary-wake",
        }
        server = ReadinessServer(config, state)
        with (
            patch("notify.readiness_ipc.load_webhook_policy", return_value={}),
            patch("notify.readiness_ipc.verify_webhook_policy", return_value=None) as verify,
        ):
            await server.start()
            try:
                result = await asyncio.to_thread(
                    NotifyReadinessClient(str(socket_path)).check,
                    "default",
                    [
                        {"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID},
                        {"workspace_id": WORKSPACE_ID, "project_id": second_project_id},
                    ],
                )
                assert [item["project_id"] for item in result] == [PROJECT_ID, second_project_id]
                assert all(item["wake_ready"] for item in result)
                assert verify.call_count == 2
            finally:
                await server.close()

    asyncio.run(run())


def test_readiness_database_failure_returns_client_compatible_unavailable_rows(tmp_path):
    async def run():
        socket_path = tmp_path / "run" / "readiness.sock"
        socket_path.parent.mkdir(mode=0o700)
        state = _State()

        def unavailable_rows(*_args, **_kwargs):
            raise RuntimeError("database unavailable")

        state.rows = unavailable_rows
        server = ReadinessServer(_config(socket_path), state)
        with patch("notify.readiness_ipc.load_webhook_policy", return_value={}):
            await server.start()
            try:
                result = await asyncio.to_thread(
                    NotifyReadinessClient(str(socket_path)).check,
                    "default",
                    [{"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID}],
                )
                assert result == [{
                    "workspace_id": WORKSPACE_ID,
                    "project_id": PROJECT_ID,
                    "wake_ready": False,
                    "reason": "source_unavailable",
                    "wake_route_id": None,
                }]
            finally:
                await server.close()

    asyncio.run(run())


def test_readiness_client_rejects_malformed_project_input_before_connect(tmp_path):
    client = NotifyReadinessClient(str(tmp_path / "missing.sock"))
    with pytest.raises(BridgeError) as raised:
        client.check("default", [{"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID, "extra": "x"}])
    assert raised.value.code == "invalid_arguments"

    projects = [{"workspace_id": WORKSPACE_ID, "project_id": PROJECT_ID}] * 2
    with pytest.raises(BridgeError) as duplicate:
        client.check("default", projects)
    assert duplicate.value.code == "invalid_arguments"

    too_many = [
        {"workspace_id": WORKSPACE_ID, "project_id": f"project-{index}"}
        for index in range(MAX_PROJECTS + 1)
    ]
    with pytest.raises(BridgeError) as oversized:
        client.check("default", too_many)
    assert oversized.value.code == "invalid_arguments"


def test_readiness_receive_enforces_one_deadline_across_partial_reads():
    clock = [0.0]

    class SlowSocket:
        timeout = None

        def settimeout(self, value):
            self.timeout = value

        def recv(self, _size):
            clock[0] += 0.06
            return b"x"

    with (
        patch("bridge.notify_readiness.time.monotonic", side_effect=lambda: clock[0]),
        pytest.raises(TimeoutError),
    ):
        NotifyReadinessClient._receive(SlowSocket(), 3, deadline=0.1)


def test_notify_config_requires_a_valid_readiness_peer_allowlist(tmp_path):
    raw = {
        "service": {
            "db_path": str(tmp_path / "notify.db"),
            "runtime_dir": str(tmp_path / "notify-run"),
        },
        "wake": {
            "enabled": True,
            "routes": {"canary-key": {"profile": "default", "route": "canary-wake"}},
        },
        "readiness_ipc": {
            "enabled": True,
            "peers": [{"uid": 1000, "profiles": ["default"]}],
        },
    }
    parsed = parse_config(raw)
    assert parsed.readiness_ipc["peers"] == ({"uid": 1000, "profiles": ("default",)},)

    raw["readiness_ipc"]["peers"][0]["profiles"] = ["../other"]
    with pytest.raises(NotifyError):
        parse_config(raw)

    raw["readiness_ipc"]["peers"][0]["profiles"] = ["worker-a"]
    with pytest.raises(NotifyError):
        parse_config(raw)

    raw["readiness_ipc"]["peers"][0]["profiles"] = ["default"]
    raw["readiness_ipc"]["socket_path"] = str(tmp_path / "custom.sock")
    with pytest.raises(NotifyError):
        parse_config(raw)
