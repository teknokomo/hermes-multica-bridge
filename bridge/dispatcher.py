"""Socket-activated Isolated sender for Hermes Multica Bridge."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import logging
import os
import platform
import re
import select
import socket
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .errors import BridgeError
from .protocol import MAX_IPC_RESPONSE_BYTES, validate_ipc_envelope
from .routes import BridgeConfig, load_config, read_credential
from .service import BridgeService, ServiceCredentials
from .state import DeliverySnapshot, DeliveryStore
from .validation import (
    MAX_IPC_REQUEST_BYTES,
    MAX_MULTICA_PAT_BYTES,
    SOURCE_TASK_ID_RE,
    strict_json_loads,
)
from .webhook import MulticaWebhookClient, webhook_url_fingerprint

LOGGER = logging.getLogger("hermes_multica_bridge")
# Keep the socket-activated sender alive across the normal ~30 second result
# polling cadence. With a 90 second idle retirement, ordinary polling reuses
# one process and cannot exhaust systemd's 10 starts / 600 seconds limit.
SOCKET_IDLE_SECONDS = 90.0
MAX_SERVICE_LIFETIME_SECONDS = 3_600.0
IPC_REQUEST_READ_SECONDS = 5.0
KANBAN_WORKER_SCOPE_RE = re.compile(
    r"\Ahermes-worker-kanban-[A-Za-z0-9][A-Za-z0-9_-]{0,127}-run-[1-9][0-9]{0,18}\.scope\Z"
)
# Older Python headers may omit SO_PEERPIDFD even when the kernel supports it.
_SO_PEERPIDFD_BY_MACHINE = {"parisc": 0x404B, "parisc64": 0x404B, "sparc": 0x56, "sparc64": 0x56}
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", _SO_PEERPIDFD_BY_MACHINE.get(platform.machine().lower(), 77))


def _libc_pidfd_open(pid: int) -> int:
    """Open a pidfd through libc when Python does not expose os.pidfd_open()."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        pidfd_open = libc.pidfd_open
    except (AttributeError, OSError) as exc:
        raise OSError(errno.ENOSYS, "pidfd_open is unavailable") from exc
    pidfd_open.argtypes = [ctypes.c_int, ctypes.c_uint]
    pidfd_open.restype = ctypes.c_int
    fd = int(pidfd_open(pid, 0))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


def linux_pidfd_open(pid: int) -> int:
    """Open a pidfd on supported Linux runtimes, including Python builds without the wrapper."""
    native = getattr(os, "pidfd_open", None)
    if callable(native):
        return native(pid, 0)
    return _libc_pidfd_open(pid)


def _read_process_cgroups(pid: int, proc_root: str | Path) -> tuple[tuple[str, ...], ...] | None:
    try:
        lines = (Path(proc_root) / str(pid) / "cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    groups: list[tuple[str, ...]] = []
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) == 3:
            groups.append(Path(fields[2]).parts)
    return tuple(groups)


def _worker_scope_cgroup(pid: int, proc_root: str | Path) -> tuple[str, ...] | None:
    """Return the exact Kanban worker cgroup path for one process."""
    groups = _read_process_cgroups(pid, proc_root)
    if groups is None:
        return None
    matches = [
        group
        for group in groups
        if group and KANBAN_WORKER_SCOPE_RE.fullmatch(group[-1])
    ]
    return matches[0] if len(matches) == 1 else None


def _expected_worker_scope_cgroup(peer_uid: int, unit: str) -> tuple[str, ...] | None:
    """Return the exact user-systemd path Hermes uses for transient worker scopes."""
    if type(peer_uid) is not int or peer_uid < 1 or not KANBAN_WORKER_SCOPE_RE.fullmatch(unit):
        return None
    return Path(
        "/",
        "user.slice",
        f"user-{peer_uid}.slice",
        f"user@{peer_uid}.service",
        "app.slice",
        unit,
    ).parts


def _unified_cgroup_v2_path(
    pid: int,
    proc_root: str | Path,
    cgroup_root: str | Path,
) -> tuple[str, ...] | None:
    """Return the process cgroup path only on a unified cgroup v2 host."""
    if not (Path(cgroup_root) / "cgroup.controllers").is_file():
        return None
    memberships = _read_process_cgroup_memberships(pid, proc_root)
    if memberships is None or len(memberships) != 1 or not memberships[0].startswith("0::/"):
        return None
    cgroup_path = Path(memberships[0].partition("::")[2])
    if not cgroup_path.is_absolute() or ".." in cgroup_path.parts:
        return None
    return cgroup_path.parts


def _is_worker_scope_leader(
    pid: int,
    proc_root: str | Path,
    cgroup_root: str | Path,
) -> bool:
    """Reject descendants by requiring the unique process rooted outside the worker cgroup."""
    group = _unified_cgroup_v2_path(pid, proc_root, cgroup_root)
    if group is None or not KANBAN_WORKER_SCOPE_RE.fullmatch(group[-1]):
        return False
    path = Path(cgroup_root).joinpath(*group[1:]) / "cgroup.procs"
    try:
        pids = [int(value) for value in path.read_text(encoding="ascii").split()]
    except (OSError, UnicodeError, ValueError):
        return False
    members = set(pids)
    if not members or pid not in members:
        return False
    roots: list[int] = []
    for member_pid in members:
        parent_pid = _read_parent_pid(member_pid, proc_root)
        if parent_pid is None:
            return False
        if parent_pid not in members:
            roots.append(member_pid)
    return roots == [pid]


def _read_process_cgroup_memberships(pid: int, proc_root: str | Path) -> tuple[str, ...] | None:
    """Read raw cgroup records so hybrid v1/v2 membership can be rejected."""
    try:
        lines = (Path(proc_root) / str(pid) / "cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    return tuple(lines) if lines else None


def _read_parent_pid(pid: int, proc_root: str | Path) -> int | None:
    try:
        stat_line = (Path(proc_root) / str(pid) / "stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    closing_paren = stat_line.rfind(")")
    if closing_paren < 0:
        return None
    fields = stat_line[closing_paren + 1 :].split()
    if len(fields) < 2 or not fields[1].isdigit():
        return None
    return int(fields[1])


def _worker_command_task_id(pid: int, proc_root: str | Path) -> str | None:
    """Read the task ID embedded by Hermes in the worker's launch argv."""
    try:
        raw = (Path(proc_root) / str(pid) / "cmdline").read_bytes()
    except OSError:
        return None
    try:
        args = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError:
        return None
    matches: list[str] = []
    for index, argument in enumerate(args[:-1]):
        if argument != "-q":
            continue
        query = args[index + 1]
        prefix = "work kanban task "
        if not query.startswith(prefix):
            continue
        task_id = query[len(prefix) :]
        if SOURCE_TASK_ID_RE.fullmatch(task_id):
            matches.append(task_id)
    return matches[0] if len(matches) == 1 else None


def _trusted_gateway_cgroup(unit: str) -> tuple[str, ...]:
    return Path("/", "system.slice", unit).parts


def _has_trusted_gateway_parent(
    peer_pid: int,
    trusted_gateway_unit: str,
    proc_root: str | Path,
    *,
    parent_pidfd_open: Callable[[int], int] | None = None,
) -> bool:
    """Pin the worker's parent while checking its trusted cgroup and PPID relationship."""
    expected = _trusted_gateway_cgroup(trusted_gateway_unit)
    parent_pid = _read_parent_pid(peer_pid, proc_root)
    if parent_pid is None or parent_pid <= 1:
        return False
    try:
        parent_pidfd = (
            parent_pidfd_open(parent_pid)
            if parent_pidfd_open is not None
            else linux_pidfd_open(parent_pid)
        )
    except (AttributeError, OSError, OverflowError):
        return False
    try:
        if not peer_pidfd_is_alive(parent_pidfd):
            return False
        if _read_parent_pid(peer_pid, proc_root) != parent_pid:
            return False
        groups = _read_process_cgroups(parent_pid, proc_root)
        if groups is None or expected not in groups:
            return False
        return (
            _read_parent_pid(peer_pid, proc_root) == parent_pid
            and peer_pidfd_is_alive(parent_pidfd)
        )
    except (OSError, ValueError):
        return False
    finally:
        os.close(parent_pidfd)


def is_trusted_gateway_process(
    peer_pid: int,
    trusted_gateway_unit: str,
    *,
    proc_root: str | Path = "/proc",
    cgroup_root: str | Path = "/sys/fs/cgroup",
) -> bool:
    """Require the configured Gateway unit on a unified cgroup v2 host."""
    if type(peer_pid) is not int or peer_pid < 1:
        return False
    expected = _trusted_gateway_cgroup(trusted_gateway_unit)
    group = _unified_cgroup_v2_path(peer_pid, proc_root, cgroup_root)
    return group == expected


def is_kanban_worker_process(
    peer_pid: int,
    peer_uid: int,
    trusted_gateway_unit: str,
    *,
    proc_root: str | Path = "/proc",
    cgroup_root: str | Path = "/sys/fs/cgroup",
    parent_pidfd_open: Callable[[int], int] | None = None,
) -> bool:
    """Reject peers unless they are the trusted Kanban worker scope leader."""
    if type(peer_pid) is not int or peer_pid < 1:
        return False
    peer_group = _worker_scope_cgroup(peer_pid, proc_root)
    if peer_group is None:
        return False
    expected_group = _expected_worker_scope_cgroup(peer_uid, peer_group[-1])
    if expected_group is None or peer_group != expected_group:
        return False
    if not _is_worker_scope_leader(peer_pid, proc_root, cgroup_root):
        return False
    return _has_trusted_gateway_parent(
        peer_pid,
        trusted_gateway_unit,
        proc_root,
        parent_pidfd_open=parent_pidfd_open,
    )


def is_kanban_worker_scope(
    peer_pid: int,
    peer_uid: int,
    source_task_id: str,
    worker_run_id: str,
    trusted_gateway_unit: str,
    *,
    proc_root: str | Path = "/proc",
    cgroup_root: str | Path = "/sys/fs/cgroup",
    parent_pidfd_open: Callable[[int], int] | None = None,
) -> bool:
    """Require the exact task/run scope, its leader, and the configured Gateway ancestor."""
    if type(peer_pid) is not int or peer_pid < 1:
        return False
    if _worker_command_task_id(peer_pid, proc_root) != source_task_id:
        return False
    expected_unit = f"hermes-worker-kanban-{source_task_id}-run-{worker_run_id}.scope"
    peer_group = _worker_scope_cgroup(peer_pid, proc_root)
    expected_group = _expected_worker_scope_cgroup(peer_uid, expected_unit)
    if peer_group is None or expected_group is None or peer_group != expected_group:
        return False
    if not _is_worker_scope_leader(peer_pid, proc_root, cgroup_root):
        return False
    return _has_trusted_gateway_parent(
        peer_pid,
        trusted_gateway_unit,
        proc_root,
        parent_pidfd_open=parent_pidfd_open,
    )


class BridgeDispatcher:
    """Authorize local IPC, load Isolated credentials, and invoke the shared bridge service."""

    def __init__(
        self,
        config: BridgeConfig,
        store: DeliveryStore,
        credential_dir: str | Path,
        *,
        config_path: str | Path | None = None,
        config_owner_uid: int = 0,
        worker_scope_check: Callable[[int, int, str, str, str], bool] | None = None,
        worker_process_check: Callable[[int, int, str], bool] | None = None,
        gateway_process_check: Callable[[int, str], bool] | None = None,
        peer_process_alive_check: Callable[[int], bool] | None = None,
        webhook_client_factory: Callable[..., MulticaWebhookClient] = MulticaWebhookClient,
        api_client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.credential_dir = Path(credential_dir)
        self.config_path = Path(config_path) if config_path is not None else None
        self.config_owner_uid = config_owner_uid
        self.worker_scope_check = worker_scope_check or is_kanban_worker_scope
        self.worker_process_check = worker_process_check or is_kanban_worker_process
        self.gateway_process_check = gateway_process_check or is_trusted_gateway_process
        self.peer_process_alive_check = peer_process_alive_check or peer_pidfd_is_alive
        self.webhook_client_factory = webhook_client_factory
        self.api_client_factory = api_client_factory

    def _current_config(self) -> BridgeConfig:
        if self.config_path is None:
            return self.config
        return load_config(
            self.config_path,
            expected_owner_uid=self.config_owner_uid,
        )

    def _require_live_peer(self, peer_pidfd: int) -> None:
        if type(peer_pidfd) is not int or peer_pidfd < 0 or not self.peer_process_alive_check(peer_pidfd):
            raise BridgeError("peer_auth_failed", "The connected peer process is no longer available.")

    def precheck_peer(self, *, peer_pid: int, peer_uid: int, peer_pidfd: int) -> None:
        """Fail before reading request bytes when UID/process identity is not trusted."""
        self._require_live_peer(peer_pidfd)
        config = self._current_config()
        if peer_uid not in config.allowed_peer_uids:
            raise BridgeError("permission_denied", "The local caller is not authorized to use this bridge.")
        if not (
            self.worker_process_check(peer_pid, peer_uid, config.trusted_gateway_unit)
            or self.gateway_process_check(peer_pid, config.trusted_gateway_unit)
        ):
            raise BridgeError(
                "worker_context_invalid",
                "The caller is not in a trusted Hermes execution context.",
            )
        self._require_live_peer(peer_pidfd)

    def _readiness(self, config: BridgeConfig) -> dict[str, Any]:
        """Validate sender policy and credentials without contacting Multica."""
        connection = config.connection
        readiness = connection.readiness_errors()
        if readiness:
            raise BridgeError(
                "configuration_incomplete",
                "The Isolated sender configuration is incomplete.",
            )
        if not connection.hmac_enabled:
            raise BridgeError("configuration_incomplete", "HMAC is required for an Isolated connection.")

        webhook_url = read_credential(self.credential_dir, config.credentials.webhook_url_ref)
        actual_fingerprint = webhook_url_fingerprint(webhook_url, connection.multica_origin)
        if not config.credentials.webhook_sha256 or actual_fingerprint != config.credentials.webhook_sha256:
            raise BridgeError("credential_mismatch", "The webhook credential does not match the trusted configuration.")

        if connection.hmac_enabled:
            if not config.credentials.hmac_signing_secret_ref:
                raise BridgeError("credential_unavailable", "The HMAC credential is unavailable.")
            read_credential(
                self.credential_dir,
                config.credentials.hmac_signing_secret_ref,
                max_bytes=8_192,
                preserve_whitespace=True,
            )
        if connection.result_tracking_enabled:
            if not config.credentials.multica_pat_ref:
                raise BridgeError("credential_unavailable", "The result credential is unavailable.")
            read_credential(
                self.credential_dir,
                config.credentials.multica_pat_ref,
                max_bytes=8_192,
                ascii_only=True,
            )
        return {
            "ok": True,
            "ready": True,
            "policy_fingerprint": connection.policy_fingerprint,
            "route_policy_fingerprint": config.route_policy_fingerprint,
        }

    def _service(self, config: BridgeConfig, operation: str) -> BridgeService:
        connection = config.connection
        webhook_url = ""
        hmac_secret = None
        pat = None

        if operation == "send":
            webhook_url = read_credential(
                self.credential_dir,
                config.credentials.webhook_url_ref,
            )
            if config.credentials.hmac_signing_secret_ref:
                hmac_secret = read_credential(
                    self.credential_dir,
                    config.credentials.hmac_signing_secret_ref,
                    max_bytes=8_192,
                    preserve_whitespace=True,
                )
        elif operation == "check_result" and config.credentials.multica_pat_ref:
            pat = read_credential(
                self.credential_dir,
                config.credentials.multica_pat_ref,
                max_bytes=8_192,
                ascii_only=True,
            )

        kwargs: dict[str, Any] = {
            "ledger_key": config.ledger_key,
            "delivery_snapshot": DeliverySnapshot(
                route_id=config.route_id,
                connection_id=config.connection_id,
                workspace_key=config.workspace_key,
                workspace_id=connection.workspace_id,
                multica_origin=connection.multica_origin,
                autopilot_id=connection.autopilot_id,
                trigger_id=connection.trigger_id,
                security_mode=connection.security_mode,
                route_policy_fingerprint=config.route_policy_fingerprint,
            ),
            "webhook_client_factory": self.webhook_client_factory,
        }
        if self.api_client_factory is not None:
            kwargs["api_client_factory"] = self.api_client_factory
        return BridgeService(
            connection,
            ServiceCredentials(
                webhook_url=webhook_url,
                hmac_signing_secret=hmac_secret,
                multica_pat=pat,
                webhook_sha256=config.credentials.webhook_sha256,
            ),
            self.store,
            **kwargs,
        )

    def handle(self, raw_request: bytes, *, peer_pid: int, peer_uid: int, peer_pidfd: int) -> dict[str, Any]:
        try:
            self._require_live_peer(peer_pidfd)
            config = self._current_config()
            if peer_uid not in config.allowed_peer_uids:
                raise BridgeError("permission_denied", "The local caller is not authorized to use this bridge.")
            if len(raw_request) > MAX_IPC_REQUEST_BYTES:
                raise BridgeError("request_too_large", "The complete local request exceeds the IPC size limit.")
            try:
                decoded = strict_json_loads(raw_request)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                raise BridgeError(
                    "invalid_request",
                    "The request must be valid JSON without duplicate keys.",
                ) from None
            envelope = validate_ipc_envelope(decoded)
            operation = envelope["operation"]
            if operation == "readiness":
                if not self.gateway_process_check(peer_pid, config.trusted_gateway_unit):
                    raise BridgeError(
                        "worker_context_invalid",
                        "Only the trusted Hermes Gateway may request sender readiness.",
                    )
                self._require_live_peer(peer_pidfd)
                response = self._readiness(config)
                LOGGER.info("operation=readiness connection=%s status=ok", config.ledger_key)
                return response

            request = envelope["request"]
            if not self.worker_scope_check(
                peer_pid,
                peer_uid,
                request["source"]["task_id"],
                request["source"]["run_id"],
                config.trusted_gateway_unit,
            ):
                raise BridgeError(
                    "worker_context_invalid",
                    "The caller is not in the active Hermes Kanban worker scope.",
                )

            self._require_live_peer(peer_pidfd)
            service = self._service(config, operation)
            if operation == "send":
                response = service.send(request)
            elif operation == "has_delivery":
                response = service.has_delivery(request)
            elif operation == "check_result":
                response = service.check_result(request)
            else:
                service.finish_result_comment_for_request(
                    request,
                    envelope["request_id"],
                    envelope["fingerprint"],
                    published=envelope["published"],
                )
                response = {"ok": True, "acknowledged": True}

            LOGGER.info(
                "operation=%s connection=%s status=%s",
                operation,
                config.ledger_key,
                "ok" if response.get("ok") else "failed",
            )
            return response
        except BridgeError as exc:
            result: dict[str, Any] = {
                "ok": False,
                "error_code": exc.code,
                "message": exc.message,
            }
            if exc.retryable:
                result["retryable"] = True
            return result
        except Exception:  # noqa: BLE001
            LOGGER.error("request failed with an internal error")
            return {
                "ok": False,
                "error_code": "internal_error",
                "message": "The trusted sender could not complete the request.",
            }


def linux_peer_pidfd(connection: socket.socket) -> int:
    """Pin the original Unix-socket peer process so its numeric PID cannot be reused."""
    peer_pidfd: int | None = None
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize("i"))
        peer_pidfd, = struct.unpack("i", raw)
        if peer_pidfd < 0:
            raise OSError("kernel returned an invalid peer pidfd")
        os.set_inheritable(peer_pidfd, False)
        return peer_pidfd
    except (OSError, struct.error):
        if peer_pidfd is not None and peer_pidfd >= 0:
            try:
                os.close(peer_pidfd)
            except OSError:
                pass
        raise BridgeError(
            "peer_auth_unavailable",
            "Stable local peer identity is unavailable on this Linux kernel.",
        ) from None


def peer_pidfd_is_alive(peer_pidfd: int) -> bool:
    """Return false after the process pinned by a pidfd exits or the descriptor is invalid."""
    try:
        poller = select.poll()
        poller.register(peer_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not poller.poll(0)
    except (OSError, ValueError):
        return False


def linux_peer_credentials(connection: socket.socket) -> tuple[int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BridgeError("peer_auth_unavailable", "The local peer identity check is unavailable.")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        return pid, uid
    except OSError:
        raise BridgeError("peer_auth_failed", "The local caller identity could not be verified.") from None


def _read_connection(connection: socket.socket) -> bytes:
    deadline = time.monotonic() + IPC_REQUEST_READ_SECONDS
    body = bytearray()
    while len(body) <= MAX_IPC_REQUEST_BYTES + 1:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeError("request_timeout", "The local request exceeded the maximum read time.")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(min(8_192, MAX_IPC_REQUEST_BYTES + 2 - len(body)))
        except TimeoutError:
            raise BridgeError("request_timeout", "The local request exceeded the maximum read time.") from None
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > MAX_IPC_REQUEST_BYTES + 1 or not body.endswith(b"\n"):
        raise BridgeError(
            "request_too_large",
            "The complete local request exceeds the IPC size limit or is incomplete.",
        )
    body = body[:-1]
    if len(body) > MAX_IPC_REQUEST_BYTES:
        raise BridgeError("request_too_large", "The complete local request exceeds the IPC size limit.")
    if b"\n" in body:
        raise BridgeError("invalid_request", "Only one request is allowed per connection.")
    return bytes(body)


def _write_response(connection: socket.socket, response: dict[str, Any]) -> None:
    data = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(data) > MAX_IPC_RESPONSE_BYTES:
        data = (
            b'{"ok":false,"error_code":"response_too_large",'
            b'"message":"The response exceeded the size limit."}\n'
        )
    try:
        connection.sendall(data)
        connection.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _read_declared_credentials(config: BridgeConfig, credential_dir: str | Path) -> tuple[Any, ...]:
    webhook_url = read_credential(credential_dir, config.credentials.webhook_url_ref)
    connection = config.connection
    fingerprint = webhook_url_fingerprint(webhook_url, connection.multica_origin)
    if config.credentials.webhook_sha256 and fingerprint != config.credentials.webhook_sha256:
        raise BridgeError(
            "credential_mismatch",
            "The webhook credential does not match the trusted configuration.",
        )
    hmac = None
    pat = None
    if config.credentials.hmac_signing_secret_ref:
        hmac = read_credential(
            credential_dir,
            config.credentials.hmac_signing_secret_ref,
            max_bytes=8_192,
            preserve_whitespace=True,
        )
    if config.credentials.multica_pat_ref:
        pat = read_credential(
            credential_dir,
            config.credentials.multica_pat_ref,
            max_bytes=MAX_MULTICA_PAT_BYTES,
            ascii_only=True,
        )
    if connection.hmac_enabled and not hmac:
        raise BridgeError("credential_unavailable", "The HMAC signing credential is unavailable.")
    if connection.result_tracking_enabled and not pat:
        raise BridgeError("credential_unavailable", "The Multica result credential is unavailable.")
    return connection, webhook_url, hmac, pat


def _check_config(config_path: str, credential_dir: str) -> int:
    try:
        config = load_config(config_path)
        connection, _url, _hmac, _pat = _read_declared_credentials(config, credential_dir)
        readiness = connection.readiness_errors()
        if readiness:
            raise BridgeError(
                "configuration_incomplete",
                "The Isolated connection is not ready: " + ", ".join(readiness) + ".",
            )
    except BridgeError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "message": exc.message}))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "security_mode": "isolated",
                "instance_id": connection.isolated_instance_id or None,
                "credential_status": "available",
            }
        )
    )
    return 0


def _check_route_config(config_path: str) -> int:
    try:
        config = load_config(config_path, expected_owner_uid=None)
    except BridgeError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "message": exc.message}))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "security_mode": "isolated",
                "default_deny": True,
                "enabled": config.connection.enabled,
            }
        )
    )
    return 0


def _activation_listener(expected_path: str, environ: dict[str, str] | None = None) -> socket.socket:
    env = os.environ if environ is None else environ
    try:
        listen_pid = int(env.get("LISTEN_PID", ""))
        listen_fds = int(env.get("LISTEN_FDS", ""))
    except ValueError as exc:
        raise BridgeError("activation_unavailable", "The systemd socket activation metadata is invalid.") from exc
    if listen_pid != os.getpid() or listen_fds != 1:
        raise BridgeError("activation_unavailable", "Exactly one systemd-activated socket is required.")
    try:
        listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
            listener.close()
            raise BridgeError("activation_unavailable", "The activated Unix socket is not listening.")
        socket_name = listener.getsockname()
        if not isinstance(socket_name, str) or socket_name != expected_path:
            listener.close()
            raise BridgeError(
                "activation_unavailable",
                "The activated socket path does not match the configured bridge instance.",
            )
        listener.settimeout(SOCKET_IDLE_SECONDS)
        return listener
    except BridgeError:
        raise
    except OSError as exc:
        raise BridgeError("activation_unavailable", "The systemd-activated Unix socket is unavailable.") from exc


def _service_accept_timeout(service_deadline: float, *, now: float | None = None) -> float:
    """Bound each accept wait by both idle retirement and the process lifetime."""
    current_time = time.monotonic() if now is None else now
    return min(SOCKET_IDLE_SECONDS, max(0.0, service_deadline - current_time))


def _serve_connection(dispatcher: BridgeDispatcher, connection: socket.socket) -> None:
    peer_pidfd: int | None = None
    try:
        peer_pid, peer_uid = linux_peer_credentials(connection)
        peer_pidfd = linux_peer_pidfd(connection)
        dispatcher.precheck_peer(peer_pid=peer_pid, peer_uid=peer_uid, peer_pidfd=peer_pidfd)
        raw_request = _read_connection(connection)
        response = dispatcher.handle(raw_request, peer_pid=peer_pid, peer_uid=peer_uid, peer_pidfd=peer_pidfd)
    except BridgeError as exc:
        response = {"ok": False, "error_code": exc.code, "message": exc.message}
        if exc.retryable:
            response["retryable"] = True
    except OSError:
        LOGGER.info("client connection ended before request completion")
        response = {
            "ok": False,
            "error_code": "client_connection_failed",
            "message": "The local client connection failed.",
        }
    try:
        _write_response(connection, response)
    finally:
        if peer_pidfd is not None:
            try:
                os.close(peer_pidfd)
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes Multica Bridge Isolated sender")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--activation",
        action="store_true",
        help="Serve connections from a systemd-activated Unix listener",
    )
    mode.add_argument(
        "--check-config",
        action="store_true",
        help="Validate Isolated configuration and loaded credentials",
    )
    mode.add_argument(
        "--check-route-config",
        action="store_true",
        help="Validate Isolated configuration without credentials",
    )
    args = parser.parse_args(argv)
    config_path = os.environ.get("HMB_CONFIG", "").strip()
    if not config_path:
        print("HMB_CONFIG must point to the route-specific Isolated config.", file=sys.stderr)
        return 1
    credential_dir = os.environ.get(
        "CREDENTIALS_DIRECTORY",
        "/run/credentials/hermes-multica-bridge",
    )
    if args.check_config:
        return _check_config(config_path, credential_dir)
    if args.check_route_config:
        return _check_route_config(config_path)

    service_deadline = time.monotonic() + MAX_SERVICE_LIFETIME_SECONDS
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    try:
        config = load_config(config_path)
        state_directory = os.environ.get("STATE_DIRECTORY")
        if not state_directory:
            raise BridgeError("state_unavailable", "The systemd state directory is not configured.")
        store = DeliveryStore(
            Path(state_directory) / "deliveries.sqlite3",
            systemd_state=True,
        )
        dispatcher = BridgeDispatcher(
            config,
            store,
            credential_dir,
            config_path=config_path,
        )
        listener = _activation_listener(config.connection.socket_path)
        try:
            while True:
                accept_timeout = _service_accept_timeout(service_deadline)
                if accept_timeout <= 0:
                    LOGGER.info("sender maximum lifetime reached; exiting")
                    break
                listener.settimeout(accept_timeout)
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    if service_deadline - time.monotonic() <= 0:
                        LOGGER.info("sender maximum lifetime reached; exiting")
                    else:
                        LOGGER.info("sender idle timeout; exiting")
                    break
                except OSError:
                    LOGGER.error("activated socket accept failed")
                    return 1
                with connection:
                    _serve_connection(dispatcher, connection)
        finally:
            listener.close()
    except BridgeError as exc:
        LOGGER.error("sender initialization failed: %s", exc.code)
        return 1
    except Exception:  # noqa: BLE001
        LOGGER.error("sender initialization failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
