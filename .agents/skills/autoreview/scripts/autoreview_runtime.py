#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import codecs
import fcntl
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable


DEFAULT_REVIEW_TIMEOUT_SECONDS = 600
MAX_ENGINE_OUTPUT_BYTES = 8 * 1024 * 1024
ENGINE_OUTPUT_CHUNK_BYTES = 8192
ENGINE_OUTPUT_QUEUE_SIZE = 32
TRANSPORT_ATTEMPTS = 3
ACTIVE_RUN_STATUSES = {"running", "retrying", "repairing"}
TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class ReviewErrorCode(str, Enum):
    ENGINE_TRANSPORT_ERROR = "ENGINE_TRANSPORT_ERROR"
    ENGINE_TIMEOUT = "ENGINE_TIMEOUT"
    ENGINE_OUTPUT_LIMIT = "ENGINE_OUTPUT_LIMIT"
    ENGINE_SCHEMA_ERROR = "ENGINE_SCHEMA_ERROR"
    ENGINE_AUTH_ERROR = "ENGINE_AUTH_ERROR"
    ENGINE_SANDBOX_ERROR = "ENGINE_SANDBOX_ERROR"
    PROMPT_CONFLICT = "PROMPT_CONFLICT"
    BUNDLE_TOO_LARGE = "BUNDLE_TOO_LARGE"
    UNSUPPORTED_OPTION = "UNSUPPORTED_OPTION"
    PREFLIGHT_ERROR = "PREFLIGHT_ERROR"


class ReviewError(RuntimeError):
    def __init__(self, code: ReviewErrorCode, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def __str__(self) -> str:
        message = terminal_safe_text(self.message)
        suffix = f"\n{terminal_safe_text(self.detail)}" if self.detail else ""
        return f"[{self.code.value}] {message}{suffix}"


def bounded_detail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)] + "\n\n[truncated]"


def terminal_safe_text(value: Any) -> str:
    """Render untrusted streamed engine text without terminal control sequences."""
    return TERMINAL_CONTROL_RE.sub(lambda match: f"\\x{ord(match.group(0)):02x}", str(value))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def process_is_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or pid < 1:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def resolve_state_dir(repo: Path, override: str | None = None) -> Path:
    if override:
        state_dir = Path(override).expanduser()
    elif os.environ.get("AUTOREVIEW_STATE_DIR"):
        state_dir = Path(os.environ["AUTOREVIEW_STATE_DIR"]).expanduser()
    elif os.environ.get("XDG_STATE_HOME"):
        state_dir = Path(os.environ["XDG_STATE_HOME"]).expanduser() / "autoreview" / "runs"
    else:
        state_dir = Path.home() / ".local" / "state" / "autoreview" / "runs"
    state_dir = state_dir.resolve()
    if state_dir == repo or repo in state_dir.parents:
        raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, "review state directory must be outside the repository")
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=state_dir, prefix=".write-test-", delete=True):
            pass
    except OSError as exc:
        raise ReviewError(
            ReviewErrorCode.ENGINE_SANDBOX_ERROR,
            f"review state directory is not writable: {state_dir}",
            detail=str(exc),
        ) from exc
    return state_dir


class ReviewRunState:
    def __init__(self, state_dir: Path, engine: str, bundle_hash: str) -> None:
        admission_key = hashlib.sha256(f"{engine}\0{bundle_hash}".encode()).hexdigest()
        lock_path = state_dir / f".admission-{admission_key}.lock"
        lock_fd = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            for candidate in state_dir.glob("*.json"):
                try:
                    existing = json.loads(candidate.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if (
                    existing.get("engine") == engine
                    and existing.get("bundle_hash") == bundle_hash
                    and existing.get("status") in ACTIVE_RUN_STATUSES
                    and process_is_alive(existing.get("controller_pid", existing.get("pid")))
                ):
                    raise ReviewError(
                        ReviewErrorCode.PREFLIGHT_ERROR,
                        f"an equivalent review is already running: {existing.get('run_id')}",
                    )
            self.run_id = str(uuid.uuid4())
            self.path = state_dir / f"{self.run_id}.json"
            self.data: dict[str, Any] = {
                "run_id": self.run_id,
                "engine": engine,
                "status": "running",
                "started_at": utc_now(),
                "updated_at": utc_now(),
                "controller_pid": os.getpid(),
                "pid": None,
                "bundle_hash": bundle_hash,
                "error_code": None,
            }
            self.write()
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def update(self, **values: Any) -> None:
        self.data.update(values)
        self.data["updated_at"] = utc_now()
        self.write()

    def write(self) -> None:
        write_private_json(self.path, self.data)


PROMPT_CONFLICT_PATTERNS = {
    "Markdown output": re.compile(r"(?im)\b(?:return|respond|output|format)\b[^\n.;]*\bmarkdown\b"),
    "alternate report structure": re.compile(r"(?im)^#{1,6}\s+output report structure\s*$"),
    "table output": re.compile(r"(?im)\b(?:return|respond|output|organize)\b[^\n.;]*\btable\b"),
    "alternate top-level JSON schema": re.compile(r'(?im)^\s*"(?:overview|verdict|action_plan)"\s*:'),
}
NEGATED_OUTPUT_PREFIX = re.compile(r"(?i)(?:do\s+not|don't|never|must\s+not)\s*$")


def validate_extra_prompt(extra_prompt: str) -> None:
    conflicts: list[str] = []
    for name, pattern in PROMPT_CONFLICT_PATTERNS.items():
        for match in pattern.finditer(extra_prompt):
            if name in {"Markdown output", "table output"}:
                line_start = extra_prompt.rfind("\n", 0, match.start()) + 1
                if NEGATED_OUTPUT_PREFIX.search(extra_prompt[line_start : match.start()]):
                    continue
            conflicts.append(name)
            break
    if conflicts:
        raise ReviewError(
            ReviewErrorCode.PROMPT_CONFLICT,
            "additional review instructions conflict with the canonical JSON output contract",
            detail=", ".join(conflicts),
        )


def executable_for_engine(args: Any, engine: str) -> str:
    return str(getattr(args, f"{engine}_bin"))


def preflight_review(
    args: Any,
    reviewers: list[Any],
    repo: Path,
    extra_prompt: str,
    canonical_schema: dict[str, Any] | None = None,
    *,
    allow_missing_engines: set[str] | frozenset[str] = frozenset(),
) -> Path:
    validate_extra_prompt(extra_prompt)
    if canonical_schema is not None:
        try:
            json.dumps(canonical_schema)
            required = set(canonical_schema["required"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, "canonical review JSON schema is invalid", detail=str(exc)) from exc
        expected = {"findings", "overall_correctness", "overall_explanation", "overall_confidence"}
        if canonical_schema.get("type") != "object" or required != expected:
            raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, "canonical review JSON schema has an unexpected root contract")
    state_dir = resolve_state_dir(repo, args.state_dir)
    for reviewer in reviewers:
        if not reviewer.tools and reviewer.engine == "copilot":
            raise ReviewError(
                ReviewErrorCode.UNSUPPORTED_OPTION,
                f"--no-tools is not supported by the {reviewer.engine} engine",
            )
        executable = executable_for_engine(reviewer, reviewer.engine)
        if not shutil.which(executable) and reviewer.engine not in allow_missing_engines:
            raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, f"review engine executable was not found: {executable}")
    try:
        with tempfile.NamedTemporaryFile(prefix="autoreview-preflight-", delete=True):
            pass
    except OSError as exc:
        raise ReviewError(ReviewErrorCode.ENGINE_SANDBOX_ERROR, "temporary directory is not writable", detail=str(exc)) from exc
    return state_dir


def classify_engine_failure(engine: str, returncode: int, output: str) -> ReviewError:
    lowered = output.lower()
    if any(
        token in lowered
        for token in (
            "stream disconnected",
            "stopped responding",
            "connection reset",
            "failed to connect",
            "service unavailable",
        )
    ) and not any(token in lowered for token in ("malformed json", "strict codex output schema")):
        code = ReviewErrorCode.ENGINE_TRANSPORT_ERROR
    elif any(token in lowered for token in ("unauthorized", "authentication failed", "invalid api key", "http 401")):
        code = ReviewErrorCode.ENGINE_AUTH_ERROR
    elif any(token in lowered for token in ("read-only file system", "readonly database", "permission denied")):
        code = ReviewErrorCode.ENGINE_SANDBOX_ERROR
    elif any(token in lowered for token in ("malformed json", "strict codex output schema", "non-json output")):
        code = ReviewErrorCode.ENGINE_SCHEMA_ERROR
    else:
        code = ReviewErrorCode.ENGINE_TRANSPORT_ERROR
    return ReviewError(code, f"{engine} engine failed with exit code {returncode}", detail=bounded_detail(output))


def _pipe_identifiers(proc: subprocess.Popen[Any]) -> set[str]:
    identifiers: set[str] = set()
    for stream in (proc.stdout, proc.stderr):
        if stream is None:
            continue
        try:
            metadata = os.fstat(stream.fileno())
        except (OSError, ValueError):
            continue
        if stat.S_ISFIFO(metadata.st_mode):
            identifiers.add(f"pipe:[{metadata.st_ino}]")
    return identifiers


def _pipe_holder_pids(pipe_identifiers: set[str]) -> set[int]:
    """Find processes retaining this run's private stdout/stderr pipes on Linux."""
    if not pipe_identifiers:
        return set()
    try:
        processes = os.scandir("/proc")
    except OSError:
        return set()

    holders: set[int] = set()
    with processes:
        for process_entry in processes:
            if not process_entry.name.isdecimal():
                continue
            pid = int(process_entry.name)
            if pid == os.getpid():
                continue
            try:
                descriptors = os.scandir(os.path.join(process_entry.path, "fd"))
            except OSError:
                continue
            with descriptors:
                for descriptor in descriptors:
                    if not descriptor.name.isdecimal():
                        continue
                    try:
                        target = os.readlink(descriptor.path)
                    except OSError:
                        continue
                    if target in pipe_identifiers:
                        holders.add(pid)
                        break
    return holders


def _process_holds_pipe(pid: int, pipe_identifiers: set[str]) -> bool:
    try:
        descriptors = os.scandir(f"/proc/{pid}/fd")
    except OSError:
        return False
    with descriptors:
        for descriptor in descriptors:
            if not descriptor.name.isdecimal():
                continue
            try:
                if os.readlink(descriptor.path) in pipe_identifiers:
                    return True
            except OSError:
                continue
    return False


def _signal_pipe_holders(pipe_identifiers: set[str], sig: signal.Signals) -> None:
    for pid in _pipe_holder_pids(pipe_identifiers):
        try:
            pidfd = os.pidfd_open(pid)
        except (AttributeError, OSError):
            continue
        try:
            # Recheck through the pidfd's stable process identity before sending
            # a signal, so PID reuse cannot redirect cleanup to another process.
            if _process_holds_pipe(pid, pipe_identifiers):
                signal.pidfd_send_signal(pidfd, sig)
        except (AttributeError, OSError):
            pass
        finally:
            os.close(pidfd)


def stop_process(
    proc: subprocess.Popen[Any], pipe_identifiers: set[str] | None = None
) -> None:
    """Terminate the session group and escaped descendants retaining its pipes."""
    pipe_identifiers = _pipe_identifiers(proc) if pipe_identifiers is None else pipe_identifiers
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    _signal_pipe_holders(pipe_identifiers, signal.SIGTERM)

    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        group_alive = True
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            group_alive = False
        pipe_holders_alive = bool(_pipe_holder_pids(pipe_identifiers))
        if not group_alive and not pipe_holders_alive:
            break
        time.sleep(0.02)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _signal_pipe_holders(pipe_identifiers, signal.SIGKILL)

    if proc.poll() is None:
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass


def show_run_status(state_dir: Path, run_id: str) -> int:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", run_id):
        raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, "invalid review run id")
    path = state_dir / f"{run_id}.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise ReviewError(ReviewErrorCode.PREFLIGHT_ERROR, f"review run was not found: {run_id}") from exc
    controller_pid = data.get("controller_pid", data.get("pid"))
    if data.get("status") in ACTIVE_RUN_STATUSES and not process_is_alive(controller_pid):
        data.update(
            status="incomplete",
            updated_at=utc_now(),
            error_code=ReviewErrorCode.ENGINE_TRANSPORT_ERROR.value,
            error="review process ended without a terminal result",
            pid=None,
        )
        write_private_json(path, data)
    print(json.dumps(data, indent=2))
    return 0 if data.get("status") in {"passed", "findings", "failed", "timed_out", "cancelled", "incomplete"} else 3


def run_with_heartbeat(
    args: list[str],
    cwd: Path,
    *,
    input_text: str | None = None,
    label: str,
    heartbeat_seconds: int = 60,
    timeout_seconds: int = DEFAULT_REVIEW_TIMEOUT_SECONDS,
    stream_output: bool = False,
    stream_display: Callable[[str, str], str | None] | None = None,
    run_state: ReviewRunState | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_with_stream(
        args,
        cwd,
        input_text=input_text,
        label=label,
        heartbeat_seconds=heartbeat_seconds,
        timeout_seconds=timeout_seconds,
        stream_display=stream_display,
        display_output=stream_output,
        run_state=run_state,
    )


def run_with_stream(
    args: list[str],
    cwd: Path,
    *,
    input_text: str | None,
    label: str,
    heartbeat_seconds: int,
    timeout_seconds: int,
    stream_display: Callable[[str, str], str | None] | None,
    display_output: bool,
    run_state: ReviewRunState | None,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    proc = subprocess.Popen(
        args,
        cwd=cwd,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )
    pipe_identifiers = _pipe_identifiers(proc)
    if run_state:
        run_state.update(pid=proc.pid)
    deadline = started + timeout_seconds
    events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=ENGINE_OUTPUT_QUEUE_SIZE)
    stopping = threading.Event()
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    decoders = {
        name: codecs.getincrementaldecoder("utf-8")("replace")
        for name in ("stdout", "stderr")
    }
    display_buffers = {"stdout": "", "stderr": ""}

    def publish_event(event: tuple[str, bytes | None]) -> bool:
        while not stopping.is_set():
            try:
                events.put(event, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def read_stream(name: str, stream: Any) -> None:
        try:
            while not stopping.is_set():
                chunk = stream.read(ENGINE_OUTPUT_CHUNK_BYTES)
                if not chunk or not publish_event((name, chunk)):
                    break
        except (OSError, ValueError):
            pass
        finally:
            # The reader owns this stream while active; bounded joins below
            # avoid blocking on descendants that retain inherited pipe handles.
            try:
                stream.close()
            except OSError:
                pass
            publish_event((name, None))

    def write_stdin() -> None:
        if proc.stdin is None or input_text is None:
            return
        try:
            proc.stdin.write(input_text.encode("utf-8"))
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            return

    threads = [
        threading.Thread(target=read_stream, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=read_stream, args=("stderr", proc.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    stdin_thread = threading.Thread(target=write_stdin, daemon=True)
    stdin_thread.start()

    def finish_threads() -> None:
        # A descendant can retain a pipe after the process group is stopped.
        # Give readers a bounded cleanup window instead of joining indefinitely.
        cleanup_deadline = time.monotonic() + 0.5
        for thread in threads:
            remaining = cleanup_deadline - time.monotonic()
            if remaining > 0:
                thread.join(timeout=remaining)
        remaining = cleanup_deadline - time.monotonic()
        if remaining > 0:
            stdin_thread.join(timeout=remaining)

    open_streams = 2
    captured_bytes = 0

    def capture_text(name: str, value: str, *, final: bool = False) -> None:
        if name == "stdout":
            stdout_parts.append(value)
        else:
            stderr_parts.append(value)
        if not display_output:
            return
        pending = display_buffers[name] + value
        while "\n" in pending:
            newline = pending.find("\n") + 1
            line, pending = pending[:newline], pending[newline:]
            display = stream_display(name, line) if stream_display else line
            if display:
                target = sys.stdout if name == "stdout" else sys.stderr
                target.write(terminal_safe_text(display))
                target.flush()
        if final and pending:
            display = stream_display(name, pending) if stream_display else pending
            if display:
                target = sys.stdout if name == "stdout" else sys.stderr
                target.write(terminal_safe_text(display))
                target.flush()
            pending = ""
        display_buffers[name] = pending

    while open_streams:
        now = time.monotonic()
        elapsed = int(now - started)
        remaining_seconds = deadline - now
        if remaining_seconds <= 0:
            stopping.set()
            stop_process(proc, pipe_identifiers)
            finish_threads()
            raise ReviewError(
                ReviewErrorCode.ENGINE_TIMEOUT,
                f"{label} review exceeded {timeout_seconds}s and was terminated",
                detail=bounded_detail("".join(stderr_parts) or "".join(stdout_parts)),
            )
        try:
            name, chunk = events.get(timeout=min(float(heartbeat_seconds), remaining_seconds))
        except KeyboardInterrupt:
            stopping.set()
            stop_process(proc, pipe_identifiers)
            finish_threads()
            raise
        except queue.Empty:
            now = time.monotonic()
            elapsed = int(now - started)
            remaining = max(0, int(deadline - now))
            print(
                f"review still running: {label} elapsed={elapsed}s remaining={remaining}s pid={proc.pid}",
                file=sys.stderr,
                flush=True,
            )
            continue
        if chunk is None:
            tail = decoders[name].decode(b"", final=True)
            try:
                capture_text(name, tail, final=True)
            except BaseException:
                stopping.set()
                stop_process(proc, pipe_identifiers)
                finish_threads()
                raise
            open_streams -= 1
            continue
        captured_bytes += len(chunk)
        if captured_bytes > MAX_ENGINE_OUTPUT_BYTES:
            stopping.set()
            stop_process(proc, pipe_identifiers)
            finish_threads()
            raise ReviewError(
                ReviewErrorCode.ENGINE_OUTPUT_LIMIT,
                f"{label} review exceeded the {MAX_ENGINE_OUTPUT_BYTES}-byte output limit",
            )
        decoded = decoders[name].decode(chunk)
        try:
            capture_text(name, decoded)
        except BaseException:
            stopping.set()
            stop_process(proc, pipe_identifiers)
            finish_threads()
            raise

    finish_threads()
    remaining_seconds = deadline - time.monotonic()
    if remaining_seconds <= 0:
        stopping.set()
        stop_process(proc, pipe_identifiers)
        finish_threads()
        raise ReviewError(
            ReviewErrorCode.ENGINE_TIMEOUT,
            f"{label} review exceeded {timeout_seconds}s and was terminated",
            detail=bounded_detail("".join(stderr_parts) or "".join(stdout_parts)),
        )
    try:
        returncode = proc.wait(timeout=remaining_seconds)
    except KeyboardInterrupt:
        stopping.set()
        stop_process(proc, pipe_identifiers)
        finish_threads()
        raise
    except subprocess.TimeoutExpired:
        stopping.set()
        stop_process(proc, pipe_identifiers)
        finish_threads()
        raise ReviewError(
            ReviewErrorCode.ENGINE_TIMEOUT,
            f"{label} review exceeded {timeout_seconds}s and was terminated",
            detail=bounded_detail("".join(stderr_parts) or "".join(stdout_parts)),
        ) from None
    return subprocess.CompletedProcess(args, returncode, "".join(stdout_parts), "".join(stderr_parts))
