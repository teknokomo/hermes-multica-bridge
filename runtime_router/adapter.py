"""Narrow subprocess adapter for the supported Multica CLI contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Instance

_ERROR_CODE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_MARKER = re.compile(r"<!-- router-request:[0-9a-f-]{36} -->")
_AUTH_EMAIL = re.compile(r"(?m)^\s*User:\s*.*?\(([^()\s]+@[^()\s]+)\)\s*$")
_RUN_CURSOR = re.compile(
    r'(?i)More runs available; use --before\s+["\']([^"\']+)["\']'
)
_TERMINAL_RUN_STATES = {
    "cancelled",
    "canceled",
    "completed",
    "done",
    "failed",
    "succeeded",
    "success",
}
_ACTIVE_RUN_STATES = {
    "queued",
    "deferred",
    "dispatched",
    "running",
    "waiting_local_directory",
}
_MAX_CLI_RESPONSE_BYTES = 1_048_576
_MAX_CLI_STDERR_BYTES = 65_536


class MulticaCliError(RuntimeError):
    def __init__(self, code: str, *, uncertain: bool = False):
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain


@dataclass(frozen=True)
class CliProfile:
    profile: str
    workspace_id: str


class MulticaCliAdapter:
    """Runs fixed argv commands and rejects unbounded or non-JSON responses."""

    def __init__(
        self,
        *,
        binary: str = "/usr/local/bin/multica",
        home: str | None = None,
        timeout: int = 30,
        spool_root: str | Path | None = None,
        runner: Any | None = None,
    ):
        if not os.path.isabs(binary) or "\x00" in binary:
            raise ValueError("Multica CLI binary must be an absolute path")
        if not 5 <= timeout <= 180:
            raise ValueError("Multica CLI timeout is outside the supported range")
        self.binary = binary
        self.home = home or os.path.expanduser("~")
        self.timeout = timeout
        self.spool_root = Path(spool_root) if spool_root else None
        self.runner = runner

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover - Hermes deployment is POSIX
                process.kill()
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass

    def _run_bounded(
        self, argv: list[str], *, input_text: str | None, env: dict[str, str]
    ) -> tuple[int, bytes, bytes, bool, bool, bool]:
        """Read CLI output incrementally and stop the process group at the cap."""
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=os.name == "posix",
            bufsize=0,
        )
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        output = bytearray()
        errors = bytearray()
        timed_out = False
        output_too_large = False
        errors_too_large = False
        pending_input = (
            memoryview(input_text.encode("utf-8")) if input_text is not None else None
        )
        stdout_open = True
        stderr_open = True
        stdin_open = process.stdin is not None
        deadline = time.monotonic() + self.timeout

        try:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            if process.stdin is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")

            while stdout_open or stderr_open or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._stop_process(process)
                    break
                for key, _mask in selector.select(min(remaining, 0.1)):
                    if key.data in {"stdout", "stderr"}:
                        stream = process.stdout if key.data == "stdout" else process.stderr
                        buffer = output if key.data == "stdout" else errors
                        maximum = (
                            _MAX_CLI_RESPONSE_BYTES
                            if key.data == "stdout"
                            else _MAX_CLI_STDERR_BYTES
                        )
                        room = maximum + 1 - len(buffer)
                        chunk = os.read(stream.fileno(), min(65536, room))
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                            if key.data == "stdout":
                                stdout_open = False
                            else:
                                stderr_open = False
                        elif len(buffer) + len(chunk) > maximum:
                            if key.data == "stdout":
                                output_too_large = True
                            else:
                                errors_too_large = True
                            self._stop_process(process)
                            break
                        else:
                            buffer.extend(chunk)
                    else:
                        assert process.stdin is not None and pending_input is not None
                        try:
                            written = os.write(
                                process.stdin.fileno(), pending_input[:65536]
                            )
                        except BrokenPipeError:
                            written = len(pending_input)
                        pending_input = pending_input[written:]
                        if not pending_input:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                            stdin_open = False
                if output_too_large or errors_too_large:
                    break

            if timed_out or output_too_large or errors_too_large:
                if stdin_open and process.stdin is not None:
                    try:
                        selector.unregister(process.stdin)
                    except KeyError:
                        pass
                    process.stdin.close()
                    stdin_open = False
                if stdout_open:
                    try:
                        selector.unregister(process.stdout)
                    except KeyError:
                        pass
                    process.stdout.close()
                    stdout_open = False
                if stderr_open:
                    try:
                        selector.unregister(process.stderr)
                    except KeyError:
                        pass
                    process.stderr.close()
                    stderr_open = False
            try:
                returncode = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._stop_process(process)
                returncode = process.wait(timeout=2)
        finally:
            selector.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            if process.stdout is not None and not process.stdout.closed:
                process.stdout.close()
        return (
            returncode,
            bytes(output),
            bytes(errors),
            output_too_large,
            errors_too_large,
            timed_out,
        )

    @staticmethod
    def _object(value: Any, key: str) -> dict[str, Any]:
        if isinstance(value, dict) and isinstance(value.get(key), dict):
            value = value[key]
        if not isinstance(value, dict):
            raise MulticaCliError("multica_cli_invalid_response")
        return value

    def _call(
        self,
        instance: Instance,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        uncertain_on_failure: bool = False,
        capture_stderr: bool = False,
        text_response: bool = False,
    ) -> (
        dict[str, Any]
        | list[Any]
        | str
        | tuple[dict[str, Any] | list[Any] | str, str]
    ):
        if any(
            not isinstance(arg, str) or "\x00" in arg or "\n" in arg or "\r" in arg
            for arg in args
        ):
            raise MulticaCliError("multica_cli_invalid_argument")
        argv = [
            self.binary,
            "--profile",
            instance.cli_profile,
            "--workspace-id",
            instance.workspace_id,
            "--server-url",
            instance.base_url,
            *args,
        ]
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": self.home,
            "XDG_CONFIG_HOME": os.path.join(self.home, ".config"),
            "LANG": "C.UTF-8",
        }
        try:
            if self.runner is None:
                (
                    returncode,
                    raw_stdout,
                    raw_stderr,
                    too_large,
                    stderr_too_large,
                    timed_out,
                ) = self._run_bounded(
                    argv, input_text=input_text, env=env
                )
                if timed_out:
                    raise MulticaCliError("multica_cli_timeout", uncertain=True)
                if too_large:
                    raise MulticaCliError(
                        "multica_cli_response_too_large",
                        uncertain=uncertain_on_failure,
                    )
                if capture_stderr and stderr_too_large:
                    raise MulticaCliError("multica_cli_response_too_large")
                try:
                    stdout = raw_stdout.decode("utf-8")
                    stderr = raw_stderr.decode("utf-8") if capture_stderr else ""
                except UnicodeDecodeError:
                    raise MulticaCliError(
                        "multica_cli_invalid_encoding",
                        uncertain=uncertain_on_failure,
                    ) from None
            else:
                result = self.runner(
                    argv,
                    input=input_text,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=self.timeout,
                    env=env,
                    text=False,
                )
                returncode = result.returncode
                raw_stdout = result.stdout if isinstance(result.stdout, bytes) else (
                    result.stdout.encode("utf-8")
                    if isinstance(result.stdout, str)
                    else b""
                )
                result_stderr = getattr(result, "stderr", None)
                raw_stderr = result_stderr if isinstance(result_stderr, bytes) else (
                    result_stderr.encode("utf-8")
                    if isinstance(result_stderr, str)
                    else b""
                )
                if len(raw_stdout) > _MAX_CLI_RESPONSE_BYTES or (
                    capture_stderr and len(raw_stderr) > _MAX_CLI_STDERR_BYTES
                ):
                    raise MulticaCliError(
                        "multica_cli_response_too_large",
                        uncertain=uncertain_on_failure,
                    )
                try:
                    stdout = raw_stdout.decode("utf-8")
                    stderr = raw_stderr.decode("utf-8") if capture_stderr else ""
                except UnicodeDecodeError:
                    raise MulticaCliError(
                        "multica_cli_invalid_encoding",
                        uncertain=uncertain_on_failure,
                    ) from None
                if len(stdout.encode("utf-8", "replace")) > _MAX_CLI_RESPONSE_BYTES:
                    raise MulticaCliError(
                        "multica_cli_response_too_large",
                        uncertain=uncertain_on_failure,
                    )
        except subprocess.TimeoutExpired:
            raise MulticaCliError("multica_cli_timeout", uncertain=True) from None
        except OSError:
            raise MulticaCliError("multica_cli_unavailable") from None
        if text_response:
            if returncode:
                raise MulticaCliError("multica_cli_rejected")
            body: dict[str, Any] | list[Any] | str = stdout
        else:
            try:
                body = json.loads(stdout)
            except (ValueError, RecursionError):
                raise MulticaCliError(
                    "multica_cli_invalid_response",
                    uncertain=uncertain_on_failure or returncode == 0,
                ) from None
        if returncode:
            raw_code = body.get("error_code") if isinstance(body, dict) else None
            code = (
                raw_code
                if isinstance(raw_code, str) and _ERROR_CODE.fullmatch(raw_code)
                else "multica_cli_rejected"
            )
            raise MulticaCliError(code, uncertain=uncertain_on_failure)
        if not isinstance(body, (dict, list, str)) or (
            isinstance(body, str) and not text_response
        ):
            raise MulticaCliError(
                "multica_cli_invalid_response", uncertain=uncertain_on_failure
            )
        return (body, stderr) if capture_stderr else body

    def workspace_list(self, instance: Instance) -> list[dict[str, Any]]:
        value = self._call(instance, ["workspace", "list", "--output", "json"])
        rows = value if isinstance(value, list) else value.get("workspaces")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise MulticaCliError("multica_cli_invalid_response")
        return rows

    def project_get(self, instance: Instance, project_id: str) -> dict[str, Any]:
        value = self._call(instance, ["project", "get", project_id, "--output", "json"])
        project = self._object(value, "project")
        if project.get("id") != project_id:
            raise MulticaCliError("multica_cli_invalid_response")
        return project

    def _current_workspace_user_id(self, instance: Instance) -> str:
        auth_result = self._call(
            instance, ["auth", "status"],
            text_response=True,
            capture_stderr=True,
        )
        assert isinstance(auth_result, tuple)
        auth_output, auth_stderr = auth_result
        assert isinstance(auth_output, str)
        match = _AUTH_EMAIL.search(auth_output) or _AUTH_EMAIL.search(auth_stderr)
        if match is None:
            raise MulticaCliError("multica_cli_identity_unavailable")
        email = match.group(1).casefold()
        members_value = self._call(
            instance, ["workspace", "member", "list", "--output", "json"]
        )
        members = (
            members_value
            if isinstance(members_value, list)
            else members_value.get("members")
            if isinstance(members_value, dict)
            else None
        )
        if not isinstance(members, list):
            raise MulticaCliError("multica_cli_invalid_response")
        matches = [
            row
            for row in members
            if isinstance(row, dict)
            and isinstance(row.get("email"), str)
            and row["email"].casefold() == email
        ]
        if (
            len(matches) != 1
            or not isinstance(matches[0].get("user_id"), str)
            or not matches[0]["user_id"]
        ):
            raise MulticaCliError("multica_cli_identity_unavailable")
        return matches[0]["user_id"]

    def runtime_list(self, instance: Instance) -> list[dict[str, Any]]:
        value = self._call(instance, ["runtime", "list", "--output", "json"])
        rows = value if isinstance(value, list) else value.get("runtimes")
        if (
            not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or any(
                not isinstance(row.get("id"), str)
                or not row.get("id")
                or row.get("workspace_id") != instance.workspace_id
                or row.get("status") not in {"online", "offline"}
                or row.get("visibility") not in {"private", "public"}
                or row.get("owner_id") is not None
                and (not isinstance(row.get("owner_id"), str) or not row["owner_id"])
                or "shared_with" in row
                and (
                    not isinstance(row["shared_with"], list)
                    or any(
                        not isinstance(user_id, str) or not user_id
                        for user_id in row["shared_with"]
                    )
                )
                or "models" in row
                and (
                    not isinstance(row["models"], list)
                    or any(
                        not isinstance(model, str) or not model
                        for model in row["models"]
                    )
                )
                for row in rows
            )
        ):
            raise MulticaCliError("multica_cli_invalid_response")
        user_id = self._current_workspace_user_id(instance)
        return [
            {
                **row,
                "accessible": bool(
                    isinstance(row.get("owner_id"), str)
                    and (
                        row["owner_id"] == user_id
                        or row["visibility"] == "public"
                        or row["visibility"] == "private"
                        and user_id in row.get("shared_with", [])
                    )
                ),
            }
            for row in rows
        ]

    def agent_get(self, instance: Instance, agent_id: str) -> dict[str, Any]:
        value = self._call(instance, ["agent", "get", agent_id, "--output", "json"])
        agent = self._object(value, "agent")
        if (
            agent.get("id") != agent_id
            or type(agent.get("max_concurrent_tasks")) is not int
            or not isinstance(agent.get("runtime_id"), str)
            or "model" in agent
            and agent["model"] is not None
            and not isinstance(agent["model"], str)
        ):
            raise MulticaCliError("multica_cli_invalid_response")
        return agent

    def verify_agent_runtime(
        self, instance: Instance, agent_id: str, runtime_id: str, model: str | None
    ) -> dict[str, Any]:
        runtimes = self.runtime_list(instance)
        target = next((row for row in runtimes if row["id"] == runtime_id), None)
        if (
            target is None
            or target.get("status") != "online"
            or target.get("accessible") is not True
        ):
            raise MulticaCliError("runtime_not_allowed")
        agent = self.agent_get(instance, agent_id)
        if agent.get("max_concurrent_tasks") != 1:
            raise MulticaCliError("agent_concurrency_invalid")
        if agent.get("runtime_id") != runtime_id:
            raise MulticaCliError("runtime_switch_failed", uncertain=True)
        agent_model = agent.get("model")
        if not isinstance(agent_model, str):
            raise MulticaCliError("runtime_default_model_unverified", uncertain=True)
        models = target.get("models")
        if model is not None:
            if agent_model != model:
                raise MulticaCliError("runtime_switch_failed", uncertain=True)
            if isinstance(models, list) and model not in models:
                raise MulticaCliError("model_unsupported")
        elif agent_model and isinstance(models, list) and agent_model not in models:
            raise MulticaCliError("runtime_default_model_unverified", uncertain=True)
        return agent

    def agent_runs(self, instance: Instance, agent_id: str) -> list[dict[str, Any]]:
        before: str | None = None
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for _ in range(50):
            args = ["agent", "tasks", agent_id, "--output", "json", "--limit", "200"]
            if before:
                args.extend(["--before", before])
            page, stderr = self._call(instance, args, capture_stderr=True)
            assert isinstance(stderr, str)
            if isinstance(page, list):
                items = page
                has_more = len(items) == 200
                cursor = _RUN_CURSOR.search(stderr)
                next_before = cursor.group(1) if cursor else None
            elif isinstance(page, dict):
                items = page.get("tasks", page.get("runs"))
                next_before = page.get("next_before", page.get("next_cursor"))
                has_more = page.get("has_more", bool(next_before))
            else:
                raise MulticaCliError("multica_cli_invalid_response")
            if not isinstance(items, list) or any(
                not isinstance(row, dict) for row in items
            ):
                raise MulticaCliError("multica_cli_invalid_response")
            if any(
                not isinstance(row.get("status"), str) or not row["status"]
                for row in items
            ):
                raise MulticaCliError("multica_cli_invalid_response")
            rows.extend(items)
            if not has_more:
                return rows
            if (
                not isinstance(next_before, str)
                or not next_before
                or next_before in seen
            ):
                raise MulticaCliError("multica_cli_pagination_incomplete")
            seen.add(next_before)
            before = next_before
        raise MulticaCliError("multica_cli_pagination_incomplete")

    @staticmethod
    def active_runs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        active = []
        for row in rows:
            status = str(row.get("status", "")).lower()
            if status in _ACTIVE_RUN_STATES or status not in _TERMINAL_RUN_STATES:
                active.append(row)
        return active

    def switch_runtime(
        self, instance: Instance, agent_id: str, runtime_id: str, model: str | None
    ) -> dict[str, Any]:
        runtimes = self.runtime_list(instance)
        target = next((row for row in runtimes if row["id"] == runtime_id), None)
        if (
            target is None
            or target.get("status") != "online"
            or target.get("accessible") is not True
        ):
            raise MulticaCliError("runtime_not_allowed")
        models = target.get("models")
        if model is not None and isinstance(models, list) and model not in models:
            raise MulticaCliError("model_unsupported")
        current_agent = self.agent_get(instance, agent_id)
        if model is None and current_agent.get("runtime_id") != runtime_id:
            raise MulticaCliError("runtime_default_model_unverified")
        args = ["agent", "update", agent_id, "--runtime-id", runtime_id]
        if model is not None:
            args.extend(["--model", model])
        args.extend(["--output", "json"])
        self._call(instance, args, uncertain_on_failure=True)
        try:
            result = self.verify_agent_runtime(instance, agent_id, runtime_id, model)
        except MulticaCliError as exc:
            raise MulticaCliError(exc.code, uncertain=True) from None
        return result

    def find_request_issue(
        self, instance: Instance, marker: str, project_id: str
    ) -> dict[str, Any] | None:
        if not _MARKER.fullmatch(marker):
            raise MulticaCliError("invalid_request_marker")
        matches: list[dict[str, Any]] = []
        offset = 0
        for _ in range(100):
            value = self._call(
                instance,
                [
                    "issue",
                    "list",
                    "--project",
                    project_id,
                    "--limit",
                    "100",
                    "--offset",
                    str(offset),
                    "--fields",
                    "id,description,project_id,workspace_id,identifier",
                    "--output",
                    "json",
                ],
            )
            if isinstance(value, list):
                rows = value
                has_more = len(rows) == 100
            elif isinstance(value, dict):
                rows = value.get("issues")
                has_more = value.get(
                    "has_more", len(rows) == 100 if isinstance(rows, list) else False
                )
            else:
                raise MulticaCliError("multica_cli_invalid_response")
            if not isinstance(rows, list) or any(
                not isinstance(row, dict) for row in rows
            ):
                raise MulticaCliError("multica_cli_invalid_response")
            for row in rows:
                description = row.get("description")
                if description is None:
                    continue
                if not isinstance(description, str):
                    raise MulticaCliError("multica_cli_invalid_response")
                if marker not in description:
                    continue
                if row.get("project_id") != project_id:
                    raise MulticaCliError("issue_marker_scope_conflict", uncertain=True)
                matches.append(row)
            if len(matches) > 1:
                raise MulticaCliError("issue_create_unknown", uncertain=True)
            if not has_more:
                return matches[0] if matches else None
            if len(rows) != 100:
                raise MulticaCliError("multica_cli_pagination_incomplete")
            offset += len(rows)
        raise MulticaCliError("multica_cli_pagination_incomplete")

    def _attachment_path(self, attachment: dict[str, Any]) -> str:
        raw_path = attachment.get("path")
        digest = attachment.get("sha256")
        size = attachment.get("size")
        if (
            self.spool_root is None
            or not isinstance(raw_path, str)
            or not Path(raw_path).is_absolute()
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(size) is not int
            or size <= 0
        ):
            raise MulticaCliError("attachment_invalid")
        root = self.spool_root
        try:
            root_info = root.lstat()
            path = Path(raw_path)
            path_info = path.lstat()
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid != os.geteuid()
                or root_info.st_mode & 0o077
                or path.parent != root
                or path.name != digest
                or not stat.S_ISREG(path_info.st_mode)
                or stat.S_ISLNK(path_info.st_mode)
                or path_info.st_uid != os.geteuid()
                or path_info.st_mode & 0o077
                or path_info.st_size != size
            ):
                raise MulticaCliError("attachment_invalid")
            fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                opened = os.fstat(fd)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_size != size
                    or opened.st_mode & 0o077
                ):
                    raise MulticaCliError("attachment_invalid")
                hasher = hashlib.sha256()
                while block := os.read(fd, 65536):
                    hasher.update(block)
                if hasher.hexdigest() != digest:
                    raise MulticaCliError("attachment_invalid")
            finally:
                os.close(fd)
            return str(path)
        except MulticaCliError:
            raise
        except OSError:
            raise MulticaCliError("attachment_invalid") from None

    def create_issue(
        self,
        instance: Instance,
        *,
        request_id: str,
        agent_id: str,
        project_id: str,
        title: str,
        description: str,
        priority: str = "medium",
        parent_id: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
        related_issue_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        marker = f"<!-- router-request:{request_id} -->"
        existing = self.find_request_issue(instance, marker, project_id)
        if existing:
            return existing
        body = description.rstrip()
        related = related_issue_ids or []
        if related:
            body += "\n\nRelated issue identifiers (context only): " + ", ".join(
                related
            )
        body += f"\n\n{marker}"
        args = [
            "issue",
            "create",
            "--project",
            project_id,
            "--title",
            title,
            "--description-stdin",
            "--assignee-id",
            agent_id,
            "--priority",
            priority,
            "--output",
            "json",
        ]
        if parent_id:
            args.extend(["--parent", parent_id])
        for attachment in attachments or []:
            args.extend(
                [
                    "--attachment",
                    self._attachment_path(attachment),
                    "--allow-external-file",
                ]
            )
        value = self._call(instance, args, input_text=body, uncertain_on_failure=True)
        try:
            issue = self._object(value, "issue")
        except MulticaCliError:
            raise MulticaCliError("issue_create_unknown", uncertain=True) from None
        if not isinstance(issue.get("id"), str):
            raise MulticaCliError("issue_create_unknown", uncertain=True)
        return issue

    def issue_get(self, instance: Instance, issue_id: str) -> dict[str, Any]:
        value = self._call(instance, ["issue", "get", issue_id, "--output", "json"])
        issue = self._object(value, "issue")
        if issue.get("id") != issue_id:
            raise MulticaCliError("multica_cli_invalid_response")
        return issue

    def cancel_issue(self, instance: Instance, issue_id: str) -> dict[str, Any]:
        self._call(
            instance,
            [
                "issue",
                "update",
                issue_id,
                "--status",
                "cancelled",
                "--no-start",
                "--output",
                "json",
            ],
            uncertain_on_failure=True,
        )
        try:
            return self.issue_get(instance, issue_id)
        except MulticaCliError:
            raise MulticaCliError("cancellation_unconfirmed", uncertain=True) from None
