"""Read-only Multica access with isolated service-owned CLI profiles."""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess  # nosec B404: fixed read-only CLI argv, isolated environment
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from bridge.errors import BridgeError
from bridge.validation import strict_json_loads
from bridge.watcher_api import WatcherApiClient

from .config import (
    Config,
    NotifyError,
    atomic_private,
    credential,
    private_dir,
    require,
)


def run_cli(argv: list[str], env: dict, timeout: float) -> bytes:
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )  # nosec B603
    except OSError:
        raise NotifyError("notify_workspace_unavailable") from None
    result = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    continue
                part = os.read(proc.stdout.fileno(), 65536)
                if not part:
                    require(
                        proc.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                        "notify_workspace_unavailable",
                    )
                    return bytes(result)
                result.extend(part)
                require(len(result) <= 4 * 1024 * 1024, "notify_event_invalid")
            raise NotifyError("notify_workspace_unavailable")
    except subprocess.TimeoutExpired:
        raise NotifyError("notify_workspace_unavailable") from None
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        proc.stdout.close()


class Multica:
    def __init__(self, config: Config, key: str):
        self.config, self.key = config, key
        self.workspace = config.workspaces[key]
        self.token = credential(self.workspace["pat_credential"])
        self.reader = WatcherApiClient(
            self.workspace["origin"],
            self.token,
            self.workspace["workspace_id"],
            timeout=config.service["request_timeout_seconds"],
        )
        private_dir(Path(config.service["runtime_dir"]))
        self.reader.max_response_bytes = 4 * 1024 * 1024
        self.home = Path(config.service["runtime_dir"]) / "cli-home" / key
        for directory in (
            self.home.parent,
            self.home,
            self.home / ".multica",
            self.home / ".multica" / "profiles",
            self.home / ".multica" / "profiles" / self.workspace["cli_profile"],
        ):
            private_dir(directory)
        atomic_private(
            self.home
            / ".multica"
            / "profiles"
            / self.workspace["cli_profile"]
            / "config.json",
            json.dumps(
                {
                    "server_url": self.workspace["origin"],
                    "workspace_id": self.workspace["workspace_id"],
                    "token": self.token,
                }
            ).encode(),
        )
        self.env = {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
        }
        self.limited = (
            True  # The source has no guaranteed durable status-transition stream.
        )

    def check_cli(self) -> None:
        binary = self.config.service["cli_binary"]
        version = run_cli([binary, "--version"], self.env, 15).decode(errors="replace")
        match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", version)
        require(
            match is not None and tuple(int(v) for v in match.groups()) >= (0, 8, 2),
            "notify_cli_contract_unavailable",
        )
        raw = run_cli([binary, "issue", "list", "--help"], self.env, 15)
        require(
            all(
                flag in raw
                for flag in (
                    b"--updated-since",
                    b"--updated-until",
                    b"--offset",
                    b"--fields",
                    b"--sort",
                    b"--direction",
                    b"--project",
                )
            ),
            "notify_cli_contract_unavailable",
        )

    def issues(
        self, project: str = "", since: float | None = None, until: float | None = None
    ):
        offset, seen = 0, set()
        for _ in range(10000):
            argv = [
                self.config.service["cli_binary"],
                "--profile",
                self.workspace["cli_profile"],
                "--server-url",
                self.workspace["origin"],
                "--workspace-id",
                self.workspace["workspace_id"],
                "issue",
                "list",
                "--output",
                "json",
                "--limit",
                "100",
                "--offset",
                str(offset),
                "--sort",
                "created_at",
                "--direction",
                "asc",
                "--fields",
                "id,identifier,workspace_id,project_id,status,updated_at,revision,assignee_type,assignee_id,labels",
            ]
            if project:
                argv += ["--project", project]
            if since is not None:
                argv += [
                    "--updated-since",
                    datetime.fromtimestamp(since, UTC).isoformat(),
                    "--updated-until",
                    datetime.fromtimestamp(until, UTC).isoformat(),
                ]
            try:
                page = strict_json_loads(
                    run_cli(
                        argv, self.env, self.config.service["request_timeout_seconds"]
                    )
                )
            except (ValueError, UnicodeError, RecursionError):
                raise NotifyError("notify_event_invalid") from None
            require(
                isinstance(page, dict)
                and isinstance(page.get("issues"), list)
                and type(page.get("has_more")) is bool
                and page.get("offset") == offset,
                "notify_event_invalid",
            )
            rows = page["issues"]
            require(
                len(rows) <= 100
                and all(
                    isinstance(v, dict) and isinstance(v.get("id"), str) for v in rows
                ),
                "notify_event_invalid",
            )
            fresh = [row for row in rows if row["id"] not in seen]
            for row in fresh:
                require(
                    row.get("workspace_id") == self.workspace["workspace_id"]
                    and (not project or row.get("project_id") == project),
                    "notify_event_invalid",
                )
                seen.add(row["id"])
                yield row
            if not page["has_more"]:
                return
            require(bool(rows) and bool(fresh), "notify_event_invalid")
            offset += len(rows)
        raise NotifyError("notify_event_invalid")

    def snapshot(self, issue_id: str) -> tuple:
        version_fields = (
            "id",
            "identifier",
            "workspace_id",
            "status",
            "revision",
            "updated_at",
            "status_entered_at",
            "history_id",
            "project_id",
            "assignee_type",
            "assignee_id",
            "labels",
            "title",
            "description",
        )
        for _ in range(3):
            issue = self.reader.get_issue(issue_id)
            require(
                issue.get("workspace_id") == self.workspace["workspace_id"],
                "notify_event_invalid",
            )
            raw_comments = self.reader._request(
                "GET", f"/api/issues/{quote(issue_id, safe='')}/comments"
            )
            if not isinstance(raw_comments, (bytes, str)):
                raise NotifyError("notify_event_invalid")
            try:
                comments = strict_json_loads(raw_comments)
            except (ValueError, UnicodeError, RecursionError):
                raise NotifyError("notify_event_invalid") from None
            require(
                isinstance(comments, list)
                and len(comments) <= 10000
                and all(isinstance(row, dict) for row in comments),
                "notify_event_invalid",
            )
            try:
                raw = self.reader._request(
                    "GET", f"/api/issues/{quote(issue_id, safe='')}/task-runs"
                )
                if not isinstance(raw, (bytes, str)):
                    raise NotifyError("notify_event_invalid")
                try:
                    runs = strict_json_loads(raw)
                except (ValueError, UnicodeError, RecursionError):
                    raise NotifyError("notify_event_invalid") from None
                require(
                    isinstance(runs, list) and len(runs) <= 10000,
                    "notify_event_invalid",
                )
            except BridgeError as exc:
                if exc.code in {
                    "result_not_found",
                    "api_forbidden",
                    "api_unavailable",
                }:
                    self.limited = True
                    runs = []
                else:
                    raise
            latest = self.reader.get_issue(issue_id)
            require(
                latest.get("workspace_id") == self.workspace["workspace_id"],
                "notify_event_invalid",
            )

            def signature(value):
                return json.dumps(
                    [value.get(k) for k in version_fields],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                )

            if signature(issue) == signature(latest):
                return (
                    latest,
                    comments,
                    runs,
                    self.reader.issue_link(latest["identifier"]),
                )
        raise NotifyError("notify_snapshot_unstable")
