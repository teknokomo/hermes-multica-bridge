from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from deploy.tools import multica_watch_register as register

WORKSPACE = "11111111-1111-4111-8111-111111111111"
CORE_PROJECT = "22222222-2222-4222-8222-222222222222"
REPO_PROJECT = "33333333-3333-4333-8333-333333333333"
CORE_ROUTE = "44444444-4444-4444-8444-444444444444"
REPO_ROUTE = "55555555-5555-4555-8555-555555555555"
ISSUE_A = "66666666-6666-4666-8666-666666666666"
ISSUE_B = "77777777-7777-4777-8777-777777777777"


def config_data() -> dict[str, object]:
    return {
        "watcher_profile": "watcher-test",
        "platform": "telegram",
        "chat_type": "thread",
        "message_id": "33",
        "multica_profile": "test-profile",
        "multica_server_url": "https://agents.example.test",
        "workspace_id": WORKSPACE,
        "sweep_since": "2026-11-08T20:00:00+03:00",
        "user_id": "12345",
        "chat_id": "-1000000000000",
        "thread_id": "33",
        "routes": {
            "core": {"route_id": CORE_ROUTE, "project_id": CORE_PROJECT},
            "repo": {"route_id": REPO_ROUTE, "project_id": REPO_PROJECT},
        },
    }


def issue(
    issue_id: str,
    *,
    project: str = CORE_PROJECT,
    updated: str = "2026-11-08T17:00:00Z",
    status: str = "todo",
    identifier: str = "LING-1",
) -> dict[str, object]:
    return {
        "id": issue_id,
        "identifier": identifier,
        "workspace_id": WORKSPACE,
        "project_id": project,
        "status": status,
        "updated_at": updated,
    }


class FakeCli:
    def __init__(
        self,
        issues: dict[str, dict[str, object]] | None = None,
        pages: dict[tuple[str, int], tuple[list[dict[str, object]], bool, int]]
        | None = None,
    ):
        self.issues = issues or {}
        self.pages = pages or {}
        self.get_calls: list[str] = []
        self.list_calls: list[tuple[str, int]] = []

    def get_issue(self, issue_id: str) -> dict[str, object]:
        self.get_calls.append(issue_id)
        if issue_id in self.issues:
            return self.issues[issue_id]
        for candidate in self.issues.values():
            if candidate.get("identifier") == issue_id:
                return candidate
        raise register.MulticaError("not found")

    def list_page(self, route: register.Route, offset: int):
        self.list_calls.append((route.name, offset))
        return self.pages.get((route.name, offset), ([], False, offset))


class FakeIpc:
    def __init__(
        self,
        *,
        register_errors: list[Exception] | None = None,
        readiness_error: Exception | None = None,
    ):
        self.mappings: list[dict[str, object]] = []
        self.readiness_calls = 0
        self.register_errors = list(register_errors or [])
        self.readiness_error = readiness_error

    def readiness(self):
        self.readiness_calls += 1
        if self.readiness_error:
            raise self.readiness_error
        return {"ok": True, "ready": True}

    def register(self, mapping):
        if self.register_errors:
            raise self.register_errors.pop(0)
        self.mappings.append(dict(mapping))
        return {"ok": True, "mapping": "registered"}


class MulticaWatchRegisterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.config = register.parse_config(config_data())
        self.journal = self.root / "state" / "mappings.json"
        self.journal.parent.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_config_normalizes_timestamp_to_utc_and_defaults_anchor(self) -> None:
        self.assertEqual(
            self.config.sweep_since, datetime(2026, 11, 8, 17, 0, tzinfo=UTC)
        )
        self.assertEqual(self.config.message_id, "33")

    def test_https_origin_preserves_ipv6_brackets(self) -> None:
        self.assertEqual(
            register._https_origin("https://[2001:db8::1]:8443"),
            "https://[2001:db8::1]:8443",
        )

    def test_config_rejects_extra_route_and_untrusted_url(self) -> None:
        data = config_data()
        data["routes"] = {
            **data["routes"],
            "extra": {"route_id": CORE_ROUTE, "project_id": CORE_PROJECT},
        }
        with self.assertRaises(register.ConfigError):
            register.parse_config(data)
        data = config_data()
        data["multica_server_url"] = "http://agents.example.test"
        with self.assertRaises(register.ConfigError):
            register.parse_config(data)

    def test_config_requires_timezone_and_distinct_projects(self) -> None:
        data = config_data()
        data["sweep_since"] = "2026-11-08T17:00:00"
        with self.assertRaises(register.ConfigError):
            register.parse_config(data)
        data = config_data()
        data["routes"]["repo"]["project_id"] = CORE_PROJECT
        with self.assertRaises(register.ConfigError):
            register.parse_config(data)

    def test_timestamp_boundary_and_offsets(self) -> None:
        cutoff = register.parse_rfc3339("2026-11-08T17:00:00Z", "cutoff")
        on_cutoff = register.parse_rfc3339("2026-11-08T20:00:00+03:00", "updated_at")
        before = register.parse_rfc3339("2026-11-08T16:59:59Z", "updated_at")
        after = register.parse_rfc3339("2026-11-08T17:00:01Z", "updated_at")
        self.assertEqual(on_cutoff, cutoff)
        self.assertLess(before, cutoff)
        self.assertGreater(after, cutoff)

    def test_timestamp_rejects_bad_and_naive_values(self) -> None:
        for value in ("bad", "2026-02-30T00:00:00Z", "2026-11-08T00:00:00"):
            with self.subTest(value=value), self.assertRaises(register.ConfigError):
                register.parse_rfc3339(value, "updated_at")

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(ValueError):
            register._strict_json('{"ok":true,"ok":false}')

    def test_issue_get_canonicalizes_uuid(self) -> None:
        raw = issue(ISSUE_A.upper())
        found = register._extract_issue(raw)
        self.assertEqual(found["id"], ISSUE_A)

    def test_issue_verification_rejects_other_project_before_ipc(self) -> None:
        cli = FakeCli({ISSUE_A: issue(ISSUE_A, project=REPO_PROJECT)})
        ipc = FakeIpc()
        with self.assertRaises(register.AppError) as raised:
            register._run_single(
                ISSUE_A,
                "core",
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(raised.exception.exit_code, 1)
        self.assertEqual(ipc.readiness_calls, 0)
        self.assertEqual(ipc.mappings, [])

    def test_multica_arguments_pin_profile_server_and_workspace(self) -> None:
        cli = register.MulticaCli(self.config)
        captured: list[str] = []

        def fake_run(command, *, env):
            captured.extend(command)
            self.assertNotIn("token-sentinel", " ".join(command))
            return json.dumps(issue(ISSUE_A)).encode()

        with patch.object(cli, "_run_bounded", side_effect=fake_run):
            cli.get_issue("LING-7")
        self.assertEqual(
            captured[:7],
            [
                str(register.MULTICA_BIN),
                "--profile",
                "test-profile",
                "--server-url",
                "https://agents.example.test",
                "--workspace-id",
                WORKSPACE,
            ],
        )
        self.assertIn("issue", captured)
        self.assertIn("get", captured)

    def test_page_loader_handles_more_than_one_hundred_items_and_deduplicates(
        self,
    ) -> None:
        items = [
            issue(str(__import__("uuid").uuid4()), identifier=f"LING-{i}")
            for i in range(100)
        ]
        duplicate = dict(items[0])
        tail = [
            issue(str(__import__("uuid").uuid4()), identifier="LING-100"),
            duplicate,
        ]
        cli = FakeCli(
            pages={
                ("core", 0): (items, True, 0),
                ("core", 100): (tail, False, 100),
            }
        )
        summary = register.SweepSummary()
        rows = register._load_project_rows(
            cli, self.config, self.config.routes["core"], summary
        )
        self.assertEqual(len(rows), 101)
        self.assertEqual(cli.list_calls, [("core", 0), ("core", 100)])
        self.assertEqual(summary.errors, 0)

    def test_page_loader_counts_inconsistent_duplicate_as_error(self) -> None:
        first = issue(ISSUE_A)
        changed = issue(ISSUE_A, updated="2026-11-08T17:01:00Z")
        cli = FakeCli(pages={("core", 0): ([first, changed], False, 0)})
        summary = register.SweepSummary()
        rows = register._load_project_rows(
            cli, self.config, self.config.routes["core"], summary
        )
        self.assertEqual(len(rows), 0)
        self.assertEqual(summary.errors, 1)

    def test_sweep_dry_run_filters_old_done_cancelled_and_includes_cutoff(self) -> None:
        rows = [
            issue(ISSUE_A, updated="2026-11-08T16:59:59Z", identifier="LING-OLD"),
            issue(ISSUE_B, updated="2026-11-08T17:00:00Z", identifier="LING-EDGE"),
            issue(
                str(__import__("uuid").uuid4()), status="done", identifier="LING-DONE"
            ),
            issue(
                str(__import__("uuid").uuid4()),
                status="cancelled",
                identifier="LING-CANCEL",
            ),
        ]
        cli = FakeCli(pages={("core", 0): (rows, False, 0)})
        ipc = FakeIpc()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = register._run_sweep(
                dry_run=True,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(code, 0)
        self.assertEqual(ipc.readiness_calls, 0)
        self.assertEqual(ipc.mappings, [])
        self.assertFalse(self.journal.exists())
        self.assertIn(
            "checked=4 registered=0 skipped=3 errors=0 dry_run=true would_register=1",
            output.getvalue(),
        )

    def test_sweep_dry_run_does_not_register_done_but_existing_mapping_still_replays(
        self,
    ) -> None:
        done = issue(ISSUE_A, status="done")
        self.assertEqual(done["status"], "done")
        route = self.config.routes["core"]
        mapping = register._mapping(self.config, route, ISSUE_A)
        journal = register._empty_journal()
        register._save_mapping(journal, self.journal, mapping, owner_uid=os.getuid())
        cli = FakeCli(pages={("core", 0): ([done], False, 0)})
        ipc = FakeIpc()
        register._run_sweep(
            dry_run=True,
            config=self.config,
            cli=cli,
            ipc=ipc,
            journal_path=self.journal,
        )
        self.assertEqual(ipc.mappings, [])
        # A previously registered issue remains in watcher state; sweep filtering
        # must not remove or alter its mapping record.
        stored = register._read_journal(self.journal, owner_uid=os.getuid())
        self.assertEqual(
            stored["mappings"][register._journal_key(mapping)]["mapping"], mapping
        )

    def test_sweep_registers_only_after_ack_and_skips_confirmed_mapping(self) -> None:
        rows = [issue(ISSUE_A), issue(ISSUE_B, identifier="LING-2")]
        cli = FakeCli(pages={("core", 0): (rows, False, 0)})
        ipc = FakeIpc()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = register._run_sweep(
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(code, 0)
        self.assertEqual(len(ipc.mappings), 2)
        second_cli = FakeCli(pages={("core", 0): (rows, False, 0)})
        second_ipc = FakeIpc()
        with contextlib.redirect_stdout(io.StringIO()):
            register._run_sweep(
                dry_run=False,
                config=self.config,
                cli=second_cli,
                ipc=second_ipc,
                journal_path=self.journal,
            )
        self.assertEqual(second_ipc.mappings, [])

    def test_single_registration_repeats_idempotently_even_when_journal_matches(
        self,
    ) -> None:
        cli = FakeCli({ISSUE_A: issue(ISSUE_A)})
        ipc = FakeIpc()
        for _ in range(2):
            with contextlib.redirect_stdout(io.StringIO()):
                code = register._run_single(
                    "LING-1",
                    "core",
                    dry_run=False,
                    config=self.config,
                    cli=cli,
                    ipc=ipc,
                    journal_path=self.journal,
                )
            self.assertEqual(code, 0)
        self.assertEqual(len(ipc.mappings), 2)
        self.assertEqual(len(cli.get_calls), 2)

    def test_lost_ack_does_not_create_confirmation_record(self) -> None:
        cli = FakeCli({ISSUE_A: issue(ISSUE_A)})
        ipc = FakeIpc(register_errors=[register.IpcUnavailable("lost acknowledgement")])
        with self.assertRaises(register.AppError) as raised:
            register._run_single(
                "LING-1",
                "core",
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(raised.exception.exit_code, 2)
        self.assertFalse(self.journal.exists())

    def test_single_registration_reports_local_mapping_conflict(self) -> None:
        old = register._mapping(self.config, self.config.routes["core"], ISSUE_A)
        old["message_id"] = "999"
        journal = register._empty_journal()
        register._save_mapping(journal, self.journal, old, owner_uid=os.getuid())
        cli = FakeCli({ISSUE_A: issue(ISSUE_A)})
        ipc = FakeIpc()
        with self.assertRaises(register.AppError) as raised:
            register._run_single(
                "LING-1",
                "core",
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(raised.exception.exit_code, 3)
        self.assertEqual(ipc.mappings, [])

    def test_sweep_rejects_malformed_updated_at_without_registration(self) -> None:
        cli = FakeCli(
            pages={("core", 0): ([issue(ISSUE_A, updated="not-a-date")], False, 0)}
        )
        ipc = FakeIpc()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = register._run_sweep(
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(code, 4)
        self.assertEqual(ipc.mappings, [])
        self.assertIn("errors=1", output.getvalue())

    def test_sweep_stops_on_ipc_rejection_and_keeps_prior_acks(self) -> None:
        rows = [issue(ISSUE_A), issue(ISSUE_B, identifier="LING-2")]
        cli = FakeCli(pages={("core", 0): (rows, False, 0)})
        ipc = FakeIpc(register_errors=[register.IpcRejected("mapping conflict")])
        with contextlib.redirect_stdout(io.StringIO()):
            code = register._run_sweep(
                dry_run=False,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(code, 3)
        self.assertEqual(ipc.mappings, [])
        self.assertFalse(self.journal.exists())

    def test_private_config_file_requires_owner_only_permissions(self) -> None:
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(config_data()))
        config_path.chmod(0o640)
        with self.assertRaises(register.ConfigError):
            register.load_config(config_path)
        config_path.chmod(0o600)
        self.assertEqual(register.load_config(config_path).workspace_id, WORKSPACE)

    def test_config_example_is_syntactically_valid_but_non_operational(self) -> None:
        example_path = Path(__file__).parents[1] / "config/multica-watch.example.json"
        example = register._strict_json(example_path.read_bytes())
        self.assertEqual(example["multica_server_url"], "https://multica.example.invalid")
        with self.assertRaises(register.ConfigError):
            register.parse_config(example)

    def test_corrupt_journal_and_symlink_are_rejected(self) -> None:
        self.journal.write_text('{"mappings":{},"mappings":{}}')
        self.journal.chmod(0o600)
        with self.assertRaises(register.ConfigError):
            register._read_journal(self.journal, owner_uid=os.getuid())
        self.journal.unlink()
        target = self.root / "target"
        target.write_text('{"mappings":{}}')
        target.chmod(0o600)
        self.journal.symlink_to(target)
        with self.assertRaises(register.ConfigError):
            register._read_journal(self.journal, owner_uid=os.getuid())

    def test_concurrent_sweeps_share_one_exclusive_journal_lock(self) -> None:
        first_inside = threading.Event()
        release_first = threading.Event()
        second_inside = threading.Event()

        def first_worker() -> None:
            with register._locked_journal(
                self.journal, owner_uid=os.getuid(), create=True
            ):
                first_inside.set()
                release_first.wait(timeout=3)

        def second_worker() -> None:
            with register._locked_journal(
                self.journal, owner_uid=os.getuid(), create=True
            ):
                second_inside.set()

        first = threading.Thread(target=first_worker)
        second = threading.Thread(target=second_worker)
        first.start()
        self.assertTrue(first_inside.wait(timeout=1))
        second.start()
        time.sleep(0.05)
        self.assertFalse(second_inside.is_set())
        release_first.set()
        first.join(timeout=2)
        second.join(timeout=2)
        self.assertTrue(second_inside.is_set())
        self.assertEqual(
            self.journal.with_suffix(".json.lock").stat().st_mode & 0o777, 0o600
        )

    def test_dry_run_creates_neither_lock_nor_journal(self) -> None:
        journal_dir = self.root / "unused-state"
        journal = journal_dir / "mappings.json"
        cli = FakeCli(pages={("core", 0): ([], False, 0)})
        with contextlib.redirect_stdout(io.StringIO()):
            register._run_sweep(
                dry_run=True,
                config=self.config,
                cli=cli,
                ipc=FakeIpc(),
                journal_path=journal,
            )
        self.assertFalse(journal_dir.exists())

    def test_ipc_readiness_and_registration_use_length_prefixed_frames(self) -> None:
        sock_path = self.root / "test.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(2)
        observed: list[dict[str, object]] = []

        def serve() -> None:
            for reply in (
                {"ok": True, "ready": True},
                {"ok": True, "mapping": "registered"},
            ):
                conn, _ = server.accept()
                with conn:
                    header = conn.recv(4)
                    size = struct.unpack("!I", header)[0]
                    body = b""
                    while len(body) < size:
                        body += conn.recv(size - len(body))
                    observed.append(json.loads(body))
                    encoded = json.dumps(reply, separators=(",", ":")).encode()
                    conn.sendall(struct.pack("!I", len(encoded)) + encoded)
            server.close()

        thread = threading.Thread(target=serve)
        thread.start()
        client = register.WatcherIpc(sock_path)
        self.assertEqual(client.readiness()["ready"], True)
        client.register(
            register._mapping(self.config, self.config.routes["core"], ISSUE_A)
        )
        thread.join(timeout=3)
        self.assertEqual(
            [item["operation"] for item in observed], ["readiness", "register_issue"]
        )

    def test_ipc_frame_enforces_16_kib_utf8_payload_limit(self) -> None:
        overhead = len(
            json.dumps({"value": ""}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        exact = register._frame(
            {"value": "x" * (register.MAX_IPC_FRAME - overhead)}
        )
        self.assertEqual(struct.unpack("!I", exact[:4])[0], register.MAX_IPC_FRAME)

        with self.assertRaises(register.IpcRejected):
            register._frame(
                {"value": "x" * (register.MAX_IPC_FRAME - overhead + 1)}
            )
        with self.assertRaises(register.IpcRejected):
            register._frame(
                {"value": "é" * (register.MAX_IPC_FRAME - overhead)}
            )

    def test_ipc_malformed_response_is_rejected(self) -> None:
        sock_path = self.root / "bad.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        def serve() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(struct.pack("!I", 7) + b'{"ok":')
            server.close()

        thread = threading.Thread(target=serve)
        thread.start()
        with self.assertRaises(register.IpcRejected):
            register.WatcherIpc(sock_path).readiness()
        thread.join(timeout=3)

    def test_ipc_uses_one_deadline_for_slow_drip_response(self) -> None:
        sock_path = self.root / "slow.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        def serve() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(4096)
                response = json.dumps(
                    {"ok": True, "ready": True}, separators=(",", ":")
                ).encode()
                frame = struct.pack("!I", len(response)) + response
                for byte in frame:
                    try:
                        conn.sendall(bytes([byte]))
                    except OSError:
                        break
                    time.sleep(0.03)
            server.close()

        thread = threading.Thread(target=serve)
        thread.start()
        started = time.monotonic()
        with self.assertRaises(register.IpcUnavailable):
            register.WatcherIpc(sock_path, timeout=0.2).readiness()
        elapsed = time.monotonic() - started
        thread.join(timeout=2)
        self.assertLess(elapsed, 0.65)

    def test_readiness_cli_prints_actual_response_and_exit_code(self) -> None:
        ipc = FakeIpc()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = register.main(["--readiness"], ipc=ipc)
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().strip(), "ok=true ready=true")
        self.assertEqual(ipc.readiness_calls, 1)

    def test_invalid_cli_modes_use_documented_input_error_code(self) -> None:
        for args in (
            [],
            ["LING-1"],
            ["LING-1", "--route", "other"],
            ["--sweep", "--route", "core"],
        ):
            cli = FakeCli()
            ipc = FakeIpc()
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), patch.object(
                register, "load_config", return_value=self.config
            ):
                result = register.main(args, config_path=self.root / "fixture.json",
                                       journal_path=self.journal, ipc=ipc, cli_factory=lambda _, fixture=cli: fixture)
                self.assertEqual(result, 4)
            self.assertEqual(cli.get_calls, [])
            self.assertEqual(cli.list_calls, [])
            self.assertEqual(ipc.mappings, [])
            self.assertFalse(self.journal.exists())

    def test_sweep_deduplicates_an_issue_returned_for_two_projects(self) -> None:
        duplicate_for_core = issue(ISSUE_A, project=CORE_PROJECT)
        duplicate_for_repo = issue(ISSUE_A, project=REPO_PROJECT)
        cli = FakeCli(
            pages={
                ("core", 0): ([duplicate_for_core], False, 0),
                ("repo", 0): ([duplicate_for_repo], False, 0),
            }
        )
        ipc = FakeIpc()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = register._run_sweep(
                dry_run=True,
                config=self.config,
                cli=cli,
                ipc=ipc,
                journal_path=self.journal,
            )
        self.assertEqual(code, 4)
        self.assertEqual(ipc.mappings, [])
        self.assertIn("checked=1", output.getvalue())
        self.assertIn("errors=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()


class ParameterizedRegistrarTests(unittest.TestCase):
    def test_max_mapping_uses_explicit_profile_platform_and_chat(self):
        data = config_data()
        data.update(watcher_profile="custom-profile", platform="max", chat_type="group",
                    thread_id=None, message_id="message.fake")
        cfg = register.parse_config(data)
        result = register._mapping(cfg, cfg.routes["core"], ISSUE_A)
        self.assertEqual(result["profile"], "custom-profile")
        self.assertEqual(result["platform"], "max")
        self.assertEqual(result["chat_type"], "group")
        self.assertEqual(result["message_id"], "message.fake")
        self.assertIsNone(result["thread_id"])

    def test_aliases_are_not_pinned_to_core_and_repo(self):
        data = config_data()
        data["routes"] = {"custom-route": data["routes"]["core"]}
        cfg = register.parse_config(data)
        self.assertEqual(set(cfg.routes), {"custom-route"})

    def test_max_thread_and_invalid_platform_fail_closed(self):
        for updates in ({"platform": "max"}, {"platform": []}, {"chat_type": []}):
            data = config_data()
            data.update(updates)
            with self.subTest(updates=updates), self.assertRaises(register.ConfigError):
                register.parse_config(data)
