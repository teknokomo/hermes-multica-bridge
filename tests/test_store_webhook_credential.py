from __future__ import annotations

import fcntl
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from bridge.errors import BridgeError
from deploy import configure_isolated_instance as helper
from deploy import store_webhook_credential as rotate_helper
from tests.helpers import (
    TEST_CONNECTION_ID,
    TEST_HMAC_SECRET,
    TEST_INSTANCE_ID,
    TEST_ORIGIN,
    TEST_ROUTE_ID,
    TEST_ROUTE_POLICY_FINGERPRINT,
    TEST_WEBHOOK_URL,
    TEST_WORKSPACE_KEY,
)


def _identity_args() -> list[str]:
    return [
        "--instance", TEST_INSTANCE_ID,
        "--route-id", TEST_ROUTE_ID,
        "--connection-id", TEST_CONNECTION_ID,
        "--workspace-key", TEST_WORKSPACE_KEY,
        "--route-policy-fingerprint", TEST_ROUTE_POLICY_FINGERPRINT,
    ]


class _TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class DeployHelperTests(unittest.TestCase):
    def _configure_example_instance(self, directory: str) -> None:
        setup_args = [
            *_identity_args(),
            "--hermes-user", "hermes-user",
            "--gateway-unit", "hermes-gateway.service",
            "--multica-origin", TEST_ORIGIN,
            "--workspace-id", "workspace-example",
            "--autopilot-id", "autopilot-example",
            "--trigger-id", "trigger-example",
            "--source-board", "example-board",
            "--root", directory,
        ]
        with patch.object(helper.sys, "stdin", _TtyInput()), patch(
            "builtins.input", return_value="12345"
        ), patch.object(
            helper.getpass,
            "getpass",
            side_effect=[TEST_WEBHOOK_URL, TEST_HMAC_SECRET],
        ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(setup_args), 0)

    def test_rotation_helper_rejects_instance_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(BridgeError):
                rotate_helper._instance_paths("../../tmp", config_root=root)
            config, destination = rotate_helper._instance_paths("example", config_root=root)
            self.assertEqual(config, root.resolve() / "example.toml")
            self.assertTrue(destination.is_relative_to(root.resolve() / "credentials"))

    def test_rotation_lock_serializes_same_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            lock_file = config.with_name(f".{config.name}.rotation.lock")

            with rotate_helper._instance_rotation_lock(
                config,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            ):
                fd = os.open(lock_file, os.O_RDWR)
                try:
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o600)
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)

            fd = os.open(lock_file, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def test_atomic_write_rejects_untrusted_directory_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "etc" / "bridge" / "secret"
            target.parent.mkdir(parents=True)
            with self.assertRaises(OSError):
                helper._atomic_write(
                    target,
                    b"secret",
                    0o600,
                    trusted_root=root,
                    expected_owner_uid=root.stat().st_uid + 1,
                )

    def test_staged_instance_writes_protected_files_without_printing_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            stderr = io.StringIO()
            hmac_secret = f" {TEST_HMAC_SECRET} "
            args = [
                *_identity_args(),
                "--hermes-user",
                "hermes-user",
                "--gateway-unit",
                "hermes-gateway.service",
                "--multica-origin",
                "https://multica.example.org",
                "--workspace-id",
                "workspace-example",
                "--autopilot-id",
                "autopilot-example",
                "--trigger-id",
                "trigger-example",
                "--source-board",
                "example-board",
                "--root",
                directory,
                "--enable",
            ]
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), patch.object(
                helper.getpass,
                "getpass",
                side_effect=[TEST_WEBHOOK_URL, hmac_secret],
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                code = helper.main(args)
            self.assertEqual(code, 0, stderr.getvalue())
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            webhook = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/webhook-url"
            hmac = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/hmac-signing-secret"
            dropin = (
                root
                / f"etc/systemd/system/hermes-multica-bridge@{TEST_INSTANCE_ID}.socket.d/10-hermes-user.conf"
            )
            self.assertTrue(config.exists())
            self.assertEqual(stat.S_IMODE(config.parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(webhook.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(hmac.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(webhook.parent.stat().st_mode), 0o700)
            self.assertEqual(hmac.read_text(encoding="utf-8"), hmac_secret)
            self.assertIn("SocketUser=hermes-user", dropin.read_text(encoding="utf-8"))
            output = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(TEST_WEBHOOK_URL, output)
            self.assertNotIn(hmac_secret, output)

    def test_staged_instance_rejects_invalid_hermes_username(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with patch.object(helper.sys, "stdin", _TtyInput()), redirect_stderr(stderr):
                code = helper.main(
                    [
                        *_identity_args(),
                        "--hermes-user",
                        "hermes-user\nSocketMode=0666",
                        "--root",
                        directory,
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("user name is invalid", stderr.getvalue())
            self.assertFalse((Path(directory) / "etc/systemd/system").exists())

    def test_staged_instance_rejects_invalid_ipc_uid_before_writing_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            args = [
                *_identity_args(),
                "--hermes-user", "hermes-user",
                "--gateway-unit", "hermes-gateway.service",
                "--root", directory,
            ]
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="0"
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = helper.main(args)
            self.assertEqual(code, 1)
            self.assertIn("UID is invalid", stderr.getvalue())
            self.assertFalse((Path(directory) / "etc/hermes-multica-bridge").exists())

    def test_staged_instance_rejects_invalid_gateway_unit_before_writing_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            args = [
                *_identity_args(),
                "--hermes-user", "hermes-user",
                "--gateway-unit", "not-a-service",
                "--root", directory,
            ]
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = helper.main(args)
            self.assertEqual(code, 1)
            self.assertIn("Gateway systemd unit is invalid", stderr.getvalue())
            self.assertFalse((Path(directory) / "etc/hermes-multica-bridge").exists())

    def test_staged_instance_rejects_hmac_secret_larger_than_sender_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = [
                *_identity_args(),
                "--hermes-user",
                "hermes-user",
                "--gateway-unit",
                "hermes-gateway.service",
                "--multica-origin",
                TEST_ORIGIN,
                "--workspace-id",
                "workspace-example",
                "--autopilot-id",
                "autopilot-example",
                "--trigger-id",
                "trigger-example",
                "--source-board",
                "example-board",
                "--root",
                directory,
            ]
            stderr = io.StringIO()
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), patch.object(
                helper.getpass,
                "getpass",
                side_effect=[TEST_WEBHOOK_URL, "x" * 4097],
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = helper.main(args)
            self.assertEqual(code, 1)
            self.assertIn("HMAC signing secret is empty or too large", stderr.getvalue())
            self.assertFalse((Path(directory) / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml").exists())

    def test_isolated_instance_update_failure_restores_previous_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            credential_root = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}"
            webhook = credential_root / "webhook-url"
            hmac = credential_root / "hmac-signing-secret"
            pat = credential_root / "multica-pat"
            dropin = root / f"etc/systemd/system/hermes-multica-bridge@{TEST_INSTANCE_ID}.socket.d/10-hermes-user.conf"
            paths = [config, webhook, hmac, pat, dropin]
            originals = {path: path.read_bytes() for path in paths}
            new_webhook = TEST_WEBHOOK_URL[:-1] + ("A" if TEST_WEBHOOK_URL[-1] != "A" else "B")
            new_hmac = "fixture-new-hmac-secret"
            args = [
                *_identity_args(),
                "--hermes-user", "hermes-user",
                "--gateway-unit", "hermes-gateway.service",
                "--multica-origin", TEST_ORIGIN,
                "--workspace-id", "workspace-example",
                "--autopilot-id", "autopilot-example",
                "--trigger-id", "trigger-example",
                "--source-board", "example-board",
                "--root", directory,
            ]
            original_atomic_write = helper._atomic_write

            def fail_new_hmac(path, data, mode, **kwargs):
                if Path(path) == hmac and data == new_hmac.encode("utf-8"):
                    raise OSError("fixture hmac write failure")
                return original_atomic_write(path, data, mode, **kwargs)

            stderr = io.StringIO()
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), patch.object(
                helper.getpass,
                "getpass",
                side_effect=[new_webhook, new_hmac],
            ), patch.object(helper, "_atomic_write", side_effect=fail_new_hmac), redirect_stdout(
                io.StringIO()
            ), redirect_stderr(stderr):
                code = helper.main(args)

            self.assertEqual(code, 1)
            for path in paths:
                self.assertEqual(path.read_bytes(), originals[path])
            self.assertFalse(helper._configuration_journal_path(config).exists())
            self.assertIn("previous files were restored", stderr.getvalue())
            self.assertNotIn(new_webhook, stderr.getvalue())
            self.assertNotIn(new_hmac, stderr.getvalue())

    def test_pending_instance_configuration_journal_restores_full_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            credential_root = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}"
            webhook = credential_root / "webhook-url"
            hmac = credential_root / "hmac-signing-secret"
            pat = credential_root / "multica-pat"
            dropin = root / f"etc/systemd/system/hermes-multica-bridge@{TEST_INSTANCE_ID}.socket.d/10-hermes-user.conf"
            paths = [config, webhook, hmac, pat, dropin]
            originals = {path: path.read_bytes() for path in paths}
            write_options = {"trusted_root": root, "expected_owner_uid": os.geteuid()}
            snapshots = helper._snapshot_configuration_files(paths, **write_options)
            journal = helper._configuration_journal_path(config)
            helper._write_configuration_journal(
                journal,
                instance=TEST_INSTANCE_ID,
                snapshots=snapshots,
                **write_options,
            )
            helper._atomic_write(config, b"broken config\n", 0o644, **write_options)
            helper._atomic_write(webhook, b"broken webhook", 0o600, **write_options)

            recovered = helper._recover_pending_configuration(
                journal,
                instance=TEST_INSTANCE_ID,
                **write_options,
            )

            self.assertTrue(recovered)
            for path in paths:
                self.assertEqual(path.read_bytes(), originals[path])
            self.assertFalse(journal.exists())

    def test_rotation_updates_webhook_credential_and_pin_together(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            setup_args = [
                *_identity_args(),
                "--hermes-user",
                "hermes-user",
                "--gateway-unit",
                "hermes-gateway.service",
                "--multica-origin",
                TEST_ORIGIN,
                "--workspace-id",
                "workspace-example",
                "--autopilot-id",
                "autopilot-example",
                "--trigger-id",
                "trigger-example",
                "--source-board",
                "example-board",
                "--root",
                directory,
            ]
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), patch.object(
                helper.getpass,
                "getpass",
                side_effect=[TEST_WEBHOOK_URL, TEST_HMAC_SECRET],
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(helper.main(setup_args), 0)

            rotated_url = TEST_WEBHOOK_URL[:-1] + ("A" if TEST_WEBHOOK_URL[-1] != "A" else "B")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch.object(rotate_helper.sys, "stdin", _TtyInput()), patch.object(
                rotate_helper.getpass, "getpass", return_value=rotated_url
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                code = rotate_helper.main(["--instance", TEST_INSTANCE_ID, "--root", directory])
            self.assertEqual(code, 0, stderr.getvalue())
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            webhook = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/webhook-url"
            self.assertEqual(webhook.read_text(encoding="utf-8"), rotated_url)
            self.assertIn(
                f'webhook_sha256 = "{rotate_helper.webhook_url_fingerprint(rotated_url, TEST_ORIGIN)}"',
                config.read_text(encoding="utf-8"),
            )
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o644)
            self.assertNotIn(rotated_url, stdout.getvalue() + stderr.getvalue())

    def test_rotation_failure_rolls_back_both_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            webhook = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/webhook-url"
            original_config = config.read_text(encoding="utf-8")
            rotated_url = TEST_WEBHOOK_URL[:-1] + ("A" if TEST_WEBHOOK_URL[-1] != "A" else "B")
            rotated_pin = rotate_helper.webhook_url_fingerprint(rotated_url, TEST_ORIGIN)
            original_atomic_write = rotate_helper._atomic_write
            fail_updated_pin_once = True

            def fail_config_update_once(path, data, mode, **kwargs):
                nonlocal fail_updated_pin_once
                if Path(path) == config and rotated_pin.encode("ascii") in data and fail_updated_pin_once:
                    fail_updated_pin_once = False
                    raise OSError("fixture config write failure")
                return original_atomic_write(path, data, mode, **kwargs)

            stderr = io.StringIO()
            with patch.object(rotate_helper.sys, "stdin", _TtyInput()), patch.object(
                rotate_helper.getpass, "getpass", return_value=rotated_url
            ), patch.object(rotate_helper, "_atomic_write", side_effect=fail_config_update_once), redirect_stderr(stderr):
                code = rotate_helper.main(["--instance", TEST_INSTANCE_ID, "--root", directory])

            self.assertEqual(code, 1)
            self.assertEqual(webhook.read_text(encoding="utf-8"), TEST_WEBHOOK_URL)
            self.assertEqual(config.read_text(encoding="utf-8"), original_config)
            self.assertFalse(rotate_helper._rotation_journal_path(config).exists())
            self.assertIn("previous credential and fingerprint were restored", stderr.getvalue())
            self.assertNotIn(rotated_url, stderr.getvalue())

    def test_pending_rotation_journal_recovers_after_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            webhook = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/webhook-url"
            journal = rotate_helper._rotation_journal_path(config)
            original_config = config.read_text(encoding="utf-8")
            rotated_url = TEST_WEBHOOK_URL[:-1] + ("A" if TEST_WEBHOOK_URL[-1] != "A" else "B")
            rotated_pin = rotate_helper.webhook_url_fingerprint(rotated_url, TEST_ORIGIN)
            updated_config = rotate_helper._replace_webhook_pin(
                original_config,
                rotate_helper.webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN),
                rotated_pin,
            )
            record = {
                "instance": TEST_INSTANCE_ID,
                "previous_config": original_config,
                "previous_webhook_url": TEST_WEBHOOK_URL,
            }
            helper._atomic_write(
                journal,
                json.dumps(record).encode("utf-8"),
                0o600,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            )
            helper._atomic_write(
                webhook,
                rotated_url.encode("utf-8"),
                0o600,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            )
            helper._atomic_write(
                config,
                updated_config.encode("utf-8"),
                0o644,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            )

            recovered = rotate_helper._recover_pending_rotation(
                config,
                webhook,
                journal,
                instance=TEST_INSTANCE_ID,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            )

            self.assertTrue(recovered)
            self.assertEqual(webhook.read_text(encoding="utf-8"), TEST_WEBHOOK_URL)
            self.assertEqual(config.read_text(encoding="utf-8"), original_config)
            self.assertFalse(journal.exists())

    def test_full_configuration_rejects_pending_rotation_journal_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._configure_example_instance(directory)
            root = Path(directory)
            config = root / f"etc/hermes-multica-bridge/{TEST_INSTANCE_ID}.toml"
            webhook = root / f"etc/hermes-multica-bridge/credentials/{TEST_INSTANCE_ID}/webhook-url"
            original_config = config.read_text(encoding="utf-8")
            original_webhook = webhook.read_text(encoding="utf-8")
            journal = rotate_helper._rotation_journal_path(config)
            record = {
                "instance": TEST_INSTANCE_ID,
                "previous_config": original_config,
                "previous_webhook_url": original_webhook,
            }
            helper._atomic_write(
                journal,
                json.dumps(record).encode("utf-8"),
                0o600,
                trusted_root=root,
                expected_owner_uid=os.geteuid(),
            )
            args = [
                *_identity_args(),
                "--hermes-user", "hermes-user",
                "--gateway-unit", "hermes-gateway.service",
                "--multica-origin", TEST_ORIGIN,
                "--workspace-id", "workspace-new",
                "--autopilot-id", "autopilot-new",
                "--trigger-id", "trigger-new",
                "--source-board", "new-board",
                "--root", directory,
            ]
            stderr = io.StringIO()
            with patch.object(helper.sys, "stdin", _TtyInput()), patch(
                "builtins.input", return_value="12345"
            ), patch.object(
                helper.getpass,
                "getpass",
                side_effect=[TEST_WEBHOOK_URL, TEST_HMAC_SECRET],
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = helper.main(args)

            self.assertEqual(code, 1)
            self.assertEqual(config.read_text(encoding="utf-8"), original_config)
            self.assertEqual(webhook.read_text(encoding="utf-8"), original_webhook)
            self.assertTrue(journal.exists())
            self.assertIn("pending webhook rotation", stderr.getvalue())

if __name__ == "__main__":
    unittest.main()
