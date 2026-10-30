from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bridge.configuration import connection_from_mapping
from bridge.errors import BridgeError
from deploy import status_isolated_instance
from deploy.status_isolated_instance import (
    _credential_name,
    _instance_paths,
    _pre_enable_readiness_errors,
    _read_staged_credential,
    _read_status_credential,
    _webhook_fingerprint_matches,
)


class StatusIsolatedInstanceTests(unittest.TestCase):
    def test_instance_path_builder_rejects_traversal_before_path_use(self) -> None:
        with self.assertRaises(BridgeError) as raised:
            _instance_paths("../../etc/passwd", None)
        self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_status_command_rejects_invalid_instance_before_config_read(self) -> None:
        output = io.StringIO()
        with patch.object(status_isolated_instance, "load_config") as load_config, redirect_stdout(output):
            result = status_isolated_instance.main(["--instance", "../../etc/passwd"])
        load_config.assert_not_called()
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "configuration_invalid")

    def test_webhook_fingerprint_requires_an_explicit_matching_pin(self) -> None:
        self.assertFalse(_webhook_fingerprint_matches(None, "a" * 64))
        self.assertFalse(_webhook_fingerprint_matches("", "a" * 64))
        self.assertFalse(_webhook_fingerprint_matches("b" * 64, "a" * 64))
        self.assertTrue(_webhook_fingerprint_matches("a" * 64, "a" * 64))

    def test_systemd_runtime_uses_loadcredential_ids(self) -> None:
        self.assertEqual(
            _credential_name(
                systemd_directory=True,
                configured_ref="HMB_WEBHOOK_URL",
                staged_name="webhook-url",
            ),
            "HMB_WEBHOOK_URL",
        )
        self.assertEqual(
            _credential_name(
                systemd_directory=False,
                configured_ref="HMB_WEBHOOK_URL",
                staged_name="webhook-url",
            ),
            "webhook-url",
        )

    def test_staged_reader_accepts_only_fixed_safe_credential_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            credential_dir = Path(temp_dir) / "credentials"
            credential_dir.mkdir(mode=0o700)
            credential = credential_dir / "webhook-url"
            credential.write_text("https://multica.example.org/example\n", encoding="utf-8")
            credential.chmod(0o600)

            value = _read_staged_credential(
                credential_dir,
                "webhook-url",
                expected_owner_uid=os.getuid(),
            )

            self.assertEqual(value, "https://multica.example.org/example")
            with self.assertRaises(BridgeError):
                _read_staged_credential(
                    credential_dir,
                    "../webhook-url",
                    expected_owner_uid=os.getuid(),
                )

    def test_staged_reader_rejects_symlinked_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            credential_dir = Path(temp_dir) / "credentials"
            credential_dir.mkdir(mode=0o700)
            target = Path(temp_dir) / "target"
            target.write_text("secret", encoding="utf-8")
            (credential_dir / "webhook-url").symlink_to(target)

            with self.assertRaises(BridgeError) as raised:
                _read_staged_credential(
                    credential_dir,
                    "webhook-url",
                    expected_owner_uid=os.getuid(),
                )

        self.assertEqual(raised.exception.code, "credential_invalid")

    def test_status_reader_keeps_systemd_credential_validation(self) -> None:
        with patch.object(status_isolated_instance, "read_credential", return_value="secret") as reader:
            value = _read_status_credential(
                "/run/credentials/example",
                systemd_directory=True,
                configured_ref="HMB_WEBHOOK_URL",
                staged_name="webhook-url",
            )

        self.assertEqual(value, "secret")
        reader.assert_called_once_with(
            "/run/credentials/example",
            "HMB_WEBHOOK_URL",
            max_bytes=4096,
            ascii_only=False,
            preserve_whitespace=False,
        )

    def test_staged_status_ignores_disabled_switch_but_reports_other_gaps(self) -> None:
        complete = connection_from_mapping(
            {
                "security_mode": "isolated",
                "enabled": False,
                "multica_origin": "https://multica.example.org",
                "workspace_id": "workspace-example",
                "autopilot_id": "autopilot-example",
                "trigger_id": "trigger-example",
                "source_boards": ["example-board"],
                "isolated_instance_id": "example",
            }
        )
        self.assertEqual(_pre_enable_readiness_errors(complete), ())
        incomplete = connection_from_mapping({"security_mode": "isolated", "enabled": False})
        self.assertIn("multica_origin", _pre_enable_readiness_errors(incomplete))

    def test_staged_status_ok_is_independent_of_later_socket_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            socket_path = Path(temp_dir) / "sender.sock"
            config = SimpleNamespace(
                connection=SimpleNamespace(
                    enabled=False,
                    hmac_enabled=True,
                    result_tracking_enabled=False,
                    isolated_instance_id="instance-example",
                    multica_origin="https://multica.example.org",
                    socket_path=str(socket_path),
                    readiness_errors=lambda: ("disabled",),
                ),
                credentials=SimpleNamespace(
                    webhook_url_ref="HMB_WEBHOOK_URL",
                    webhook_sha256="a" * 64,
                    hmac_signing_secret_ref="HMB_HMAC_SIGNING_SECRET",
                    multica_pat_ref="HMB_MULTICA_PAT",
                ),
            )
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"CREDENTIALS_DIRECTORY": ""}),
                patch.object(
                    status_isolated_instance,
                    "_instance_paths",
                    return_value=(Path(temp_dir) / "config.toml", Path(temp_dir)),
                ),
                patch.object(status_isolated_instance, "load_config", return_value=config),
                patch.object(status_isolated_instance, "_read_status_credential", return_value="fixture-webhook"),
                patch.object(status_isolated_instance, "webhook_url_fingerprint", return_value="a" * 64),
                redirect_stdout(output),
            ):
                exit_code = status_isolated_instance.main(["--instance", "instance-example"])

        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(result["ok"])
        self.assertFalse(result["enabled"])
        self.assertFalse(result["socket_available"])


if __name__ == "__main__":
    unittest.main()
