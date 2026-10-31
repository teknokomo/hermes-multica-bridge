from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from bridge.errors import BridgeError
from bridge.routes import load_config, read_credential
from tests.helpers import (
    TEST_INSTANCE_ID,
    isolated_config_text,
)


class RouteConfigTests(unittest.TestCase):
    @staticmethod
    def _write(directory: str, text: str, name: str = "bridge.toml") -> Path:
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_loads_default_deny_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(
                self._write(directory, isolated_config_text()),
                expected_owner_uid=os.getuid(),
            )
        self.assertEqual(config.connection.security_mode, "isolated")
        self.assertEqual(
            config.connection.socket_path,
            f"/run/hermes-multica-bridge/{TEST_INSTANCE_ID}.sock",
        )
        self.assertEqual(config.trusted_gateway_unit, "hermes-gateway.service")

    def test_enabled_config_requires_hmac_ref_webhook_pin_and_result_tracking_requires_pat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_hmac = isolated_config_text(enabled=True, include_hmac_ref=False)
            with self.assertRaises(BridgeError) as hmac_error:
                load_config(self._write(directory, missing_hmac), expected_owner_uid=os.getuid())
            self.assertEqual(hmac_error.exception.code, "configuration_invalid")
            self.assertEqual(
                hmac_error.exception.message,
                "An enabled Isolated connection requires an HMAC credential reference.",
            )
            missing_pin = isolated_config_text(enabled=True)
            fingerprint_line = next(
                line for line in missing_pin.splitlines() if line.startswith("webhook_sha256 = ")
            )
            missing_pin = missing_pin.replace(fingerprint_line, 'webhook_sha256 = ""')
            with self.assertRaises(BridgeError) as pin_error:
                load_config(self._write(directory, missing_pin), expected_owner_uid=os.getuid())
            self.assertEqual(pin_error.exception.code, "configuration_invalid")
            self.assertEqual(
                pin_error.exception.message,
                "An enabled Isolated connection requires a webhook fingerprint.",
            )
            missing_pat = isolated_config_text(
                enabled=True,
                result_tracking=True,
                include_pat_ref=False,
            )
            with self.assertRaises(BridgeError) as pat_error:
                load_config(self._write(directory, missing_pat), expected_owner_uid=os.getuid())
            self.assertEqual(pat_error.exception.code, "configuration_invalid")
            self.assertEqual(
                pat_error.exception.message,
                "Result tracking requires a Multica PAT credential reference.",
            )

    def test_route_identity_must_match_isolated_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mismatched = isolated_config_text().replace(
                "r-018f0000000070008000000000000001",
                "r-018f0000000070008000000000000002",
            )
            with self.assertRaises(BridgeError) as raised:
                load_config(self._write(directory, mismatched), expected_owner_uid=os.getuid())
        self.assertEqual(raised.exception.code, "configuration_invalid")

    def test_rejects_world_writable_or_symlinked_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, isolated_config_text())
            os.chmod(path, 0o666)
            with self.assertRaises(BridgeError):
                load_config(path, expected_owner_uid=os.getuid())
            target = self._write(directory, isolated_config_text(), "target.toml")
            link = Path(directory) / "link.toml"
            link.symlink_to(target)
            with self.assertRaises(BridgeError):
                load_config(link, expected_owner_uid=os.getuid())

    def test_version_field_is_rejected_as_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text = "version = 1\n" + isolated_config_text()
            with self.assertRaises(BridgeError):
                load_config(
                    self._write(directory, text),
                    expected_owner_uid=os.getuid(),
                )

    def test_unknown_nested_connection_field_is_rejected(self) -> None:
        text = isolated_config_text().replace(
            'security_mode = "isolated"',
            'security_mode = "isolated"\nsecurity_mdoe = "standard"',
        )
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(
            BridgeError
        ) as raised:
            load_config(
                self._write(directory, text),
                expected_owner_uid=os.getuid(),
            )

        self.assertEqual(raised.exception.code, "configuration_invalid")
        self.assertEqual(
            raised.exception.message,
            "connection contains unsupported fields.",
        )

    def test_credential_reader_rejects_symlink_and_empty_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "TOKEN").write_text("fake-value", encoding="utf-8")
            self.assertEqual(read_credential(root, "TOKEN"), "fake-value")
            (root / "HMAC").write_text(" secret key \n", encoding="utf-8")
            self.assertEqual(
                read_credential(root, "HMAC", preserve_whitespace=True),
                " secret key \n",
            )
            (root / "EMPTY").write_text("", encoding="utf-8")
            with self.assertRaises(BridgeError):
                read_credential(root, "EMPTY")
            (root / "LINK").symlink_to(root / "TOKEN")
            with self.assertRaises(BridgeError):
                read_credential(root, "LINK")


if __name__ == "__main__":
    unittest.main()
