from __future__ import annotations

import unittest

from bridge.configuration import (
    connection_from_mapping,
    normalize_multica_origin,
)
from bridge.errors import BridgeError


class ConfigurationTests(unittest.TestCase):
    def test_standard_defaults_are_disabled_and_hmac_on(self) -> None:
        cfg = connection_from_mapping({})
        self.assertEqual(cfg.security_mode, "standard")
        self.assertFalse(cfg.enabled)
        self.assertTrue(cfg.hmac_enabled)
        self.assertFalse(cfg.result_tracking_enabled)

    def test_non_string_security_mode_fails_as_configuration_error(self) -> None:
        with self.assertRaises(BridgeError):
            connection_from_mapping({"security_mode": []})

    def test_unknown_connection_setting_is_rejected_instead_of_ignored(self) -> None:
        with self.assertRaises(BridgeError) as raised:
            connection_from_mapping({"security_mdoe": "isolated"})

        self.assertEqual(raised.exception.code, "configuration_invalid")
        self.assertEqual(
            raised.exception.message,
            "connection contains unsupported fields.",
        )

    def test_origin_is_https_only_and_pathless(self) -> None:
        self.assertEqual(normalize_multica_origin("https://MULTICA.example.org/"), "https://multica.example.org")
        for value in (
            "http://multica.example.org",
            "https://user@multica.example.org",
            "https://multica.example.org/path",
            "https://multica.example.org/?q=1",
            "https://мультика.example.org",
        ):
            with self.subTest(value=value), self.assertRaises(BridgeError):
                normalize_multica_origin(value)

    def test_source_boards_accept_json_or_comma_list_without_duplicates(self) -> None:
        self.assertEqual(connection_from_mapping({"source_boards": "a,b"}).source_boards, ("a", "b"))
        self.assertEqual(connection_from_mapping({"source_boards": '["a","b"]'}).source_boards, ("a", "b"))
        with self.assertRaises(BridgeError):
            connection_from_mapping({"source_boards": ["a", "a"]})

    def test_isolated_socket_is_instance_scoped(self) -> None:
        cfg = connection_from_mapping({"security_mode": "isolated", "isolated_instance_id": "team_a"})
        self.assertEqual(cfg.socket_path, "/run/hermes-multica-bridge/team_a.sock")
        with self.assertRaises(BridgeError):
            _ = connection_from_mapping({"security_mode": "isolated"}).socket_path

    def test_isolated_readiness_requires_hmac(self) -> None:
        cfg = connection_from_mapping(
            {
                "security_mode": "isolated",
                "isolated_instance_id": "team_a",
                "hmac_enabled": False,
            }
        )

        self.assertIn("hmac_enabled", cfg.readiness_errors())

    def test_policy_fingerprint_covers_policy_but_not_profile_enable_switch(self) -> None:
        base = connection_from_mapping(
            {
                "security_mode": "isolated",
                "enabled": False,
                "multica_origin": "https://multica.example.org",
                "workspace_id": "workspace",
                "autopilot_id": "autopilot",
                "trigger_id": "trigger",
                "source_boards": ["board"],
                "isolated_instance_id": "team_a",
            }
        )
        enabled = connection_from_mapping({**base.__dict__, "enabled": True, "source_boards": ["board"]})
        changed = connection_from_mapping(
            {**base.__dict__, "trigger_id": "other-trigger", "source_boards": ["board"]}
        )
        self.assertEqual(base.policy_fingerprint, enabled.policy_fingerprint)
        self.assertNotEqual(base.policy_fingerprint, changed.policy_fingerprint)

    def test_standard_readiness_checks_secret_presence(self) -> None:
        cfg = connection_from_mapping(
            {
                "enabled": True,
                "multica_origin": "https://multica.example.org",
                "workspace_id": "workspace",
                "autopilot_id": "autopilot",
                "trigger_id": "trigger",
                "source_boards": ["board"],
                "result_tracking_enabled": True,
            }
        )
        errors = cfg.readiness_errors(secret_presence={})
        self.assertIn("webhook_url", errors)
        self.assertIn("hmac_signing_secret", errors)
        self.assertIn("multica_pat", errors)

if __name__ == "__main__":
    unittest.main()
