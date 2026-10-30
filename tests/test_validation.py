from __future__ import annotations

import unittest

from bridge.errors import BridgeError
from bridge.validation import (
    idempotency_key,
    request_fingerprint,
    strict_json_loads,
    validate_tool_request,
)
from tests.helpers import sample_request


class ValidationTests(unittest.TestCase):
    def test_accepts_canonical_hermes_request(self) -> None:
        result = validate_tool_request(sample_request())
        self.assertEqual(result["source"]["system"], "hermes")
        self.assertEqual(result["task"]["title"], "Example task")

    def test_rejects_model_controlled_extra_fields(self) -> None:
        for request in (
            {**sample_request(), "url": "https://attacker.invalid"},
            {**sample_request(), "workspace_id": "other"},
        ):
            with self.subTest(request=request), self.assertRaises(BridgeError):
                validate_tool_request(request)

    def test_fingerprint_excludes_worker_run_but_includes_task_content(self) -> None:
        one = sample_request(run_id="12")
        retry = sample_request(run_id="13")
        changed = sample_request(run_id="13", body="changed")
        self.assertEqual(request_fingerprint(one), request_fingerprint(retry))
        self.assertNotEqual(request_fingerprint(one), request_fingerprint(changed))

    def test_duplicate_json_keys_and_nonstandard_constants_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            strict_json_loads('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            strict_json_loads('{"a":NaN}')

    def test_idempotency_key_is_stable_per_request_id_and_connection(self) -> None:
        self.assertEqual(idempotency_key("conn-a", "request-a"), idempotency_key("conn-a", "request-a"))
        self.assertNotEqual(idempotency_key("conn-a", "request-a"), idempotency_key("conn-b", "request-a"))
        self.assertNotEqual(idempotency_key("conn-a", "request-a"), idempotency_key("conn-a", "request-b"))


if __name__ == "__main__":
    unittest.main()
