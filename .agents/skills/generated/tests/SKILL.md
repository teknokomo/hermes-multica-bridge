---
name: tests
description: "Skill for the Tests area of hermes-multica-bridge. 118 symbols across 19 files."
---

# Tests

118 symbols | 19 files | Cohesion: 77%

## When to Use

- Working with code in `tests/`
- Understanding how test_client_rejects_invalid_url_without_opening_connection, test_posts_expected_payload_and_stable_idempotency_header, test_401_and_429_errors_do_not_expose_url_or_body work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `tests/test_dispatcher.py` | setUp, FakeWebhookClient, test_sender_sends_once_and_records_only_ids_and_hashes, test_wrong_peer_is_rejected_before_network, test_unallowlisted_source_task_is_rejected_before_network (+19) |
| `tests/test_webhook.py` | FakeResponse, IncompleteResponse, FakeOpener, test_client_rejects_invalid_url_without_opening_connection, test_posts_expected_payload_and_stable_idempotency_header (+11) |
| `bridge/dispatcher.py` | __init__, _send, _check_config, _check_route_config, main (+6) |
| `tests/test_routes.py` | route_config, _write_config, test_loads_one_default_deny_route, test_rejects_route_drift_and_world_writable_config, test_enabled_route_requires_one_allowlisted_source_task (+5) |
| `tests/test_tool.py` | test_tool_uses_unix_socket_and_returns_structured_result, test_invalid_request_does_not_connect, test_tool_requires_active_allowlisted_worker_context, test_model_cannot_choose_task_id_or_message, test_unexpected_ipc_error_is_sanitized (+5) |
| `tests/test_state.py` | setUp, _begin, test_retries_keep_same_key_and_are_bounded, test_source_task_cannot_change_payload_after_first_submission, test_source_task_reuses_the_persisted_request_id (+4) |
| `bridge/routes.py` | _validate_root_contract, _parse_peer_uids, _one_route_row, load_config, BridgeConfig (+1) |
| `tests/test_validation.py` | test_rejects_unknown_route_fields_and_task_types, test_idempotency_key_is_stable_and_request_fingerprint_tracks_content, test_duplicate_json_keys_are_rejected, test_accepts_only_the_fixed_probe_contract, test_accepts_maximum_source_task_id (+1) |
| `bridge/webhook.py` | as_dict, MulticaWebhookClient, send, validate_webhook_url, webhook_url_fingerprint |
| `bridge/validation.py` | request_fingerprint, idempotency_key, strict_json_loads, _validate_identifier, validate_tool_request |

## Entry Points

Start here when exploring this area:

- **`test_client_rejects_invalid_url_without_opening_connection`** (Function) — `tests/test_webhook.py:78`
- **`test_posts_expected_payload_and_stable_idempotency_header`** (Function) — `tests/test_webhook.py:96`
- **`test_401_and_429_errors_do_not_expose_url_or_body`** (Function) — `tests/test_webhook.py:118`
- **`test_network_timeout_is_unknown_and_not_retried_inside_client`** (Function) — `tests/test_webhook.py:135`
- **`test_response_size_is_bounded`** (Function) — `tests/test_webhook.py:145`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `FakeResponse` | Class | `tests/test_webhook.py` | 25 |
| `IncompleteResponse` | Class | `tests/test_webhook.py` | 38 |
| `FakeOpener` | Class | `tests/test_webhook.py` | 43 |
| `MulticaWebhookClient` | Class | `bridge/webhook.py` | 196 |
| `DeliveryStore` | Class | `bridge/state.py` | 66 |
| `FakeWebhookClient` | Class | `tests/test_dispatcher.py` | 27 |
| `RaisingClient` | Class | `tests/test_dispatcher.py` | 116 |
| `ResetConnection` | Class | `tests/test_dispatcher.py` | 168 |
| `UnreadableConnection` | Class | `tests/test_dispatcher.py` | 192 |
| `BridgeConfig` | Class | `bridge/routes.py` | 61 |
| `BridgeDispatcher` | Class | `bridge/dispatcher.py` | 121 |
| `Attempt` | Class | `bridge/state.py` | 17 |
| `BridgeIpcClient` | Class | `bridge/protocol.py` | 16 |
| `EchoDispatcher` | Class | `tests/test_dispatcher.py` | 224 |
| `SlowConnection` | Class | `tests/test_dispatcher.py` | 254 |
| `Listener` | Class | `tests/test_dispatcher.py` | 135 |
| `FakeContext` | Class | `tests/test_tool.py` | 17 |
| `test_client_rejects_invalid_url_without_opening_connection` | Function | `tests/test_webhook.py` | 78 |
| `test_posts_expected_payload_and_stable_idempotency_header` | Function | `tests/test_webhook.py` | 96 |
| `test_401_and_429_errors_do_not_expose_url_or_body` | Function | `tests/test_webhook.py` | 118 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → BridgeError` | cross_community | 5 |
| `Main → Open` | cross_community | 5 |
| `Main → BridgeError` | cross_community | 5 |
| `Handle → BridgeError` | cross_community | 5 |
| `Handle → Open` | cross_community | 5 |
| `Main → Open` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Bridge | 29 calls |

## How to Explore

1. `inspect({action: "context", repo: "<repo>", target: "test_client_rejects_invalid_url_without_opening_connection"})` — see callers and callees
2. `search({action: "semantic", repo: "<repo>", query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
