---
name: bridge
description: "Skill for the Bridge area of hermes-multica-bridge. 45 symbols across 9 files."
---

# Bridge

45 symbols | 9 files | Cohesion: 77%

## When to Use

- Working with code in `bridge/`
- Understanding how test_state_directory_resolves_only_expected_systemd_dynamic_user_link, test_state_directory_rejects_group_or_world_access, finish_attempt work
- Modifying bridge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `bridge/webhook.py` | WebhookResult, _safe_identifier, _invalid_response, _duplicate_result, _skipped_result (+8) |
| `bridge/routes.py` | Route, _validate_route_identity, _parse_source_task_ids, _parse_credential_fingerprint, _parse_limits (+6) |
| `bridge/state.py` | _resolve_state_directory, __init__, _ensure_database_file, _connect, _initialize (+1) |
| `bridge/dispatcher.py` | linux_peer_credentials, _read_process_cgroups, _read_parent_pid, _has_trusted_gateway_ancestor, is_kanban_worker_process (+1) |
| `.agents/skills/autoreview/scripts/autoreview` | bounded, read_text, load_datasets |
| `tests/test_routes.py` | test_state_directory_resolves_only_expected_systemd_dynamic_user_link, test_state_directory_rejects_group_or_world_access |
| `tests/test_dispatcher.py` | test_worker_scope_requires_exact_scope_and_trusted_gateway_ancestor, test_worker_scope_rejects_same_uid_scope_spoof_without_gateway_ancestor |
| `bridge/errors.py` | BridgeError |
| `tests/test_webhook.py` | test_redirect_handler_refuses_redirects |

## Entry Points

Start here when exploring this area:

- **`test_state_directory_resolves_only_expected_systemd_dynamic_user_link`** (Function) — `tests/test_routes.py:119`
- **`test_state_directory_rejects_group_or_world_access`** (Function) — `tests/test_routes.py:141`
- **`finish_attempt`** (Function) — `bridge/state.py:202`
- **`linux_peer_credentials`** (Function) — `bridge/dispatcher.py:236`
- **`test_worker_scope_requires_exact_scope_and_trusted_gateway_ancestor`** (Function) — `tests/test_dispatcher.py:276`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Route` | Class | `bridge/routes.py` | 43 |
| `BridgeError` | Class | `bridge/errors.py` | 5 |
| `WebhookResult` | Class | `bridge/webhook.py` | 69 |
| `test_state_directory_resolves_only_expected_systemd_dynamic_user_link` | Function | `tests/test_routes.py` | 119 |
| `test_state_directory_rejects_group_or_world_access` | Function | `tests/test_routes.py` | 141 |
| `finish_attempt` | Function | `bridge/state.py` | 202 |
| `linux_peer_credentials` | Function | `bridge/dispatcher.py` | 236 |
| `test_worker_scope_requires_exact_scope_and_trusted_gateway_ancestor` | Function | `tests/test_dispatcher.py` | 276 |
| `test_worker_scope_rejects_same_uid_scope_spoof_without_gateway_ancestor` | Function | `tests/test_dispatcher.py` | 297 |
| `is_kanban_worker_process` | Function | `bridge/dispatcher.py` | 90 |
| `is_kanban_worker_scope` | Function | `bridge/dispatcher.py` | 104 |
| `bounded` | Function | `.agents/skills/autoreview/scripts/autoreview` | 181 |
| `read_text` | Function | `.agents/skills/autoreview/scripts/autoreview` | 194 |
| `load_datasets` | Function | `.agents/skills/autoreview/scripts/autoreview` | 359 |
| `test_redirect_handler_refuses_redirects` | Function | `tests/test_webhook.py` | 89 |
| `redirect_request` | Function | `bridge/webhook.py` | 55 |
| `_NoRedirect` | Class | `bridge/webhook.py` | 54 |
| `_resolve_state_directory` | Function | `bridge/state.py` | 24 |
| `__init__` | Function | `bridge/state.py` | 67 |
| `_ensure_database_file` | Function | `bridge/state.py` | 75 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → BridgeError` | cross_community | 5 |
| `Main → Open` | cross_community | 5 |
| `Main → BridgeError` | cross_community | 5 |
| `Handle → BridgeError` | cross_community | 5 |
| `Handle → Open` | cross_community | 5 |
| `Test_compact_diff_omits_lockfile_body → Bounded` | cross_community | 4 |
| `Test_local_bundle_omits_untracked_lockfile_body → Bounded` | cross_community | 4 |
| `Test_local_bundle_does_not_follow_untracked_symlink → Bounded` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 2 calls |

## How to Explore

1. `inspect({action: "context", repo: "<repo>", target: "test_state_directory_resolves_only_expected_systemd_dynamic_user_link"})` — see callers and callees
2. `search({action: "semantic", repo: "<repo>", query: "bridge"})` — find related execution flows
3. Read key files listed above for implementation details
