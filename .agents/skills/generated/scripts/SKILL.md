---
name: scripts
description: "Skill for the Scripts area of hermes-multica-bridge. 101 symbols across 3 files."
---

# Scripts

101 symbols | 3 files | Cohesion: 75%

## When to Use

- Working with code in `.agents/`
- Understanding how test_failure_classification_distinguishes_transport_schema_and_sandbox, test_timeout_terminates_process_group, test_timeout_is_not_delayed_by_long_heartbeat work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `.agents/skills/autoreview/scripts/autoreview` | write_json_temp, make_temp_path, run_codex, run_claude, run_droid (+54) |
| `.agents/skills/autoreview/scripts/test-autoreview-reliability.py` | test_failure_classification_distinguishes_transport_schema_and_sandbox, test_timeout_terminates_process_group, test_timeout_is_not_delayed_by_long_heartbeat, test_stream_timeout_terminates_process_group, test_bundle_split_is_bounded_and_lossless (+18) |
| `.agents/skills/autoreview/scripts/autoreview_runtime.py` | ReviewError, bounded_detail, classify_engine_failure, stop_process, run_with_heartbeat (+14) |

## Entry Points

Start here when exploring this area:

- **`test_failure_classification_distinguishes_transport_schema_and_sandbox`** (Function) — `.agents/skills/autoreview/scripts/test-autoreview-reliability.py:71`
- **`test_timeout_terminates_process_group`** (Function) — `.agents/skills/autoreview/scripts/test-autoreview-reliability.py:82`
- **`test_timeout_is_not_delayed_by_long_heartbeat`** (Function) — `.agents/skills/autoreview/scripts/test-autoreview-reliability.py:93`
- **`test_stream_timeout_terminates_process_group`** (Function) — `.agents/skills/autoreview/scripts/test-autoreview-reliability.py:107`
- **`bounded_detail`** (Function) — `.agents/skills/autoreview/scripts/autoreview_runtime.py:52`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `ReviewError` | Class | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 40 |
| `CodexStreamDisplay` | Class | `.agents/skills/autoreview/scripts/autoreview` | 598 |
| `ClaudeStreamDisplay` | Class | `.agents/skills/autoreview/scripts/autoreview` | 643 |
| `Tee` | Class | `.agents/skills/autoreview/scripts/autoreview` | 1460 |
| `ReviewRunState` | Class | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 110 |
| `test_failure_classification_distinguishes_transport_schema_and_sandbox` | Function | `.agents/skills/autoreview/scripts/test-autoreview-reliability.py` | 71 |
| `test_timeout_terminates_process_group` | Function | `.agents/skills/autoreview/scripts/test-autoreview-reliability.py` | 82 |
| `test_timeout_is_not_delayed_by_long_heartbeat` | Function | `.agents/skills/autoreview/scripts/test-autoreview-reliability.py` | 93 |
| `test_stream_timeout_terminates_process_group` | Function | `.agents/skills/autoreview/scripts/test-autoreview-reliability.py` | 107 |
| `bounded_detail` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 52 |
| `classify_engine_failure` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 217 |
| `stop_process` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 241 |
| `run_with_heartbeat` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 278 |
| `run_with_stream` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 354 |
| `finish_threads` | Function | `.agents/skills/autoreview/scripts/autoreview_runtime.py` | 408 |
| `write_json_temp` | Function | `.agents/skills/autoreview/scripts/autoreview` | 418 |
| `make_temp_path` | Function | `.agents/skills/autoreview/scripts/autoreview` | 425 |
| `run_codex` | Function | `.agents/skills/autoreview/scripts/autoreview` | 431 |
| `run_claude` | Function | `.agents/skills/autoreview/scripts/autoreview` | 480 |
| `run_droid` | Function | `.agents/skills/autoreview/scripts/autoreview` | 515 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Test_transport_failure_retries_then_persists_pass → ReviewError` | cross_community | 6 |
| `Test_transport_failure_retries_then_persists_pass → Write_json_temp` | cross_community | 6 |
| `Test_transport_failure_retries_then_persists_pass → Make_temp_path` | cross_community | 6 |
| `Test_transport_failure_retries_then_persists_pass → Claude_allowed_tools` | cross_community | 6 |
| `Test_non_json_result_gets_one_repair_pass → ReviewError` | cross_community | 6 |
| `Test_non_json_result_gets_one_repair_pass → Write_json_temp` | cross_community | 6 |
| `Test_non_json_result_gets_one_repair_pass → Make_temp_path` | cross_community | 6 |
| `Test_non_json_result_gets_one_repair_pass → Claude_allowed_tools` | cross_community | 6 |
| `Test_schema_invalid_json_gets_one_repair_pass → ReviewError` | cross_community | 6 |
| `Test_schema_invalid_json_gets_one_repair_pass → Write_json_temp` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Bridge | 3 calls |
| Tests | 1 calls |

## How to Explore

1. `inspect({action: "context", repo: "<repo>", target: "test_failure_classification_distinguishes_transport_schema_and_sandbox"})` — see callers and callees
2. `search({action: "semantic", repo: "<repo>", query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
