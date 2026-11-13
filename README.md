🇬🇧 **English** | 🇷🇺 [Русский](README-RU.md)

[![Version](https://img.shields.io/github/v/release/teknokomo/hermes-multica-bridge?label=version&color=blue&sort=semver)](https://github.com/teknokomo/hermes-multica-bridge/releases/latest)
[![License: Omsk Open License](https://img.shields.io/badge/license-Omsk%20Open%20License-green)](LICENSE.md)

![Teknokomo — 73rd Meridian](docs/assets/teknokomo-om73-en.jpg)

## Developers

Developed by [Teknokomo](https://universo.pro/).

Made with the support of the [73rd Meridian Consortium](https://om73.ru).

# Important! Grave! Важно!

-   Workers of the world, unite!
-   Proletoj el ĉiuj landoj, unuiĝu!
-   Пролетарии всех стран, соединяйтесь!

# Hermes Multica Bridge

## Overview

`hermes-multica-bridge` is a Hermes plugin for Autopilot and Workspace: it sends the current pinned Kanban task, creates and manages Workspace issues from trusted MAX or Telegram messages, and lets users create routes bounded by operator grants.

Version 0.6.0 retains two security modes:

- **Standard** — the plugin sends HTTPS requests itself. Non-secret topology is stored in the profile's `ConnectionRegistry`; each Route's webhook/HMAC/PAT credentials are managed through the public Hermes plugin credential API and read at runtime only through `agent.secret_scope`.
- **Isolated** — the plugin never receives Multica secrets. Each new Route uses a separate socket-activated systemd sender instance with root-owned configuration and systemd credentials.

The Bridge is disabled by default: `enabled=false`. The model cannot spoof the message source, choose an arbitrary Workspace/project, or provide credentials, URLs, or attachment paths.

## Features

- Hermes tools with a narrow contract:
  - `multica_list_routes` — takes no arguments and lists only Routes allowed for the current message source and/or pinned Kanban worker;
  - `multica_send_task` — sends the current pinned Kanban task and accepts only an optional `route_id`;
  - `multica_check_task_result` — reads results only for a previously stored delivery and accepts only an optional `route_id`;
- Workspace routes with `multica_workspace_send`, `multica_workspace_get`, `multica_workspace_comment`, and `multica_workspace_update`;
- automatic issue creation in configured Workspaces/projects and attachment of available files from the current Hermes message;
- a restricted legacy watcher for source chats and completion wake through the central notify service for new routes;
- HMAC-SHA256 in the `X-Hub-Signature-256` header, computed over the exact bytes sent;
- a stable `Idempotency-Key` for each logical card version;
- bounded retries and a local SQLite ledger;
- strict HTTPS origin and webhook path validation; redirects and environment proxies are forbidden;
- any number of Connections, Workspaces, and Routes within one Hermes profile; tests cover at least 10 Routes;
- per-route Standard credentials; dynamic routes use the credential anchor from their allowed grant;
- self-service Workspace routes within operator grants and exact source/thread ACLs;
- project, squad, or workspace scope with an explicit project required on send;
- read-only wake coverage checks for each project;
- an eighth tool, `multica_route_create`, and a packaged Skill for safe usage;
- separate Isolated instances with their own socket/config/state/credentials for every new Route;
- new result states are posted as deduplicated comments to the same Hermes Kanban task;
- profile state stores are created cleanly; unknown and previous internal schemas are rejected without migration.

## Architecture

```mermaid
flowchart LR
  K[Hermes Kanban Worker] --> P[hermes-multica-bridge]
  P -->|Autopilot Standard| H[HTTPS + HMAC]
  P -->|Autopilot Isolated IPC| S[systemd sender]
  S --> M[Multica Autopilot]
  H --> M
  C[MAX / Telegram message] -->|trusted Hermes source| W[Workspace tools]
  W -->|configured workspace + project| I[Multica issue]
  I --> N[Notify completion wake]
  N -->|task.completed snapshot| P
  I --> E[Multica events / polling]
  E --> X[Isolated watcher]
  X -->|exact source reply| C
```

In Isolated mode, the sender verifies Linux `SO_PEERCRED` and `SO_PEERPIDFD`, the allowed UID, the exact Hermes user-systemd path for the task/run-specific worker cgroup (`user-<uid>.slice/user@<uid>.service/app.slice/...scope`), the task ID from the Hermes worker's launch arguments, the cgroup's root process, and its direct parent in the precisely configured Gateway systemd unit before making an external request. Pidfds pin the original peer and its Gateway parent during these checks; after reading the cgroup, the sender rechecks the worker's PPID and the parent's liveness. Model subprocesses do not cross this boundary: their PID, parent, and launch arguments differ from those of the trusted worker process.

The current architecture does not require a manual allowlist of individual card IDs by default: authorization applies to the **current pinned Kanban task** that Hermes is already executing. Trusted context includes the board, task ID, current run ID, `task_runs.profile`, assignee, status, and the Gateway-recorded `worker_pid`; the task and run must identify the current plugin process PID. Route policy limits `source_boards` and profile/assignee and can require an exact OperatorGrant `(board, task_id, route_id)`. Standard reads the canonical task from pinned Kanban state, while Isolated also compares `task_id` with the worker's unchanged launch arguments and `task_id`/`run_id` with the exact worker cgroup.

## Trusted payload

The model can pass only an optional `route_id` to the send/result tools. URL, Workspace, Autopilot, trigger, credentials, and task body are not accepted as arguments. The Bridge reads `HERMES_KANBAN_BOARD`, `HERMES_KANBAN_TASK`, `HERMES_KANBAN_RUN_ID`, and the pinned Hermes Kanban DB, then builds:

```json
{
  "source": {
    "system": "hermes",
    "board": "example-board",
    "task_id": "task-id",
    "run_id": "worker-run-id"
  },
  "task": {
    "title": "Card title",
    "body": "Card text"
  }
}
```

`request_fingerprint` excludes the worker `run_id`, so a repeated worker run for the same unchanged card keeps one logical request and the same idempotency key. If the card title/body changes after delivery, result lookup ends with `request_conflict`.

## Standard

### Configuration

Non-secret topology is configured in the native Desktop **Registry**:

- Connection: `connection_id`, name, `multica_origin`, security mode, shared HTTP/rate-limit/HMAC policy;
- Workspace: `workspace_key`, `connection_id`, external `workspace_id`;
- Route: `route_id`, Connection/Workspace, Autopilot, trigger, event, source/profile/assignee/grant policy, and result tracking.

Each Route has its own write-only `webhook|hmac|pat` credentials. The public `ctx.credentials` API passes only the plugin ID, UUIDv7 Route ID, and fixed credential type to Hermes; Hermes computes the opaque environment variable name, stores/deletes the value in the selected profile scope, and returns only its presence. This API does not expose secret values or accept arbitrary environment variable names.

## Workspace Bridge

A static 0.5.0 Workspace route is bound to one `workspace_id` and one project. A 0.6.0 route can be scoped to a project list, squad, or workspace; dynamic `all_workspace` is allowed only by an active operator grant and always requires an explicit `project_id` on send. The tools do not accept `platform`, author, chat, thread, or message ID as model arguments. In the target Hermes build, the plugin reads these fields from the session context bound to the current Gateway turn through bound-only `get_bound_session_env()` so that stale process environment values are not used. In shared sessions this API returns the current message actor; legacy `get_session_env(USER_ID)` describes the session recipient and is not used for authorization. Incomplete context stops the operation before any Multica write request. A route is authorized only when platform, user ID, chat ID, and any configured thread allowlist match.

A redacted single-profile template with four disabled Workspace routes and a separate Autopilot example is in [config/registry.om73.example.json](config/registry.om73.example.json). Replace `REPLACE-*` values only in local configuration.

Static Workspace routes run in Standard mode and use profile-scoped Multica PAT credentials. Dynamic routes read the PAT only through the operator-owned static credential anchor for the same connection/workspace; no PAT is copied into dynamic state. `allowed_assignees` uses `{id,type,label}` objects with type `member`, `agent`, or `squad`; external IDs must be canonical UUIDs. `default_assignee` must match an allowed pair. Legacy strings load as `member` and expose `legacy_assignee_entry` in `multica_list_routes` and the Dashboard. Autopilot continues to accept its existing string Hermes assignees.

`multica_workspace_send` creates an issue; a parent must belong to the same Workspace/project, and a subtask assignee is selected from the typed allowlist. An ID without a type is resolved only when exactly one match exists. Without an assignment, the operation is rejected before POST unless `allow_unassigned=true`; an unassigned issue returns `ok:false`, sends one notice to the current chat through public `ctx.post_message()`, and is not reported as started work. Reads, comments, and updates recheck that the issue belongs to the route. With `require_assignee=true`, an assignment cannot be removed; inviting members is not supported.

Only files from `get_current_attachments()` for the current Hermes turn are attached automatically. The plugin checks platform/chat/author/message ID, MIME type, extension, count, and size. The path comes only from a trusted Hermes descriptor, never from model arguments; the file is opened without following symlinks, and its identity and metadata are checked before and after reading. Data is sent to Multica from memory, no temporary file is created, and the path is not included in a response or log. This Hermes build's helper does not provide images, so they cannot be attached; a route with `require_source_attachment=true` rejects a message if no suitable file is available.

Session context and attachment descriptors come from Hermes's internal `gateway.session_context` and are tracked as `T38-DEBT-3`: after each Hermes update, recheck the contract and run context/attachment regression tests. The plugin does not require local changes to `register_tool()` or `model_tools` and does not pass `pass_context`.

The ledger binds each write to a profile, route, and source message. After create/update, the plugin uses a separate GET to compare actual state with the request; if readback differs or is unavailable, it returns `assignee_verification_failed`, and a retry performs only GET, never a second POST. A confirmed operation returns its saved result.

After issue creation, the plugin writes `origin`, `origin_route`, and `created_by` metadata, plus HMAC-SHA-256 pseudonyms of the author and source message keyed from the route's profile-scoped Multica PAT, without raw user/chat/message IDs. `related_issue_ids` is validated locally and stored as a compact JSON string. For `test=true`, it writes `origin_test=true`; metadata failure does not undo the issue and returns one `metadata_incomplete` warning. An unknown metadata write outcome is never retried automatically.

The watcher is a separate `hermes-multica-watcher.service` process running as `om73-watcher`. It uses its own root-owned configuration, systemd credentials, and private SQLite state, and cannot access the Hermes home directory. The plugin registers a verified issue-to-source-message mapping through a Unix socket, where the peer UID is checked with `SO_PEERCRED`. The watcher reconnects to the WebSocket with backoff and also reconciles issues/comments by polling every 30–60 seconds. On the first reconciliation it suppresses comments created before the chat mapping was registered; later comments and changes are delivered only when a mapping exists.

In verbose mode, notification delivery records confirmed sends as `delivered`, proven rejections as `not_sent`, and lost responses after a possible send as `delivery_unknown`. Only an explicit HTTP 429 is retried on a later reconciliation; `delivery_unknown` is never retried. Telegram sends are paced per chat, while MAX keeps its existing pacing. A failed watcher mapping stays in the profile ledger and later authorized Workspace operations retry it from the stored source fields; `get` never maps an issue from its current caller context. If the platform cannot reply to the exact source message/thread, the notification is not sent to the parent chat.

Inbound Workspace support depends on an adapter in the target build that sets session context for each current message. The MAX inbound adapter and its correct source binding must be verified separately on the target Gateway. Outbound MAX watcher delivery is implemented separately.

The plugin runtime computes the same deterministic environment variable name and reads its value only through `agent.secret_scope.get_secret()`. One Hermes profile can contain multiple independent Multica Connections and Routes.

## Isolated

In Isolated mode, Route topology is stored in the registry, while an operator installs secrets and trusted OS/systemd settings outside Hermes. Each Route has its own instance. The instance ID is deterministic: `r-<route_id_without_hyphens>`.

A fresh installation uses:

```text
hermes-multica-bridge@<instance>.socket
hermes-multica-bridge@<instance>.service
/run/hermes-multica-bridge/<instance>.sock
/etc/hermes-multica-bridge/<instance>.toml
/etc/hermes-multica-bridge/credentials/<instance>/
```

Operator helper:

```bash
sudo python3 /opt/hermes-multica-bridge/deploy/configure_isolated_instance.py \
  --instance <route-instance-id> \
  --route-id <route-id> \
  --connection-id <connection-id> \
  --workspace-key <workspace-key> \
  --route-policy-fingerprint <route-policy-fingerprint>
```

The Desktop displays the full command with non-secret Route identity. The helper verifies that `instance` matches `route_id`, prompts for secrets interactively with echo disabled, and creates root-owned configuration/credentials and a socket drop-in for the selected Hermes OS user. The socket unit creates `/run/hermes-multica-bridge` as a root-owned parent, and each instance gets its own socket. After checking the files, the operator separately runs `systemctl daemon-reload` and enables the instance socket.

Details: [deploy/README.md](deploy/README.md).

## Hermes UI

The unified package contains three surfaces:

- `plugin.yaml` + Python plugin — Hermes Autopilot and Workspace tools;
- `dashboard/` — web dashboard tab;
- `desktop/plugin.js` — a native Desktop page registered through the public `ROUTES_AREA`/`SIDEBAR_NAV_AREA` SDK.

The native Desktop shows **Overview**, **Registry**, and **Diagnostics** for the focused session's profile (falling back to the gateway profile). The Registry can create multiple Connections/Workspaces/Routes, set exact OperatorGrants, rotate route-scoped Standard credentials, and provide commands for a specific Isolated Route.

The backend rejects enabling a Route until required destination/policy fields and per-route readiness are complete. On first enable, the Route destination is locked; an enabled or used Route cannot be deleted or redirected, and retirement uses disable + tombstone. For Isolated, the dashboard runs a local `readiness` probe through the route-specific socket; it makes no HTTP request to Multica and returns no secret values.

The custom UI shows only secret presence and safe status. Profile/generation guards prevent a late status/save/credential response from changing another profile's state, including after an A→B→A profile switch.

## HMAC and HTTPS

For each webhook:

1. JSON is serialized once into `raw_body`.
2. HMAC-SHA256 is calculated over those same `raw_body` bytes.
3. `X-Hub-Signature-256: sha256=<hex>` is sent.
4. A stable `Idempotency-Key` is sent.
5. The HTTP request sends the exact bytes that were signed.

The client accepts only an HTTPS URL with the same origin as `multica_origin` and an allowed Multica webhook path. Userinfo, query, fragment, redirects, and environment proxies are forbidden. `request_timeout_seconds` sets one absolute monotonic deadline for DNS, connect/TLS, HTTP headers, and body reading, not separate socket waits. DNS runs in a bounded daemon resolver; at most four stuck system lookups are allowed at once. After that limit is reached, new requests end at their own deadline without creating more resolver threads.

HMAC is enabled by default. In Standard mode, the operator may explicitly disable `hmac_enabled`, leaving the bearer webhook URL. A new Isolated Route requires HMAC and fails closed if an attempt is made to enable it without HMAC.

## Result retrieval

With `result_tracking_enabled=true`, a separate read-only Multica PAT is required.

`multica_check_task_result`:

1. reads the current pinned Hermes task again;
2. finds its ledger record;
3. uses only the `run_id` saved at webhook delivery and the original Route's immutable destination snapshot;
4. reads the Multica run and related Issue/comments using the saved `multica_origin`/`autopilot_id`, even if the Route has since been disabled or tombstoned;
5. normalizes the status;
6. orders changes to one status using the monotonic Multica `Issue.revision` and prevents stale rollback;
7. reserves a comment in the ledger for a new status;
8. while that reservation is fresh, prevents the next result snapshot from overtaking the comment publication;
9. writes a bounded comment to the same Hermes task;
10. confirms the reservation only after a successful write.

Rechecking the same result does not create a duplicate. If writing the comment fails, the reservation is released and the next check can retry publication.

Normalized statuses: `pending`, `accepted`, `running`, `succeeded`, `failed`, `skipped`, `unknown`.

Webhook `accepted` means only that Multica accepted the delivery/created a run. It does not mean the task is complete.

## Local ledger

The SQLite ledger stores only the delivery and result state that is needed:

- route-scoped partition key;
- immutable snapshot: `route_id`, `connection_id`, `workspace_key`, external `workspace_id`, `multica_origin`, `autopilot_id`, `trigger_id`, security mode, and route/policy fingerprint;
- request/delivery/run/issue/task IDs;
- fingerprint/idempotency state;
- attempts/rate-limit state;
- result fingerprint and comment reservation state;
- the latest server-side Issue revision used to order result snapshots.

Webhook URLs, PATs, HMAC secrets, and secret response bodies are not stored in the ledger.

## Configuration lifecycle

The plugin is version 0.6.0. The 0.5.0 registry loads without rewrites or internal versioning; dynamic routes use a separate store and reject unknown schemas. Watcher state retains its documented one-way migration from 0.2.0.

Switching between Standard and Isolated does not transfer secrets automatically. A new mode is enabled only after its own readiness check. Enabling a Route locks its destination; use a new Route for another destination and disable + tombstone the previous one.

## Requirements

- Linux with systemd for the watcher and Isolated sender;
- Python 3.11+;
- Hermes Agent 0.22.4 or later with `gateway.session_context.get_bound_session_env` and `get_current_attachments` available in the target build; the MAX/Telegram adapter must bind this data to the current turn;
- Linux 6.5+, systemd, unified cgroup v2, `SO_PEERCRED`, and `SO_PEERPIDFD` for Isolated mode only;
- an HTTPS Multica endpoint;
- a Multica PAT for Workspace API and the watcher; a read-only PAT for Autopilot result tracking;
- `websockets` for the Multica WebSocket watcher.

## Local verification

The main offline suite makes no live Multica requests and uses fake credentials/mocked HTTP.

```bash
python3 -m pytest -q
node --test tests/test_desktop_profile_guard.mjs tests/test_desktop_registry_ui.mjs
python3 -m compileall -q bridge notify dashboard deploy tests
```

The release gate also includes Ruff, Bandit, package build/metadata checks, `hermes plugins validate` and `doctor` on a clean staging copy, `systemd-analyze verify`, a secret/personal-data scan, and project Thermos/Autoreview.

## Development status

The product version is 0.6.0. It adds scoped routes, operator grants, route creation from trusted source context, and read-only per-project notify readiness; it introduces no internal API or registry versions. Completion wake handles only new transitions to done. Server installation, live Multica use, commit/push, and publication remain separate stages.

## License

The project is distributed under the **Omsk Open License — Base Modification. Attribution.**

The full English text is in [LICENSE.md](LICENSE.md).

## Hermes compatibility

Workspace does not require a paired Hermes core patch. To work with the target custom build, the plugin reads source context and current attachment descriptors through Hermes's internal `gateway.session_context`; this seam is tracked as `T38-DEBT-3`.

Three limited technical debts remain: `bridge/hermes.py` uses the private Kanban DB API only to check `worker_pid`, which is not exposed by `kanban_show`; `dashboard/plugin_api.py` uses `plugins_settings` because the dashboard route receives no `PluginContext`; and Workspace uses the internal Gateway session context because plugin tools receive no `tool_context`. After each Hermes update, run `plugins validate`, `plugins doctor --ci`, the `kanban_show`/`kanban_comment` tests, the Dashboard registry test, and the Workspace source/attachment tests. These debts can be removed when the corresponding public APIs become available.

Inbound MAX depends on a suitable MAX adapter being available in the Hermes build in use.

## Notification policy

Policy is configured only in watcher TOML. Without notifications, verbose preserves 0.2.0 behavior; quiet is explicitly enabled.

| Class | When it is sent |
|---|---|
| question | QUESTION:/ВОПРОС: or an operator mention while blocked |
| blocked | Transition into blocked |
| final | Transition into done/in_review with the latest eligible REPORT:/ОТЧЁТ: |
| failed | A received task:failed event |
| cancelled | Transition into cancelled, only when explicitly enabled |

Quiet suppresses ordinary and own comments. Reports are never sent separately; final selects the latest eligible report, including seen comments, at or after cycle_started_at when known, or within lookback only when the cycle boundary is unknown. Exact historical transitions cannot be recovered: migrated snapshots use updated_at for the status boundary and leave the cycle boundary unknown. An observed final-to-nonfinal transition starts a new cycle; quiet snapshots follow every status, including those outside allowed_statuses.

```toml
notifications = { mode = "quiet", events = ["question", "blocked", "final", "failed"], final_statuses = ["done", "in_review"], max_attempts = 5, sending_timeout_seconds = 300 }
```

final_statuses must belong to allowed_statuses. For cancelled, add it to both events and allowed_statuses. Invalid policy disables its route; readiness exposes degraded status and diagnostics. Policy is available through route_policies IPC and best-effort multica_list_routes.

All quiet classes use a durable payload and a send budget including the initial send and HTTP 429. Delays are 30/60/120/300/600 seconds, then 600. A lost response may cause a duplicate; server-side exactly-once delivery is not promised. Exhaustion records retry_exhausted. Verbose retains its existing retries.

State migration is one-way. Installation requires a consistent SQLite backup, SHA-256, an S3 copy, and a TOML snapshot. Rollback requires stopping the watcher, restoring DB/TOML, and running 0.2.0; mappings added after the snapshot are lost.

### Backfill registrar

## Central notifications 0.4.0

`hermes-multica-notify` is a separate process: Multica WS + read-only CLI → normalized events → subscriptions → durable outbox → Telegram/MAX. Intake and the seven Hermes tools retain their behavior; the existing watcher remains independent.

TOML contains service/policy/accounts/workspaces; SQLite stores subscriptions and runtime state. Example: `config/notify.example.toml`. It is disabled and contains placeholders. Tokens come only from systemd credentials or private files, and Multica CLI 0.8.2+ receives a separate HOME/profile per workspace.

```bash
hermes-multica-notify --config /REPLACE/notify.toml init --db-path /REPLACE/notify.sqlite3 --runtime-dir /REPLACE/runtime
hermes-multica-notify --config /REPLACE/notify.toml run
hermes-multica-notify --config /REPLACE/notify.toml subscription list --json
hermes-multica-notify --config /REPLACE/notify.toml status --json
hermes-multica-notify --config /REPLACE/notify.toml doctor --offline
```

Before adding subscriptions, the service must project the TOML infrastructure into SQLite. `workspace add` appends a table, preserves comments, and requests SIGHUP. An invalid reload keeps the previous projection; removing a workspace/account disables dependent subscriptions.

A subscription selects an account, platform, chat_type, and chat; Telegram threads require a thread ID, while MAX threads are rejected. An empty thread means the chat itself; empty project/squad means no filter. Squad matches only type=squad assignments; labels require every listed name. Quiet is the default.

REPORT is never sent separately, including in verbose mode. A final message includes the latest report from the current observed cycle; an unknown boundary uses a 15-minute lookback. Missing transitions are not synthesized; repeated observed completions use a persistent transition_seq.

Disable cancels pending/retry entries. Inflight delivery may finish; re-enable sets since=now. `replay ID` and `dead-letter retry ID` explicitly requeue dead/cancelled entries with retained payloads and keep their recipient.

Every POST consumes an attempt, including the one-time fallback without reply after a confirmed anchor error. The thread is preserved. A lost response permits retry and a possible duplicate; exactly-once is not guaranteed. Telegram groups and threads are paced at least 3 seconds apart per chat (no more than 20 per minute); Telegram private chats retain 1-second pacing, and MAX pacing is unchanged. The account-wide cap remains 20 messages/s.

Polling runs every 45 seconds with a 300-second overlap. Full reconciliation runs every 300±30 seconds, at most two concurrently and one per workspace. Only available Multica history can be recovered; status exposes recovery_mode/history_gap_seconds/source_history_limited.

The event log is retained for 7 days and terminal notifications for 30; delivered payloads are cleared immediately, while dead/cancelled payloads remain replayable for 30 days. Processed keys live for the subscription lifetime; pending hints are coalesced by workspace/issue/type (per task ID for `task:failed`), have no age expiry, and are capped at 10,000 per workspace. On overflow, new unique hints are rejected with a diagnostic; a historical `--since` subscription triggers a full scan of available history. Processed hints last 24 hours, and rejected hints last 7 days.

`import-watcher --watcher-config ... --bindings ... --dry-run` validates explicit TOML bindings without writing. A real import creates infrastructure TOML tables and disabled subscriptions after reload; mappings/old DBs are not copied. `import-issues --subscription ID` loads a baseline without historical delivery. `--shadow` marks a separate subscription to an explicitly selected test chat.

Installation, LoadCredential drop-ins, cutover, cron, and live pilots are separate stages. Cutover requires consistent DB/TOML backups and an S3 copy; enabling a production subscription requires disabling its old watcher path. Rollback stops notify, restores previous watcher routes, and checks readiness. See `deploy/README.md`.

Pacing serializes dispatch through request completion so scheduler delays cannot bunch POST requests; this is a conservative limit, not a throughput promise of 20/s. Changing delivery_workers or request_timeout_seconds requires a restart; reload rejects that candidate. Status exposes heartbeat, cursor lag, and degraded state.

Before combining an issue with comments and task runs, the service rereads the issue and retries up to three times to obtain a coherent snapshot. If it keeps changing, the event is deferred and the cursor does not advance.

## Completion wake 0.5.0

Notify detects a new issue transition to `done`, stores an immutable read-only snapshot, and makes one automatic HMAC V2 request to the loopback Hermes webhook. The `event`, `event_type`, and `type` payload fields are all `task.completed`.

Hermes starts the agent in the pinned profile and sends only its final response to the configured Telegram topic or MAX group. `sent` means the webhook admitted the wake; it does not confirm response delivery.

Regular notify messages are suppressed for every registered wake subscription. The first baseline does not wake; repeated scans do not duplicate a job; after reopening, a new transition to `done` creates a new job.

Timeouts, lost responses, and expired sends become `delivery_unknown` with no automatic retry. A confirmed `duplicate` counts as admitted; `ignored` is an error. Manual replay keeps the wake ID and can duplicate a response if Hermes already handled the request.

Before enable, the CLI and doctor compare profile, event, HMAC presence, target, thread, absence of route scripts/skills/coalescing, and safe toolset against the protected operator export `webhook-policy.json`. Notify does not read Hermes home; the export contains private chat/thread IDs but no secrets and must be readable only by the administrator and service.

```bash
hermes-multica-notify --config /REPLACE/notify.toml wake add --subscription REPLACE_LABEL --profile default --route REPLACE_ROUTE
hermes-multica-notify --config /REPLACE/notify.toml wake list
hermes-multica-notify --config /REPLACE/notify.toml wake status --json
hermes-multica-notify --config /REPLACE/notify.toml wake replay REPLACE_WAKE_ID --confirm
```

Wake is disabled by default. Live enablement requires preapproved `test=true` project and topic, backups, and a separately agreed Gateway restart window; without a test target, E2E stops with `test_target_not_configured`.

## Scoped routes and grants 0.6.0

The operator-edited registry stores `route_grants`; operators configure grants, not the model. A grant binds a profile, connection, workspace, source chat/thread/user, projects or squad, typed assignees, credential anchor, a route quota counted independently for that grant, and expiry. A disabled or expired grant blocks new operations.

The eighth tool, `multica_route_create`, uses only trusted message source context. If multiple grants match, it returns `grant_required` with IDs of only the eligible grants; the route is created as `pending` unless the operator explicitly enables `auto_approve`. Approval and revocation are available only to operators through the Dashboard.

A route can narrow a grant but cannot broaden its ACL. `allowed_thread_ids` is checked against the exact bound Hermes thread for every Workspace tool; thread IDs are never accepted as model arguments. A mismatch stops the operation before a Multica call.

`project` means one project; `squad` and finite `workspace` scopes use an allowlist. `all_workspace` is available only to a dynamic workspace route with active `allow_all_projects=true`; send always requires an explicit `project_id`. Static 0.5.0 routes are never converted automatically.

A completion route uses `wake_mode=completion` with `watcher_enabled=false`. It does not call the old watcher or its mapping; notify reports readiness separately for every allowed project. Aggregate `wake_ready` never promises coverage for future projects in an open scope.

Notify readiness is checked through a separate read-only Unix socket. The service checks `SO_PEERCRED`, allowed UIDs and profiles, and frame size before parsing JSON; IPC grants no access to the notify SQLite database or credentials. Notify unavailability is a warning and does not block task creation.

A dynamic route reads the Multica PAT through a static credential anchor for the same connection/workspace. The secret is never copied to dynamic-route SQLite; the anchor, grant, workspace, and credential are rechecked before each operation.

The package includes the `hermes-multica-bridge` Skill: it directs the agent to bridge tools and forbids bypasses through shell, Multica CLI, or SQL. Installing the Skill creates no grants, routes, or subscriptions.

Dynamic routes live in a separate profile database with private permissions, transactional quotas, and audit records. Unknown schemas are rejected before the file is changed; revocation is retained as a terminal state, and new routes become visible without a Gateway restart.

The product version is 0.6.0. The 0.5.0 registry continues to load without rewrites. Grant, credential-anchor, and notify-subscription setup and publication remain separate operator stages; the old watcher is not started automatically.
