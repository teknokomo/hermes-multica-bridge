---
name: thermo-nuclear-review
description: Deep correctness and security review for the Python Hermes Multica Bridge, especially trust boundaries, secrets, HTTP delivery, IPC, and idempotency.
metadata:
  version: "1.0.0"
  scope: "bridge-correctness-security"
---

# Correctness and security review

Review changed behavior against `SECURITY.md` and the fixed version-0.1 test-route contract.

## Trust boundaries

- Confirm the Hermes tool accepts no model-controlled route, message, task, URL, or idempotency value.
- Verify Unix peer credentials and trusted Kanban Worker ancestry are checked before request-body reads; verify the exact task/run scope after strict parsing.
- Fail closed when `/proc`, cgroup, PID ancestry, operator configuration, credential metadata, or systemd state cannot be verified.
- Check PID reuse/TOCTOU handling, symlink rejection, ownership, file modes, request size, and absolute deadlines at the relevant boundary.

## Credential and network safety

- Ensure the bearer URL and other secrets never enter Git, tool output, prompts, logs, exceptions, SQLite, or normal reports.
- Verify credentials are supplied only through systemd `LoadCredential`; the Hermes plugin process must not receive the credential directory.
- Validate exact HTTPS host/path/token shape and the operator-pinned fingerprint. Confirm normal certificate verification, redirect refusal, and no environment-proxy leakage.
- Bound response size and total sender lifetime. Treat malformed, partial, or ambiguous responses as unknown/retryable only when the stable idempotency contract makes a retry safe.

## Delivery and persistence

- Verify that Workspace/Autopilot/trigger/event values come from operator configuration and dispatch remains bound to the pinned Hermes task/run identity. Enforce default-deny behavior and the approved payload contract without a static task-ID allowlist.
- Check UUIDv7 request IDs, stable idempotency keys, transaction boundaries, compare-and-swap updates, duplicate prevention, retry/rate limits, and crash behavior.
- Confirm the ledger stores only approved metadata and that webhook acceptance is not reported as agent completion.
- Verify HTTP and IPC error responses are sanitized and do not leak response bodies or transport exception details.

## Compatibility and evidence

- Check Hermes manifest/API requirements and documented public plugin interfaces; do not patch or monkeypatch Hermes internals.
- Check the documented Multica webhook contract for the supported Multica version and identify unverified live assumptions.
- Require focused regression tests for changed security boundaries. Local tests do not prove production systemd permissions or runtime ancestry.
- Classify findings by concrete impact: critical, high, medium, or low/advisory. Do not flag unrelated SQL, WebSocket, or frontend concerns.
