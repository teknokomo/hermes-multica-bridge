# Hermes Multica Bridge Thermos Review

Review the changed source, tests, packaging, and deployment templates for correctness, security, concurrency, and maintainability. Treat `README.md` and `SECURITY.md` as the intended version-0.1 contract, but verify claims against code.

## Correctness and security

- Verify the model may pass only the optional `route_id` selector to choose among Routes already authorized for the pinned task/run/profile/assignee/state and any exact operator grant. `route_id` must never widen authorization or supply a destination; payload, source task, URL, request ID, and idempotency key remain runtime-controlled. Ambiguous route selection must fail closed.
- Check the sender authenticates the Unix peer before reading, accepts only the exact task/run cgroup-v2 worker leader, rejects child/orphan processes, and fails closed on missing or inconsistent process evidence. Respect `SECURITY.md`'s trust boundary: the worker process and loaded plugins are trusted computing base; report an IPC policy bypass only when a model-controlled path can reach the sender as that leader or otherwise evade those checks.
- Check strict JSON parsing, duplicate-key rejection, schema validation, request/response size limits, monotonic deadlines, and sanitized errors.
- Verify the route is default-deny and bound to the approved Workspace, Autopilot, trigger, event, and source board. Authorize only the current pinned Hermes task through trusted runtime task/run identity; do not use a static task-ID allowlist.
- Verify the webhook credential is isolated with systemd credentials; do not leak URL/token values through logs, exceptions, prompts, ledger records, or tool responses.
- Check URL validation, exact HTTPS host/path/token format, pinned fingerprint, TLS verification, redirect refusal, proxy handling, response bounds, and total service runtime bounds.
- Review UUIDv7 request IDs, stable idempotency across retries, SQLite transaction/uniqueness guarantees, attempt limits, and crash/partial-response handling.
- Check the effective systemd socket/service ownership, permissions, DynamicUser, state directory, capability restrictions, and required network families. The socket template uses `SocketMode=0600`; the setup helper creates an instance drop-in with `SocketUser=<configured Hermes user>`. Verify that generated drop-in before reporting that the template leaves the socket inaccessible to the configured Gateway.
- Verify Hermes and Multica contracts, compatibility declarations, and that acceptance is distinguished from task completion.

## Maintainability and evidence

- Check modularity, function complexity, import cycles, Python 3.11 compatibility, typing, names, and avoidable dependencies.
- Require focused offline tests for changed behavior; confirm tests use fake credentials and mocked network calls.
- Check that package metadata, `MANIFEST.in`, directory-plugin layout, and docs agree.
- Keep documentation operationally accurate. Do not claim target-VPS behavior from local static checks.
- Do not apply unrelated Universo monorepo rules for React, SQL stores, WebSockets, pnpm, or Playwright.

Put each concrete actionable issue in the canonical Autoreview `findings` array, mapping critical/high/medium/low to P0/P1/P2/P3. Use categories `security`, `bug`, `regression`, `test_gap`, or `maintainability`. Keep the review result in the helper's canonical JSON contract; do not add a second report schema.
