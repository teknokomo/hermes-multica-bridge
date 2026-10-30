# Hermes Multica Bridge Correctness and Security

Apply this rubric to changed code and its immediate trust-boundary callers.

## Identity, authorization, and IPC

- The tool may accept an optional model-selected `route_id` only to choose among routes already authorized for the pinned task/run/profile/assignee/state and exact operator grant. It must never widen authorization or supply a destination. Message, task ID, URL, request ID, and idempotency key remain runtime-controlled.
- Check `SO_PEERCRED`, general trusted-worker admission before body reads, and exact task/run scope plus trusted Gateway ancestry after parsing.
- Fail closed on unavailable or malformed `/proc`/cgroup evidence, operator config, and credential metadata. Review PID reuse, symlink, owner, and permission checks.
- Check strict JSON, duplicate-key rejection, exact field sets, UTF-8 behavior, 4 KiB request bound, absolute read deadline, and response framing.

## Webhook and secrets

- Keep the bearer URL out of the plugin, model context, source tree, shell arguments, logs, error text, SQLite, and ordinary output.
- Validate the pinned exact HTTPS URL for the allowed host, port, path, and token format. Verify TLS normally, refuse redirects, ignore untrusted proxy environment settings, and cap response size and total service lifetime.
- Ensure systemd `LoadCredential`, `DynamicUser`, socket permissions, and state-directory protections match the documented trust boundary.
- Return only sanitized error codes; never expose response bodies or exception details from HTTP libraries.

## Delivery state

- Verify fixed Workspace/Autopilot/trigger/event, default-deny routing, source-board allowlisting, and authorization of the current pinned task by exact trusted runtime task/run identity. A static source-task-ID allowlist is not part of the current architecture.
- Check UUIDv7 generation, deterministic Idempotency-Key, changed-payload conflict, uniqueness, transaction atomicity, retry/rate limits, and ambiguous delivery behavior.
- Confirm a duplicate is only treated as a confirmed delivery when the required Multica identifiers are present.
- Distinguish webhook accepted, execution pending, task completed, and result returned; do not claim completion without evidence.

## Compatibility and tests

- Verify the declared Hermes minimum/API and use documented plugin interfaces without core monkeypatches.
- Check Multica response/event shape against the supported version and identify live assumptions.
- Require regression tests for changed security or state invariants. Local mocks do not prove live server configuration.
- Report actionable findings in the canonical Autoreview schema; do not add an alternate output structure.
