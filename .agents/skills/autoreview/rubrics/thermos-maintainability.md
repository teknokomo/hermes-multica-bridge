# Hermes Multica Bridge Maintainability and Code Quality

Review the implementation for focused Python modules and testable security boundaries.

## Structure and clarity

- Keep modules and functions focused. Flag files approaching 1,000 lines or functions that combine unrelated responsibilities.
- Check for circular imports, duplicate policy logic, unnecessary abstraction, hidden side effects, and confusing state transitions.
- Prefer explicit types and names. Keep the runtime dependency set small and Python 3.11+ compatible.
- Check that errors are translated at boundaries and that logs contain useful safe diagnostics without credentials or message text.

## Tests and packaging

- Require offline unit tests for changed validation, IPC, systemd-process verification, HTTP parsing, idempotency, and SQLite behavior.
- Verify tests use fake credentials, local sockets, and mocked HTTP; they must not send live Multica requests.
- Check Ruff/Bandit results, package contents, Python entry points, Hermes directory-plugin manifest, and that docs describe the actual install format.
- Update `README.md`, `SECURITY.md`, deployment instructions, and changelog when behavior or operational assumptions change.

## Project scope

Do not apply requirements for React, Vitest, Playwright, pnpm workspaces, SQL stores, or WebSocket origin checks; those do not belong to this repository. Report concrete maintainability findings through the canonical Autoreview schema.
