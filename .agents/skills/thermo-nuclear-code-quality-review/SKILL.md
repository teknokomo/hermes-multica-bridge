---
name: thermo-nuclear-code-quality-review
description: Review Python maintainability, module boundaries, error handling, tests, packaging, and documentation for the Hermes Multica Bridge.
metadata:
  version: "1.0.0"
  scope: "bridge-maintainability"
---

# Maintainability and code quality review

Review the patch for focused modules, simple control flow, useful types, clear names, and a small dependency surface.

## Rubric

1. Flag files approaching 1,000 lines and functions with unrelated responsibilities; propose a focused split when complexity warrants it.
2. Check for circular imports, duplicate validation, hidden global state, and abstractions that make the security boundary harder to follow.
3. Require unit coverage for changed validation, IPC, cgroup, credential, retry, ledger, and response-parsing behavior.
4. Check Python 3.11+ compatibility, type hints, consistent formatting, Ruff/Bandit compliance, and that runtime dependencies remain justified.
5. Verify `pyproject.toml`, `MANIFEST.in`, package build, Hermes manifest declarations, and the actual directory-plugin installation contract agree.
6. Update Russian user/deployment documentation and English code comments where behavior changes. Keep operational claims clear about what was and was not tested live.

## Findings

Separate blockers from follow-up suggestions. Do not demand React, Vitest, Playwright, pnpm workspace, SQL-store, or WebSocket checks in this Python-only repository.
