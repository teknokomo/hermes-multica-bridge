---
name: ontoindex-code-intelligence
description: Use the repository-specific OntoIndex graph for Python symbol search, context, impact, and diff checks in Hermes Multica Bridge.
metadata:
  version: "1.0.0"
  scope: "hermes-multica-bridge"
---

# OntoIndex for Hermes Multica Bridge

OntoIndex 2.3.4 is used here as a local code-AST and execution-flow graph for this source repository. It is not an OWL/RDF semantic-web tool. Its database is repository-specific and belongs in the ignored `.ontoindex/` directory; never copy another project's index.

## Setup and status

The OntoIndex CLI is installed on the developer machine. Use it from this repository. In MCP calls, explicitly set `repo` to `hermes-multica-bridge` or this repository's absolute path; do not rely on the server's default repository:

```bash
ontoindex status --repo "$PWD"
ontoindex analyze --skip-git --skip-agents-md --name hermes-multica-bridge "$PWD"
```

This repository has no initial Git commit yet, so analysis must use `--skip-git`; `analyze` accepts a path argument rather than `--repo`. After the first commit, refresh with `ontoindex analyze "$PWD"`. Do not run `ontoindex setup` from this project unless asked to change MCP client configuration.

## Safe use

- Check `ontoindex status` before graph-backed claims. The graph may not include uncommitted edits.
- Use search/context to find Python symbols and callers, then inspect source and tests directly.
- Run impact analysis before edits when the index is usable and represents the target source. Otherwise use direct source inspection and state that graph impact was unavailable.
- After changes, run diff verification only when the graph identity and target source are valid; pass the changed files and executed tests explicitly when needed.
- Never treat the graph as authoritative for secret-flow or systemd/runtime behavior. Verify those against source, tests, unit files, and the target host separately.
- Avoid regenerating indexes concurrently. If OntoIndex reports stale state or another analysis job is active, inspect the status first and keep one analyzer process at a time.

## Relevant project areas

- `bridge/tool.py`: Hermes plugin tool boundary.
- `bridge/dispatcher.py`: Unix socket, process/cgroup authorization, and request dispatch.
- `bridge/routes.py`: operator-owned allowlist and webhook credential validation.
- `bridge/webhook.py`: HTTPS transport and Multica response parsing.
- `bridge/state.py`: SQLite idempotency and delivery ledger.
- `deploy/systemd/`: socket activation and sender sandbox.

The repository is small; use the graph where it adds context, not as ceremony for documentation-only or single-line changes.
