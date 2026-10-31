# Project instructions

This repository contains a Python Hermes directory plugin and a restricted, systemd socket-activated sender for an explicitly allowlisted Multica route.

## Before changing code

- Read `README.md`, `SECURITY.md`, and the relevant sections of `deploy/README.md`.
- Check the current diff and preserve unrelated user changes.
- Keep the fixed route, default-deny policy, disabled example configuration, and secret boundaries intact unless the user explicitly authorizes a scoped change.
- Use Python 3.11+ and the existing project layout. Do not add runtime dependencies without a concrete need.
- Keep user-facing documentation in Russian. Maintain `README.md` as an English, line-for-line structural counterpart to `README-RU.md`; keep source comments/docstrings in English.

## Security and operations

- Treat webhook URLs, bearer credentials, signing secrets, tokens, and private server details as secrets. Never put them in source, prompts, logs, test fixtures, or reports.
- Offline tests must use fake credentials and mocked HTTP. Do not contact Multica or install/restart services on a VPS as part of ordinary code work.
- A live webhook request, configuration change, credential installation, or systemd deployment is an external write. Do it only when the user has explicitly authorized that specific stage.
- Do not copy production credentials, change Hermes `default`, or broaden the approved route/task allowlist.
- Do not treat webhook acceptance as proof that the assigned Multica agent completed the task.

## Verification

When the user requests QA/verification, run the focused checks documented in `README.md`: unit tests, compile check, Ruff, Bandit, package build/metadata validation, Hermes plugin doctor/validator, and systemd unit verification where available.

For code changes, code review, or final QA, apply the local Thermos skills and the project-local Autoreview helper:

```bash
.agents/skills/autoreview/scripts/autoreview \
  --mode local \
  --prompt-file .agents/skills/autoreview/rubrics/thermos.md
```

Run the Autoreview helper's deterministic reliability checks when its files change:

```bash
python3 .agents/skills/autoreview/scripts/test-autoreview-reliability.py
```

Treat review output as advisory until findings are checked against the code. A review is complete only after a terminal `PASS`, `FAIL`, `UNAVAILABLE`, or `INCOMPLETE` result; a running review is not a pass. Fix accepted actionable findings and repeat affected checks and review.

## OntoIndex

- The repository-local graph lives in `.ontoindex/` and is ignored by Git. Never copy it from another repository.
- Use OntoIndex only when its status identifies this repository and its indexed source is current. For uncommitted or stale files, inspect the actual source/diff; do not claim graph coverage for files the index does not contain.
- Before editing a function or class, run impact analysis when a usable current graph exists. If it does not, use direct source inspection and state that graph-backed impact was unavailable.
- Run diff verification after changes when the graph can represent the changed source. OntoIndex is supporting evidence, not a substitute for tests, security review, or direct inspection.
- Do not run `ontoindex setup` from this project unless the user asks to change MCP client configuration.

## Scope boundaries

- Do not commit, publish, or deploy unless the user asks for that action.
- Keep build outputs, caches, credentials, runtime configuration, and the OntoIndex database out of Git.

<!-- ontoindex:start -->
# OntoIndex — Code Intelligence

This project is indexed by OntoIndex as **hermes-multica-bridge** (2917 symbols, 6695 relationships, 251 execution flows). Use the OntoIndex MCP tools to understand code, assess impact, and navigate safely.

> The graph index is commit-based. If any OntoIndex tool warns the index is stale, or current HEAD differs from the indexed commit, coordinate first; exactly one process must run `ontoindex analyze` before graph-backed claims. Never silently assume dirty or uncommitted worktree changes are represented in the graph — verify current source or the diff for those changes.

## Always Do

Use OntoIndex in this order:

1. **Explore/search** — MCP `search({action: "semantic", repo: "hermes-multica-bridge", query: "concept"})` to find execution flows instead of grepping.
2. **Inspect context** — MCP `inspect({action: "context", repo: "hermes-multica-bridge", target: "symbolName"})` for a symbol's callers, callees, and execution flows.
3. **Impact before edits** — MCP `impact({action: "symbol", repo: "hermes-multica-bridge", target: "symbolName", direction: "upstream"})` or CLI `ontoindex impact --repo hermes-multica-bridge <symbol>`; report the blast radius and MUST warn on HIGH or CRITICAL risk before editing.
4. **gn_verify_diff before commit** — MCP `gn_verify_diff({repo: "hermes-multica-bridge", scope: "all"})` or CLI `ontoindex detect-changes --repo hermes-multica-bridge` to confirm only expected symbols and execution flows changed.

## Never Do

- NEVER edit a function, class, or method without first running MCP `impact` or CLI `ontoindex impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use MCP `refactor({action: "rename", ...})` which understands the call graph.
- NEVER commit changes without running MCP `gn_verify_diff` or CLI `ontoindex detect-changes` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `ontoindex://repo/hermes-multica-bridge/context` | Codebase overview, check index freshness |
| `ontoindex://repo/hermes-multica-bridge/clusters` | All functional areas |
| `ontoindex://repo/hermes-multica-bridge/processes` | All execution flows |
| `ontoindex://repo/hermes-multica-bridge/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Start here, any task | `.claude/skills/ontoindex/ontoindex-navigation/SKILL.md` |
| Understand architecture / "How does X work?" | `.claude/skills/ontoindex/ontoindex-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/ontoindex/ontoindex-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/ontoindex/ontoindex-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/ontoindex/ontoindex-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/ontoindex/ontoindex-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/ontoindex/ontoindex-cli/SKILL.md` |

<!-- ontoindex:end -->
