---
name: autoreview
description: Use for structured review of local code changes, final QA, security and maintainability review, or an explicit autoreview request. Provides the project-local bundle-driven review helper.
---

# Autoreview

Use the project-local helper as an advisory closeout review. It complements focused tests and direct code inspection; it is not deployment or merge approval.

## Run a review

For dirty local changes:

```bash
.agents/skills/autoreview/scripts/autoreview \
  --mode local \
  --prompt-file .agents/skills/autoreview/rubrics/thermos.md
```

Use the correctness/security or maintainability rubric alone only when the task is deliberately limited to that review dimension:

```bash
.agents/skills/autoreview/scripts/autoreview --mode local --prompt-file .agents/skills/autoreview/rubrics/thermos-correctness.md
.agents/skills/autoreview/scripts/autoreview --mode local --prompt-file .agents/skills/autoreview/rubrics/thermos-maintainability.md
```

Review the actual changes before running the helper. Check every finding against the implementation and adjacent code. Fix accepted actionable findings, run affected tests, and rerun the review. Do not make speculative changes solely to silence a reviewer.

## Review status

- A heartbeat means the review is still running.
- A review is complete only after `PASS`, `FAIL`, `UNAVAILABLE`, or `INCOMPLETE`.
- Report an unavailable engine, timeout, or incomplete run honestly; none is equivalent to `PASS`.
- Preserve unrelated user changes and do not include secrets in review prompts or evidence files.
- With Codex CLI, an initial WebSocket `HTTP 426 Upgrade Required` is not terminal when the CLI automatically continues over HTTP. Let that fallback complete and judge the run by the final helper status. Do not switch to another review engine solely because the WebSocket attempt received 426.

## Deterministic helper checks

When Autoreview files are added or changed, run:

```bash
python3 .agents/skills/autoreview/scripts/test-autoreview-reliability.py
```

The helper can run Codex, Claude, Droid, or Copilot reviewers when configured. Engine fallback and multi-reviewer panels are opt-in. For this repository, use the bridge-specific Thermos rubric rather than the source monorepo's generic rubric.
