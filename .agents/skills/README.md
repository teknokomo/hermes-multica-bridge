# Project skills and review tools

This directory contains the review workflow for the standalone Hermes Multica Bridge project.

- `autoreview/` contains the bundle-driven review helper, its deterministic reliability checks, and the bridge-specific Thermos rubrics.
- `thermos/` coordinates the correctness/security and maintainability reviews.
- `thermo-nuclear-review/` focuses on correctness, security, data handling, and concurrency.
- `thermo-nuclear-code-quality-review/` focuses on Python maintainability, tests, packaging, and documentation.
- `ontoindex-code-intelligence/` documents project-scoped use of OntoIndex. The actual index is generated separately in `.ontoindex/` and is not copied from another repository.
- OntoIndex 2.3.4 generated project-specific skill notes under `generated/` and its CLI guidance under `.claude/skills/ontoindex/`; these are derived from this repository's source graph.

The Autoreview scripts were copied from the local `upstream-universo-platformo-react/.agents/skills/autoreview/scripts` implementation. The workflows and rubrics here are adapted for Python, Hermes plugins, Unix IPC, systemd, Multica webhooks, and the bridge's security boundaries.

Start with the instructions in the repository-root `AGENTS.md`. The standard final review command is:

```bash
.agents/skills/autoreview/scripts/autoreview \
  --mode local \
  --prompt-file .agents/skills/autoreview/rubrics/thermos.md
```

Autoreview requires a configured review engine such as Codex. If the helper reports `UNAVAILABLE` or `INCOMPLETE`, report that status; do not describe it as a clean review.
