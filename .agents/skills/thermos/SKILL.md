---
name: thermos
description: Orchestrate correctness/security and maintainability review for the Hermes Multica Bridge using the local Autoreview helper and project-specific rubrics.
metadata:
  version: "1.0.0"
  scope: "hermes-multica-bridge"
---

# Thermos review

Use Thermos for code changes, explicit code reviews, and final QA. It combines the bridge-specific security/correctness rubric with the maintainability rubric and returns one Autoreview result.

## Required checks

1. Read the changed code, its callers, tests, `SECURITY.md`, and relevant deployment documentation.
2. Run relevant unit tests and static checks independently of the reviewer.
3. Run `.agents/skills/autoreview/scripts/autoreview --mode local --prompt-file .agents/skills/autoreview/rubrics/thermos.md`.
4. Verify findings against source and tests, fix accepted actionable issues, and repeat affected checks and review.
5. Report reviewed scope, commands/evidence, accepted or rejected findings, and the final helper status.

Critical security/correctness issues and high-severity findings block a clean recommendation. Do not infer that a local pass proves the live VPS, Multica, credentials, or systemd setup is correct.
