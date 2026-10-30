#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import autoreview_runtime


SCRIPT_DIR = Path(__file__).resolve().parent
LOADER = importlib.machinery.SourceFileLoader("autoreview_module", str(SCRIPT_DIR / "autoreview"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
AUTOREVIEW = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUTOREVIEW
LOADER.exec_module(AUTOREVIEW)


class AutoreviewReliabilityTests(unittest.TestCase):
    @staticmethod
    def valid_report() -> str:
        return AUTOREVIEW.json.dumps(
            {
                "findings": [],
                "overall_correctness": "patch is correct",
                "overall_explanation": "No actionable findings.",
                "overall_confidence": 0.9,
            }
        )

    def test_all_thermos_rubrics_preserve_canonical_output_contract(self) -> None:
        rubric_dir = SCRIPT_DIR.parent / "rubrics"
        for path in sorted(rubric_dir.glob("thermos*.md")):
            with self.subTest(path=path.name):
                AUTOREVIEW.validate_extra_prompt(path.read_text())

    def test_review_prompt_explains_redaction_placeholders(self) -> None:
        rendered = AUTOREVIEW.build_prompt(
            Path("."), "local", None, "fixture bundle", "", ""
        )

        self.assertIn("sanitizer placeholders", rendered)
        self.assertIn("Never infer a defect from a placeholder alone", rendered)
        self.assertIn("Verify each finding against the exact source lines", rendered)
        self.assertIn("Trace values through constructors, properties, and helper calls", rendered)

    def test_multiline_redaction_advances_after_a_diff_boundary(self) -> None:
        diff = (
            "diff --git a/config.yaml b/config.yaml\n"
            "--- a/config.yaml\n"
            "+++ b/config.yaml\n"
            "@@ -1,2 +1,2 @@\n"
            "+private_key: |\n"
            "+  fixture-private-material\n"
            "@@ -10,1 +10,1 @@\n"
            " setting: clean\n"
        )
        child = (
            "import importlib.machinery, importlib.util, sys\n"
            "from pathlib import Path\n"
            "helper = Path(sys.argv[1])\n"
            "sys.path.insert(0, str(helper.parent))\n"
            "loader = importlib.machinery.SourceFileLoader('helper', str(helper))\n"
            "spec = importlib.util.spec_from_loader(loader.name, loader)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = module\n"
            "loader.exec_module(module)\n"
            "sys.stdout.write(module.redact_sensitive_content(sys.argv[2]))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", child, str(SCRIPT_DIR / "autoreview"), diff],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[REDACTED]", result.stdout)
        self.assertNotIn("fixture-private-material", result.stdout)
        self.assertIn("@@ -10,1 +10,1 @@", result.stdout)

    def test_conflicting_markdown_output_instruction_fails_preflight(self) -> None:
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.validate_extra_prompt("Return the review as Markdown.")
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PROMPT_CONFLICT)

    def test_negated_markdown_output_instruction_is_allowed(self) -> None:
        AUTOREVIEW.validate_extra_prompt("Do not return the review as Markdown.")

    def test_negated_markdown_does_not_hide_positive_table_conflict(self) -> None:
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.validate_extra_prompt("Do not return Markdown; output the findings as a table.")
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PROMPT_CONFLICT)

    def test_review_error_escapes_terminal_controls(self) -> None:
        error = AUTOREVIEW.ReviewError(
            AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR,
            "engine failed \x1b[31m",
            detail="untrusted output \x1b]0;title\x07",
        )

        rendered = str(error)

        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn(r"\x1b[31m", rendered)
        self.assertIn(r"\x07", rendered)

    def test_bundle_split_is_bounded_and_lossless(self) -> None:
        bundle = "# Header\n\n" + "\n\n".join(
            AUTOREVIEW.bundle_file_section(f"file-{index}", "x" * 4000)
            for index in range(8)
        )
        parts = AUTOREVIEW.split_bundle(bundle, 10_000)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(len(part) <= 10_000 for part in parts))
        self.assertEqual("".join(part.rstrip() for part in parts).count('## File: "file-'), 8)

    def test_oversized_section_repeats_file_context(self) -> None:
        body = "".join(f"line-{index:04d} {'x' * 70}\n" for index in range(400))
        parts = AUTOREVIEW.split_bundle(AUTOREVIEW.bundle_file_section("src/large.py", body), 10_000)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(part.splitlines()[1].startswith('## File: "src/large.py"') for part in parts))
        self.assertTrue(all(len(part) <= 10_000 for part in parts))
        self.assertIn("[continued 2]", parts[1].splitlines()[1])
        self.assertRegex(parts[1], r"AUTOREVIEW_SOURCE_START_LINE: [1-9][0-9]+")

    def test_oversized_diff_continuation_preserves_hunk_line_context(self) -> None:
        body = (
            "diff --git a/src/large.py b/src/large.py\n"
            "--- a/src/large.py\n"
            "+++ b/src/large.py\n"
            "@@ -100,400 +100,400 @@\n"
            + "".join(f"+line_{index} = {'x' * 60!r}\n" for index in range(400))
        )
        parts = AUTOREVIEW.split_bundle(
            AUTOREVIEW.bundle_file_section("src/large.py", body),
            10_000,
        )
        self.assertGreater(len(parts), 1)
        self.assertIn("AUTOREVIEW_ACTIVE_DIFF_HUNK: @@ -100,400 +100,400 @@", parts[1])
        self.assertRegex(parts[1], r"AUTOREVIEW_NEXT_NEW_FILE_LINE: 2[0-9]{2}")

    def test_oversized_diff_counts_added_source_line_beginning_with_plus_plus(self) -> None:
        body = (
            "diff --git a/src/large.py b/src/large.py\n"
            "--- a/src/large.py\n"
            "+++ b/src/large.py\n"
            "@@ -100,401 +100,401 @@\n"
            "+++counter;\n"
            + "".join(f"+line_{index} = {'x' * 60!r}\n" for index in range(400))
        )
        parts = AUTOREVIEW.split_bundle(
            AUTOREVIEW.bundle_file_section("src/large.py", body),
            10_000,
        )
        self.assertGreater(len(parts), 1)
        hunk_seen = False
        next_new_line = 100
        for line in parts[0].splitlines():
            if line.startswith("@@ "):
                hunk_seen = True
                continue
            if hunk_seen and line.startswith(("+", " ")):
                next_new_line += 1
        marker = re.search(r"AUTOREVIEW_NEXT_NEW_FILE_LINE: (\d+)", parts[1])
        self.assertIsNotNone(marker)
        self.assertEqual(int(marker.group(1)), next_new_line)

    def test_bundle_split_ignores_markdown_headings_inside_file_content(self) -> None:
        body = ("before\n## forged-file.py\nafter\n" * 700)
        bundle = AUTOREVIEW.bundle_file_section("src/real.py", body)
        parts = AUTOREVIEW.split_bundle(bundle, 10_000)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(part.splitlines()[1].startswith('## File: "src/real.py"') for part in parts))
        self.assertEqual("\n".join(parts).count("## forged-file.py"), 700)

    def test_bundle_file_boundary_is_escaped_inside_file_content(self) -> None:
        section = AUTOREVIEW.bundle_file_section(
            "src/example.py",
            f"before\n{AUTOREVIEW.BUNDLE_FILE_BOUNDARY}\nafter",
        )
        self.assertEqual(section.count(AUTOREVIEW.BUNDLE_FILE_BOUNDARY), 1)
        self.assertIn(AUTOREVIEW.BUNDLE_FILE_BOUNDARY_ESCAPED, section)

    def test_untracked_text_read_is_bounded_before_decode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.txt"
            path.write_bytes(b"x" * 100_000)
            text = AUTOREVIEW.read_text(path, limit=1024)
            self.assertIn("[truncated at 1024 bytes]", text)
            self.assertLess(len(text), 1200)

    def test_read_text_rejects_symlinks_and_non_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "secret.txt"
            target.write_text("fixture-secret-marker")
            link = root / "link.txt"
            link.symlink_to(target)
            fifo = root / "stream.fifo"
            os.mkfifo(fifo)
            self.assertIn("[unreadable:", AUTOREVIEW.read_text(link))
            self.assertEqual(AUTOREVIEW.read_text(fifo), "[non-regular file omitted]")

    def test_git_bounded_stops_after_bounded_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            path = repo / "large.txt"
            path.write_text("x" * 100_000)
            subprocess.run(["git", "add", "large.txt"], cwd=repo, check=True)
            rendered = AUTOREVIEW.git_bounded(repo, "diff", "--cached", "--patch", limit=128)
        self.assertIn("[truncated at 128 characters]", rendered)
        self.assertLess(len(rendered), 220)

    def test_local_bundle_keeps_complete_large_untracked_source(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            marker = "tail-marker-untracked"
            (repo / "large.py").write_text(("value = 1\n" * 4_000) + marker + "\n")
            bundle = AUTOREVIEW.local_bundle(repo)
        self.assertIn(marker, bundle)
        self.assertNotIn("[truncated at 24000 bytes]", bundle)

    def test_local_bundle_keeps_complete_large_tracked_patch(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            path = repo / "large.py"
            path.write_text("".join(f"old_{index} = {index}\n" for index in range(3_000)))
            subprocess.run(["git", "add", "large.py"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            marker = "tail-marker-tracked"
            path.write_text("".join(f"new_{index} = {index}\n" for index in range(3_000)) + marker + "\n")
            bundle = AUTOREVIEW.local_bundle(repo)
        self.assertIn(marker, bundle)
        self.assertNotIn("[truncated at 24000 characters]", bundle)

    def test_generated_and_binary_paths_are_summarized(self) -> None:
        self.assertTrue(AUTOREVIEW.should_summarize_patch("pnpm-lock.yaml"))
        self.assertTrue(AUTOREVIEW.should_summarize_patch("docs/screenshot.png"))
        self.assertFalse(AUTOREVIEW.should_summarize_patch("src/service.ts"))

    def test_sensitive_untracked_paths_are_omitted_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            (repo / ".env.local").write_text("FIXTURE_VALUE=must-not-enter-review\n")
            credential_dir = repo / "credentials"
            credential_dir.mkdir()
            (credential_dir / "prod.toml").write_text("fixture='must-not-enter-review'\n")
            (repo / "service.py").write_text("VALUE = 'review-me'\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("sensitive untracked file omitted from review prompt", bundle)
            self.assertNotIn("must-not-enter-review", bundle)
            self.assertIn("VALUE = 'review-me'", bundle)

    def test_environment_file_suffix_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            config = repo / "config"
            config.mkdir()
            (config / "production.env").write_text("SECRET=must-not-enter-review\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("sensitive untracked file omitted from review prompt", bundle)
            self.assertNotIn("must-not-enter-review", bundle)

    def test_private_backup_directory_is_omitted_from_review_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            backup = repo / ".backup" / "production-report.md"
            backup.parent.mkdir(parents=True)
            backup.write_text("private-path-marker must-not-enter-review\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn(".backup/production-report.md", bundle)
            self.assertIn("sensitive untracked file omitted from review prompt", bundle)
            self.assertNotIn("private-path-marker", bundle)

    def test_git_paths_preserve_whitespace_and_newlines(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            names = [" leading.py ", "line\nbreak.py"]
            for name in names:
                (repo / name).write_text("VALUE = 1\n")
            self.assertEqual(
                set(AUTOREVIEW.git_paths(repo, "ls-files", "--others", "--exclude-standard")),
                set(names),
            )
            self.assertEqual(AUTOREVIEW.review_paths(repo, "local", None, "HEAD"), set(names))
            bundle = AUTOREVIEW.local_bundle(repo)
            for name in names:
                self.assertIn(AUTOREVIEW.json.dumps(name, ensure_ascii=True), bundle)

    def test_har_and_log_artifacts_are_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            (repo / "capture.har").write_text("private-cookie-marker\n")
            (repo / "debug.log").write_text("private-log-marker\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertNotIn("private-cookie-marker", bundle)
            self.assertNotIn("private-log-marker", bundle)

    def test_sensitive_tracked_patch_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            (repo / ".env").write_text("FIXTURE_VALUE=old-marker\n")
            subprocess.run(["git", "add", ".env"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            (repo / ".env").write_text("FIXTURE_VALUE=new-marker\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("sensitive file patch omitted from review prompt", bundle)
            self.assertNotIn("new-marker", bundle)

    def test_tracked_patch_redaction_uses_complete_multiline_secret_context(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            secret_lines = [f"  fixture-private-key-line-{index}" for index in range(1, 7)]
            original = "private_key: |\n" + "\n".join(secret_lines) + "\nsetting: old\n"
            changed = "private_key: |\n" + "\n".join(secret_lines) + "\nsetting: new\n"
            (repo / "config.yaml").write_text(original)
            subprocess.run(["git", "add", "config.yaml"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            (repo / "config.yaml").write_text(changed)

            bundle = AUTOREVIEW.local_bundle(repo)

            self.assertIn("setting: new", bundle)
            self.assertIn("[REDACTED]", bundle)
            for secret_line in secret_lines:
                self.assertNotIn(secret_line.strip(), bundle)

    def test_ordinary_config_content_redacts_credentials(self) -> None:
        token = "awt_" + "Z" * 43
        body = (
            'multica_origin = "https://multica.example.org"\n'
            f'webhook_url = "https://multica.example.org/api/webhooks/autopilots/{token}"\n'
            'multica_pat = "fixture-private-pat"\n'
            'Authorization: Bearer fixture-private-bearer\n'
        )
        section = AUTOREVIEW.bundle_file_section("config/route.toml", body)
        self.assertIn("multica_origin", section)
        self.assertNotIn(token, section)
        self.assertNotIn("fixture-private-pat", section)
        self.assertNotIn("fixture-private-bearer", section)
        self.assertGreaterEqual(section.count("[REDACTED]"), 3)

    def test_python_sensitive_field_annotations_are_preserved_and_defaults_redacted(self) -> None:
        body = (
            "class StandardSecrets:\n"
            "    webhook_url: str\n"
            "    hmac_signing_secret: str | None\n"
            '    multica_pat: str = "fixture-private-pat"\n'
            "    private_key: str = configured_key\n"
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body, source_path="bridge/secrets.py")

        self.assertIn("webhook_url: str", redacted)
        self.assertIn("hmac_signing_secret: str | None", redacted)
        self.assertIn('multica_pat: str = "[REDACTED]"', redacted)
        self.assertIn("private_key: str = configured_key", redacted)
        self.assertNotIn("fixture-private-pat", redacted)

    def test_python_sensitive_boolean_expressions_keep_their_logic(self) -> None:
        body = (
            "def secret_presence(secrets):\n"
            "    return {\n"
            "        \"multica_pat\": bool(secrets.multica_pat),\n"
            "        \"token\": \"fixture-private-token-value\",\n"
            "    }\n"
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body, source_path="dashboard/plugin_api.py")

        ast.parse(redacted)
        self.assertIn("\"multica_pat\": bool(secrets.multica_pat)", redacted)
        self.assertIn('\"token\": "[REDACTED]"', redacted)
        self.assertNotIn("fixture-private-token-value", redacted)

    def test_python_sensitive_code_references_are_preserved_but_literals_are_redacted(self) -> None:
        body = (
            "def build():\n"
            "    return send(\n"
            "        webhook_url=secrets.webhook_url,\n"
            '        webhook_url_ref=_credential_ref(credentials.get("webhook_url_ref"), "credentials.webhook_url_ref") or "",\n'
            '        hmac_signing_secret="fixture-private-signing-secret",\n'
            '        multica_pat=load_pat("A7bCd91ef"),\n'
            "    )\n"
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body, source_path="bridge/routes.py")

        ast.parse(redacted)
        self.assertIn("webhook_url=secrets.webhook_url,", redacted)
        self.assertIn(
            'webhook_url_ref=_credential_ref(credentials.get("webhook_url_ref"), "credentials.webhook_url_ref") or "",',
            redacted,
        )
        self.assertIn('hmac_signing_secret="[REDACTED]"', redacted)
        self.assertIn('multica_pat="[REDACTED]"', redacted)
        self.assertNotIn("fixture-private-signing-secret", redacted)
        self.assertNotIn("A7bCd91ef", redacted)

    def test_sensitive_python_function_signature_defaults_are_redacted(self) -> None:
        body = (
            'def send(label: str = "видимый", token: str = "fixture-token-value", api_key=\'fixture-key-value\'): return token\n'
            'async def connect(*, webhook_url: str = r"fixture-webhook-value"): ...\n'
            'def keep(token: str = configured_token, non_secret_token: str = "visible"): ...\n'
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body, source_path="bridge/client.py")

        ast.parse(redacted)
        self.assertNotIn("fixture-token-value", redacted)
        self.assertNotIn("fixture-key-value", redacted)
        self.assertNotIn("fixture-webhook-value", redacted)
        self.assertIn('token: str = "[REDACTED]"', redacted)
        self.assertIn("api_key='[REDACTED]'", redacted)
        self.assertIn('label: str = "видимый"', redacted)
        self.assertIn('webhook_url: str = r"[REDACTED]"', redacted)
        self.assertIn("token: str = configured_token", redacted)
        self.assertIn('non_secret_token: str = "visible"', redacted)

    def test_sensitive_python_function_signature_defaults_are_redacted_in_diff(self) -> None:
        body = (
            "diff --git a/bridge/client.py b/bridge/client.py\n"
            "@@ -1,1 +1,1 @@\n"
            '+def send(token: str = "fixture-diff-token"): ...\n'
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body, source_path="bridge/client.py")

        self.assertNotIn("fixture-diff-token", redacted)
        self.assertIn('+def send(token: str = "[REDACTED]"): ...', redacted)

    def test_prefixed_sensitive_environment_assignments_are_redacted(self) -> None:
        body = (
            "export GITHUB_TOKEN=fixture-github-token-value\n"
            "HERMES_MULTICA_BRIDGE_HMAC_SIGNING_SECRET=fixture-hmac-value\n"
            "+AWS_SECRET_ACCESS_KEY=fixture-aws-value\n"
            "private_key=fixture-private-key-assignment\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("fixture-github-token-value", redacted)
        self.assertNotIn("fixture-hmac-value", redacted)
        self.assertNotIn("fixture-aws-value", redacted)
        self.assertNotIn("fixture-private-key-assignment", redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 4)

    def test_sensitive_assignments_with_env_suffix_are_redacted(self) -> None:
        body = (
            'MULTICA_PAT_ENV = "fixture-private-pat-env-value"\n'
            'HMAC_SIGNING_SECRET_ENV = "fixture-private-hmac-env-value"\n'
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body)

        self.assertNotIn("fixture-private-pat-env-value", redacted)
        self.assertNotIn("fixture-private-hmac-env-value", redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 2)

    def test_private_key_pem_block_is_redacted(self) -> None:
        body = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-private-key-body\n-----END OPENSSH PRIVATE KEY-----\nafter"
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("fixture-private-key-body", redacted)
        self.assertIn("[PRIVATE KEY REDACTED]", redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))
        self.assertEqual(redacted.splitlines().index("after"), body.splitlines().index("after"))

    def test_sensitive_assignment_redaction_preserves_code_delimiters(self) -> None:
        body = (
            'TEST_HMAC_SECRET = "fixture-private-secret"\n'
            "client.send(\n"
            "    hmac_secret=TEST_HMAC_SECRET,\n"
            "    hmac_required=True,\n"
            ")\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertIn("hmac_secret=TEST_HMAC_SECRET,", redacted)
        self.assertIn('TEST_HMAC_SECRET = "[REDACTED]"', redacted)
        self.assertNotIn("fixture-private-secret", redacted)
        self.assertIn("hmac_required=True,", redacted)

    def test_multiline_sensitive_assignment_literals_are_redacted(self) -> None:
        body = (
            "API_KEY = (\n"
            '    "provider-secret",\n'
            ")\n"
            'SAFE_LABEL = "visible"\n'
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("provider-secret", redacted)
        self.assertIn('    "[REDACTED]",', redacted)
        self.assertIn('SAFE_LABEL = "visible"', redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_multiline_sensitive_assignment_with_opener_comment_is_redacted(self) -> None:
        body = (
            "API_KEY = (  # provider credential\n"
            '    "actual-value",\n'
            ")\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("actual-value", redacted)
        self.assertIn("# provider credential", redacted)
        self.assertIn('"[REDACTED]"', redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_diff_replacement_multiline_sensitive_assignment_keeps_sides_isolated(self) -> None:
        body = (
            "diff --git a/config.py b/config.py\n"
            "@@ -1,3 +1,3 @@\n"
            " API_KEY = (\n"
            '-    "old-provider-secret",\n'
            "-)\n"
            '+    "new-provider-secret",\n'
            "+)\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("old-provider-secret", redacted)
        self.assertNotIn("new-provider-secret", redacted)
        self.assertEqual(redacted.count('"[REDACTED]"'), 2)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_triple_quoted_sensitive_assignment_is_redacted(self) -> None:
        body = (
            'API_KEY = """\n'
            "provider-secret-line-one\n"
            "provider-secret-line-two\n"
            '""".strip()\n'
            'SAFE_LABEL = "visible"\n'
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("provider-secret-line-one", redacted)
        self.assertNotIn("provider-secret-line-two", redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn('SAFE_LABEL = "visible"', redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_yaml_sensitive_block_scalar_is_redacted(self) -> None:
        body = (
            "service:\n"
            "  password: |\n"
            "    provider-secret-line-one\n"
            "    provider-secret-line-two\n"
            "  visible: yes\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("provider-secret-line-one", redacted)
        self.assertNotIn("provider-secret-line-two", redacted)
        self.assertIn("  password: |", redacted)
        self.assertIn("  visible: yes", redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_multiline_sensitive_redaction_preserves_diff_markers(self) -> None:
        body = (
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1,1 +1,4 @@\n"
            '+API_KEY = """\n'
            "+provider-secret\n"
            '+"""\n'
            "+SAFE = True\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("provider-secret", redacted)
        added = [line for line in redacted.splitlines() if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(len(added), 4)
        self.assertTrue(all(line.startswith("+") for line in added))
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_multiline_diff_redaction_tracks_old_and_new_sides_independently(self) -> None:
        body = (
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1,3 +1,3 @@\n"
            ' API_KEY = """\n'
            "-old-provider-secret\n"
            '-"""\n'
            "+new-provider-secret\n"
            '+"""  # changed closing line\n'
        )

        redacted = AUTOREVIEW.redact_sensitive_content(body)

        self.assertNotIn("old-provider-secret", redacted)
        self.assertNotIn("new-provider-secret", redacted)
        self.assertIn('-[REDACTED]\n', redacted)
        self.assertIn('+[REDACTED]\n', redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_sensitive_mapping_redaction_has_bounded_backtracking(self) -> None:
        sensitive_name = "api_" + "key"
        body = '{"' + sensitive_name + '": "' + ("\\" * 4_000) + "\n"

        def timeout_handler(_signum, _frame):
            raise TimeoutError("credential redaction regex exceeded its bound")

        previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, 1.0)
        try:
            redacted = AUTOREVIEW.redact_sensitive_content(body)
        finally:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            signal.signal(signal.SIGALRM, previous_handler)

        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_python_config_literals_redact_without_breaking_source(self) -> None:
        body = (
            "values = (\n"
            "    'hmac_signing_secret_ref = \"fixture-hmac-secret\"',\n"
            "    'multica_pat_ref = \"fixture-pat\"',\n"
            ")\n"
            "PRIVATE_KEY_BLOCK_RE = re.compile(\n"
            "    r\"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\"\n"
            ")\n"
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("fixture-hmac-secret", redacted)
        self.assertNotIn("fixture-pat", redacted)
        self.assertIn("PRIVATE_KEY_BLOCK_RE = re.compile(", redacted)
        self.assertIn('"[REDACTED]"', redacted)

    def test_double_quoted_python_literal_redaction_preserves_escaped_quotes(self) -> None:
        body = (
            'values = (\n    "hmac_signing_secret_ref = '
            + chr(92)
            + '"fixture-secret'
            + chr(92)
            + '"",\n)\n'
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("fixture-secret", redacted)
        self.assertIn(r'\"[REDACTED]\"', redacted)

    def test_redaction_preserves_python_sources_and_quoted_mapping_fields(self) -> None:
        root = SCRIPT_DIR.parents[3]
        paths = [SCRIPT_DIR / "autoreview", *root.rglob("*.py")]
        excluded = {".git", ".ontoindex", ".venv", "__pycache__", "build", "dist"}
        seen: set[Path] = set()
        for path in paths:
            resolved = path.resolve()
            if resolved in seen or any(part in excluded for part in path.parts):
                continue
            seen.add(resolved)
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            with self.subTest(path=path.relative_to(root)):
                ast.parse(AUTOREVIEW.redact_sensitive_content(source), filename=str(path))

        body = (
            "config = {\n"
            '    "webhook_url": "fixture-webhook-url",\n'
            "    'hmac_signing_secret': 'fixture-hmac-secret',\n"
            "}\n"
            'values = (\n    "private_key=fixture-private-key",\n)\n'
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("fixture-webhook-url", redacted)
        self.assertNotIn("fixture-hmac-secret", redacted)
        self.assertNotIn("fixture-private-key", redacted)

    def test_redacted_route_tests_remain_valid_python(self) -> None:
        source_path = SCRIPT_DIR.parents[3] / "tests" / "test_routes.py"
        source = source_path.read_text(encoding="utf-8")
        redacted = AUTOREVIEW.redact_sensitive_content(source)
        ast.parse(redacted)
        self.assertNotIn("HMB_HMAC_SIGNING_SECRET", redacted)
        self.assertNotIn("HMB_MULTICA_PAT", redacted)

    def test_url_query_credentials_are_redacted(self) -> None:
        body = 'CALLBACK_URL = "https://example.test/callback?access_token=fixture-query-secret&next=/home"\n'
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("fixture-query-secret", redacted)
        self.assertIn("access_token=[REDACTED]&next=/home", redacted)

    def test_json_private_key_fields_are_redacted(self) -> None:
        body = '{"ssh_private_key":"fixture-json-private-key"}'
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("fixture-json-private-key", redacted)
        self.assertIn('[REDACTED]', redacted)

    def test_compact_json_credentials_are_redacted(self) -> None:
        body = '{"nested":{"multica_pat":"fixture-json-pat","api_key":"fixture-json-key"}}'
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        self.assertNotIn("fixture-json-pat", redacted)
        self.assertNotIn("fixture-json-key", redacted)
        self.assertEqual(redacted.count('[REDACTED]'), 2)

    def test_single_quoted_inline_python_mapping_credentials_are_redacted(self) -> None:
        body = "config = {'multica_pat': 'fixture-inline-pat', \"hmac_signing_secret\": \"fixture-inline-secret\"}\n"
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("fixture-inline-pat", redacted)
        self.assertNotIn("fixture-inline-secret", redacted)
        self.assertEqual(redacted.count('[REDACTED]'), 2)

    def test_prefixed_and_triple_quoted_inline_mapping_credentials_are_redacted(self) -> None:
        body = (
            'config = {"api_key": r"fixture-raw-secret", '
            '"hmac_signing_secret": b"fixture-bytes-secret"}\n'
            'nested = {"multica_pat": r"""fixture-triple-secret\nsecond-line"""}\n'
        )
        redacted = AUTOREVIEW.redact_sensitive_content(body)
        ast.parse(redacted)
        self.assertNotIn("fixture-raw-secret", redacted)
        self.assertNotIn("fixture-bytes-secret", redacted)
        self.assertNotIn("fixture-triple-secret", redacted)
        self.assertNotIn("second-line", redacted)
        self.assertIn('r"[REDACTED]"', redacted)
        self.assertIn('b"[REDACTED]"', redacted)
        self.assertEqual(redacted.count("\n"), body.count("\n"))

    def test_commit_ref_cannot_be_interpreted_as_git_option(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            (repo / "file.txt").write_text("fixture\n")
            subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            output = repo / "must-not-be-created"
            with self.assertRaises(SystemExit):
                AUTOREVIEW.resolve_commit_ref(repo, f"--output={output}")
            with self.assertRaises(SystemExit):
                AUTOREVIEW.branch_bundle(repo, f"--output={output}")
            with self.assertRaises(SystemExit):
                AUTOREVIEW.commit_bundle(repo, f"--output={output}")
            self.assertFalse(output.exists())

    def test_changed_path_with_git_pathspec_magic_is_reviewed_literally(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            special = repo / ":(exclude)secret.py"
            special.write_text("before = True\n", encoding="utf-8")
            subprocess.run(["git", "--literal-pathspecs", "add", "--", special.name], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            special.write_text("after = True\n", encoding="utf-8")

            bundle = AUTOREVIEW.local_bundle(repo)

            self.assertIn('## File: ":(exclude)secret.py"', bundle)
            self.assertIn("+after = True", bundle)

    def test_codex_review_runs_tool_free_in_an_empty_workspace(self) -> None:
        observed = {}

        def fake_run(command, cwd, **kwargs):
            observed["cwd"] = Path(cwd)
            observed["command"] = command
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text(self.valid_report(), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        args = argparse.Namespace(
            tools=False,
            web_search=False,
            model=None,
            thinking=None,
            stream_engine_output=False,
            codex_bin="codex",
            timeout=10,
        )
        with tempfile.TemporaryDirectory() as repo_dir, mock.patch.object(
            AUTOREVIEW, "run_with_heartbeat", side_effect=fake_run
        ):
            repo = Path(repo_dir)
            (repo / ".env").write_text("SECRET=excluded-from-review\n")
            output = AUTOREVIEW.run_codex(args, repo, "sanitized review prompt")
        self.assertEqual(output, self.valid_report())
        self.assertNotEqual(observed["cwd"], repo)
        self.assertEqual(Path(observed["command"][observed["command"].index("-C") + 1]), observed["cwd"])
        self.assertIn("--skip-git-repo-check", observed["command"])
        self.assertIn("--ignore-user-config", observed["command"])
        self.assertIn("--ignore-rules", observed["command"])
        self.assertIn("mcp_servers={}", observed["command"])
        self.assertIn('web_search="disabled"', observed["command"])
        self.assertIn("apps", observed["command"])
        self.assertIn("multi_agent", observed["command"])
        self.assertIn("shell_tool", observed["command"])
        self.assertFalse((observed["cwd"] / ".env").exists())

    def test_codex_tools_are_disabled_by_default_and_can_be_explicitly_enabled(self) -> None:
        with mock.patch.object(sys, "argv", ["autoreview", "--engine", "codex"]):
            args = AUTOREVIEW.parse_args()
            self.assertFalse(args.tools)
            self.assertFalse(args.tools_explicit)
        with mock.patch.object(sys, "argv", ["autoreview", "--engine", "codex", "--tools"]):
            args = AUTOREVIEW.parse_args()
            self.assertTrue(args.tools)
            self.assertTrue(args.tools_explicit)
        with mock.patch.object(sys, "argv", ["autoreview", "--engine", "claude"]):
            self.assertTrue(AUTOREVIEW.parse_args().tools)

    def test_codex_reviewer_stays_tool_free_when_primary_engine_is_claude(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["autoreview", "--engine", "claude", "--reviewers", "codex,claude"],
        ):
            reviewers = AUTOREVIEW.reviewer_args(AUTOREVIEW.parse_args())
        tools_by_engine = {reviewer.engine: reviewer.tools for reviewer in reviewers}
        self.assertEqual(tools_by_engine, {"codex": False, "claude": True})

    def test_review_json_rejects_duplicate_report_keys(self) -> None:
        report = (
            '{"findings":[],"findings":[],"overall_correctness":"patch is correct",'
            '"overall_explanation":"No actionable findings.","overall_confidence":0.9}'
        )
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.extract_json(report)
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_SCHEMA_ERROR)

    def test_review_json_rejects_duplicate_nested_and_jsonl_keys(self) -> None:
        nested_duplicate = '{"metadata":{"value":1,"value":2}}'
        self.assertIsNone(AUTOREVIEW.parse_json_candidate(nested_duplicate))

        duplicate_event = '{"structured_output":{"findings":[]},"structured_output":{"findings":[]}}'
        self.assertIsNone(AUTOREVIEW.extract_json_from_jsonl(duplicate_event))

        report = '{"findings":[],"findings":[],"overall_correctness":"patch is correct"}'
        event = AUTOREVIEW.json.dumps({"result": report})
        self.assertIsNone(AUTOREVIEW.extract_json_from_jsonl(event))

    def test_empty_reviewer_list_is_rejected(self) -> None:
        args = argparse.Namespace(
            reviewers=",",
            panel=False,
            engine="codex",
            model=None,
            thinking=None,
        )
        with self.assertRaises(SystemExit):
            AUTOREVIEW.reviewer_args(args)

    def test_stream_callback_failure_stops_engine_process(self) -> None:
        args = [
            sys.executable,
            "-c",
            "import time; print('[]', flush=True); time.sleep(30)",
        ]
        with mock.patch.object(
            autoreview_runtime,
            "stop_process",
            wraps=autoreview_runtime.stop_process,
        ) as stop_process:
            with self.assertRaises(RuntimeError):
                AUTOREVIEW.run_with_heartbeat(
                    args,
                    SCRIPT_DIR,
                    label="stream-callback-fixture",
                    heartbeat_seconds=1,
                    timeout_seconds=5,
                    stream_output=True,
                    stream_display=lambda _name, _line: (_ for _ in ()).throw(RuntimeError("fixture")),
                )
        stop_process.assert_called_once()

    def test_stream_displays_handle_json_scalars(self) -> None:
        self.assertEqual(AUTOREVIEW.CodexStreamDisplay()("stdout", "[]\n"), "[]\n")
        self.assertEqual(AUTOREVIEW.ClaudeStreamDisplay()("stdout", "null\n"), "null\n")

    def test_dataset_content_redacts_credentials(self) -> None:
        token = "awt_" + "Z" * 43
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.txt"
            path.write_text(
                f"webhook_url = https://multica.example.org/api/webhooks/autopilots/{token}\n"
                "Authorization: Bearer fixture-private-bearer\n"
                "hmac_signing_secret = fixture-private-signing-secret\n"
            )
            rendered = AUTOREVIEW.load_datasets(argparse.Namespace(dataset=[str(path)]))
        self.assertIn("# Dataset:", rendered)
        self.assertNotIn(token, rendered)
        self.assertNotIn("fixture-private-bearer", rendered)
        self.assertNotIn("fixture-private-signing-secret", rendered)
        self.assertGreaterEqual(rendered.count("[REDACTED]"), 3)

    def test_sensitive_dataset_path_is_omitted_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials" / "prod.toml"
            with mock.patch.object(AUTOREVIEW, "read_text") as read_text:
                rendered = AUTOREVIEW.load_datasets(argparse.Namespace(dataset=[str(path)]))
        read_text.assert_not_called()
        self.assertIn("sensitive dataset omitted from review prompt", rendered)

    def test_symlink_and_non_regular_datasets_are_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside.txt"
            target.write_text("fixture-private-dataset-marker\n")
            symlink = root / "evidence.txt"
            symlink.symlink_to(target)
            fifo = root / "evidence.fifo"
            os.mkfifo(fifo)
            rendered = AUTOREVIEW.load_datasets(
                argparse.Namespace(dataset=[str(symlink), str(fifo)])
            )
        self.assertIn("symlink dataset omitted from review prompt", rendered)
        self.assertIn("non-regular dataset omitted from review prompt", rendered)
        self.assertNotIn("fixture-private-dataset-marker", rendered)

    def test_failure_classification_distinguishes_transport_schema_and_sandbox(self) -> None:
        cases = {
            AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR: "stream disconnected before completion",
            AUTOREVIEW.ReviewErrorCode.ENGINE_SCHEMA_ERROR: "malformed JSON for strict Codex output schema",
            AUTOREVIEW.ReviewErrorCode.ENGINE_SANDBOX_ERROR: "attempt to write a readonly database",
        }
        for expected, output in cases.items():
            with self.subTest(expected=expected):
                error = AUTOREVIEW.classify_engine_failure("codex", 1, output)
                self.assertEqual(error.code, expected)

    def test_fallback_is_limited_to_engine_unavailability(self) -> None:
        self.assertIn(AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR, AUTOREVIEW.FALLBACK_ERROR_CODES)
        self.assertIn(AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT, AUTOREVIEW.FALLBACK_ERROR_CODES)
        self.assertNotIn(AUTOREVIEW.ReviewErrorCode.ENGINE_SCHEMA_ERROR, AUTOREVIEW.FALLBACK_ERROR_CODES)
        self.assertNotIn(AUTOREVIEW.ReviewErrorCode.ENGINE_AUTH_ERROR, AUTOREVIEW.FALLBACK_ERROR_CODES)
        self.assertNotIn(AUTOREVIEW.ReviewErrorCode.ENGINE_SANDBOX_ERROR, AUTOREVIEW.FALLBACK_ERROR_CODES)

    def test_droid_review_disables_tools_even_when_generic_tools_are_enabled(self) -> None:
        args = argparse.Namespace(
            thinking=None,
            droid_bin=sys.executable,
            model=None,
            tools=True,
            timeout=1,
            stream_engine_output=False,
        )
        completed = subprocess.CompletedProcess([], 0, "{}", "")
        with tempfile.TemporaryDirectory() as repo_dir:
            with mock.patch.object(AUTOREVIEW, "run_with_heartbeat", return_value=completed) as run:
                AUTOREVIEW.run_droid(args, Path(repo_dir), "review fixture")
        command = run.call_args.args[0]
        self.assertIn("--disabled-tools", command)
        self.assertEqual(command[command.index("--disabled-tools") + 1], "*")

    def test_claude_review_never_gets_repository_read_tools(self) -> None:
        args = argparse.Namespace(
            claude_allowed_tools="Read,Grep,Glob,WebSearch,WebFetch,Bash",
            web_search=False,
        )
        self.assertEqual(AUTOREVIEW.claude_allowed_tools(args), "")
        args.web_search = True
        self.assertEqual(AUTOREVIEW.claude_allowed_tools(args), "WebSearch,WebFetch")

    def test_claude_web_review_restricts_available_tools_to_remote_only_set(self) -> None:
        args = argparse.Namespace(
            claude_bin="claude",
            claude_allowed_tools="Read,Grep,Glob,WebSearch,WebFetch,Bash",
            web_search=True,
            tools=True,
            stream_engine_output=False,
            model=None,
            thinking=None,
            timeout=1,
        )
        completed = subprocess.CompletedProcess([], 0, "{}", "")
        with tempfile.TemporaryDirectory() as repo_dir, mock.patch.object(
            AUTOREVIEW, "run_with_heartbeat", return_value=completed
        ) as run:
            AUTOREVIEW.run_claude(args, Path(repo_dir), "review fixture")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--tools") + 1], "WebSearch,WebFetch")
        self.assertEqual(command[command.index("--allowedTools") + 1], "WebSearch,WebFetch")
        self.assertNotIn("Read", command)
        self.assertNotIn("Grep", command)
        self.assertNotIn("Bash", command)

    def test_timeout_terminates_process_group(self) -> None:
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                SCRIPT_DIR,
                label="fixture",
                heartbeat_seconds=1,
                timeout_seconds=1,
            )
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)

    def test_timeout_is_not_delayed_by_long_heartbeat(self) -> None:
        started = time.monotonic()
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                SCRIPT_DIR,
                label="long-heartbeat-fixture",
                heartbeat_seconds=60,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)
        self.assertLess(elapsed, 2.5)

    def test_stream_timeout_terminates_process_group(self) -> None:
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
                SCRIPT_DIR,
                label="stream-fixture",
                heartbeat_seconds=1,
                timeout_seconds=1,
                stream_output=True,
            )
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)

    def test_stream_output_escapes_terminal_control_sequences(self) -> None:
        output = io.StringIO()
        code = "import sys; sys.stdout.write('unsafe\\x1b[2J\\x07\\rline\\n'); sys.stdout.flush()"
        with contextlib.redirect_stdout(output):
            result = AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", code],
                SCRIPT_DIR,
                label="stream-sanitize-fixture",
                timeout_seconds=5,
                stream_output=True,
            )
        self.assertEqual(result.returncode, 0)
        rendered = output.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\r", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertIn("\\x07", rendered)

    def test_engine_output_is_bounded_without_stream_display(self) -> None:
        started = time.monotonic()
        with mock.patch.object(autoreview_runtime, "MAX_ENGINE_OUTPUT_BYTES", 16_384):
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.run_with_heartbeat(
                    [sys.executable, "-c", "import os; exec(\"while True: os.write(1, b'x' * 4096)\")"],
                    SCRIPT_DIR,
                    label="output-limit-fixture",
                    heartbeat_seconds=1,
                    timeout_seconds=5,
                )
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_OUTPUT_LIMIT)
        self.assertNotIn("xxxxx", str(caught.exception))
        self.assertLess(time.monotonic() - started, 3)

    def test_stream_output_limit_counts_stdout_and_stderr_together(self) -> None:
        code = (
            "import os\n"
            "while True: os.write(1, b'a' * 2048); os.write(2, b'b' * 2048)"
        )
        started = time.monotonic()
        with mock.patch.object(autoreview_runtime, "MAX_ENGINE_OUTPUT_BYTES", 16_384):
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.run_with_heartbeat(
                    [sys.executable, "-c", code],
                    SCRIPT_DIR,
                    label="combined-output-limit-fixture",
                    heartbeat_seconds=1,
                    timeout_seconds=5,
                    stream_output=True,
                )
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_OUTPUT_LIMIT)
        self.assertLess(time.monotonic() - started, 3)

    def test_bounded_capture_preserves_split_utf8_and_suppresses_display(self) -> None:
        output = io.StringIO()
        code = (
            "import os; "
            "data = 'Привет 🌍\\n'.encode(); "
            "[os.write(1, bytes([byte])) for byte in data]"
        )
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            result = AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", code],
                SCRIPT_DIR,
                label="bounded-utf8-fixture",
                timeout_seconds=5,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "Привет 🌍\n")
        self.assertEqual(result.stderr, "")
        self.assertEqual(output.getvalue(), "")

    def test_timeout_is_enforced_after_child_closes_output_pipes(self) -> None:
        started = time.monotonic()
        code = "import os,time; os.close(1); os.close(2); time.sleep(30)"
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", code],
                SCRIPT_DIR,
                label="closed-pipes-fixture",
                heartbeat_seconds=60,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)
        self.assertLess(elapsed, 2.5)

    def test_timeout_kills_descendant_after_process_group_leader_exits(self) -> None:
        started = time.monotonic()
        code = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
        )
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", code],
                SCRIPT_DIR,
                label="exited-leader-fixture",
                heartbeat_seconds=60,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)
        self.assertLess(elapsed, 2.5)

    def test_stream_timeout_kills_descendant_after_process_group_leader_exits(self) -> None:
        started = time.monotonic()
        code = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
        )
        with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
            AUTOREVIEW.run_with_heartbeat(
                [sys.executable, "-c", code],
                SCRIPT_DIR,
                label="stream-exited-leader-fixture",
                heartbeat_seconds=60,
                timeout_seconds=1,
                stream_output=True,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)
        self.assertLess(elapsed, 2.5)

    def test_stream_timeout_kills_escaped_descendant_holding_pipes(self) -> None:
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_path = Path(temp_dir) / "escaped-child.pid"
            child_code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)"
            parent_code = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]], start_new_session=True); "
                "time.sleep(0.1)"
            )
            try:
                with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                    AUTOREVIEW.run_with_heartbeat(
                        [sys.executable, "-c", parent_code, str(pid_path), child_code],
                        SCRIPT_DIR,
                        label="stream-escaped-descendant-fixture",
                        heartbeat_seconds=60,
                        timeout_seconds=1,
                        stream_output=True,
                    )
                elapsed = time.monotonic() - started
                self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.ENGINE_TIMEOUT)
                self.assertLess(elapsed, 2.5)
                self.assertTrue(pid_path.exists(), "escaped descendant did not start")
                escaped_pid = int(pid_path.read_text())
                try:
                    stat = Path(f"/proc/{escaped_pid}/stat").read_text()
                except FileNotFoundError:
                    stat = ""
                else:
                    process_state = stat[stat.rfind(")") + 2 : stat.rfind(")") + 3]
                    self.assertEqual(process_state, "Z", "escaped descendant is still running after timeout")
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text()), signal.SIGKILL)
                    except (OSError, ValueError):
                        pass

    def test_stream_cancellation_after_pipe_eof_stops_engine(self) -> None:
        started = time.monotonic()
        code = "import os,time; os.close(1); os.close(2); time.sleep(30)"
        timer = threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            with mock.patch.object(
                autoreview_runtime,
                "stop_process",
                wraps=autoreview_runtime.stop_process,
            ) as stop_process:
                with self.assertRaises(KeyboardInterrupt):
                    AUTOREVIEW.run_with_heartbeat(
                        [sys.executable, "-c", code],
                        SCRIPT_DIR,
                        label="stream-final-wait-cancel-fixture",
                        heartbeat_seconds=60,
                        timeout_seconds=5,
                        stream_output=True,
                    )
            stop_process.assert_called_once()
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - started, 2.5)

    def test_run_state_reaches_terminal_status_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            state = AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "abc")
            state.update(status="passed", pid=None, completed_at=AUTOREVIEW.utc_now())
            payload = AUTOREVIEW.json.loads(state.path.read_text())
            self.assertEqual(payload["status"], "passed")
            self.assertFalse(state.path.is_relative_to(Path(repo_dir)))
            self.assertEqual(state.path.stat().st_mode & 0o777, 0o600)

    def test_status_marks_orphaned_running_process_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir:
            state = AUTOREVIEW.ReviewRunState(Path(state_dir), "claude", "abc")
            state.data.pop("controller_pid", None)
            state.update(status="running", pid=999_999_999)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(AUTOREVIEW.show_run_status(Path(state_dir), state.run_id), 0)
            payload = AUTOREVIEW.json.loads(state.path.read_text())
            self.assertEqual(payload["status"], "incomplete")
            self.assertEqual(payload["error_code"], AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR.value)

    def test_status_keeps_run_active_while_controller_is_alive(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir:
            state = AUTOREVIEW.ReviewRunState(Path(state_dir), "claude", "abc")
            state.update(status="running", pid=999_999_999)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(AUTOREVIEW.show_run_status(Path(state_dir), state.run_id), 3)
            payload = AUTOREVIEW.json.loads(state.path.read_text())
            self.assertEqual(payload["status"], "running")

    def test_duplicate_retrying_run_is_rejected_while_controller_is_alive(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir:
            state = AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "same-bundle")
            state.update(status="retrying", pid=None)
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "same-bundle")
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_duplicate_live_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir:
            state = AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "same-bundle")
            state.update(status="running", pid=AUTOREVIEW.os.getpid())
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "same-bundle")
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_duplicate_run_admission_is_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir:
            runtime = sys.modules["autoreview_runtime"]
            real_write = runtime.write_private_json
            first_write_entered = threading.Event()
            release_first_write = threading.Event()
            calls = 0
            call_lock = threading.Lock()

            def delayed_write(path, data):
                nonlocal calls
                with call_lock:
                    calls += 1
                    current = calls
                if current == 1:
                    first_write_entered.set()
                    self.assertTrue(release_first_write.wait(timeout=2))
                real_write(path, data)

            results: list[object] = []

            def create_state() -> None:
                try:
                    results.append(AUTOREVIEW.ReviewRunState(Path(state_dir), "codex", "same-bundle"))
                except Exception as exc:  # noqa: BLE001 - test captures the competing constructor result
                    results.append(exc)

            with mock.patch.object(runtime, "write_private_json", side_effect=delayed_write):
                first = threading.Thread(target=create_state)
                second = threading.Thread(target=create_state)
                first.start()
                self.assertTrue(first_write_entered.wait(timeout=2))
                second.start()
                time.sleep(0.05)
                self.assertTrue(second.is_alive())
                release_first_write.set()
                first.join(timeout=2)
                second.join(timeout=2)

            self.assertEqual(len(results), 2)
            self.assertEqual(sum(isinstance(item, AUTOREVIEW.ReviewRunState) for item in results), 1)
            errors = [item for item in results if isinstance(item, AUTOREVIEW.ReviewError)]
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_transport_failure_retries_then_persists_pass(self) -> None:
        transport = AUTOREVIEW.ReviewError(
            AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR,
            "fixture transport failure",
        )
        args = argparse.Namespace(engine="codex")
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            with mock.patch.object(AUTOREVIEW, "run_engine", side_effect=[transport, transport, self.valid_report()]) as engine:
                with mock.patch.object(AUTOREVIEW.time, "sleep"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        report = AUTOREVIEW.run_reviewer(args, Path(repo_dir), "prompt", set(), [], Path(state_dir))
            self.assertEqual(engine.call_count, 3)
            self.assertEqual(report["overall_correctness"], "patch is correct")
            states = list(Path(state_dir).glob("*.json"))
            self.assertEqual(len(states), 1)
            self.assertEqual(AUTOREVIEW.json.loads(states[0].read_text())["status"], "passed")

    def test_partial_panel_cannot_report_clean_pass(self) -> None:
        args = argparse.Namespace(allow_partial_panel=True, require_finding=[])
        reviewers = [
            argparse.Namespace(engine="codex", model=None, thinking=None),
            argparse.Namespace(engine="claude", model=None, thinking=None),
        ]
        failure = RuntimeError("fixture reviewer failure \x1b[31m")

        def fake_reviewer(reviewer, *_args, **_kwargs):
            if reviewer.engine == "claude":
                raise failure
            return AUTOREVIEW.json.loads(self.valid_report())

        output = io.StringIO()
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            with mock.patch.object(AUTOREVIEW, "run_reviewer", side_effect=fake_reviewer):
                with contextlib.redirect_stdout(output):
                    report = AUTOREVIEW.run_panel(
                        args,
                        reviewers,
                        Path(repo_dir),
                        "prompt",
                        set(),
                        Path(state_dir),
                    )
        self.assertEqual(report["overall_correctness"], "patch is incorrect")
        self.assertIn("Panel incomplete", report["overall_explanation"])
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn(r"\x1b[31m", output.getvalue())

    def test_non_json_result_gets_one_repair_pass(self) -> None:
        args = argparse.Namespace(engine="claude")
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            with mock.patch.object(AUTOREVIEW, "run_engine", side_effect=["plain text", self.valid_report()]) as engine:
                with contextlib.redirect_stdout(io.StringIO()):
                    report = AUTOREVIEW.run_reviewer(args, Path(repo_dir), "prompt", set(), [], Path(state_dir))
            self.assertEqual(engine.call_count, 2)
            self.assertIn("Convert the candidate review", engine.call_args_list[1].args[2])
            self.assertEqual(report["findings"], [])

    def test_schema_invalid_json_gets_one_repair_pass(self) -> None:
        args = argparse.Namespace(engine="claude")
        invalid_report = AUTOREVIEW.json.dumps({"findings": []})
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            with mock.patch.object(AUTOREVIEW, "run_engine", side_effect=[invalid_report, self.valid_report()]) as engine:
                with contextlib.redirect_stdout(io.StringIO()):
                    report = AUTOREVIEW.run_reviewer(args, Path(repo_dir), "prompt", set(), [], Path(state_dir))
            self.assertEqual(engine.call_count, 2)
            self.assertIn("Convert the candidate review", engine.call_args_list[1].args[2])
            self.assertEqual(report["overall_correctness"], "patch is correct")

    def test_repair_pass_retries_transport_failure(self) -> None:
        args = argparse.Namespace(engine="claude")
        transport = AUTOREVIEW.ReviewError(
            AUTOREVIEW.ReviewErrorCode.ENGINE_TRANSPORT_ERROR,
            "fixture transport failure",
        )
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            with mock.patch.object(AUTOREVIEW, "run_engine", side_effect=["plain text", transport, self.valid_report()]) as engine:
                with mock.patch.object(AUTOREVIEW.time, "sleep"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        report = AUTOREVIEW.run_reviewer(args, Path(repo_dir), "prompt", set(), [], Path(state_dir))
            self.assertEqual(engine.call_count, 3)
            self.assertEqual(report["findings"], [])

    def test_preflight_allows_codex_without_tools(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            args = argparse.Namespace(
                state_dir=state_dir,
                codex_bin=sys.executable,
                claude_bin=sys.executable,
                droid_bin=sys.executable,
                copilot_bin=sys.executable,
            )
            reviewer = argparse.Namespace(engine="codex", tools=False, codex_bin=sys.executable)
            self.assertEqual(
                AUTOREVIEW.preflight_review(args, [reviewer], Path(repo_dir), ""),
                Path(state_dir),
            )

    def test_preflight_still_rejects_copilot_without_tools(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            args = argparse.Namespace(
                state_dir=state_dir,
                codex_bin=sys.executable,
                claude_bin=sys.executable,
                droid_bin=sys.executable,
                copilot_bin=sys.executable,
            )
            reviewer = argparse.Namespace(engine="copilot", tools=False, copilot_bin=sys.executable)
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.preflight_review(args, [reviewer], Path(repo_dir), "")
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.UNSUPPORTED_OPTION)

    def test_preflight_rejects_invalid_canonical_schema(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            args = argparse.Namespace(state_dir=state_dir)
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.preflight_review(args, [], Path(repo_dir), "", {"type": "array", "required": []})
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_preflight_allows_missing_primary_when_configured_fallback_exists(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            missing = "autoreview-primary-that-does-not-exist"
            args = argparse.Namespace(
                state_dir=state_dir,
                codex_bin=missing,
                claude_bin=sys.executable,
            )
            primary = argparse.Namespace(engine="codex", tools=True, codex_bin=missing)
            fallback = argparse.Namespace(engine="claude", tools=True, claude_bin=sys.executable)
            result = AUTOREVIEW.preflight_review(
                args,
                [primary, fallback],
                Path(repo_dir),
                "",
                allow_missing_engines={"codex"},
            )
            self.assertEqual(result, Path(state_dir).resolve())

    def test_preflight_rejects_missing_fallback_executable(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            missing_primary = "autoreview-primary-that-does-not-exist"
            missing_fallback = "autoreview-fallback-that-does-not-exist"
            args = argparse.Namespace(
                state_dir=state_dir,
                codex_bin=missing_primary,
                claude_bin=missing_fallback,
            )
            primary = argparse.Namespace(engine="codex", tools=True, codex_bin=missing_primary)
            fallback = argparse.Namespace(engine="claude", tools=True, claude_bin=missing_fallback)
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.preflight_review(
                    args,
                    [primary, fallback],
                    Path(repo_dir),
                    "",
                    allow_missing_engines={"codex"},
                )
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_preflight_rejects_missing_primary_without_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as state_dir:
            missing = "autoreview-primary-that-does-not-exist"
            args = argparse.Namespace(state_dir=state_dir, codex_bin=missing)
            reviewer = argparse.Namespace(engine="codex", tools=True, codex_bin=missing)
            with self.assertRaises(AUTOREVIEW.ReviewError) as caught:
                AUTOREVIEW.preflight_review(args, [reviewer], Path(repo_dir), "")
            self.assertEqual(caught.exception.code, AUTOREVIEW.ReviewErrorCode.PREFLIGHT_ERROR)

    def test_main_module_imports_runtime_executable_resolver(self) -> None:
        self.assertIs(AUTOREVIEW.executable_for_engine, autoreview_runtime.executable_for_engine)

    def test_report_rejects_extra_code_location_keys_and_boolean_line(self) -> None:
        base_finding = {
            "title": "Example",
            "body": "Example body",
            "priority": "P2",
            "confidence": 0.9,
            "category": "bug",
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            for location in (
                {"file_path": "example.py", "line": 1, "extra": "bad"},
                {"file_path": "example.py", "line": True},
            ):
                report = {
                    "findings": [{**base_finding, "code_location": location}],
                    "overall_correctness": "patch is incorrect",
                    "overall_explanation": "Example finding.",
                    "overall_confidence": 0.9,
                }
                with self.subTest(location=location), self.assertRaises(SystemExit):
                    AUTOREVIEW.validate_report(report, repo, {"example.py"}, [])

    def test_report_preserves_whitespace_in_changed_file_path(self) -> None:
        path = " spaced.py "
        report = {
            "findings": [
                {
                    "title": "Whitespace path",
                    "body": "The finding belongs to the exact changed path.",
                    "priority": "P2",
                    "confidence": 0.9,
                    "category": "bug",
                    "code_location": {"file_path": path, "line": 1},
                }
            ],
            "overall_correctness": "patch is incorrect",
            "overall_explanation": "Exact path fixture.",
            "overall_confidence": 0.9,
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            AUTOREVIEW.validate_report(report, Path(repo_dir), {path}, [])
        self.assertEqual(report["findings"][0]["code_location"]["file_path"], path)

    def test_report_normalizes_clean_verdict_when_findings_remain(self) -> None:
        report = {
            "findings": [
                {
                    "title": "Example",
                    "body": "Example body",
                    "priority": "P2",
                    "confidence": 0.9,
                    "category": "bug",
                    "code_location": {"file_path": "example.py", "line": 1},
                }
            ],
            "overall_correctness": "patch is correct",
            "overall_explanation": "Contradictory fixture verdict.",
            "overall_confidence": 0.9,
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            AUTOREVIEW.validate_report(report, Path(repo_dir), {"example.py"}, [])
        self.assertEqual(report["overall_correctness"], "patch is incorrect")
        self.assertIn("Normalized verdict", report["overall_explanation"])

    def test_print_report_escapes_terminal_control_sequences(self) -> None:
        report = {
            "findings": [
                {
                    "title": "bad\x1b]52;c;clipboard\x07",
                    "body": "body\x1b[2J",
                    "priority": "P2",
                    "confidence": 0.9,
                    "category": "bug",
                    "code_location": {"file_path": "example.py", "line": 1},
                }
            ],
            "overall_correctness": "patch is incorrect",
            "overall_explanation": "explanation\rspoof",
            "overall_confidence": 0.9,
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            AUTOREVIEW.print_report(report)
        rendered = output.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\r", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertIn("\\x07", rendered)
        self.assertIn("\\x0d", rendered)

    def test_copilot_review_does_not_enable_unrestricted_web_fetch(self) -> None:
        args = argparse.Namespace(
            thinking=None,
            tools=True,
            copilot_bin="copilot",
            stream_engine_output=False,
            model=None,
            web_search=True,
            timeout=1,
        )
        completed = subprocess.CompletedProcess([], 0, self.valid_report(), "")
        with tempfile.TemporaryDirectory() as repo_dir, mock.patch.object(
            AUTOREVIEW, "run_with_heartbeat", return_value=completed
        ) as runner:
            AUTOREVIEW.run_copilot(args, Path(repo_dir), "review prompt")
        command = runner.call_args.args[0]
        self.assertNotIn("--allow-all-urls", command)
        self.assertFalse(any("web_fetch" in value for value in command))

    def test_compact_diff_omits_lockfile_body(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
            (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
            subprocess.run(["git", "add", "pnpm-lock.yaml"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo, check=True)
            (repo / "pnpm-lock.yaml").write_text("secret-marker-that-must-not-enter-the-bundle\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("generated, lock, or binary patch omitted", bundle)
            self.assertNotIn("secret-marker-that-must-not-enter-the-bundle", bundle)

    def test_local_bundle_omits_untracked_lockfile_body(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            (repo / "pnpm-lock.yaml").write_text("secret-marker-that-must-not-enter-the-bundle\n")
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("generated, lock, or binary file omitted", bundle)
            self.assertNotIn("secret-marker-that-must-not-enter-the-bundle", bundle)

    def test_local_bundle_does_not_follow_untracked_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as external_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            external = Path(external_dir) / "secret.txt"
            external.write_text("external-secret-marker\n")
            (repo / "external-link").symlink_to(external)
            bundle = AUTOREVIEW.local_bundle(repo)
            self.assertIn("symlink target", bundle)
            self.assertNotIn("external-secret-marker", bundle)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo is unavailable on this platform")
    def test_local_bundle_omits_untracked_fifo_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            fifo = repo / "review.pipe"
            os.mkfifo(fifo)
            original_git_paths = AUTOREVIEW.git_paths

            def git_paths_with_fifo(current_repo, *args):
                if args == ("ls-files", "--others", "--exclude-standard"):
                    return ["review.pipe"]
                return original_git_paths(current_repo, *args)

            with mock.patch.object(AUTOREVIEW, "git_paths", side_effect=git_paths_with_fifo), mock.patch.object(
                AUTOREVIEW,
                "read_text",
                side_effect=AssertionError("non-regular files must not be opened"),
            ) as reader:
                bundle = AUTOREVIEW.local_bundle(repo)
            reader.assert_not_called()
            self.assertIn("non-regular untracked file omitted", bundle)

    def test_web_search_is_opt_in(self) -> None:
        with mock.patch.object(sys, "argv", ["autoreview"]):
            self.assertFalse(AUTOREVIEW.parse_args().web_search)
        with mock.patch.object(sys, "argv", ["autoreview", "--web-search"]):
            self.assertTrue(AUTOREVIEW.parse_args().web_search)


if __name__ == "__main__":
    unittest.main()
