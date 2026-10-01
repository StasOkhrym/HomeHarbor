"""Malformed owned config must fail a read-only gate without changing bytes."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class LanguageChecksTests(unittest.TestCase):
    def test_invalid_config_fails_without_rewriting(self):
        for suffix, content in (("toml", "broken = ["), ("json", '{"broken":}')):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"bad.{suffix}"
                path.write_text(content)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/lint_files.py"), str(path)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid", result.stderr.lower())
                self.assertEqual(path.read_text(), content)

    def test_other_owned_languages_reject_invalid_syntax(self):
        cases = [
            (
                [
                    str(ROOT / "node_modules/.bin/eslint"),
                    "--stdin",
                    "--stdin-filename",
                    "scripts/tests/negative.mjs",
                ],
                "export const broken = ;",
            ),
            (
                [
                    str(ROOT / "node_modules/.bin/stylelint"),
                    "--stdin",
                    "--stdin-filename",
                    "internal/control/httpapi/static/negative.css",
                ],
                "body { color: red;",
            ),
            (
                ["ruff", "check", "--stdin-filename", "scripts/tests/negative.py", "-"],
                "def broken(:",
            ),
            (["hadolint", "-"], "NOT_A_DOCKER_INSTRUCTION anything"),
        ]
        for command, source in cases:
            with self.subTest(tool=Path(command[0]).name):
                result = subprocess.run(
                    command, input=source, cwd=ROOT, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0, "malformed source passed owned-code lint")
