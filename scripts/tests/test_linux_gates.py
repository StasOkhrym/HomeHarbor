"""Check actual Go test discovery and the Lima mount contract."""

import json
import os
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class LinuxGateTests(unittest.TestCase):
    def discovery(self, *args):
        result = subprocess.run(
            ["go", "list", "-json", *args, "./internal/acceptance"],
            cwd=ROOT,
            env={**os.environ, "GOOS": "linux"},
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

        return json.loads(result.stdout).get("TestGoFiles", [])

    def test_portable_linux_excludes_privileged_acceptance(self):
        self.assertNotIn("network_linux_test.go", self.discovery())
        self.assertNotIn("resolved_linux_test.go", self.discovery())

    def test_explicit_linux_acceptance_discovers_required_scenarios(self):
        discovered = self.discovery("-tags=network_acceptance")

        self.assertIn("network_linux_test.go", discovered)
        self.assertIn("resolved_linux_test.go", discovered)

    def test_lima_template_does_not_mount_home(self):
        config = yaml.safe_load((ROOT / "deploy/lima/ubuntu.yaml").read_text())
        for mount in config.get("mounts", []):
            self.assertNotIn(mount["location"], ("~", str(Path.home())))
            self.assertFalse(mount.get("writable", False))
