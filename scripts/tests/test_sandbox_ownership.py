"""Shared manual sandbox ownership; real paths/locks, controlled Docker boundary."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from sandbox_ownership import SandboxOwnership  # noqa: E402


class InventoryBoundary:
    def __init__(self):
        self.items = {"container": [], "network": [], "volume": []}
        self.selections = []

    def __call__(self, args, **kwargs):
        if "inspect" in args:
            index = args.index("inspect")
            kind = "container" if index == 1 else args[1]
            ids = args[index + 1 :]

            return json.dumps([item for item in self.items[kind] if item["Id"] in ids])

        kind = "container" if args[1] == "ps" else args[1]
        if kind not in self.items or "--filter" not in args:
            raise AssertionError("Ownership may only read Docker inventory")

        selection = args[args.index("--filter") + 1]
        self.selections.append(selection)
        selected = []
        for item in self.items[kind]:
            labels = (
                item.get("Config", {}).get("Labels", {})
                if kind == "container"
                else item.get("Labels", {})
            )
            if selection.startswith("name="):
                matches = selection[5:] in item["Name"]
            else:
                key, _, value = selection.removeprefix("label=").partition("=")
                matches = labels.get(key) == value

            if matches:
                selected.append(item["Id"])

        return "\n".join(selected)


class SandboxOwnershipTests(unittest.TestCase):
    def owner(self, root, docker, *, project="homeharbor-ios-sandbox", directory=".sandbox-ios"):
        return SandboxOwnership(Path(root), project=project, directory=directory, run=docker)

    def test_separate_projects_keep_distinct_state_and_independent_real_locks(self):
        with tempfile.TemporaryDirectory() as temporary:
            docker = InventoryBoundary()
            ios = self.owner(temporary, docker)
            mac = self.owner(temporary, docker, project="homeharbor-sandbox", directory=".sandbox")
            mac.create_owner()
            sentinel = mac.sandbox / "private-state"
            sentinel.write_bytes(b"original-mac-state")
            ios.create_owner()

            self.assertEqual(
                json.loads(ios.owner_file.read_text())["project"], "homeharbor-ios-sandbox"
            )
            self.assertEqual(
                json.loads(mac.owner_file.read_text())["project"], "homeharbor-sandbox"
            )
            self.assertEqual(sentinel.read_bytes(), b"original-mac-state")

            same_ios = self.owner(temporary, docker)

            with ios.lock(), mac.lock():
                with self.assertRaisesRegex(ValueError, "active"):
                    with same_ios.lock():
                        self.fail("The same state must have one owner")

            self.assertIn(
                "label=com.docker.compose.project=homeharbor-ios-sandbox", docker.selections
            )

            docker.items["volume"] = [
                {
                    "Id": "ios-volume",
                    "Name": "homeharbor-ios-sandbox_db",
                    "Labels": {
                        "com.docker.compose.project": "homeharbor-ios-sandbox",
                        "io.homeharbor.sandbox.workspace": str(Path(temporary).resolve()),
                        "io.homeharbor.sandbox.owner": str(os.getuid()),
                    },
                }
            ]

            self.assertEqual([item["Id"] for item in ios.inventory()["volume"]], ["ios-volume"])
            self.assertEqual(mac.inventory()["volume"], [])

    def test_foreign_named_or_mislabelled_resource_blocks_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            docker = InventoryBoundary()
            owner = self.owner(temporary, docker)
            for labels in [
                {},
                {"com.docker.compose.project": "homeharbor-ios-sandbox"},
                {
                    "com.docker.compose.project": "homeharbor-ios-sandbox",
                    "io.homeharbor.sandbox.workspace": "/another/workspace",
                    "io.homeharbor.sandbox.owner": str(os.getuid()),
                },
            ]:
                with self.subTest(labels=labels):
                    docker.items["volume"] = [
                        {"Id": "volume", "Name": "homeharbor-ios-sandbox_db", "Labels": labels}
                    ]

                    with self.assertRaisesRegex(ValueError, "foreign|ownership"):
                        owner.create_owner()

                    self.assertFalse(owner.owner_file.exists())

    def test_symlinked_state_cannot_reuse_or_modify_mac_private_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mac = root / ".sandbox"
            mac.mkdir()
            private = mac / "private-state"
            private.write_bytes(b"kept")
            (root / ".sandbox-ios").symlink_to(mac, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                self.owner(root, InventoryBoundary()).create_owner()

            self.assertEqual(private.read_bytes(), b"kept")
            self.assertFalse((mac / "workflow-owner.json").exists())

    def test_unsafe_scope_is_rejected_before_state_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            for directory in ["../.sandbox", "/tmp/foreign-sandbox", ".", "state/nested"]:
                with self.subTest(directory=directory), self.assertRaises(ValueError):
                    self.owner(temporary, InventoryBoundary(), directory=directory)

            for project in ["--all", "project;command", "", "MixedCase"]:
                with self.subTest(project=project), self.assertRaises(ValueError):
                    self.owner(temporary, InventoryBoundary(), project=project)

            self.assertEqual(list(Path(temporary).iterdir()), [])
