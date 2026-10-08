"""Conservative gates: path optimization must never silently drop coverage."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "ci_changes", Path(__file__).resolve().parents[1] / "ci_changes.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ChangeTests(unittest.TestCase):
    def test_local_compose_changes_select_required_gates(self):
        for path in ("deploy/compose.yaml", "deploy/traefik/routes.toml"):
            with self.subTest(path=path):
                gates = MODULE.classify(["README.md", path], True, False)

                self.assertTrue(gates["compose"])
                self.assertTrue(all(gates.values()))
                self.assertNotIn("deployment", gates)

    def test_classification(self):
        cases = (
            (["docs/architecture.md", "README.md"], set()),
            (["docs/architecture.md", "internal/control/httpapi/static/admin.js"], {"fast"}),
            (
                ["internal/control/devices/storage/repository.go"],
                {"fast", "integration", "network", "fuzz", "vulnerability"},
            ),
            (
                ["internal/platform/redissecurity/store.go"],
                {"fast", "integration", "network", "fuzz", "vulnerability"},
            ),
            (
                ["internal/control/workflows/activation.go"],
                {"fast", "integration", "network", "fuzz", "vulnerability"},
            ),
            (
                ["internal/control/transactions/activation.go"],
                {"fast", "integration", "network", "fuzz", "vulnerability"},
            ),
            (["internal/node/reconciler.go"], {"fast", "network", "fuzz", "vulnerability"}),
            (["internal/snapshot/snapshot.go"], {"fast", "network", "fuzz", "vulnerability"}),
            (["deploy/compose.yaml"], set(MODULE.GATES)),
        )
        for paths, expected in cases:
            with self.subTest(paths=paths):
                result = MODULE.classify(paths, True, False)
                self.assertEqual({key for key, value in result.items() if value}, expected)

    def test_actual_workflow_path_runs_integration(self):
        path = "internal/control/workflows/activation.go"

        self.assertTrue((Path(__file__).resolve().parents[2] / path).is_file())
        self.assertTrue(MODULE.classify([path], True, False)["integration"])

    def test_protected_storage_keeps_security_and_network_gates(self):
        for path in (
            "internal/control/identity/redis/sessions.go",
            "internal/control/snapshots/storage/repository.go",
            "internal/control/httpapi/authorization.go",
        ):
            with self.subTest(path=path):
                gates = MODULE.classify([path], True, False)

                self.assertTrue(all(gates[gate] for gate in ("network", "fuzz", "vulnerability")))

    def test_uncertain_or_shared_changes_run_every_gate(self):
        for paths, base, full in (
            ([], False, False),
            (["README.md"], True, True),
            (["go.mod"], True, False),
            (["internal/unknown/new.go"], True, False),
            (["internal/control/newmodule/new.go"], True, False),
            (["Makefile"], True, False),
        ):
            self.assertTrue(all(MODULE.classify(paths, base, full).values()))

    def test_rename_and_delete_include_old_paths(self):
        paths = MODULE.parse_changes(
            b"R100\0internal/node/state.go\0docs/state.md\0D\0internal/snapshot/old.go\0"
        )

        self.assertEqual(
            paths, ["internal/node/state.go", "docs/state.md", "internal/snapshot/old.go"]
        )

        result = MODULE.classify(paths, True, False)

        self.assertTrue(result["network"])
        self.assertTrue(result["fuzz"])

    def test_malformed_diff_is_rejected(self):
        for data in (b"R100\0old\0", b"unexpected\0file\0"):
            with self.assertRaises(ValueError):
                MODULE.parse_changes(data)
