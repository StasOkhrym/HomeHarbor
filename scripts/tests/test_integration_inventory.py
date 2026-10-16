"""The real contract-result validator must require the new telemetry adapter."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("integration_contracts", SCRIPTS / "integration.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
sys.path.pop(0)


class IntegrationInventoryTests(unittest.TestCase):
    def test_missing_telemetry_adapter_cannot_pass_contract_gate(self):
        packages = sorted(integration.ADAPTERS - {"control/telemetry/storage"})
        records = [
            {
                "Action": "pass",
                "Package": "test/internal/" + package,
                "Test": "TestPostgresContract",
            }
            for package in packages
        ]
        named = [
            ("control/workflows", "TestRedisRecoveryChallengeConsumedOnceAcrossReplicas"),
            ("control/devices/storage", "TestPostgresRecoveredCredentialInvalidatesOldCredential"),
            ("control/coordination", "TestPostgresCoordinationCrossReplicaRevoke"),
            ("platform/redissecurity", "TestRedisChallengeConsumedExactlyOnce"),
            ("control/identity/redis", "TestRedisSessionSharedTTLAndRevoke"),
            ("../migrations", "TestConcurrentUpSerializesWithAdvisoryLock"),
        ]
        records.extend(
            {"Action": "pass", "Package": "test/internal/" + package, "Test": name}
            for package, name in named
        )
        with self.assertRaisesRegex(ValueError, "control/telemetry/storage"):
            integration.validate_events(json.dumps(record) for record in records)
