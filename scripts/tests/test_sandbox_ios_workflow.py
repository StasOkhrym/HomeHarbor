"""Owned iPhone preparation on real files; external OS/Go boundaries only."""

import hashlib
import importlib
import json
import plistlib
import shutil
import ssl
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from test_sandbox_ios_material import RootBoundary  # noqa: E402


class HostBoundary(RootBoundary):
    def __init__(self):
        super().__init__()
        self.effects = []
        self.address = "192.168.50.7"
        self.networks = [{"Id": "legacy", "IPAM": {"Config": [{"Subnet": "172.30.60.0/24"}]}}]
        self.routes = "Destination Gateway Flags Netif\ndefault 192.168.50.1 UGScg en0\n192.168.50/24 link#4 UCS en0\n"

    def __call__(self, args, **kwargs):
        self.effects.append(args)
        if args == ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]:
            return '"unix:///var/run/docker.sock"'
        if args == ["/sbin/ifconfig", "-a"]:
            return f"en0: flags=8863\n\tinet {self.address} netmask 0xffffff00 broadcast 192.168.50.255\n"
        if args == ["netstat", "-rn", "-f", "inet"]:
            return self.routes
        if args == ["docker", "network", "ls", "--quiet"]:
            return "\n".join(item["Id"] for item in self.networks)
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps(self.networks)

        return super().__call__(args, **kwargs)


def workflow_fixture(root, boundary):
    try:
        module = importlib.import_module("sandbox_ios_workflow")
    except ModuleNotFoundError:
        raise AssertionError("isolated iPhone preparation workflow is missing") from None

    root = Path(root)
    shutil.copytree(ROOT / "config", root / "config")
    shutil.copytree(ROOT / "deploy", root / "deploy")
    (root / ".sandbox").mkdir()
    (root / ".sandbox/legacy").write_bytes(b"preserve-original")
    return module.IOSWorkflow(root, run=boundary)


class IOSWorkflowTests(unittest.TestCase):
    def flow(self, root, boundary):
        return workflow_fixture(root, boundary)

    def bytes(self, state):
        return {p.relative_to(state): p.read_bytes() for p in state.rglob("*") if p.is_file()}

    def test_prepare_preserves_identity_and_legacy_state_and_exports_only_public_ca_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            flow = self.flow(temporary, boundary)
            flow.prepare("192.168.50.7")

            self.assertEqual(boundary.calls, 1)

            state = flow.sandbox
            first = self.bytes(state)
            flow.prepare("192.168.50.7")

            self.assertEqual(self.bytes(state), first)
            self.assertEqual(boundary.calls, 1)
            self.assertEqual((flow.root / ".sandbox/legacy").read_bytes(), b"preserve-original")
            self.assertIn(
                "SANDBOX_BACKEND_SUBNET=10.242.60.0/24", (state / "network.env").read_text()
            )

            metadata = json.loads((state / "lan.json").read_bytes())

            self.assertEqual(metadata["endpoints"]["address"], "192.168.50.7")

            public = state / "public"

            self.assertEqual(
                {p.name for p in public.iterdir()},
                {
                    "homeharbor-ios.mobileconfig",
                    "control-ca.pem",
                    "site-ca.pem",
                    "fingerprints.txt",
                },
            )

            profile = plistlib.loads((public / "homeharbor-ios.mobileconfig").read_bytes())

            self.assertEqual(profile["PayloadType"], "Configuration")
            self.assertFalse(profile["PayloadRemovalDisallowed"])
            self.assertNotIn("PayloadScope", profile)

            payloads = profile["PayloadContent"]

            self.assertEqual(len(payloads), 2)
            self.assertEqual({p["PayloadType"] for p in payloads}, {"com.apple.security.root"})

            fingerprints = (public / "fingerprints.txt").read_text()
            for payload, name in zip(payloads, ["control-ca.pem", "site-ca.pem"], strict=True):
                der = ssl.PEM_cert_to_DER_cert((public / name).read_text())

                self.assertEqual(payload["PayloadContent"], der)
                self.assertIn(hashlib.sha256(der).hexdigest().upper(), fingerprints)
                self.assertNotIn(b"PRIVATE KEY", plistlib.dumps(payload))

            for directory in [state, state / "secrets", public]:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

            self.assertEqual(stat.S_IMODE((state / "root-passphrase").stat().st_mode), 0o600)
            self.assertFalse(
                any("compose" in args or args[0] == "security" for args in boundary.effects)
            )

    def test_prepare_refuses_changed_endpoint_and_partial_readiness_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            flow = self.flow(temporary, boundary)
            flow.prepare("192.168.50.7")
            before = self.bytes(flow.sandbox)
            boundary.address = "192.168.50.8"

            with self.assertRaises(ValueError):
                flow.prepare("192.168.50.8")

            self.assertEqual(self.bytes(flow.sandbox), before)

            (flow.sandbox / "lan.json").unlink()
            before = self.bytes(flow.sandbox)

            with self.assertRaises(ValueError):
                flow.prepare("192.168.50.8")

            self.assertEqual(self.bytes(flow.sandbox), before)
            self.assertEqual(boundary.calls, 1)

    def test_prepare_refuses_unassigned_ip_and_pool_conflicts_before_private_creation(self):
        for address, routes in [
            ("192.168.50.8", ""),
            ("192.168.50.7", "10/8 link#4 UCS utun9\n172.16/12 link#4 UCS utun9\n"),
        ]:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as temporary:
                boundary = HostBoundary()
                if routes:
                    boundary.routes = routes

                flow = self.flow(temporary, boundary)

                with self.assertRaises(ValueError):
                    flow.prepare(address)

                self.assertEqual(boundary.calls, 0)
                self.assertFalse((flow.sandbox / "secrets").exists())
                self.assertFalse((flow.sandbox / "lan.json").exists())

    def test_prepare_checks_all_destinations_before_generating_or_publishing(self):
        for kind in ["symlink", "directory"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                boundary = HostBoundary()
                flow = self.flow(temporary, boundary)
                flow.create_owner()
                external = flow.root / "outside"
                external.write_bytes(b"preserve")
                if kind == "symlink":
                    (flow.sandbox / "public").symlink_to(flow.root, target_is_directory=True)
                else:
                    (flow.sandbox / "compose.yaml").mkdir()

                with self.assertRaises(ValueError):
                    flow.prepare("192.168.50.7")

                self.assertEqual(external.read_bytes(), b"preserve")
                self.assertEqual(boundary.calls, 0)
                self.assertFalse((flow.sandbox / "control.toml").exists())

    def test_root_failure_never_publishes_partial_ready_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            boundary.fail = True
            flow = self.flow(temporary, boundary)

            with self.assertRaises(ValueError):
                flow.prepare("192.168.50.7")

            self.assertEqual(
                {p.name for p in flow.sandbox.iterdir()}, {"workflow.lock", "workflow-owner.json"}
            )
            self.assertEqual((flow.root / ".sandbox/legacy").read_bytes(), b"preserve-original")

    def test_up_starts_only_infrastructure_and_down_preserves_own_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            flow = self.flow(temporary, boundary)

            with (
                patch("sandbox_ios_workflow.available_ports"),
                patch("sandbox_ios_workflow.probe_kernel"),
                patch.dict(
                    "os.environ", {"COMPOSE_FILE": "/foreign.yaml", "SANDBOX_HTTPS_PORT": "8443"}
                ),
            ):
                flow.up("192.168.50.7")
                before = self.bytes(flow.sandbox)
                flow.down()

            self.assertEqual(self.bytes(flow.sandbox), before)

            mutations = [a for a in boundary.effects if "compose" in a]
            startup = next(a for a in mutations if "up" in a)

            self.assertEqual(
                startup[startup.index("--wait-timeout") + 2 :],
                ["db", "redis", "migrate", "control", "relay", "proxy", "dns", "site"],
            )

            for args in mutations:
                self.assertEqual(args[args.index("--project-name") + 1], "homeharbor-ios-sandbox")
                self.assertEqual(args[args.index("--file") + 1], str(flow.sandbox / "compose.yaml"))
                self.assertNotIn("--volumes", args)
                self.assertNotIn("/foreign.yaml", args)

            self.assertFalse(
                any("network-close" in a or "security" == a[0] for a in boundary.effects)
            )

    def test_busy_ports_or_edited_compose_refuse_start_before_provisioning(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            flow = self.flow(temporary, boundary)

            with patch("sandbox_ios_workflow.available_ports", side_effect=ValueError("occupied")):
                with self.assertRaises(ValueError):
                    flow.up("192.168.50.7")

            self.assertFalse(any("compose" in a or "build" in a for a in boundary.effects))

            compose = flow.sandbox / "compose.yaml"
            compose.write_text("services: {foreign: {image: foreign}}")
            before = self.bytes(flow.sandbox)

            with self.assertRaises(ValueError):
                flow.down()

            self.assertEqual(self.bytes(flow.sandbox), before)
            self.assertFalse(any("compose" in a for a in boundary.effects))

    def test_status_is_read_only_and_refuses_remote_docker_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = HostBoundary()
            flow = self.flow(temporary, boundary)
            flow.prepare("192.168.50.7")
            before = self.bytes(flow.sandbox)
            status = flow.status()

            self.assertEqual(status["control"], "https://192.168.50.7:19443")
            self.assertEqual(status["containers"], 0)
            self.assertEqual(self.bytes(flow.sandbox), before)

            with patch.dict("os.environ", {"DOCKER_HOST": "ssh://other-machine"}):
                with self.assertRaises(ValueError):
                    flow.down()

            self.assertFalse(any("down" in a for a in boundary.effects))

    def test_down_refuses_missing_network_file_and_nested_symlink_before_compose(self):
        for problem in ["missing-network", "nested-symlink"]:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                boundary = HostBoundary()
                boundary.networks = []
                flow = self.flow(temporary, boundary)
                flow.prepare("192.168.50.7")
                if problem == "missing-network":
                    (flow.sandbox / "network.env").unlink()
                else:
                    (flow.sandbox / "secrets/redirect").symlink_to(flow.root / ".sandbox/legacy")

                with self.assertRaises(ValueError):
                    flow.down()

                self.assertFalse(any("compose" in a for a in boundary.effects))
