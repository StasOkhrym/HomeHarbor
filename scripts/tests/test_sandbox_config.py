"""Static contracts for the opt-in sandbox; these never start Docker or touch macOS."""

import ipaddress
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/compose.sandbox.yaml"


def sandbox_config():
    if not COMPOSE.exists():
        return {}

    defaults = re.sub(r"\$\{[A-Z0-9_]+:-([^}]+)\}", r"\1", COMPOSE.read_text())

    return yaml.safe_load(defaults) or {}


def networks(service):
    return set(service.get("networks", {}))


class SandboxConfigTests(unittest.TestCase):
    def test_sandbox_networks_isolated(self):
        cfg = sandbox_config()

        self.assertEqual(cfg.get("name"), "homeharbor-sandbox")

        topology = cfg.get("networks", {})
        for name, subnet in (
            ("backend", "172.30.60.0/24"),
            ("underlay", "172.28.40.0/24"),
            ("private", "172.29.50.0/24"),
        ):
            self.assertEqual(
                topology.get(name, {}).get("ipam", {}).get("config", [{}])[0].get("subnet"),
                subnet,
            )

        self.assertTrue(topology.get("backend", {}).get("internal"))
        self.assertTrue(topology.get("private", {}).get("internal"))

        services = cfg.get("services", {})
        for name in ("db", "redis", "migrate", "control"):
            self.assertEqual(networks(services.get(name, {})), {"backend"})

        self.assertEqual(networks(services.get("gateway", {})), {"underlay", "private"})
        self.assertEqual(
            services.get("relay", {}).get("networks", {}).get("underlay", {}).get("ipv4_address"),
            "172.28.40.20",
        )
        self.assertEqual(networks(services.get("dns", {})), {"private"})
        self.assertEqual(networks(services.get("site", {})), {"private"})

    def test_private_services_have_no_published_ports(self):
        services = sandbox_config().get("services", {})
        for name in ("db", "redis", "gateway", "dns", "site"):
            self.assertIn(name, services)

            service = services.get(name, {})

            self.assertFalse(service.get("ports"), f"{name} publishes a private port")
            self.assertNotEqual(service.get("network_mode"), "host")
            self.assertFalse(service.get("privileged"))
            self.assertFalse(any("docker.sock" in str(m) for m in service.get("volumes", [])))

    def test_sandbox_state_is_not_dev_state(self):
        cfg = sandbox_config()
        generated_configs = (
            cfg.get("configs", {}).get(name, {})
            for name in ("control_config", "relay_config", "gateway_config")
        )
        for item in (*generated_configs, *cfg.get("secrets", {}).values()):
            self.assertIn("../.sandbox/", item.get("file", ""))
            self.assertNotIn(".local", item.get("file", ""))

        self.assertIn(".sandbox/", (ROOT / ".gitignore").read_text())

    def test_underlay_cannot_reach_private_fixture(self):
        services = sandbox_config().get("services", {})
        for name in ("dns", "site"):
            self.assertTrue(networks(services.get(name, {})).isdisjoint({"underlay", "backend"}))

            command = " ".join(services.get(name, {}).get("command", []))

            self.assertIn("10.200.0.0/24", command)
            self.assertIn("172.29.50.2", command)

        gateway = services.get("gateway", {})

        self.assertIn("NET_ADMIN", gateway.get("cap_add", []))
        self.assertFalse(gateway.get("privileged"))

        fence = ROOT / "deploy/sandbox/gateway-fence.sh"

        self.assertTrue(fence.exists(), "gateway lacks its independent underlay/private fence")
        self.assertIn("nft", fence.read_text())
        self.assertIn("drop", fence.read_text())

    def test_relay_allocated_port_maps_one_to_one(self):
        relay = sandbox_config().get("services", {}).get("relay", {})

        self.assertEqual(relay.get("ports"), ["127.0.0.1:52000-52015:52000-52015/udp"])
        self.assertNotIn("privileged", relay)

    def test_container_owns_gateway_forwarding(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_init import SANDBOX, configuration

        gateway = sandbox_config()["services"]["gateway"]

        self.assertIn("net.ipv4.ip_forward=1", gateway["sysctls"])
        self.assertFalse(gateway.get("privileged"))

        generated = configuration(8443)
        settings = tomllib.loads(generated[SANDBOX / "gateway.toml"][0].decode())

        self.assertFalse(
            settings["dns"]["enable_forwarding"],
            "gateway must not write Docker-owned read-only sysctls",
        )

    def test_endpoint_audience_matches_gateway_and_host(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_init import (
            SANDBOX,
            check_destination,
            configuration,
            endpoint_audience,
            legacy_manifest_without_acl,
            render_manifest,
        )
        from sandbox_preflight import PROFILES

        host = endpoint_audience("host", 8443)
        gateway = endpoint_audience("gateway", 8443)

        self.assertEqual(host.control, "https://control.localhost:8443")
        self.assertEqual(host.relay, "wss://relay.localhost:8443/relay/udp")
        self.assertEqual(gateway.control, "https://control.sandbox:8443")
        self.assertEqual(gateway.relay, "wss://relay.sandbox:8443/relay/udp")
        self.assertNotEqual(host.control, gateway.control)

        docs = configuration(8443)

        self.assertTrue(all(path.is_relative_to(SANDBOX) for path in docs))
        self.assertIn(b"udp_port_min = 52000", docs[SANDBOX / "relay.toml"][0])
        self.assertIn(b'"relay.sandbox" = "relay"', docs[SANDBOX / "relay.toml"][0])
        self.assertIn(b'"relay.localhost" = "relay.localhost"', docs[SANDBOX / "relay.toml"][0])
        self.assertIn(b"control.sandbox", docs[SANDBOX / "gateway.toml"][0])
        self.assertIn(b'profile_id = "sandbox"', docs[SANDBOX / "admin.toml"][0])
        self.assertIn(b'ca_file = "', docs[SANDBOX / "admin.toml"][0])

        alternate = PROFILES[1].environment()
        selected_docs = configuration(8443, alternate)

        self.assertIn(b'overlay_pool = "10.243.0.0/24"', selected_docs[SANDBOX / "admin.toml"][0])
        self.assertIn(
            b'overlay_address = "10.243.0.2/32"', selected_docs[SANDBOX / "gateway.toml"][0]
        )
        self.assertIn(b'allowed_prefixes = ""', selected_docs[SANDBOX / "gateway.toml"][0])
        self.assertIn(b"10.242.60.10/32", selected_docs[SANDBOX / "control.toml"][0])
        self.assertNotIn(b"10.200.0.2/32", selected_docs[SANDBOX / "gateway.toml"][0])

        manifest = render_manifest(alternate)

        self.assertIn(b'prefix = "10.241.50.0/24"', manifest)
        self.assertIn(b'resolver = "10.241.50.53"', manifest)
        self.assertNotIn(b"172.29.50.", manifest)

        signed_input = tomllib.loads(manifest.decode())

        self.assertEqual(
            set(signed_input["profiles"][0]["acl_rule_ids"]),
            {"sandbox-dns-udp", "sandbox-dns-tcp", "sandbox-site-web"},
        )
        self.assertEqual(
            {
                (rule["destination"], rule["protocol"], rule["port_from"], rule["port_to"])
                for rule in signed_input["acl"]
            },
            {
                ("10.241.50.53/32", "udp", 53, 53),
                ("10.241.50.53/32", "tcp", 53, 53),
                ("10.241.50.80/32", "tcp", 8080, 8080),
            },
        )
        self.assertIn(b"acl_rule_ids = []", legacy_manifest_without_acl(alternate))
        self.assertNotIn(b"[[acl]]", legacy_manifest_without_acl(alternate))

        with self.assertRaises(ValueError):
            check_destination(ROOT / ".local/sandbox/root-key.age")


class SandboxPoolTests(unittest.TestCase):
    def test_preflight_rejects_overlapping_networks(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_preflight import reject_overlaps, select_profile

        existing = [ipaddress.ip_network("172.29.50.0/24")]

        with self.assertRaises(ValueError):
            reject_overlaps(existing)

        profile = select_profile([ipaddress.ip_network("172.28.0.0/16"), *existing])

        self.assertEqual(str(profile.underlay), "10.240.40.0/24")
        self.assertEqual(str(profile.private), "10.241.50.0/24")
        self.assertEqual(profile.environment()["SANDBOX_RELAY_UNDERLAY_IP"], "10.240.40.20")

    def test_preflight_probes_wireguard_nft_and_forwarding(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_preflight import probe_kernel

        with patch("sandbox_preflight.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            probe_kernel("fixture-probe")

        command = run.call_args.args[0]

        self.assertEqual(command[:5], ["docker", "run", "--rm", "--network", "none"])
        self.assertIn("NET_ADMIN", command)
        self.assertIn("net.ipv4.ip_forward=1", command)
        self.assertIn("ip link add wg-hhprobe type wireguard", command[-1])
        self.assertIn("nft add table", command[-1])

    def test_selected_profile_round_trips_and_rejects_modified_addresses(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_preflight import PROFILES, load_profile, save_profile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.env"
            save_profile(PROFILES[1], path)

            self.assertEqual(load_profile(path), PROFILES[1].environment())

            contents = path.read_text().replace("10.242.60.10", "10.242.60.11")
            path.write_text(contents)

            with self.assertRaises(ValueError):
                load_profile(path)

            path.unlink()
            path.symlink_to(Path(directory) / "elsewhere")

            with self.assertRaises(ValueError):
                load_profile(path)

    def test_preflight_refuses_to_reassign_live_project_networks(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_preflight import preflight

        with (
            patch("sandbox_preflight.require_commands"),
            patch("sandbox_preflight.project_containers", return_value=True),
            patch("sandbox_preflight.host_routes") as routes,
            patch("sandbox_preflight.save_profile") as save,
        ):
            with self.assertRaisesRegex(ValueError, "existing sandbox project"):
                preflight()

        routes.assert_not_called()
        save.assert_not_called()

    def test_pool_preflight_checks_overlap_without_provisioning_or_probe(self):
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from sandbox_preflight import PROFILES, preflight

        with (
            patch("sandbox_preflight.require_commands"),
            patch("sandbox_preflight.project_containers", return_value=False),
            patch("sandbox_preflight.host_routes", return_value=[]),
            patch("sandbox_preflight.docker_networks", return_value=[]),
            patch("sandbox_preflight.NETWORK_FILE") as network_file,
            patch("sandbox_preflight.probe_kernel") as probe,
            patch("sandbox_preflight.save_profile") as save,
        ):
            network_file.exists.return_value = False

            self.assertEqual(preflight(check_only=True), PROFILES[0])

            with patch(
                "sandbox_preflight.docker_networks",
                return_value=[profile.underlay for profile in PROFILES],
            ):
                with self.assertRaisesRegex(ValueError, "no collision-free"):
                    preflight(check_only=True)

        probe.assert_not_called()
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
