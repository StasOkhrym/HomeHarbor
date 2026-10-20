"""Pure manual iPhone flow outputs; no Docker daemon or installed trust required."""

import re
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from sandbox_ios_config import LANEndpoints, configuration_documents, render_compose  # noqa: E402
from sandbox_preflight import PROFILES  # noqa: E402


class IOSSandboxConfigurationTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        shutil.copytree(ROOT / "config", root / "config")
        shutil.copytree(ROOT / "deploy", root / "deploy")
        (root / ".sandbox").mkdir()
        (root / ".sandbox/private-state").write_bytes(b"old-mac-state")
        return root

    def test_configurations_bind_phone_admin_and_container_audiences_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture(temporary)
            documents = configuration_documents(root, PROFILES[2], LANEndpoints("192.168.50.7"))
            parsed = {path.name: tomllib.loads(data.decode()) for path, data in documents.items()}
            control = parsed["control.toml"]
            self.assertEqual(control["server"]["public_url"], "https://192.168.50.7:19443")
            self.assertEqual(control["auth"]["rp_id"], "ios-admin.localhost")
            self.assertEqual(control["auth"]["rp_origin"], "https://ios-admin.localhost:19445")
            self.assertFalse(control["auth"]["allow_remote_setup"])
            self.assertEqual(control["relay"]["public_url"], "wss://192.168.50.7:19444/relay/udp")
            self.assertEqual(control["networking"]["network_id"], "ios-sandbox-network")
            self.assertEqual(control["security"]["trusted_proxy_cidrs"], ["10.252.60.10/32"])
            relay = parsed["relay.toml"]
            self.assertEqual(relay["server"]["udp_listen_address"], ":52120")
            self.assertEqual(relay["server"]["udp_port_min"], 52120)
            self.assertEqual(relay["server"]["udp_port_max"], 52135)
            self.assertEqual(
                relay["server"]["udp_advertise_hosts"],
                {"192.168.50.7": "192.168.50.7", "relay.ios-sandbox": "relay"},
            )
            admin = parsed["admin.toml"]
            self.assertEqual(admin["endpoint"], "https://ios-admin.localhost:19445")
            self.assertEqual(admin["base_url"], "https://192.168.50.7:19443/invite")
            self.assertEqual(admin["network_id"], "ios-sandbox-network")
            self.assertEqual(admin["profile_id"], "ios-sandbox")
            self.assertEqual(admin["root_key_file"], str(root / ".sandbox-ios/root-key.age"))
            proxy = parsed["proxy.toml"]
            self.assertEqual(proxy["entryPoints"]["websecure"]["address"], ":8443")
            self.assertEqual(proxy["entryPoints"]["mobilecontrol"]["address"], ":8444")
            self.assertEqual(proxy["entryPoints"]["mobilerelay"]["address"], ":8445")
            routers = parsed["proxy-routes.toml"]["http"]["routers"]
            self.assertEqual(routers["admin"]["rule"], "Host(`ios-admin.localhost`)")
            self.assertEqual(routers["mobilecontrol"]["entryPoints"], ["mobilecontrol"])
            self.assertEqual(routers["mobilecontrol"]["service"], "control")
            self.assertEqual(routers["mobilerelay"]["entryPoints"], ["mobilerelay"])
            self.assertEqual(routers["mobilerelay"]["service"], "relay")
            self.assertEqual((root / ".sandbox/private-state").read_bytes(), b"old-mac-state")
            self.assertFalse((root / ".sandbox-ios").exists(), "Rendering must not write state")
            for path in documents:
                self.assertTrue(path.is_relative_to(root / ".sandbox-ios"))

    def test_gateway_uses_signed_dynamic_peers_without_static_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture(temporary)
            documents = configuration_documents(root, PROFILES[2], LANEndpoints("192.168.50.7"))
            gateway = tomllib.loads(documents[root / ".sandbox-ios/gateway.toml"].decode())

            self.assertTrue(gateway["relay"]["signed_peers"])
            self.assertEqual(gateway["node"]["control_url"], "https://control.ios-sandbox:8443")
            self.assertEqual(
                gateway["relay"]["websocket_url"], "wss://relay.ios-sandbox:8443/relay/udp"
            )
            self.assertEqual(gateway["relay"]["wireguard_address"], "127.0.0.1:51820")
            self.assertEqual(gateway["wireguard"]["listen_port"], 51820)

            for key in ["session_id", "destination_device_id", "ticket", "ticket_file"]:
                self.assertEqual(gateway["relay"].get(key, ""), "")

            for key in ["peer_public_key", "overlay_address", "allowed_prefixes", "routes"]:
                self.assertEqual(gateway["wireguard"].get(key, ""), "")

            self.assertEqual(gateway["coordination"]["network_id"], "ios-sandbox-network")
            self.assertEqual(
                gateway["coordination"]["url"], "wss://control.ios-sandbox:8443/api/v1/coordination"
            )
            self.assertFalse(gateway["dns"]["enable_forwarding"])

    def test_composed_topology_publishes_only_selected_ingress_and_isolated_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture(temporary)
            compose = yaml.safe_load(render_compose(root, LANEndpoints("192.168.50.7")))

            self.assertEqual(compose["name"], "homeharbor-ios-sandbox")

            services = compose["services"]

            self.assertEqual(
                services["proxy"]["ports"],
                ["192.168.50.7:19443:8444", "192.168.50.7:19444:8445", "127.0.0.1:19445:8443"],
            )
            self.assertEqual(
                services["relay"]["ports"], ["192.168.50.7:52120-52135:52120-52135/udp"]
            )

            for name in ["db", "redis", "gateway", "dns", "site", "control"]:
                self.assertFalse(services[name].get("ports"))

            self.assertTrue(compose["networks"]["private"]["internal"])
            self.assertTrue(compose["networks"]["backend"]["internal"])
            self.assertEqual(
                services["proxy"]["networks"]["underlay"]["aliases"],
                ["control.ios-sandbox", "relay.ios-sandbox"],
            )

            for name, configuration in compose["configs"].items():
                self.assertTrue(
                    Path(configuration["file"]).is_relative_to(root / ".sandbox-ios"), name
                )

            for name, secret in compose["secrets"].items():
                self.assertTrue(
                    Path(secret["file"]).is_relative_to(root / ".sandbox-ios/secrets"), name
                )

            self.assertEqual((root / ".sandbox/private-state").read_bytes(), b"old-mac-state")

    def test_endpoints_reject_public_wildcard_loopback_and_ambiguous_ports(self):
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "1.1.1.1",
            "169.254.1.2",
            "::1",
            "192.168.1.1/path",
            "192.168.001.1",
        ]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                LANEndpoints(address)

        for options in [
            {"control_port": 443},
            {"admin_port": 19443},
            {"udp_min": 52135, "udp_max": 52120},
            {"udp_max": 65536},
            {"udp_min": 52120, "udp_max": 52140},
            {"control_port": True},
        ]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                LANEndpoints("192.168.50.7", **options)

    def test_lan_endpoint_cannot_be_inside_selected_docker_or_overlay_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture(temporary)
            for address in ["10.252.60.7", "10.250.40.7", "10.251.50.7", "10.253.0.7"]:
                with self.subTest(address=address), self.assertRaises(ValueError):
                    configuration_documents(root, PROFILES[2], LANEndpoints(address))

    def test_mobile_ingress_excludes_browser_admin_and_companion_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture(temporary)
            documents = configuration_documents(root, PROFILES[2], LANEndpoints("192.168.50.7"))
            routers = tomllib.loads(documents[root / ".sandbox-ios/proxy-routes.toml"].decode())[
                "http"
            ]["routers"]
            rule = routers["mobilecontrol"]["rule"]
            expression = re.fullmatch(r"Host\(`192\.168\.50\.7`\) && PathRegexp\(`([^`]+)`\)", rule)

            self.assertIsNotNone(expression, "LAN ingress must not expose the full admin backend")

            pattern = expression[1]
            for path in [
                "/readyz",
                "/api/v1/invites/proof",
                "/api/v1/invites/invite_123",
                "/api/v1/invites/invite_123/challenge",
                "/api/v1/invites/invite_123/claim",
                "/api/v1/devices/credentials/challenge",
                "/api/v1/devices/credentials/recovery",
                "/api/v1/devices/credentials/rotate",
                "/api/v1/devices/self/metadata",
                "/api/v1/coordination",
                "/api/v1/coordination/snapshots",
                "/api/v1/relay-sessions",
            ]:
                with self.subTest(path=path):
                    self.assertIsNotNone(re.fullmatch(pattern, path))

            for path in [
                "/admin/login",
                "/api/v1/auth/owner/password",
                "/api/v1/admin/devices",
                "/api/v1/enrollment-tokens",
                "/api/v1/enroll",
                "/api/v1/devices",
                "/api/v1/devices/device-id",
                "/api/v1/invites/invite_123/approval",
                "/api/v1/coordination/snapshot/companion",
                "/api/v1/coordination/snapshot/companion-challenge",
                "/metrics",
                "/api/v1/invites/../admin",
                "/api/v1/invites/" + "a" * 129,
            ]:
                with self.subTest(path=path):
                    self.assertIsNone(re.fullmatch(pattern, path))

            self.assertEqual(
                routers["mobilerelay"]["rule"], "Host(`192.168.50.7`) && Path(`/relay/udp`)"
            )
