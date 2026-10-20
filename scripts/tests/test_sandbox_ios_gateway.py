"""Gateway binds real public enrollment metadata; tokens stay at stdin boundary."""

import base64
import json
import tempfile
import tomllib
import unittest

from test_sandbox_ios_workflow import HostBoundary, workflow_fixture


class GatewayBoundary(HostBoundary):
    def __init__(self):
        super().__init__()
        self.identity = {
            "device_id": "real-enrolled-gateway",
            "identity_public_key": base64.urlsafe_b64encode(bytes([8]) * 32).decode().rstrip("="),
            "wireguard_public_key": base64.b64encode(bytes([9]) * 32).decode(),
        }
        self.enroll_inputs = []
        self.enroll_output = None
        self.container = None

    def __call__(self, args, **kwargs):
        if args[:3] == ["docker", "ps", "--all"]:
            return self.container["Id"] if self.container else ""
        if args[:2] == ["docker", "inspect"]:
            return json.dumps([self.container] if self.container else [])
        if "compose" in args and "enroll" in args:
            self.effects.append(args)
            self.enroll_inputs.append(kwargs.get("input"))
            self.last_enroll_env = kwargs.get("env")

            return (
                self.enroll_output if self.enroll_output is not None else json.dumps(self.identity)
            )

        return super().__call__(args, **kwargs)


class IOSGatewayTests(unittest.TestCase):
    def test_gateway_enrollment_binds_only_real_identity_and_bounded_ios_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            token = "private-token-sentinel"
            flow.gateway("enroll", token=token)

            self.assertEqual(boundary.enroll_inputs, [token + "\n"])
            self.assertFalse(any(token in arg for args in boundary.effects for arg in args))
            self.assertNotIn(token, str(boundary.last_enroll_env))
            self.assertEqual(
                json.loads((flow.sandbox / "gateway-public.json").read_bytes()), boundary.identity
            )

            manifest = tomllib.loads((flow.sandbox / "initial-snapshot.toml").read_text())

            self.assertEqual(manifest["network_id"], "ios-sandbox-network")
            self.assertEqual(manifest["profiles"][0]["id"], "ios-sandbox")
            self.assertEqual(manifest["devices"][0]["id"], "real-enrolled-gateway")
            self.assertEqual(
                manifest["devices"][0]["identity_public_key"],
                boundary.identity["identity_public_key"],
            )
            self.assertEqual(
                manifest["devices"][0]["wireguard_public_key"],
                boundary.identity["wireguard_public_key"],
            )
            self.assertEqual(manifest["devices"][0]["overlay_address"], "10.243.0.2/32")
            self.assertEqual(manifest["routes"][0]["prefix"], "10.241.50.0/24")
            self.assertEqual(manifest["routes"][0]["resolver"], "10.241.50.53")
            self.assertEqual(manifest["routes"][0]["gateway_id"], "real-enrolled-gateway")
            self.assertEqual(
                {item["source_device_id"] for item in manifest["acl"]}, {"real-enrolled-gateway"}
            )
            self.assertEqual({item["port_to"] for item in manifest["acl"]}, {53, 8080})
            self.assertFalse(
                any(
                    token.encode() in p.read_bytes() for p in flow.sandbox.rglob("*") if p.is_file()
                )
            )

            before = (flow.sandbox / "initial-snapshot.toml").read_bytes()
            flow.gateway("enroll", token="unused-retry-token")

            self.assertEqual((flow.sandbox / "initial-snapshot.toml").read_bytes(), before)

            flow.gateway("run")
            startup = next(a for a in boundary.effects if "up" in a)

            self.assertEqual(
                startup[startup.index("up") :], ["up", "--detach", "--no-deps", "gateway"]
            )

    def test_invalid_or_changed_public_export_cannot_replace_bound_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            boundary.enroll_output = json.dumps(
                {**boundary.identity, "credential": "private-sentinel"}
            )

            with self.assertRaises(ValueError):
                flow.gateway("enroll", token="token")

            self.assertFalse((flow.sandbox / "gateway-public.json").exists())
            self.assertFalse((flow.sandbox / "initial-snapshot.toml").exists())

            boundary.enroll_output = None
            flow.gateway("enroll", token="token")
            before = {
                p.name: p.read_bytes()
                for p in [
                    flow.sandbox / "gateway-public.json",
                    flow.sandbox / "initial-snapshot.toml",
                ]
            }
            boundary.identity["device_id"] = "different-gateway"

            with self.assertRaises(ValueError):
                flow.gateway("enroll", token="token")

            for name, data in before.items():
                self.assertEqual((flow.sandbox / name).read_bytes(), data)

    def test_unbound_or_edited_manifest_refuses_run_and_enrollment_before_token_consumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")

            with self.assertRaises(ValueError):
                flow.gateway("run")

            flow.gateway("enroll", token="token")
            (flow.sandbox / "initial-snapshot.toml").write_text('network_id = "foreign"\n')
            boundary.enroll_inputs.clear()
            for action in ["enroll", "run"]:
                with self.assertRaises(ValueError):
                    flow.gateway(action, token="token")

            self.assertEqual(boundary.enroll_inputs, [])
            self.assertFalse(any("up" in a for a in boundary.effects))

    def test_public_trust_info_uses_domain_separated_ios_network_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            info = flow.trust_info()

            self.assertEqual(info["network_id"], "ios-sandbox-network")
            self.assertEqual(info["root_public_key"], "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
            self.assertEqual(
                info["fingerprint"],
                "898c98d239383429287de6a9dcf7f7f541e60aea146ff4935b59a470a4674bbd",
            )
            self.assertEqual(set(info), {"network_id", "root_public_key", "fingerprint"})

    def test_invalid_token_is_rejected_before_any_gateway_enrollment_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            for token in ["", "has space", "x" * 4097, "line\nbreak"]:
                with self.assertRaises(ValueError):
                    flow.gateway("enroll", token=token)

            self.assertEqual(boundary.enroll_inputs, [])

    def test_running_gateway_refuses_enrollment_before_token_consumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            boundary.container = {
                "Id": "owned-gateway",
                "State": {"Running": True},
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": "homeharbor-ios-sandbox",
                        "com.docker.compose.service": "gateway",
                        "io.homeharbor.sandbox.workspace": str(flow.root),
                        "io.homeharbor.sandbox.owner": str(flow.uid),
                    }
                },
            }

            with self.assertRaises(ValueError):
                flow.gateway("enroll", token="token")

            self.assertEqual(boundary.enroll_inputs, [])
            self.assertFalse((flow.sandbox / "gateway-public.json").exists())

    def test_partial_gateway_binding_refuses_without_consuming_token_or_starting(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = GatewayBoundary()
            flow = workflow_fixture(temporary, boundary)
            flow.prepare("192.168.50.7")
            flow.gateway("enroll", token="token")
            (flow.sandbox / "initial-snapshot.toml").unlink()
            boundary.enroll_inputs.clear()
            for action in ["enroll", "run"]:
                with self.assertRaises(ValueError):
                    flow.gateway(action, token="token")

            self.assertEqual(boundary.enroll_inputs, [])
            self.assertFalse(any("up" in a for a in boundary.effects))
