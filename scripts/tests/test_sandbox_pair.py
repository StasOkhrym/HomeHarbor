"""Bounded native client/gateway pair documents without private state or host effects."""

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from sandbox_preflight import PROFILES  # noqa: E402


def identity(device, seed):
    return {
        "device_id": device,
        "identity_public_key": base64.urlsafe_b64encode(bytes([seed]) * 32).decode().rstrip("="),
        "wireguard_public_key": base64.b64encode(bytes([seed + 1]) * 32).decode(),
    }


class SandboxPairTests(unittest.TestCase):
    def documents(self, directory, **changes):
        from sandbox_pair import pair_documents

        arguments = {
            "sandbox": Path(directory) / ".sandbox",
            "selected": PROFILES[1].environment(),
            "gateway": identity("_gateway", 1),
            "client": identity("client-1", 4),
            "root": base64.urlsafe_b64encode(bytes([8]) * 32).decode().rstrip("="),
            "uid": 501,
            "https_port": 8553,
            "wireguard_port": 51830,
            "bridge_port": 51831,
        }

        return pair_documents(**(arguments | changes))

    def test_pair_documents_pin_identity_scope_and_endpoint_audience(self):
        with tempfile.TemporaryDirectory() as temp:
            sandbox = Path(temp) / ".sandbox"
            docs = self.documents(temp)

            self.assertEqual(
                set(docs),
                {
                    sandbox / "native-client.toml",
                    sandbox / "gateway.toml",
                    sandbox / "network-helper.json",
                },
            )
            self.assertTrue(all(mode == 0o600 for _, mode in docs.values()))

            native = tomllib.loads(docs[sandbox / "native-client.toml"][0].decode())
            gateway = tomllib.loads(docs[sandbox / "gateway.toml"][0].decode())
            policy = json.loads(docs[sandbox / "network-helper.json"][0])

            self.assertEqual(native["node"]["control_url"], "https://control.localhost:8553")
            self.assertEqual(native["node"]["state_path"], str(sandbox / "client.json"))
            self.assertEqual(native["node"]["ca_file"], str(sandbox / "secrets/relay_tls_ca"))
            self.assertEqual(
                native["relay"]["websocket_url"], "wss://relay.localhost:8553/relay/udp"
            )
            self.assertEqual(native["relay"]["destination_device_id"], "_gateway")
            self.assertEqual(native["relay"]["listen_address"], "127.0.0.1:51831")
            self.assertEqual(native["relay"]["wireguard_address"], "127.0.0.1:51830")
            self.assertEqual(
                native["wireguard"]["peer_public_key"],
                identity("_gateway", 1)["wireguard_public_key"],
            )
            self.assertEqual(native["wireguard"]["listen_port"], 51830)

            for field in ("interface", "overlay_address", "allowed_prefixes", "routes"):
                self.assertEqual(native["wireguard"][field], "")

            self.assertEqual(
                native["native"],
                {
                    "enabled": True,
                    "overlay": "10.243.0.0/24",
                    "private": "10.241.50.0/24",
                    "suffix": "sandbox.home.arpa",
                },
            )
            self.assertEqual(native["direct"]["candidates"], "")
            self.assertEqual(native["dns"], {"link": "", "enable_forwarding": False})
            self.assertEqual(native["coordination"]["network_id"], "sandbox-network")
            self.assertEqual(
                native["coordination"]["root_public_key_file"], str(sandbox / "root-public.key")
            )
            self.assertEqual(gateway["node"]["control_url"], "https://control.sandbox:8443")
            self.assertEqual(gateway["node"]["state_path"], "/var/lib/homeharbor/gateway.json")
            self.assertEqual(
                gateway["relay"]["websocket_url"], "wss://relay.sandbox:8443/relay/udp"
            )
            self.assertEqual(gateway["relay"]["destination_device_id"], "client-1")
            self.assertEqual(gateway["relay"]["session_id"], native["relay"]["session_id"])
            self.assertTrue(native["relay"]["session_id"])
            self.assertEqual(
                gateway["wireguard"]["peer_public_key"],
                identity("client-1", 4)["wireguard_public_key"],
            )
            self.assertEqual(gateway["wireguard"]["overlay_address"], "10.243.0.2/32")
            self.assertEqual(gateway["wireguard"]["allowed_prefixes"], "")
            self.assertEqual(gateway["wireguard"]["routes"], "")
            self.assertFalse(
                gateway["dns"]["enable_forwarding"],
                "paired gateway must preserve Docker's forwarding ownership",
            )
            self.assertEqual(
                policy,
                {
                    "version": 1,
                    "owner_uid": 501,
                    "root_public_key": base64.urlsafe_b64encode(bytes([8]) * 32)
                    .decode()
                    .rstrip("="),
                    "network_id": "sandbox-network",
                    "device_id": "client-1",
                    "local_wireguard_public_key": identity("client-1", 4)["wireguard_public_key"],
                    "relay_peer_public_key": identity("_gateway", 1)["wireguard_public_key"],
                    "overlay": "10.243.0.0/24",
                    "private": "10.241.50.0/24",
                    "suffix": "sandbox.home.arpa",
                    "bridge_endpoint": "127.0.0.1:51831",
                    "wireguard_listen_port": 51830,
                },
            )

            for doc in (native, gateway):
                self.assertNotIn("token", doc["node"])
                self.assertNotIn("enrollment_token_file", doc["node"])
                self.assertNotIn("ticket_file", doc["relay"])

    def test_pair_documents_refuse_reused_identity_keys_and_unbounded_inputs(self):
        bad_inputs = [
            {"uid": 0},
            {"uid": -1},
            {"uid": True},
            {"root": "not-a-root"},
            {"root": identity("_gateway", 1)["identity_public_key"]},
            {"client": identity("_gateway", 4)},
            {
                "client": {
                    **identity("client-1", 4),
                    "wireguard_public_key": identity("_gateway", 1)["wireguard_public_key"],
                }
            },
            {
                "client": {
                    **identity("client-1", 4),
                    "identity_public_key": identity("_gateway", 1)["identity_public_key"],
                }
            },
            {"client": {**identity("client-1", 4), "device_credential": "private-sentinel"}},
            {"selected": {**PROFILES[1].environment(), "SANDBOX_PRIVATE_SUBNET": "0.0.0.0/0"}},
            {"https_port": 0},
            {"wireguard_port": 65536},
            {"bridge_port": 51830},
        ]

        with tempfile.TemporaryDirectory() as temp:
            for changes in bad_inputs:
                with self.subTest(changes=list(changes)):
                    with self.assertRaises(ValueError) as caught:
                        self.documents(temp, **changes)

                    self.assertNotIn("private-sentinel", str(caught.exception))

    def test_initializer_retains_prepared_pair_and_rejects_silent_reprovision(self):
        import sandbox_init
        from tooling import atomic_write

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sandbox = root / ".sandbox"
            sandbox.mkdir()
            shutil.copytree(ROOT / "config", root / "config")
            for name, content in (
                ("gateway-public.json", json.dumps(identity("_gateway", 1))),
                ("client-public.json", json.dumps(identity("client-1", 4))),
                ("root-public.key", base64.urlsafe_b64encode(bytes([8]) * 32).decode().rstrip("=")),
            ):
                (sandbox / name).write_text(content)

            with (
                patch.object(sandbox_init, "ROOT", root),
                patch.object(sandbox_init, "SANDBOX", sandbox),
                patch("os.getuid", return_value=501),
            ):
                docs = sandbox_init.configuration(8553, PROFILES[1].environment())

                self.assertIn(sandbox / "native-client.toml", docs)
                self.assertIn(sandbox / "network-helper.json", docs)

                gateway = tomllib.loads(docs[sandbox / "gateway.toml"][0].decode())

                self.assertEqual(gateway["relay"]["destination_device_id"], "client-1")

                for path, (content, mode) in docs.items():
                    atomic_write(path, content, mode)

                repeated = sandbox_init.configuration(8553, PROFILES[1].environment())
                for name in ("native-client.toml", "gateway.toml", "network-helper.json"):
                    self.assertEqual(repeated[sandbox / name], docs[sandbox / name])

                (sandbox / "client-public.json").write_text(json.dumps(identity("new-client", 4)))

                with self.assertRaises(ValueError):
                    sandbox_init.configuration(8553, PROFILES[1].environment())

                for name in ("native-client.toml", "gateway.toml", "network-helper.json"):
                    self.assertEqual((sandbox / name).read_bytes(), docs[sandbox / name][0])

    def test_prepare_cli_preserves_ports_and_refuses_owner_change_without_writing(self):
        from sandbox_preflight import save_profile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            for name in (
                "sandbox_prepare.py",
                "sandbox_pair.py",
                "sandbox_init.py",
                "sandbox_identity.py",
                "sandbox_preflight.py",
                "dev_init.py",
                "tls_material.py",
                "tooling.py",
            ):
                shutil.copy(ROOT / "scripts" / name, scripts / name)
            shutil.copytree(ROOT / "config", root / "config")
            sandbox = root / ".sandbox"
            sandbox.mkdir()
            save_profile(PROFILES[1], sandbox / "network.env")
            for name, content in (
                ("gateway-public.json", json.dumps(identity("_gateway", 1))),
                ("client-public.json", json.dumps(identity("client-1", 4))),
                ("root-public.key", base64.urlsafe_b64encode(bytes([8]) * 32).decode().rstrip("=")),
                ("control.toml", "[server]\npublic_url = 'https://control.localhost:8553'\n"),
                ("client.json", "private-client-sentinel"),
                ("root-key.age", "private-root-sentinel"),
            ):
                (sandbox / name).write_text(content)
            # The production command requires a non-root operator. Pin only
            # that OS dependency in this subprocess so root CI exercises it.
            runner = "import os,runpy,sys; os.getuid=lambda:501; sys.argv=sys.argv[1:]; sys.path.insert(0,os.path.dirname(sys.argv[0])); runpy.run_path(sys.argv[0],run_name='__main__')"
            command = [sys.executable, "-c", runner, str(scripts / "sandbox_prepare.py")]
            result = subprocess.run(
                [*command, "--wireguard-port", "58830", "--bridge-port", "58831"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            paths = [
                sandbox / name
                for name in ("gateway.toml", "native-client.toml", "network-helper.json")
            ]
            before = {path: path.read_bytes() for path in paths}
            policy = json.loads(before[sandbox / "network-helper.json"])
            self.assertEqual(policy["wireguard_listen_port"], 58830)
            self.assertEqual(policy["bridge_endpoint"], "127.0.0.1:58831")
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in paths))
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))
            (sandbox / "client-public.json").write_text(json.dumps(identity("other-client", 4)))
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))
            for sentinel, name in (
                ("private-client-sentinel", "client.json"),
                ("private-root-sentinel", "root-key.age"),
            ):
                self.assertEqual((sandbox / name).read_text(), sentinel)
                self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
