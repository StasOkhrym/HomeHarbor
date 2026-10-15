"""Public bootstrap metadata and initial-manifest contracts; no host effects."""

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

from sandbox_init import render_manifest  # noqa: E402
from sandbox_preflight import PROFILES  # noqa: E402


def public_gateway():
    return {
        "device_id": "_enrolled-gateway_1",
        "identity_public_key": base64.urlsafe_b64encode(bytes([1]) * 32).decode().rstrip("="),
        "wireguard_public_key": base64.b64encode(bytes([2]) * 32).decode(),
    }


class SandboxIdentityTests(unittest.TestCase):
    def test_enrolled_gateway_replaces_every_manifest_reference(self):
        public = public_gateway()
        content = render_manifest(PROFILES[1].environment(), public)
        manifest = tomllib.loads(content.decode())

        self.assertEqual(manifest["network_id"], "sandbox-network")
        self.assertEqual(
            manifest["devices"],
            [
                {
                    "id": "_enrolled-gateway_1",
                    "role": "gateway",
                    "identity_public_key": public["identity_public_key"],
                    "wireguard_public_key": public["wireguard_public_key"],
                    "overlay_address": "10.243.0.2/32",
                }
            ],
        )
        self.assertEqual(manifest["gateways"][0]["device_id"], "_enrolled-gateway_1")
        self.assertEqual(manifest["routes"][0]["gateway_id"], "_enrolled-gateway_1")
        self.assertEqual(manifest["profiles"][0]["device_ids"], ["_enrolled-gateway_1"])
        self.assertEqual(
            {rule["source_device_id"] for rule in manifest["acl"]}, {"_enrolled-gateway_1"}
        )
        self.assertEqual(
            {
                (rule["destination"], rule["protocol"], rule["port_from"], rule["port_to"])
                for rule in manifest["acl"]
            },
            {
                ("10.241.50.53/32", "udp", 53, 53),
                ("10.241.50.53/32", "tcp", 53, 53),
                ("10.241.50.80/32", "tcp", 8080, 8080),
            },
        )
        self.assertNotIn(b"REPLACE_WITH", content)
        self.assertNotIn(b'"gateway-1"', content)

    def test_manifest_binding_rejects_private_extra_fields_and_malformed_keys(self):
        for field, value in (
            ("device_credential", "private-value"),
            ("identity_public_key", "invalid"),
            ("wireguard_public_key", base64.b64encode(bytes(32)).decode()),
            ("device_id", "bad\n[acl]"),
            ("device_id", "a" * 129),
        ):
            with self.subTest(field=field):
                public = {**public_gateway(), field: value}

                with self.assertRaises(ValueError) as caught:
                    render_manifest(PROFILES[1].environment(), public)

                self.assertNotIn("private-value", str(caught.exception))

    def test_public_metadata_loader_rejects_ambiguous_or_unsafe_files(self):
        from sandbox_identity import load_public_identity

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "public.json"
            public = public_gateway()
            path.write_text(json.dumps(public))

            self.assertEqual(load_public_identity(path), public)

            invalid = [
                '{"device_id":"first","device_id":"second"}',
                json.dumps(public) + "{}",
                " " * 8193,
                json.dumps({**public, "wireguard": {"private_key": "private-value"}}),
            ]
            for content in invalid:
                path.write_text(content)

                with self.assertRaises(ValueError):
                    load_public_identity(path)

            path.unlink()
            target = Path(temp) / "elsewhere"
            target.write_text(json.dumps(public))
            path.symlink_to(target)

            with self.assertRaises(ValueError):
                load_public_identity(path)

            self.assertIsNone(load_public_identity(Path(temp) / "missing"))

    def test_bound_manifest_is_stable_and_identity_or_acl_changes_require_review(self):
        from sandbox_init import resolve_manifest

        selected, public = PROFILES[1].environment(), public_gateway()
        placeholder = render_manifest(selected)
        bound = resolve_manifest(placeholder, selected, public)

        self.assertEqual(resolve_manifest(bound, selected, public), bound)

        for candidate in (
            {**public, "device_id": "other-gateway"},
            None,
        ):
            with self.assertRaises(ValueError):
                resolve_manifest(bound, selected, candidate)

        with self.assertRaises(ValueError):
            resolve_manifest(bound.replace(b"port_to = 8080", b"port_to = 9000"), selected, public)

        with self.assertRaises(ValueError):
            resolve_manifest(bound, PROFILES[2].environment(), public)

    def test_reinitialization_preserves_bound_gateway_and_private_material(self):

        import sandbox_init
        from dev_init import SECRET_BYTES
        from sandbox_preflight import load_profile, save_profile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sandbox = root / ".sandbox"
            secrets = sandbox / "secrets"
            secrets.mkdir(parents=True)
            shutil.copytree(ROOT / "config", root / "config")
            shutil.copytree(ROOT / "deploy/sandbox", root / "deploy/sandbox")
            for name in SECRET_BYTES:
                size = SECRET_BYTES[name]
                (secrets / name).write_bytes(base64.b64encode(bytes([3]) * size))

            for name in (
                "relay_tls_ca",
                "relay_tls_cert",
                "relay_tls_key",
                "frontend_tls_cert",
                "frontend_tls_key",
                "site_tls_cert",
                "site_tls_key",
                "site_tls_ca",
            ):
                (secrets / name).write_bytes(b"existing-tls-material")

            (secrets / "site_tls_ca").write_bytes(b"existing-separate-site-authority")
            for name, data in (
                ("relay-ca-key.pem", b"existing-ca-key"),
                ("site-ca-key.pem", b"existing-site-ca-key"),
                ("root-key.age", b"existing-encrypted-root"),
                ("root-passphrase", b"private-passphrase"),
                ("root-public.key", b"same-public-root"),
            ):
                (sandbox / name).write_bytes(data)

            (secrets / "root_public_key").write_bytes(b"same-public-root")
            public = public_gateway()
            (sandbox / "gateway-public.json").write_text(json.dumps(public))
            save_profile(PROFILES[1], sandbox / "network.env")
            (sandbox / "initial-snapshot.toml").write_bytes(
                render_manifest(PROFILES[1].environment(), public)
            )
            private = {path: path.read_bytes() for path in sandbox.rglob("*") if path.is_file()}

            # TLS verification is the external crypto boundary, covered by
            # existing TLS tests/live fixture checks. Exercise actual config
            # generation, metadata loading, manifest selection and file writes.
            with (
                patch.object(sandbox_init, "ROOT", root),
                patch.object(sandbox_init, "SANDBOX", sandbox),
                patch.object(sandbox_init, "NETWORK_FILE", sandbox / "network.env"),
                patch.object(
                    sandbox_init, "load_profile", lambda: load_profile(sandbox / "network.env")
                ),
                patch.object(sandbox_init, "require_commands"),
                patch.object(sandbox_init, "verify_pair"),
                patch.object(sandbox_init, "same_authority", return_value=False),
            ):
                sandbox_init.initialize()
                sandbox_init.initialize()

            for path, before in private.items():
                self.assertEqual(path.read_bytes(), before, str(path.relative_to(root)))

    def test_only_exact_unsigned_http_fixture_migrates_to_https(self):
        from sandbox_init import resolve_manifest

        selected, gateway = PROFILES[1].environment(), public_gateway()
        secure = render_manifest(selected, gateway)
        old = secure.replace(b'url = "https://site.', b'url = "http://site.')

        self.assertEqual(resolve_manifest(old, selected, gateway), secure)

        for changed in (
            old.replace(b"port_to = 8080", b"port_to = 8081"),
            old.replace(b"site.sandbox.home.arpa", b"other.sandbox.home.arpa"),
        ):
            with self.assertRaises(ValueError):
                resolve_manifest(changed, selected, gateway)

    def test_binding_cli_is_repeatable_and_preserves_conflicting_manifest(self):
        from sandbox_preflight import save_profile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            for name in (
                "sandbox_bind.py",
                "sandbox_init.py",
                "sandbox_identity.py",
                "sandbox_pair.py",
                "sandbox_preflight.py",
                "dev_init.py",
                "tls_material.py",
                "tooling.py",
            ):
                shutil.copy(ROOT / "scripts" / name, scripts / name)
            shutil.copytree(ROOT / "deploy/sandbox", root / "deploy/sandbox")
            sandbox = root / ".sandbox"
            sandbox.mkdir()
            save_profile(PROFILES[1], sandbox / "network.env")
            manifest = sandbox / "initial-snapshot.toml"
            manifest.write_bytes(render_manifest(PROFILES[1].environment()))
            (sandbox / "gateway-public.json").write_text(json.dumps(public_gateway()))
            (sandbox / "root-key.age").write_bytes(b"private-root-sentinel")
            command = [sys.executable, str(scripts / "sandbox_bind.py")]
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            bound = manifest.read_bytes()
            self.assertEqual(
                tomllib.loads(bound.decode())["devices"][0]["id"], "_enrolled-gateway_1"
            )
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(manifest.read_bytes(), bound)
            changed = bound.replace(b"port_to = 8080", b"port_to = 9000")
            manifest.write_bytes(changed)
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(manifest.read_bytes(), changed)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"private-root-sentinel", result.stderr)
            self.assertEqual((sandbox / "root-key.age").read_bytes(), b"private-root-sentinel")


if __name__ == "__main__":
    unittest.main()
