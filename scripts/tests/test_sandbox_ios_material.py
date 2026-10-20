"""Real staged TLS/private files; only the Go root CLI is an external boundary."""

import base64
import contextlib
import io
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from sandbox_ios_config import ADMIN_HOST, CONTROL_HOST, RELAY_HOST, LANEndpoints  # noqa: E402
from sandbox_ios_material import material_documents  # noqa: E402
from sandbox_ownership import CommandFailure, SandboxOwnership  # noqa: E402
from test_tooling import strict_tls_handshake  # noqa: E402
from tls_material import same_authority  # noqa: E402


class RootBoundary:
    def __init__(self):
        self.fail = False
        self.phrase_modes = []
        self.calls = 0

    def __call__(self, args, **kwargs):
        if args[0] == "docker":
            return ""
        if args[0] != "go" or "init-root" not in args:
            raise AssertionError("Unexpected external effect")

        self.calls += 1
        phrase = Path(args[args.index("--passphrase-file") + 1])
        self.phrase_modes.append(stat.S_IMODE(phrase.stat().st_mode))
        if self.fail:
            raise CommandFailure(1)

        # Opaque stand-in for the external CLI's already-tested age encryption.
        # Never claim this marker is an actual encrypted root key.
        Path(args[args.index("--key") + 1]).write_bytes(b"opaque-root-cli-result")
        return base64.urlsafe_b64encode(bytes([7]) * 32).decode().rstrip("=") + "\n"


class IOSMaterialTests(unittest.TestCase):
    def owner(self, directory, boundary):
        owner = SandboxOwnership(
            Path(directory),
            project="homeharbor-ios-sandbox",
            directory=".sandbox-ios",
            run=boundary,
        )
        owner.create_owner()
        return owner

    def publish(self, documents):
        for path, (data, mode) in documents.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)

    def test_real_tls_staging_is_isolated_idempotent_and_never_prints_private_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".sandbox").mkdir()
            old = root / ".sandbox/private-state"
            old.write_bytes(b"original-mac-private-state")
            boundary = RootBoundary()
            owner = self.owner(root, boundary)
            output = io.StringIO()

            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                documents = material_documents(owner, LANEndpoints("192.168.50.7"))

            self.assertEqual(output.getvalue(), "")
            self.assertFalse((owner.sandbox / "secrets").exists())
            self.assertEqual(old.read_bytes(), b"original-mac-private-state")
            self.assertEqual(boundary.phrase_modes, [0o600])
            self.assertEqual(boundary.calls, 1)

            self.publish(documents)
            secrets = owner.sandbox / "secrets"
            ca = secrets / "relay_tls_ca"
            certificate = secrets / "frontend_tls_cert"
            key = secrets / "frontend_tls_key"
            for hostname in [ADMIN_HOST, CONTROL_HOST, RELAY_HOST, "192.168.50.7"]:
                strict_tls_handshake(ca, certificate, key, hostname)

            self.assertFalse(same_authority(ca, secrets / "site_tls_ca"))

            strict_tls_handshake(
                secrets / "site_tls_ca",
                secrets / "site_tls_cert",
                secrets / "site_tls_key",
                "site.sandbox.home.arpa",
            )

            self.assertEqual(material_documents(owner, LANEndpoints("192.168.50.7")), documents)
            self.assertEqual(boundary.calls, 1, "Existing companion identity cannot be regenerated")

            for path, (_, mode) in documents.items():
                self.assertTrue(path.is_relative_to(owner.sandbox))

                if path.name in {
                    "relay_tls_key",
                    "frontend_tls_key",
                    "site_tls_key",
                    "root-key.age",
                    "relay-ca-key.pem",
                    "site-ca-key.pem",
                    "root-passphrase",
                    "postgres_password",
                    "redis_password",
                    "relay_ticket_key",
                    "session_signing_key",
                    "ceremony_encryption_key",
                }:
                    self.assertEqual(mode, 0o600, path.name)
                else:
                    self.assertEqual(mode, 0o644, path.name)

    def test_partial_material_and_changed_ip_are_rejected_without_rotation(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = RootBoundary()
            owner = self.owner(temporary, boundary)
            documents = material_documents(owner, LANEndpoints("192.168.50.7"))
            self.publish(documents)
            missing = owner.sandbox / "secrets/frontend_tls_key"
            saved = missing.read_bytes()
            missing.unlink()
            before = {path: path.read_bytes() for path in documents if path.exists()}

            with self.assertRaises(ValueError):
                material_documents(owner, LANEndpoints("192.168.50.7"))

            self.assertEqual({path: path.read_bytes() for path in before}, before)
            self.assertFalse(missing.exists())

            missing.write_bytes(saved)

            with self.assertRaises(ValueError):
                material_documents(owner, LANEndpoints("192.168.50.8"))

            self.assertEqual(boundary.calls, 1)
            self.assertEqual(missing.read_bytes(), saved)

    def test_symlinked_secret_is_rejected_before_reading_or_generating_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = RootBoundary()
            owner = self.owner(temporary, boundary)
            external = Path(temporary) / "foreign"
            external.write_bytes(b"foreign-private-state")
            (owner.sandbox / "secrets").mkdir()
            (owner.sandbox / "secrets/relay_tls_ca").symlink_to(external)

            with self.assertRaisesRegex(ValueError, "symlink"):
                material_documents(owner, LANEndpoints("192.168.50.7"))

            self.assertEqual(boundary.calls, 0)
            self.assertEqual(external.read_bytes(), b"foreign-private-state")

    def test_failed_root_cli_does_not_publish_partial_tls_or_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = RootBoundary()
            boundary.fail = True
            owner = self.owner(temporary, boundary)

            with self.assertRaises(CommandFailure):
                material_documents(owner, LANEndpoints("192.168.50.7"))

            self.assertEqual(list(owner.sandbox.iterdir()), [owner.owner_file])
            self.assertEqual(boundary.phrase_modes, [0o600])

    def test_wrong_project_or_state_directory_is_rejected_before_root_generation(self):
        for project in ["homeharbor-sandbox", "homeharbor-ios-sandbox"]:
            with self.subTest(project=project), tempfile.TemporaryDirectory() as temporary:
                boundary = RootBoundary()
                owner = SandboxOwnership(
                    Path(temporary), project=project, directory=".sandbox", run=boundary
                )
                owner.create_owner()

                with self.assertRaises(ValueError):
                    material_documents(owner, LANEndpoints("192.168.50.7"))

                self.assertEqual(boundary.calls, 0)
