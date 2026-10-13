"""Explicit browser trust contracts; fake macOS boundary, no keychain mutation."""

import base64
import hashlib
import importlib
import io
import plistlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.tests.test_sandbox_workflow import DockerBoundary

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

DER = b"public-certificate-fixture"
PEM = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(DER) + b"\n-----END CERTIFICATE-----\n"
CERT_ID = hashlib.sha1(DER).hexdigest().upper()
FINGERPRINT = hashlib.sha256(DER).hexdigest().upper()


def scoped_entry(host="control.localhost"):
    return {
        "trustSettings": [
            {
                "kSecTrustSettingsPolicyName": "sslServer",
                "kSecTrustSettingsPolicy": b"ssl-policy",
                "kSecTrustSettingsPolicyString": host,
            }
        ]
    }


class SecurityBoundary:
    def __init__(self, entry=None):
        self.entries = {"OTHER": {"trustSettings": []}}
        if entry is not None:
            self.entries[CERT_ID] = entry

        self.calls = []
        self.fail_add = False
        self.change_other = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[1] == "trust-settings-export":
            Path(args[-1]).write_bytes(plistlib.dumps({"trustList": self.entries}))
        if args[1] == "add-trusted-cert":
            if self.fail_add:
                return SimpleNamespace(
                    returncode=1, stdout=b"private-sentinel", stderr=b"private-sentinel"
                )
            self.entries[CERT_ID] = scoped_entry()
            if self.change_other:
                self.entries["OTHER"] = scoped_entry("foreign.example")
        if args[1] == "verify-cert" and args[args.index("-n") + 1] == "relay.localhost":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


class SandboxTrustTests(unittest.TestCase):
    def invoke(self, temp, security, *, terminal=True, confirmation=FINGERPRINT):
        from sandbox_workflow import Workflow

        try:
            trust = importlib.import_module("sandbox_trust")
        except ModuleNotFoundError:
            self.fail("sandbox CA trust scenario is not implemented")
        flow = Workflow(Path(temp), run=DockerBoundary(), uid=501)
        flow.create_owner()
        ca = flow.sandbox / "secrets/relay_tls_ca"
        ca.parent.mkdir(exist_ok=True)
        if not ca.exists() and not ca.is_symlink():
            ca.write_bytes(PEM)
        (ca.parent / "frontend_tls_cert").write_bytes(PEM)
        with patch("sandbox_trust.sys.platform", "darwin"):
            trust.trust_ca(flow, run=security, terminal=terminal, prompt=lambda _: confirmation)
        return flow

    def test_make_exposes_explicit_trust_scenario(self):
        result = subprocess.run(
            ["make", "-n", "sandbox-trust-ca"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scripts/sandbox.sh trust-ca", result.stdout)

    def test_confirmed_trust_has_only_hostname_ssl_and_user_keychain(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()) as output:
            security = SecurityBoundary()
            self.invoke(temp, security)
            command = next(a for a in security.calls if a[1] == "add-trusted-cert")

            self.assertEqual(
                command[:8],
                [
                    "/usr/bin/security",
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-p",
                    "ssl",
                    "-s",
                    "control.localhost",
                ],
            )
            self.assertNotIn("-d", command)
            self.assertNotIn("-e", command)
            self.assertIn(str(Path.home() / "Library/Keychains/login.keychain-db"), command)
            self.assertIn(FINGERPRINT, output.getvalue())
            self.assertEqual(security.entries["OTHER"], {"trustSettings": []})

    def test_repeat_is_read_only_and_needs_no_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            security = SecurityBoundary(scoped_entry())
            self.invoke(temp, security, terminal=False, confirmation="must not prompt")

            self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))

    def test_noninteractive_or_wrong_fingerprint_refuses_mutation(self):
        for terminal, confirmation in [(False, FINGERPRINT), (True, "yes"), (True, "0" * 64)]:
            with (
                self.subTest(terminal=terminal, confirmation=confirmation),
                tempfile.TemporaryDirectory() as temp,
            ):
                security = SecurityBoundary()

                with self.assertRaisesRegex(ValueError, "terminal|fingerprint"):
                    self.invoke(temp, security, terminal=terminal, confirmation=confirmation)

                self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))

    def test_existing_broader_or_different_trust_is_never_replaced(self):
        for entry in [
            {"trustSettings": []},
            scoped_entry("relay.localhost"),
            {"trustSettings": [*scoped_entry()["trustSettings"], {}]},
        ]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temp:
                security = SecurityBoundary(entry)

                with self.assertRaisesRegex(ValueError, "existing.*trust"):
                    self.invoke(temp, security)

                self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))

    def test_unrelated_trust_change_is_detected_and_snapshots_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            security = SecurityBoundary()
            security.change_other = True

            with self.assertRaisesRegex(ValueError, "trust.*changed|verification"):
                self.invoke(temp, security)

            snapshots = list((Path(temp) / ".sandbox/browser-trust").glob("*/before.plist"))

            self.assertEqual(len(snapshots), 1)
            self.assertEqual(snapshots[0].stat().st_mode & 0o777, 0o600)

    def test_failed_security_output_is_not_disclosed(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()) as output:
            security = SecurityBoundary()
            security.fail_add = True

            with self.assertRaises(ValueError) as error:
                self.invoke(temp, security)

            self.assertNotIn("private-sentinel", str(error.exception) + output.getvalue())

    def test_owner_and_symlink_checks_precede_security(self):
        from sandbox_workflow import Workflow

        try:
            trust = importlib.import_module("sandbox_trust")
        except ModuleNotFoundError:
            self.fail("sandbox CA trust scenario is not implemented")

        with tempfile.TemporaryDirectory() as temp:
            flow = Workflow(Path(temp), run=DockerBoundary(), uid=501)
            security = SecurityBoundary()

            with self.assertRaisesRegex(ValueError, "ownership"):
                trust.trust_ca(flow, run=security, terminal=True, prompt=lambda _: FINGERPRINT)

            self.assertEqual(security.calls, [])

            flow.create_owner()
            ca = flow.sandbox / "secrets/relay_tls_ca"
            ca.parent.mkdir()
            external = flow.root / "foreign.pem"
            external.write_bytes(PEM)
            ca.symlink_to(external)

            with self.assertRaisesRegex(ValueError, "symlink"):
                self.invoke(temp, security)

            self.assertEqual(security.calls, [])

    def test_platform_and_foreign_resources_refuse_before_keychain_access(self):
        from sandbox_trust import trust_ca
        from sandbox_workflow import Workflow

        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = Workflow(Path(temp), run=docker, uid=501)
            flow.create_owner()
            security = SecurityBoundary()

            with (
                patch("sandbox_trust.sys.platform", "linux"),
                self.assertRaisesRegex(ValueError, "macOS"),
            ):
                trust_ca(flow, run=security)

            docker.resources["volume"] = [{"Name": "homeharbor-sandbox_foreign", "Labels": {}}]

            with (
                patch("sandbox_trust.sys.platform", "darwin"),
                self.assertRaisesRegex(ValueError, "ownership"),
            ):
                trust_ca(flow, run=security)

            self.assertEqual(security.calls, [])

    def test_host_scope_verification_failure_is_reported(self):
        for rejected_host in ["control.localhost", "relay.localhost"]:
            with self.subTest(host=rejected_host), tempfile.TemporaryDirectory() as temp:
                security = SecurityBoundary(scoped_entry())

                def run(args, *, rejected_host=rejected_host, boundary=security, **kwargs):
                    if args[1] == "verify-cert":
                        host = args[args.index("-n") + 1]
                        code = 1 if host == "control.localhost" else 0
                        if host == rejected_host:
                            return SimpleNamespace(returncode=code, stdout=b"", stderr=b"")

                    return boundary(args, **kwargs)

                with self.assertRaisesRegex(ValueError, "verification"):
                    self.invoke(temp, run, terminal=False)

                self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))

    def test_snapshot_symlink_does_not_change_foreign_file_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            foreign = Path(temp) / "foreign.plist"
            foreign.write_bytes(plistlib.dumps({"trustList": {}}))
            foreign.chmod(0o644)

            def run(args, **kwargs):
                self.assertEqual(args[1], "trust-settings-export")

                Path(args[-1]).symlink_to(foreign)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with self.assertRaisesRegex(ValueError, "regular"):
                self.invoke(temp, run)

            self.assertEqual(foreign.stat().st_mode & 0o777, 0o644)
