"""Shared trust policy with iPhone SANs; fake only external macOS trust/openssl."""

import contextlib
import io
import plistlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_sandbox_ios_workflow import HostBoundary, workflow_fixture
from test_sandbox_trust import (
    CERT_ID,
    FINGERPRINT,
    LEAF_FINGERPRINT,
    LEAF_ID,
    LEAF_PEM,
    PEM,
    chrome_entry,
    scoped_entry,
)


class IOSSecurityBoundary:
    def __init__(self):
        self.entries = {"existing-mac": scoped_entry("control.localhost")}
        self.calls = []
        self.sans = "DNS:ios-admin.localhost, DNS:control.ios-sandbox, DNS:relay.ios-sandbox, IP Address:192.168.50.7"

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == "/usr/bin/openssl":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "CA:FALSE\nX509v3 Subject Alternative Name:\n " + self.sans + "\n"
                ).encode(),
                stderr=b"",
            )

        if args[1] == "trust-settings-export":
            Path(args[-1]).write_bytes(plistlib.dumps({"trustList": self.entries}))

        if args[1] == "add-trusted-cert":
            if "trustAsRoot" in args:
                self.entries[LEAF_ID] = chrome_entry()
            else:
                self.entries[CERT_ID] = scoped_entry(args[args.index("-s") + 1])

        if args[1] == "verify-cert":
            host = args[args.index("-n") + 1]
            accepted = (host == "ios-admin.localhost" and CERT_ID in self.entries) or (
                host in {"ios-admin.localhost", "relay.ios-sandbox", "192.168.50.7"}
                and LEAF_ID in self.entries
            )

            return SimpleNamespace(returncode=0 if accepted else 1, stdout=b"", stderr=b"")

        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


class IOSBrowserTrustTests(unittest.TestCase):
    def flow(self, temporary):
        flow = workflow_fixture(temporary, HostBoundary())
        flow.prepare("192.168.50.7")
        (flow.sandbox / "secrets/relay_tls_ca").write_bytes(PEM)
        (flow.sandbox / "secrets/frontend_tls_cert").write_bytes(LEAF_PEM)
        return flow

    def audience(self):
        from sandbox_trust import BrowserAudience

        return BrowserAudience(
            control_host="ios-admin.localhost",
            relay_host="relay.ios-sandbox",
            server_names=frozenset(
                {"ios-admin.localhost", "control.ios-sandbox", "relay.ios-sandbox"}
            ),
            ip_addresses=frozenset({"192.168.50.7"}),
        )

    def test_safari_trust_is_scoped_to_ios_admin_and_preserves_mac_entries(self):
        from sandbox_trust import trust_ca

        with tempfile.TemporaryDirectory() as temporary:
            flow = self.flow(temporary)
            security = IOSSecurityBoundary()
            before = dict(security.entries)

            with (
                contextlib.redirect_stdout(io.StringIO()),
                patch("sandbox_trust.sys.platform", "darwin"),
            ):
                trust_ca(
                    flow,
                    run=security,
                    audience=self.audience(),
                    terminal=True,
                    prompt=lambda _: FINGERPRINT,
                )
                trust_ca(flow, run=security, audience=self.audience(), terminal=False)

            changes = [a for a in security.calls if a[1] == "add-trusted-cert"]

            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0][changes[0].index("-s") + 1], "ios-admin.localhost")
            self.assertIn("trustRoot", changes[0])
            self.assertNotIn("-d", changes[0])
            self.assertEqual(security.entries["existing-mac"], before["existing-mac"])

    def test_chrome_pins_leaf_with_real_ip_san_and_verifies_ios_audience(self):
        from sandbox_trust import trust_ca

        with tempfile.TemporaryDirectory() as temporary:
            flow = self.flow(temporary)
            security = IOSSecurityBoundary()

            with (
                contextlib.redirect_stdout(io.StringIO()),
                patch("sandbox_trust.sys.platform", "darwin"),
            ):
                trust_ca(
                    flow,
                    run=security,
                    audience=self.audience(),
                    browser="chrome",
                    terminal=True,
                    prompt=lambda _: LEAF_FINGERPRINT,
                )
                trust_ca(
                    flow, run=security, audience=self.audience(), browser="chrome", terminal=False
                )

            changes = [a for a in security.calls if a[1] == "add-trusted-cert"]

            self.assertEqual(len(changes), 1)
            self.assertIn("trustAsRoot", changes[0])
            self.assertNotIn("-s", changes[0])
            self.assertEqual(Path(changes[0][-1]).read_bytes(), LEAF_PEM)
            self.assertNotIn(CERT_ID, security.entries)

    def test_wrong_ip_dns_encoded_ip_or_extra_san_refuses_before_trust_mutation(self):
        from sandbox_trust import trust_ca

        for change in [
            "IP Address:192.168.50.8",
            "DNS:192.168.50.7",
            "IP Address:192.168.50.7, DNS:foreign.example",
        ]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                flow = self.flow(temporary)
                security = IOSSecurityBoundary()
                security.sans = security.sans.replace("IP Address:192.168.50.7", change)

                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    patch("sandbox_trust.sys.platform", "darwin"),
                    self.assertRaises(ValueError),
                ):
                    trust_ca(
                        flow,
                        run=security,
                        audience=self.audience(),
                        browser="chrome",
                        terminal=True,
                        prompt=lambda _: LEAF_FINGERPRINT,
                    )

                self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))

    def test_existing_different_hostname_rule_is_not_replaced(self):
        from sandbox_trust import trust_ca

        with tempfile.TemporaryDirectory() as temporary:
            flow = self.flow(temporary)
            security = IOSSecurityBoundary()
            security.entries[CERT_ID] = scoped_entry("control.localhost")

            with (
                contextlib.redirect_stdout(io.StringIO()),
                patch("sandbox_trust.sys.platform", "darwin"),
                self.assertRaises(ValueError),
            ):
                trust_ca(
                    flow,
                    run=security,
                    audience=self.audience(),
                    terminal=True,
                    prompt=lambda _: FINGERPRINT,
                )

            self.assertFalse(any(a[1] == "add-trusted-cert" for a in security.calls))
