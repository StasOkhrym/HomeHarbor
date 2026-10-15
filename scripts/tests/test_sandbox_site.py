"""Real private-site TLS/listener contracts; never touch Docker or host trust."""

import os
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import sandbox_site as site  # noqa: E402
from sandbox_diagnostics import probe  # noqa: E402
from tls_material import (  # noqa: E402
    issue,
    issue_authority,
    verify_pair,  # noqa: E402
)
from tooling import quiet_run  # noqa: E402


class SandboxSiteTests(unittest.TestCase):
    def test_both_listeners_are_live_and_tls_enforces_site_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "index.html").write_text("HOMEHARBOR-SANDBOX-PRIVATE-SITE")
            ca, ca_key = issue_authority(directory, "Disposable fixture test CA")
            (directory / ".curlrc").write_text("insecure\n")
            for hostname, accepted in [
                ("site.sandbox.home.arpa", True),
                ("control.localhost", False),
            ]:
                certificate, key = issue(directory, hostname, ca, ca_key, [hostname])

                with site.listeners(
                    str(directory), certificate, key, host="127.0.0.1", https_port=0, http_port=0
                ) as servers:
                    workers = [
                        Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
                        for server in servers
                    ]
                    for worker in workers:
                        worker.start()

                    try:
                        ports = {
                            "https_port": servers[0].server_port,
                            "http_port": servers[1].server_port,
                        }
                        if accepted:
                            site.check(ca, **ports)
                        else:
                            with self.assertRaises(ssl.SSLCertVerificationError):
                                site.check(ca, **ports)

                        with patch.dict(os.environ, {"CURL_HOME": str(directory)}):
                            self.assertEqual(
                                probe(
                                    f"https://site.sandbox.home.arpa:{ports['https_port']}/",
                                    ca=ca,
                                    resolve=f"site.sandbox.home.arpa:{ports['https_port']}:127.0.0.1",
                                ),
                                accepted,
                                "user curl configuration weakened TLS verification",
                            )
                    finally:
                        for server in servers:
                            server.shutdown()

                        for worker in workers:
                            worker.join(timeout=3)

                            self.assertFalse(worker.is_alive())

    def test_exact_leaf_rejects_extra_ip_uri_and_duplicate_dns_sans(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ca, ca_key = issue_authority(directory, "Disposable SAN contract CA")
            cert, key = issue(directory, "site", ca, ca_key, ["site.sandbox.home.arpa"])
            extension = directory / "site.ext"
            original = extension.read_text()
            for extra in (
                "IP:127.0.0.1",
                "URI:https://other.example",
                "DNS:site.sandbox.home.arpa",
            ):
                extension.write_text(original.rstrip() + "," + extra + "\n")
                quiet_run(
                    "openssl",
                    "x509",
                    "-req",
                    "-days",
                    "1",
                    "-sha256",
                    "-in",
                    str(directory / "site.csr"),
                    "-CA",
                    str(ca),
                    "-CAkey",
                    str(ca_key),
                    "-set_serial",
                    "20",
                    "-extfile",
                    str(extension),
                    "-out",
                    str(cert),
                )

                with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "domains"):
                    verify_pair(cert, key, ca, ["site.sandbox.home.arpa"], exact_names=True)
