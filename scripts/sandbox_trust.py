"""Explicit per-user, hostname-scoped macOS certificate trust for the sandbox."""

import hashlib
import ipaddress
import plistlib
import re
import ssl
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sandbox_identity import read_public_file
from tooling import atomic_write

SECURITY = "/usr/bin/security"
HOST = "control.localhost"
SERVER_NAMES = frozenset({HOST, "relay.localhost", "control.sandbox", "relay.sandbox"})


@dataclass(frozen=True)
class BrowserAudience:
    control_host: str = HOST
    relay_host: str = "relay.localhost"
    server_names: frozenset[str] = SERVER_NAMES
    ip_addresses: frozenset[str] = frozenset()


MAC_AUDIENCE = BrowserAudience()


def security_command(args, *, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError(
            "macOS trust command failed; inspect saved trust state before retry"
        ) from None


def export_trust(path, run):
    result = run([SECURITY, "trust-settings-export", str(path)])
    if result.returncode:
        if b"No Trust Settings were found" in result.stdout + result.stderr:
            atomic_write(path, plistlib.dumps({"trustList": {}}))
        else:
            raise ValueError("cannot export macOS user trust; command output withheld")

    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("user trust snapshot must be a bounded regular file")

    path.chmod(0o600)

    try:
        document = plistlib.loads(path.read_bytes())
        entries = document["trustList"]
        if not isinstance(entries, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError, plistlib.InvalidFileException):
        raise ValueError("cannot decode macOS user trust snapshot") from None

    return entries


def scoped_trust(entry, browser="safari", *, host=HOST):
    if not isinstance(entry, dict):
        return False

    rules = entry.get("trustSettings")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return False

    rule = rules[0]
    required = {"kSecTrustSettingsPolicy", "kSecTrustSettingsPolicyName"}
    if browser == "safari":
        required.add("kSecTrustSettingsPolicyString")

    # Apple defines an omitted result as trustRoot. Reject extra usage/error rules.
    return (
        required <= set(rule) <= required | {"kSecTrustSettingsResult"}
        and rule["kSecTrustSettingsPolicyName"] == "sslServer"
        and (browser == "chrome" or rule["kSecTrustSettingsPolicyString"] == host)
        and type(rule.get("kSecTrustSettingsResult", 1)) is int
        and rule.get("kSecTrustSettingsResult", 1) == (2 if browser == "chrome" else 1)
        and isinstance(rule["kSecTrustSettingsPolicy"], bytes)
        and bool(rule["kSecTrustSettingsPolicy"])
    )


def validate_server_leaf(certificate, ca, run, names=SERVER_NAMES, *, ip_addresses=frozenset()):
    result = run(
        [
            "/usr/bin/openssl",
            "verify",
            "-purpose",
            "sslserver",
            "-CAfile",
            str(ca),
            str(certificate),
        ]
    )
    if result.returncode:
        raise ValueError("server certificate does not verify against the sandbox CA")

    result = run(
        [
            "/usr/bin/openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-text",
        ]
    )
    if result.returncode:
        raise ValueError("cannot inspect sandbox server certificate")

    try:
        properties = result.stdout.decode("ascii")
        san = re.search(r"X509v3 Subject Alternative Name:\s*\n([^\n]+)", properties)
        actual_names = [part.strip() for part in san[1].split(",")] if san else []
        actual = set()
        for name in actual_names:
            if name.startswith("IP Address:"):
                actual.add("IP:" + str(ipaddress.ip_address(name.removeprefix("IP Address:"))))
            else:
                actual.add(name)

        expected = {"DNS:" + name for name in names} | {
            "IP:" + str(ipaddress.ip_address(value)) for value in ip_addresses
        }
        if (
            "CA:FALSE" not in properties
            or "CA:TRUE" in properties
            or len(actual_names) != len(expected)
            or actual != expected
        ):
            raise ValueError
    except (UnicodeError, ValueError):
        raise ValueError(
            "server certificate must be CA:FALSE with exactly the selected sandbox SAN names"
        ) from None


def verify_scope(
    certificate,
    ca,
    run,
    *,
    relay_accepted=False,
    host=HOST,
    relay_host="relay.localhost",
    ip_addresses=frozenset(),
):
    checks = [
        (host, True),
        (relay_host, relay_accepted),
        ("unrelated.localhost", False),
    ]
    checks.extend((value, relay_accepted) for value in sorted(ip_addresses))
    if host != HOST:
        checks.append((HOST, False))

    for checked_host, accepted in checks:
        result = run(
            [
                SECURITY,
                "verify-cert",
                "-q",
                "-L",
                "-p",
                "ssl",
                "-n",
                checked_host,
                "-c",
                str(certificate),
                "-c",
                str(ca),
            ]
        )
        if (result.returncode == 0) != accepted:
            raise ValueError("macOS hostname trust verification failed; inspect saved trust state")


def trust_ca(
    flow,
    *,
    run=security_command,
    terminal=None,
    prompt=input,
    browser="safari",
    target="control",
    audience=MAC_AUDIENCE,
):
    if browser not in {"safari", "chrome"}:
        raise ValueError("TRUST_BROWSER must be safari or chrome")
    if target not in {"control", "site"}:
        raise ValueError("TRUST_TARGET must be control or site")
    if target == "site" and browser != "chrome":
        raise ValueError(
            "private site trust requires TRUST_BROWSER=chrome for single-leaf SSL trust"
        )

    host = audience.control_host if target == "control" else "site.sandbox.home.arpa"
    names = audience.server_names if target == "control" else frozenset({host})
    ips = audience.ip_addresses if target == "control" else frozenset()
    flow.require_owner()
    if sys.platform != "darwin":
        raise ValueError("sandbox browser trust requires macOS")

    with flow.lock():
        flow.inventory()
        ca = flow.sandbox / "secrets" / ("relay_tls_ca" if target == "control" else "site_tls_ca")
        certificate = (
            flow.sandbox
            / "secrets"
            / ("frontend_tls_cert" if target == "control" else "site_tls_cert")
        )
        history = flow.sandbox / "browser-trust"
        for path in (ca, certificate, history):
            flow.check_path(path)

        content, leaf = read_public_file(ca), read_public_file(certificate)
        if content is None or leaf is None:
            raise ValueError("run sandbox-up before browser trust; CA/certificate missing")

        try:
            trusted = leaf if browser == "chrome" else content
            text = trusted.decode("ascii")
            if text.count("-----BEGIN CERTIFICATE-----") != 1:
                raise ValueError

            der = ssl.PEM_cert_to_DER_cert(text)
        except (UnicodeError, ValueError):
            raise ValueError("sandbox CA must contain one public PEM certificate") from None

        fingerprint = hashlib.sha256(der).hexdigest().upper()
        cert_id = hashlib.sha1(der).hexdigest().upper()
        print(
            f"Sandbox browser {'server certificate' if browser == 'chrome' else 'CA'} SHA-256: {fingerprint}"
        )
        history.mkdir(mode=0o700, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="inspect-", dir=history) as temporary:
            staged = Path(temporary)
            atomic_write(staged / "ca.pem", content)
            atomic_write(staged / "frontend.pem", leaf)
            if browser == "chrome":
                validate_server_leaf(
                    staged / "frontend.pem", staged / "ca.pem", run, names, ip_addresses=ips
                )
                print("Chrome mode trusts only this CA:FALSE server certificate for SSL.")
                print("Certificate SANs: " + ", ".join(sorted(names | ips)))
            else:
                print(f"Safari mode trusts this CA only for SSL hostname {host}.")

            before = export_trust(staged / "before.plist", run)
            leaf_id = (
                hashlib.sha1(ssl.PEM_cert_to_DER_cert(leaf.decode("ascii"))).hexdigest().upper()
            )
            relay_accepted = target == "control" and (
                browser == "chrome" or scoped_trust(before.get(leaf_id), "chrome")
            )
            if cert_id in before:
                if not scoped_trust(before[cert_id], browser, host=host):
                    raise ValueError("existing certificate trust differs; refusing to replace it")

                verify_scope(
                    staged / "frontend.pem",
                    staged / "ca.pem",
                    run,
                    relay_accepted=relay_accepted,
                    host=host,
                    relay_host=audience.relay_host,
                    ip_addresses=ips,
                )
                print("Exact browser SSL trust already installed; no change.")
                if browser == "safari":
                    print(
                        "Use Safari for scoped CA trust; Chrome requires explicit server certificate trust."
                    )

                return

            if terminal is None:
                terminal = sys.stdin.isatty()

            if not terminal:
                raise ValueError("new browser trust needs terminal fingerprint confirmation")

            try:
                answer = prompt("Confirm the displayed browser certificate SHA-256 fingerprint: ")
            except KeyboardInterrupt:
                print("Browser trust confirmation cancelled; no change.")
                return 130
            except EOFError:
                raise ValueError("browser trust confirmation ended; no change") from None

            if answer.strip().replace(":", "").upper() != fingerprint:
                raise ValueError("browser CA fingerprint confirmation did not match; no change")

            # Retain before/after records only when a mutation may have occurred.
            record = Path(tempfile.mkdtemp(prefix="approved-", dir=history))
            atomic_write(record / "trusted.pem", trusted)
            atomic_write(record / "before.plist", (staged / "before.plist").read_bytes())
            args = [
                SECURITY,
                "add-trusted-cert",
                "-r",
                "trustAsRoot" if browser == "chrome" else "trustRoot",
                "-p",
                "ssl",
            ]
            if browser == "safari":
                args += ["-s", host]

            args += [
                "-k",
                str(Path.home() / "Library/Keychains/login.keychain-db"),
                str(record / "trusted.pem"),
            ]
            result = run(args, timeout=180)
            after = export_trust(record / "after.plist", run)
            if result.returncode:
                raise ValueError("browser CA trust command failed; private output withheld")
            if (
                set(after) != set(before) | {cert_id}
                or any(after.get(key) != value for key, value in before.items())
                or not scoped_trust(after.get(cert_id), browser, host=host)
            ):
                raise ValueError("user trust changed unexpectedly; inspect saved trust snapshots")

            verify_scope(
                staged / "frontend.pem",
                staged / "ca.pem",
                run,
                relay_accepted=relay_accepted,
                host=host,
                relay_host=audience.relay_host,
                ip_addresses=ips,
            )

        print(f"Verified {browser} user SSL trust; previous trust entries preserved.")
        print("A renewed Chrome server certificate requires explicit trust of its new fingerprint.")
