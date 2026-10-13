"""Explicit per-user, hostname-scoped macOS certificate trust for the sandbox."""

import hashlib
import plistlib
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

from sandbox_identity import read_public_file
from tooling import atomic_write

SECURITY = "/usr/bin/security"
HOST = "control.localhost"


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


def scoped_trust(entry):
    if not isinstance(entry, dict):
        return False
    rules = entry.get("trustSettings")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return False
    rule = rules[0]
    required = {
        "kSecTrustSettingsPolicy",
        "kSecTrustSettingsPolicyName",
        "kSecTrustSettingsPolicyString",
    }
    # Apple defines an omitted result as trustRoot. Reject extra usage/error rules.
    return (
        required <= set(rule) <= required | {"kSecTrustSettingsResult"}
        and rule["kSecTrustSettingsPolicyName"] == "sslServer"
        and rule["kSecTrustSettingsPolicyString"] == HOST
        and type(rule.get("kSecTrustSettingsResult", 1)) is int
        and rule.get("kSecTrustSettingsResult", 1) == 1
        and isinstance(rule["kSecTrustSettingsPolicy"], bytes)
        and bool(rule["kSecTrustSettingsPolicy"])
    )


def verify_scope(certificate, ca, run):
    for host, accepted in ((HOST, True), ("relay.localhost", False)):
        result = run(
            [
                SECURITY,
                "verify-cert",
                "-q",
                "-L",
                "-p",
                "ssl",
                "-n",
                host,
                "-c",
                str(certificate),
                "-c",
                str(ca),
            ]
        )
        if (result.returncode == 0) != accepted:
            raise ValueError("macOS hostname trust verification failed; inspect saved trust state")


def trust_ca(flow, *, run=security_command, terminal=None, prompt=input):
    flow.require_owner()
    if sys.platform != "darwin":
        raise ValueError("sandbox browser trust requires macOS")
    with flow.lock():
        flow.inventory()
        ca = flow.sandbox / "secrets/relay_tls_ca"
        certificate = flow.sandbox / "secrets/frontend_tls_cert"
        history = flow.sandbox / "browser-trust"
        for path in (ca, certificate, history):
            flow.check_path(path)
        content, leaf = read_public_file(ca), read_public_file(certificate)
        if content is None or leaf is None:
            raise ValueError("run sandbox-up before browser trust; CA/certificate missing")
        try:
            text = content.decode("ascii")
            if text.count("-----BEGIN CERTIFICATE-----") != 1:
                raise ValueError
            der = ssl.PEM_cert_to_DER_cert(text)
        except (UnicodeError, ValueError):
            raise ValueError("sandbox CA must contain one public PEM certificate") from None
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        cert_id = hashlib.sha1(der).hexdigest().upper()
        print(f"Sandbox browser CA SHA-256: {fingerprint}")
        history.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="inspect-", dir=history) as temporary:
            staged = Path(temporary)
            atomic_write(staged / "ca.pem", content)
            atomic_write(staged / "frontend.pem", leaf)
            before = export_trust(staged / "before.plist", run)
            if cert_id in before:
                if not scoped_trust(before[cert_id]):
                    raise ValueError("existing certificate trust differs; refusing to replace it")
                verify_scope(staged / "frontend.pem", staged / "ca.pem", run)
                print("Exact SSL hostname trust already installed; no change.")
                print("Use Safari for this scoped trust; Chrome ignores hostname constraints.")
                return
            if terminal is None:
                terminal = sys.stdin.isatty()
            if not terminal:
                raise ValueError("new browser trust needs terminal fingerprint confirmation")
            answer = prompt(f"Trust only SSL {HOST}? Type the displayed SHA-256 fingerprint: ")
            if answer.strip().replace(":", "").upper() != fingerprint:
                raise ValueError("browser CA fingerprint confirmation did not match; no change")
            # Retain before/after records only when a mutation may have occurred.
            record = Path(tempfile.mkdtemp(prefix="approved-", dir=history))
            atomic_write(record / "ca.pem", content)
            atomic_write(record / "before.plist", (staged / "before.plist").read_bytes())
            result = run(
                [
                    SECURITY,
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-p",
                    "ssl",
                    "-s",
                    HOST,
                    "-k",
                    str(Path.home() / "Library/Keychains/login.keychain-db"),
                    str(record / "ca.pem"),
                ],
                timeout=180,
            )
            after = export_trust(record / "after.plist", run)
            if result.returncode:
                raise ValueError("browser CA trust command failed; private output withheld")
            if (
                set(after) != set(before) | {cert_id}
                or any(after.get(key) != value for key, value in before.items())
                or not scoped_trust(after.get(cert_id))
            ):
                raise ValueError("user trust changed unexpectedly; inspect saved trust snapshots")
            verify_scope(staged / "frontend.pem", staged / "ca.pem", run)
        print("Verified user SSL trust for control.localhost; previous trust entries preserved.")
        print(
            "Open sandbox login in Safari; complete passkey setup and retain recovery codes privately."
        )
