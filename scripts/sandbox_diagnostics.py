"""Public diagnostics and real packet probes for the optional native sandbox."""

import hashlib
import json
import ssl
import subprocess

from sandbox_identity import read_public_file
from sandbox_preflight import load_profile

PUBLIC_EVENTS = frozenset(
    {
        "control.listening",
        "relay.starting",
        "http.request",
        "audit.delivery_retry",
        "snapshot.applied",
        "snapshot.rejected",
        "coordination.connected",
        "coordination.disconnected",
        "relay.connected",
        "relay.disconnected",
        "credential.rotated",
        "credential.expired",
        "network.applied",
        "network.closed",
    }
)
SLOG_EVENTS = {
    "control listening": "control.listening",
    "relay starting": "relay.starting",
    "http request": "http.request",
    "audit delivery retry scheduled": "audit.delivery_retry",
}


def public_log_lines(output):
    """Allow only typed public fields; dropping unknown/free-text avoids redaction gaps."""

    lines = []
    for raw in output.splitlines()[-300:]:
        body = raw.split(" | ", 1)[-1]

        try:
            event = json.loads(body)
        except ValueError:
            continue

        if not isinstance(event, dict):
            continue

        message = event.get("msg")
        name = event.get("event")
        if name is None and isinstance(message, str):
            name = SLOG_EVENTS.get(message)

        if not isinstance(name, str) or name not in PUBLIC_EVENTS:
            continue

        public = {"event": name}
        level = event.get("level")
        if isinstance(level, str) and level.lower() in {"debug", "info", "warn", "error"}:
            public["level"] = level.lower()

        for field in ("revision", "previous_revision"):
            if type(event.get(field)) is int and event[field] >= 0:
                public[field] = event[field]

        if type(event.get("status")) is int and 100 <= event["status"] <= 599:
            public["status"] = event["status"]

        method = event.get("method")
        if isinstance(method, str) and method in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        }:
            public["method"] = method

        lines.append(json.dumps(public, sort_keys=True))

    return lines or ["No public structured runtime events. Use sandbox-status and sandbox-check."]


def probe(url, *, ca=None, resolve=None):
    options = []
    if ca is not None:
        options += ["--cacert", str(ca)]

    if resolve is not None:
        options += ["--resolve", resolve]

    result = subprocess.run(
        [
            "/usr/bin/curl",
            "--disable",
            "--noproxy",
            "*",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            *options,
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    return result.returncode == 0 and result.stdout == "200"


def check(flow, action):
    if action not in {"allowed", "denied"}:
        raise ValueError("choose expected scenario: CHECK=allowed or CHECK=denied")

    flow.require_owner()

    with flow.lock():
        flow.inventory()
        selected = load_profile(flow.sandbox / "network.env")
        site = selected["SANDBOX_SITE_IP"]
        # Prove verified HTTPS and the forbidden listener INSIDE the fixture.
        # Broken TLS or a dead listener must never masquerade as ACL denial.
        ca = flow.sandbox / "secrets/site_tls_ca"
        certificate = flow.sandbox / "secrets/site_tls_cert"
        for path in (ca, certificate):
            flow.check_path(path)

        ca_bytes, certificate_bytes = read_public_file(ca), read_public_file(certificate)
        if ca_bytes is None or certificate_bytes is None:
            raise ValueError("sandbox site CA/certificate missing; initialize before packet checks")

        try:
            certificate_der = ssl.PEM_cert_to_DER_cert(certificate_bytes.decode("ascii"))
        except (ValueError, UnicodeError):
            raise ValueError("sandbox site certificate must be public PEM") from None

        report = flow.compose(
            "exec",
            "-T",
            "site",
            "python3",
            "/usr/local/libexec/homeharbor-site.py",
            "--check",
            timeout=10,
        )

        try:
            identity = json.loads(report)
        except (ValueError, TypeError):
            raise ValueError("private site TLS health identity is unavailable") from None

        if identity != {
            "certificate_sha256": hashlib.sha256(certificate_der).hexdigest(),
            "ca_sha256": hashlib.sha256(ca_bytes).hexdigest(),
        }:
            raise ValueError("private site TLS identity differs from local CA/certificate")

        named = probe("https://site.sandbox.home.arpa:8080/", ca=ca)
        # Bypass DNS only for this second packet probe; still verify the same
        # HTTPS hostname and CA. Never weaken verification for an IP literal.
        direct = probe(
            "https://site.sandbox.home.arpa:8080/",
            ca=ca,
            resolve=f"site.sandbox.home.arpa:8080:{site}",
        )
        forbidden = probe(f"http://{site}:8081/")
        print(
            f"Native packet probes: hostname:8080={named}, private-IP:8080={direct}, non-profile:8081={forbidden}"
        )
        if forbidden or named != (action == "allowed") or direct != (action == "allowed"):
            raise ValueError("sandbox packet probes differ from the selected signed scenario")

        print(
            "Packet probes match expected state. Browser, DNS ownership, rotation and interrupted recovery remain separate evidence."
        )

    return 0
