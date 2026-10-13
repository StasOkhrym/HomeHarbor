"""Public diagnostics and real packet probes for the optional native sandbox."""

import json
import subprocess

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


def probe(url):
    result = subprocess.run(
        [
            "/usr/bin/curl",
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
        # First prove the forbidden endpoint is alive INSIDE the private fixture.
        # A dead listener would make an external timeout a meaningless ACL result.
        flow.compose(
            "exec",
            "-T",
            "site",
            "wget",
            "-q",
            "-O",
            "/dev/null",
            "http://127.0.0.1:8081/",
            timeout=10,
        )
        named = probe("http://site.sandbox.home.arpa:8080/")
        direct = probe(f"http://{site}:8080/")
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
