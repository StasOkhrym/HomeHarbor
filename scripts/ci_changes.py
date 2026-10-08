"""Select fixed CI gates; uncertainty always requests the complete backend gate."""

import json
import os
import subprocess

GATES = ("fast", "integration", "network", "fuzz", "vulnerability", "compose")
PROTECTED = (
    "internal/node/",
    "internal/agent/",
    "internal/tunnel/",
    "internal/companion/",
    "internal/invite/",
    "internal/snapshot/",
    "internal/protocol/",
    "internal/relay/",
    "internal/app/control/",
    "internal/app/node/",
    "internal/app/relay/",
    "internal/acceptance/",
    "internal/platform/redissecurity/",
    *(
        f"internal/control/{module}/"
        for module in (
            "identity",
            "devices",
            "routes",
            "policy",
            "profiles",
            "services",
            "invites",
            "snapshots",
            "coordination",
            "audit",
            "httpapi",
            "transactions",
            "workflows",
        )
    ),
)


def classify(paths: list[str], base_available: bool, full: bool) -> dict[str, bool]:
    enabled = set()
    if full or not base_available:
        return dict.fromkeys(GATES, True)
    for path in paths:
        if path == "README.md" or path.startswith("docs/") and path.endswith(".md"):
            continue
        if path.startswith(
            ("internal/control/httpapi/static/", "internal/control/httpapi/templates/")
        ):
            enabled.add("fast")
            continue
        compose = path.startswith(("deploy/", ".github/workflows/"))
        migration = path.startswith("migrations/")
        protected = path.startswith(PROTECTED)
        if not (compose or migration or protected):
            # Shared tooling/dependencies and unclassified runtime files fail safe.
            return dict.fromkeys(GATES, True)
        enabled.add("fast")
        # Categories overlap: signed-state/session storage needs both durable
        # contracts and protected networking/security gates, never just one.
        if (
            compose
            or migration
            or "/storage/" in path
            or "/redis" in path
            or path.startswith(("internal/control/workflows/", "internal/control/transactions/"))
        ):
            enabled.add("integration")
        if compose:
            enabled.add("compose")
        enabled.update(("network", "fuzz", "vulnerability"))
    return {gate: gate in enabled for gate in GATES}


def parse_changes(data: bytes) -> list[str]:
    fields = data.decode("utf-8", errors="strict").split("\0")
    if fields.pop() != "":
        raise ValueError("unterminated git diff")

    paths = []
    while fields:
        status = fields.pop(0)
        if not status or status[0] not in "ACDMRTUXB":
            raise ValueError("invalid git diff status")

        count = 2 if status[0] in "RC" else 1
        if len(fields) < count or any(not path for path in fields[:count]):
            raise ValueError("incomplete git diff")

        paths.extend(fields[:count])
        del fields[:count]

    return paths


def main() -> None:
    base = os.environ.get("CI_BASE", "")
    valid = (
        len(base) == 40 and all(char in "0123456789abcdef" for char in base) and base != "0" * 40
    )
    paths = []
    if valid:
        result = subprocess.run(
            ["git", "diff", "--name-status", "-z", "--find-renames", base, "HEAD", "--"],
            capture_output=True,
        )
        valid = result.returncode == 0
        if valid:
            try:
                paths = parse_changes(result.stdout)
            except (ValueError, UnicodeError):
                valid = False

    print(json.dumps(classify(paths, valid, os.environ.get("CI_FULL") == "true")))


if __name__ == "__main__":
    main()
