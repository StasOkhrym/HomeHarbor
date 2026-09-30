#!/bin/sh
set -eu

for name in TEST_DATABASE_URL TEST_REDIS_URL; do
    case "$name" in
        TEST_DATABASE_URL) value=${TEST_DATABASE_URL:-} ;;
        TEST_REDIS_URL) value=${TEST_REDIS_URL:-} ;;
    esac
    if [ -z "$value" ]; then
        printf '%s is required; use make integration-local for isolated SQL and Redis\n' "$name" >&2
        exit 2
    fi
done

# Explicit URLs authorize mutation of these test services. Never infer a
# deployment URL. Capture JSON without a pipe so go test failures survive.
output=$(mktemp)
trap 'rm -f "$output"' EXIT
status=0
go test -json ./internal/control/*/storage ./internal/control/identity/redis ./internal/app/control/storage ./internal/platform/events ./internal/platform/redissecurity ./migrations \
    -run 'Integration|Postgres|Redis|Contract|AdvisoryLock' -count=1 >"$output" || status=$?
python3 - "$output" "$status" <<'PY'
import json
import sys

passed = set()
adapters = set()
skipped = []
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    if event.get("Output"):
        print(event["Output"], end="")
    name = event.get("Test", "")
    package = event.get("Package", "")
    if event.get("Action") == "skip" and name:
        skipped.append(f"{package}/{name}")
    if event.get("Action") == "pass" and name and "/" not in name:
        if name.startswith("TestPostgres") and "/control/" in package:
            passed.add("PostgreSQL")
            if package.endswith("/storage"):
                adapters.add(package.split("/internal/", 1)[-1])
        if name.startswith("TestRedis") and package.endswith("/platform/redissecurity"):
            passed.add("Redis")
        if name == "TestRedisSessionSharedTTLAndRevoke" and package.endswith("/control/identity/redis"):
            passed.add("Redis browser sessions")
        if "AdvisoryLock" in name and package.endswith("/migrations"):
            passed.add("migration advisory lock")
status = int(sys.argv[2])
if status:
    raise SystemExit(status)
if skipped:
    raise SystemExit("Required integration tests skipped: " + ", ".join(skipped))
missing = {"PostgreSQL", "Redis", "Redis browser sessions", "migration advisory lock"} - passed
if missing:
    raise SystemExit("Required integration tests did not run: " + ", ".join(sorted(missing)))
required_adapters = {
    "control/" + module + "/storage" for module in
    ("audit", "devices", "identity", "invites", "policy", "routes", "services", "snapshots")
} | {"app/control/storage"}
missing_adapters = required_adapters - adapters
if missing_adapters:
    raise SystemExit("SQL adapters without executed contracts: " + ", ".join(sorted(missing_adapters)))
print("SQL, Redis and migration integration tests passed without skips")
PY
