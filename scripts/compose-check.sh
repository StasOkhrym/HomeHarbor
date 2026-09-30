#!/bin/sh
set -eu

# Render the same Compose file used by local development before starting any
# service. This catches accidental secret-boundary regressions that a YAML
# parser alone cannot see: control needs runtime credentials, while migrate
# must receive only the database password.
./scripts/dev-init.sh >/dev/null

output=$(mktemp)
trap 'rm -f "$output"' EXIT
CONTROL_DOMAIN="${CONTROL_DOMAIN:-control.localhost}" \
RELAY_DOMAIN="${RELAY_DOMAIN:-relay.localhost}" \
CADDYFILE=Caddyfile.local \
CONTROL_CONFIG=../.local/control.toml \
RELAY_CONFIG=../.local/relay.toml \
    docker compose -f deploy/compose.yaml config --format json >"$output"

python3 - "$output" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)

services = document["services"]
control = {item["source"] for item in services["control"]["secrets"]}
migrate = {item["source"] for item in services["migrate"]["secrets"]}
expected_control = {
    "postgres_password",
    "session_signing_key",
    "ceremony_encryption_key",
    "relay_ticket_key",
    "root_public_key",
}
expected_migrate = {"postgres_password"}
if control != expected_control:
    raise SystemExit(f"control secrets = {sorted(control)}, want {sorted(expected_control)}")
if migrate != expected_migrate:
    raise SystemExit(f"migrate secrets = {sorted(migrate)}, want {sorted(expected_migrate)}")
print("Compose secret boundaries are valid")
PY
