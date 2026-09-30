#!/bin/sh
set -eu

# Rendering must be read-only: do not initialize keys, configs or secrets.
output=$(mktemp)
integration=$(mktemp)
trap 'rm -f "$output" "$integration"' EXIT
export CONTROL_DOMAIN="${CONTROL_DOMAIN:-control.localhost}"
export RELAY_DOMAIN="${RELAY_DOMAIN:-relay.localhost}"
export CADDYFILE=Caddyfile.local
export CONTROL_CONFIG="${CONTROL_CONFIG:-../config/control.example.toml}"
export RELAY_CONFIG="${RELAY_CONFIG:-../config/relay.example.toml}"
docker compose -f deploy/compose.yaml config --format json >"$output"
docker compose -f deploy/compose.integration.yaml config --format json >"$integration"

python3 - "$output" "$integration" <<'PY'
import json
import shlex
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    services = json.load(stream)["services"]
def secrets(service):
    return {item["source"] for item in service.get("secrets", [])}
expected_control = {
    "postgres_password", "redis_password", "session_signing_key",
    "ceremony_encryption_key", "relay_ticket_key", "root_public_key",
}
if secrets(services["control"]) != expected_control:
    raise SystemExit("control must receive exactly its runtime secrets")
if secrets(services["migrate"]) != {"postgres_password"}:
    raise SystemExit("migrate must receive only the database password")
if services["redis"].get("ports"):
    raise SystemExit("Redis must remain private in the deployment stack")
caddy = services["caddy"]
if set(caddy.get("cap_drop", [])) != {"ALL"} or set(caddy.get("cap_add", [])) != {"NET_BIND_SERVICE"}:
    raise SystemExit("caddy must drop all capabilities and add only NET_BIND_SERVICE")
with open(sys.argv[2], encoding="utf-8") as stream:
    integration = json.load(stream)["services"]
if set(integration) != {"postgres", "redis"}:
    raise SystemExit("integration stack must contain only PostgreSQL and Redis")
for name, service in integration.items():
    ports = service.get("ports", [])
    if not ports or any(port.get("host_ip") != "127.0.0.1" for port in ports):
        raise SystemExit(f"integration {name} ports must bind only to loopback")
for redis in (services["redis"], integration["redis"]):
    if secrets(redis) != {"redis_password"}:
        raise SystemExit("Redis must receive only its password secret")
    command = "\n".join(redis.get("command", []))
    tokens = shlex.split(command)
    for flag, value in (("--maxmemory", "128mb"), ("--maxmemory-policy", "noeviction"), ("--aclfile", "/tmp/users.acl")):
        if flag not in tokens or tokens[tokens.index(flag) + 1] != value:
            raise SystemExit(f"Redis must use {flag} {value}")
    if "/run/secrets/redis_password" not in command or "sha256sum" not in tokens:
        raise SystemExit("Redis ACL must hash the file credential")
    if str(redis.get("mem_limit")) != "268435456":
        raise SystemExit("Redis must have a 256 MiB container memory limit")
    health = " ".join(redis.get("healthcheck", {}).get("test", []))
    if "REDISCLI_AUTH" not in health or "/run/secrets/redis_password" not in health or "PONG" not in health:
        raise SystemExit("Redis healthcheck must authenticate and require PONG")
print("Compose SQL/Redis secret boundaries and limits are valid")
PY
