#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
RUNTIME_UID=$(id -u)
RUNTIME_GID=$(id -g)
export RUNTIME_UID RUNTIME_GID
test "$RUNTIME_UID" -ne 0 || {
    echo 'Run local development as a non-root user' >&2
    exit 2
}
export PROXY_BIND_ADDRESS=127.0.0.1
export PROXY_HTTP_PORT="${DEV_HTTP_PORT:-8088}"
export PROXY_HTTPS_PORT="${DEV_HTTPS_PORT:-8443}"
export CONTROL_CONFIG=../.local/control.toml RELAY_CONFIG=../.local/relay.toml
export TRAEFIK_CONFIG=./traefik/local.toml
export TRAEFIK_DYNAMIC_DIR=../.local/traefik/dynamic TRAEFIK_STATE_DIR=../.local/traefik/state

compose() { docker compose -f deploy/compose.yaml -f deploy/compose.local.yaml "$@"; }
case "${1:-}" in
up)
    sh scripts/doctor.sh compose
    python3 scripts/dev_init.py
    # A failed build leaves the running stack available. Recreate only
    # after validation/build; retain DB volumes and migration dependencies.
    compose config --quiet
    compose build
    compose up -d --force-recreate --remove-orphans --wait --wait-timeout 180
    printf '\nBackend ready: https://%s:%s/admin/login\n' "${CONTROL_DOMAIN:-control.localhost}" "$PROXY_HTTPS_PORT"
    ;;
down) compose down --remove-orphans ;;
logs) compose logs --follow --tail 100 ;;
*)
    echo 'usage: scripts/dev.sh up|down|logs' >&2
    exit 2
    ;;
esac
