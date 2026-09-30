#!/bin/sh
set -eu

command -v docker >/dev/null 2>&1 || {
    echo "docker is required; run make doctor-compose first" >&2
    exit 1
}
docker info >/dev/null 2>&1 || {
    echo "docker daemon is unavailable; start Docker before make integration-local" >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to encode the generated database password" >&2
    exit 1
}

./scripts/dev-init.sh >/dev/null

port=${INTEGRATION_POSTGRES_PORT:-55432}
case "$port" in
    ''|*[!0-9]*)
        echo "INTEGRATION_POSTGRES_PORT must be numeric" >&2
        exit 2
        ;;
esac
if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
    echo "INTEGRATION_POSTGRES_PORT must be between 1024 and 65535" >&2
    exit 2
fi

project="go-tunnels-integration-$$"
compose() {
    docker compose \
        --project-name "$project" \
        --file deploy/compose.yaml \
        --file deploy/compose.integration.yaml \
        "$@"
}

cleanup() {
    # This project name is unique to this process, so removing its volume
    # cannot touch the developer's normal Compose database.
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

INTEGRATION_POSTGRES_PORT="$port" compose up --detach --wait --wait-timeout 120 postgres
password=$(tr -d '[:space:]' < secrets/postgres_password)
database_url=$(python3 - "$password" "$port" <<'PY'
from urllib.parse import quote
import sys

password, port = sys.argv[1:]
print(f"postgres://go_tunnels:{quote(password, safe='')}@127.0.0.1:{port}/go_tunnels?sslmode=disable")
PY
)

TEST_DATABASE_URL="$database_url" ./scripts/integration.sh
