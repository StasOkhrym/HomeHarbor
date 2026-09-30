#!/bin/sh
set -eu

postgres_port=${INTEGRATION_POSTGRES_PORT:-55432}
redis_port=${INTEGRATION_REDIS_PORT:-56379}
validate_port() {
    case "$2" in
        ''|*[!0-9]*) printf '%s must be numeric\n' "$1" >&2; exit 2 ;;
    esac
    if [ "$2" -lt 1024 ] || [ "$2" -gt 65535 ]; then
        printf '%s must be between 1024 and 65535\n' "$1" >&2; exit 2
    fi
}
validate_port INTEGRATION_POSTGRES_PORT "$postgres_port"
validate_port INTEGRATION_REDIS_PORT "$redis_port"
if [ "$postgres_port" = "$redis_port" ]; then
    echo 'SQL and Redis ports must differ' >&2; exit 2
fi
for name in docker openssl python3; do
    command -v "$name" >/dev/null 2>&1 || { printf '%s is required\n' "$name" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo 'Docker daemon is unavailable; start Docker' >&2; exit 1; }

# Independent of .local, trust keys and deployment secrets.
umask 077
INTEGRATION_SECRETS_DIR=$(mktemp -d)
INTEGRATION_POSTGRES_PORT=$postgres_port
INTEGRATION_REDIS_PORT=$redis_port
export INTEGRATION_SECRETS_DIR INTEGRATION_POSTGRES_PORT INTEGRATION_REDIS_PORT
project="go-tunnels-integration-$$"
compose() {
    docker compose --project-name "$project" --file deploy/compose.integration.yaml "$@"
}
cleanup() {
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -f "$INTEGRATION_SECRETS_DIR/postgres_password" "$INTEGRATION_SECRETS_DIR/redis_password"
    rmdir "$INTEGRATION_SECRETS_DIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for name in postgres redis; do
    openssl rand -base64 32 | tr -d '\n' >"$INTEGRATION_SECRETS_DIR/${name}_password"
done
compose up --detach --wait --wait-timeout 120 postgres redis

TEST_DATABASE_URL=$(python3 - "$INTEGRATION_SECRETS_DIR/postgres_password" "$postgres_port" <<'PY'
from pathlib import Path
from urllib.parse import quote
import sys
password = quote(Path(sys.argv[1]).read_text().strip(), safe="")
print(f"postgres://go_tunnels:{password}@127.0.0.1:{sys.argv[2]}/go_tunnels?sslmode=disable")
PY
)
TEST_REDIS_URL=$(python3 - "$INTEGRATION_SECRETS_DIR/redis_password" "$redis_port" <<'PY'
from pathlib import Path
from urllib.parse import quote
import sys
password = quote(Path(sys.argv[1]).read_text().strip(), safe="")
print(f"redis://:{password}@127.0.0.1:{sys.argv[2]}/0")
PY
)
export TEST_DATABASE_URL TEST_REDIS_URL
./scripts/integration.sh
