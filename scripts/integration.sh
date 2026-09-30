#!/bin/sh
set -eu

if [ -z "${TEST_DATABASE_URL:-}" ]; then
    echo "TEST_DATABASE_URL is required; integration tests never guess or mutate a database" >&2
    exit 2
fi

CONTROL_DOMAIN="${CONTROL_DOMAIN:-control.localhost}" \
RELAY_DOMAIN="${RELAY_DOMAIN:-relay.localhost}" \
	docker compose -f deploy/compose.yaml config >/dev/null
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test ./... -run 'Integration|Postgres|Contract' -count=1
