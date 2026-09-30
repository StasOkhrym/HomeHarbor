#!/bin/sh
set -eu

if [ -z "${TEST_DATABASE_URL:-}" ]; then
    echo "TEST_DATABASE_URL is required; use make integration-local for an isolated local database" >&2
    exit 2
fi

# This command intentionally does not start Compose or run migrations against
# an inferred URL. Callers own the database lifecycle and must opt into the
# exact database that the tests are allowed to mutate.
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test ./... -run 'Integration|Postgres|Contract|AdvisoryLock' -count=1
