#!/bin/sh
set -eu

docker compose -f deploy/compose.yaml config >/dev/null
go test ./... -run 'Integration|Postgres|Contract'
echo "integration prerequisites passed; external PostgreSQL/network namespace scenarios are not enabled by this command yet"
