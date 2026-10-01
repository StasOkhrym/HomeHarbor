#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output=$(mktemp)
trap 'rm -f "$output"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# shellcheck disable=SC2086
set -- ${GO_PACKAGES:-./cmd/... ./internal/... ./migrations/...}
golangci-lint fmt --diff "$@" >"$output"
if test -s "$output"; then
    cat "$output"
    echo 'Run make fmt to format Go sources' >&2
    exit 1
fi
ruff format --no-cache --check scripts
npm run format:check
djlint internal/control/httpapi/templates --check
