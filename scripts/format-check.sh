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
formatter_status=0
golangci-lint fmt --diff "$@" >"$output" || formatter_status=$?
if test -s "$output"; then
    cat "$output"
    if test "$formatter_status" -le 1; then
        echo 'Run make fmt to format Go sources' >&2
        exit 1
    fi
fi
if test "$formatter_status" -ne 0; then
    exit "$formatter_status"
fi
ruff format --no-cache --check scripts
npm run format:check
djlint internal/web/assets/templates --check
