#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python_command=${PYTHON:-python3}
make lint
"$python_command" -m unittest discover -s scripts/tests
node --test internal/web/assets/tests/browser.test.cjs
# Package scope comes from Make; direct script invocation has the same fallback.
# shellcheck disable=SC2086
set -- ${GO_PACKAGES:-./cmd/... ./internal/... ./migrations/...}
go test -race "$@" -count=1 -timeout=90s
go build ./cmd/...
if [ "${FULL:-0}" = 1 ]; then
    make integration security
    "$python_command" scripts/compose_check.py
    make acceptance
fi
