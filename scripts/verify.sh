#!/bin/sh
set -eu

formatted=$(gofmt -l cmd internal migrations)
test -z "$formatted" || {
    echo "Go files are not formatted" >&2
    printf '%s\n' "$formatted" >&2
    exit 1
}
go test ./...
go vet ./...
go build ./cmd/...
