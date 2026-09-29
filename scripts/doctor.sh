#!/bin/sh
set -eu

missing=0
for command_name in go git golangci-lint; do
    if command -v "$command_name" >/dev/null 2>&1; then
        printf '%s: %s\n' "$command_name" "$(command -v "$command_name")"
    else
        printf '%s: missing\n' "$command_name" >&2
        missing=1
    fi
done

if command -v docker >/dev/null 2>&1; then
    printf 'docker: %s\n' "$(docker --version)"
    if docker compose version >/dev/null 2>&1; then
        printf 'docker compose: available\n'
    else
        printf 'docker compose: missing\n' >&2
        missing=1
    fi
else
    printf 'docker: missing (required for local Compose)\n' >&2
    missing=1
fi

if command -v limactl >/dev/null 2>&1; then
    printf 'limactl: %s\n' "$(limactl --version | head -n 1)"
else
    printf 'limactl: missing (optional until Linux network tests)\n'
fi

if command -v xcodebuild >/dev/null 2>&1; then
    printf 'xcodebuild: available\n'
else
    printf 'xcodebuild: missing (required for iOS physical-device testing)\n'
fi

exit "$missing"
