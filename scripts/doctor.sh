#!/bin/sh
set -eu

profile=${1:-all}
case "$profile" in
    all|compose|ios)
        ;;
    *)
        printf 'usage: %s [all|compose|ios]\n' "$0" >&2
        exit 2
        ;;
esac

missing=0
for command_name in go git golangci-lint; do
    if command -v "$command_name" >/dev/null 2>&1; then
        printf '%s: %s\n' "$command_name" "$(command -v "$command_name")"
    else
        printf '%s: missing\n' "$command_name" >&2
        missing=1
    fi
done

if [ "$profile" = all ] || [ "$profile" = compose ]; then
    if command -v docker >/dev/null 2>&1; then
        printf 'docker: %s\n' "$(docker --version)"
        if docker compose version >/dev/null 2>&1; then
            printf 'docker compose: available\n'
        else
            printf 'docker compose: missing\n' >&2
            missing=1
        fi
        if docker info >/dev/null 2>&1; then
            printf 'docker daemon: available\n'
        else
            printf 'docker daemon: unavailable (start Docker before make dev-up)\n' >&2
            missing=1
        fi
    else
        printf 'docker: missing (required for local Compose)\n' >&2
        missing=1
    fi
fi

if [ "$profile" = all ]; then
    if command -v limactl >/dev/null 2>&1; then
        printf 'limactl: %s\n' "$(limactl --version | head -n 1)"
    else
        printf 'limactl: missing (optional until Linux network tests)\n'
    fi
fi

if [ "$profile" = all ] || [ "$profile" = ios ]; then
    if command -v xcodebuild >/dev/null 2>&1 && xcodebuild -version >/dev/null 2>&1; then
        printf 'xcodebuild: full Xcode available\n'
    else
        printf 'xcodebuild: full Xcode unavailable (required for iOS physical-device testing)\n' >&2
        missing=1
    fi
fi

exit "$missing"
