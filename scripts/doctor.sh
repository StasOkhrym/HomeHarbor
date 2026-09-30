#!/bin/sh
set -eu

profile=${1:-backend}
case "$profile" in
    backend|compose|e2e|ios|all) ;;
    *) printf 'usage: %s [backend|compose|e2e|ios|all]\n' "$0" >&2; exit 2 ;;
esac

missing=0
require_command() {
    if command -v "$1" >/dev/null 2>&1; then
        printf '%s: %s\n' "$1" "$(command -v "$1")"
    else
        printf '%s: missing (profile %s)\n' "$1" "$profile" >&2
        missing=1
    fi
}
if [ "$profile" != ios ]; then
    for name in go git golangci-lint python3; do require_command "$name"; done
fi
case "$profile" in
    compose|e2e|all)
        require_command docker
        require_command openssl
        if command -v docker >/dev/null 2>&1; then
            if ! docker compose version >/dev/null 2>&1; then
                printf 'docker compose: missing\n' >&2; missing=1
            fi
            if ! docker info >/dev/null 2>&1; then
                printf 'docker daemon: unavailable; start Docker\n' >&2; missing=1
            fi
        fi
        ;;
esac
case "$profile" in
    e2e|all)
        for name in limactl curl ssh; do require_command "$name"; done
        ;;
esac
case "$profile" in
    ios|all)
        if command -v xcodebuild >/dev/null 2>&1 && xcodebuild -version >/dev/null 2>&1; then
            printf 'xcodebuild: full Xcode available\n'
        else
            printf 'xcodebuild: full Xcode unavailable (required for iOS builds)\n' >&2
            missing=1
        fi
        ;;
esac
exit "$missing"
