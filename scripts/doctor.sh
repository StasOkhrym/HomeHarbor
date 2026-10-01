#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
profile=${1:-backend}
case "$profile" in
backend | compose | e2e | all) ;;
*)
    printf 'usage: %s [backend|compose|e2e|all]\n' "$0" >&2
    exit 2
    ;;
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
case "$profile" in
backend | all) for name in go git golangci-lint python3 node npm ruff djlint shellcheck yamllint sqlfluff hadolint; do require_command "$name"; done ;;
compose) for name in docker openssl python3; do require_command "$name"; done ;;
e2e) for name in go python3 curl; do require_command "$name"; done ;;
esac
if command -v python3 >/dev/null 2>&1; then
    version=$(python3 --version)
    version=${version#Python }
    major=${version%%.*}
    rest=${version#*.}
    minor=${rest%%.*}
    case "$major:$minor" in
    *[!0-9:]* | : | *:)
        echo 'Cannot determine Python version' >&2
        missing=1
        ;;
    *) if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 11 ]; }; then
        echo 'Python 3.11+ is required' >&2
        missing=1
    fi ;;
    esac
fi
case "$profile" in
compose | all)
    if [ "$profile" = all ]; then
        require_command docker
        require_command openssl
    fi
    if command -v docker >/dev/null 2>&1; then
        if ! docker compose version >/dev/null 2>&1; then
            echo 'docker compose: missing' >&2
            missing=1
        fi
        if ! docker info >/dev/null 2>&1; then
            echo 'docker daemon: unavailable; start Docker' >&2
            missing=1
        fi
    fi
    ;;
esac
case "$profile" in
e2e | all)
    if [ "$profile" = all ]; then require_command curl; fi
    if [ "$(uname -s)" = Linux ]; then
        for name in ip nft wg systemctl resolvectl; do require_command "$name"; done
        if [ "$(id -u)" -ne 0 ]; then
            echo 'Linux acceptance requires root in a disposable VM' >&2
            missing=1
        fi
        if command -v systemctl >/dev/null 2>&1 && ! systemctl is-active --quiet systemd-resolved; then
            echo 'Real systemd-resolved must be running' >&2
            missing=1
        fi
    else
        for name in limactl ssh; do require_command "$name"; done
    fi
    ;;
esac
exit "$missing"
