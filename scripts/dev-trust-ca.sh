#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
test -s secrets/relay_tls_ca || {
    echo 'Run make dev-up first' >&2
    exit 2
}

if [ "$(uname -s)" = Darwin ]; then
    # Trust is an explicit operator action, never a side effect of starting up.
    security add-trusted-cert -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "$(pwd)/secrets/relay_tls_ca"
else
    printf 'Install this test CA in your browser/system: %s/secrets/relay_tls_ca\n' "$(pwd)"
fi
