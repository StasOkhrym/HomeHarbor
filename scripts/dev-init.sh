#!/bin/sh
set -eu

mkdir -p .local secrets

control_domain=${CONTROL_DOMAIN:-control.localhost}
relay_domain=${RELAY_DOMAIN:-relay.localhost}

if [ ! -f .local/control.toml ]; then
	cp config/control.example.toml .local/control.toml
	sed -i.bak \
	    -e "s/tunnel.example.com/$control_domain/g" \
	    -e "s/relay.example.com/$relay_domain/g" \
	    .local/control.toml
	rm -f .local/control.toml.bak
fi
if [ ! -f .local/relay.toml ]; then
	cp config/relay.example.toml .local/relay.toml
fi

create_secret() {
    path=$1
    bytes=$2
    if [ ! -f "$path" ]; then
        umask 077
        openssl rand -base64 "$bytes" | tr -d '\n' > "$path"
    fi
    chmod 0600 "$path"
}

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to initialize local secrets" >&2
    exit 1
}

create_secret secrets/postgres_password 32
create_secret secrets/relay_ticket_key 32
create_secret secrets/session_signing_key 48
create_secret secrets/ceremony_encryption_key 24

echo "local configuration and secrets are ready"
