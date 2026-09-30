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
if [ ! -f .local/admin.toml ]; then
	cp config/admin.example.toml .local/admin.toml
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

# The trusted companion owns the encrypted root key. Compose receives only its
# public half, so the control plane can verify signed snapshots without gaining
# the ability to mint one. If one half is missing, stop instead of generating
# a replacement trust anchor that would strand already-paired gateways.
if [ ! -f .local/root-key.age ] && [ ! -f .local/root-public.key ]; then
    command -v go >/dev/null 2>&1 || {
        echo "go is required to initialize the local companion root key" >&2
        exit 1
    }
    create_secret .local/root-passphrase 32
    go run ./cmd/admin init-root \
        -key .local/root-key.age \
        -passphrase-file .local/root-passphrase \
        > .local/root-public.key
    chmod 0644 .local/root-public.key
fi
if [ ! -f .local/root-key.age ] || [ ! -f .local/root-public.key ]; then
    echo "local companion root key is incomplete; restore both .local/root-key.age and .local/root-public.key" >&2
    exit 1
fi
cp .local/root-public.key secrets/root_public_key
chmod 0644 secrets/root_public_key

# These local-only substitutions make the one-shot companion commands point at
# the same Caddy origin and key files as Compose, without changing tracked
# example configuration or placing passphrases in command-line arguments.
sed -i.bak \
    -e 's|^# passphrase_file = .*|passphrase_file = ".local/root-passphrase"|' \
    -e 's|^root_key_file = .*|root_key_file = ".local/root-key.age"|' \
    -e "s|^endpoint = .*|endpoint = \"https://$control_domain\"|" \
    -e "s|^base_url = .*|base_url = \"https://$control_domain/invite\"|" \
    -e 's|^# snapshot_manifest_file = .*|snapshot_manifest_file = ".local/initial-snapshot.toml"|' \
    -e 's|^invite_attempts_file = .*|invite_attempts_file = ".local/invite-attempts.json"|' \
    .local/admin.toml
rm -f .local/admin.toml.bak

if ! grep -q '^snapshot_manifest_file[[:space:]]*=' .local/admin.toml; then
    printf '%s\n' 'snapshot_manifest_file = ".local/initial-snapshot.toml"' >> .local/admin.toml
fi
if ! grep -q '^invite_attempts_file[[:space:]]*=' .local/admin.toml; then
    printf '%s\n' 'invite_attempts_file = ".local/invite-attempts.json"' >> .local/admin.toml
fi

if [ ! -f .local/initial-snapshot.toml ]; then
    cp config/initial-snapshot.example.toml .local/initial-snapshot.toml
fi

# Enable signed snapshot verification in the local control config. Existing
# local config is edited in place only for this mandatory secret reference.
sed -i.bak \
    -e 's|^# root_public_key_file = .*|root_public_key_file = "/run/secrets/root_public_key"|' \
    .local/control.toml
rm -f .local/control.toml.bak

echo "local configuration and secrets are ready"
