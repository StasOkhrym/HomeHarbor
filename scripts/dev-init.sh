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
	sed -i.bak -e "s/relay.example.com/$relay_domain/g" .local/relay.toml
	rm -f .local/relay.toml.bak
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

require_secret_length() {
    path=$1
    expected=$2
    actual=$(wc -c <"$path" | tr -d '[:space:]')
    if [ "$actual" -ne "$expected" ]; then
        echo "$path must contain exactly $expected bytes (found $actual); restore it or remove it to regenerate local state" >&2
        exit 1
    fi
}

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to initialize local secrets" >&2
    exit 1
}

create_secret secrets/postgres_password 32
create_secret secrets/redis_password 32
create_secret secrets/relay_ticket_key 32
create_secret secrets/session_signing_key 48
create_secret secrets/ceremony_encryption_key 24

# These files are base64 text generated above. Checking their encoded lengths
# catches truncated mounts and accidental empty files before Compose starts a
# control process that can never pass its authentication validation.
require_secret_length secrets/postgres_password 44
require_secret_length secrets/redis_password 44
require_secret_length secrets/relay_ticket_key 44
require_secret_length secrets/session_signing_key 64
require_secret_length secrets/ceremony_encryption_key 32

# Local-only backend CA. Production receives operator-provisioned TLS files;
# dev-init never rotates existing material or repairs a half-written key pair.
if [ ! -f secrets/relay_tls_ca ] && [ ! -f secrets/relay_tls_cert ] && [ ! -f secrets/relay_tls_key ]; then
    if [ -e .local/relay-ca-key.pem ]; then
        echo 'Existing local relay CA key without its certificates; restore the TLS files before retrying' >&2
        exit 1
    fi
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 \
        -subj '/CN=Go Tunnels Local Relay CA' \
        -keyout .local/relay-ca-key.pem -out secrets/relay_tls_ca >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -sha256 -subj '/CN=relay' \
        -keyout secrets/relay_tls_key -out .local/relay-tls.csr >/dev/null 2>&1
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' \
        'subjectAltName=DNS:relay,DNS:localhost,IP:127.0.0.1' > .local/relay-tls.ext
    openssl x509 -req -days 365 -sha256 -in .local/relay-tls.csr \
        -CA secrets/relay_tls_ca -CAkey .local/relay-ca-key.pem -set_serial 2 \
        -extfile .local/relay-tls.ext -out secrets/relay_tls_cert >/dev/null 2>&1
fi
for path in secrets/relay_tls_ca secrets/relay_tls_cert secrets/relay_tls_key; do
    if [ ! -s "$path" ]; then
        echo "Missing relay TLS file $path; restore the complete existing set" >&2
        exit 1
    fi
done
chmod 0600 secrets/relay_tls_key
chmod 0644 secrets/relay_tls_cert secrets/relay_tls_ca

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
if [ ! -s .local/root-passphrase ]; then
    echo "local companion root passphrase is missing; restore .local/root-passphrase before using the existing root key" >&2
    exit 1
fi
chmod 0600 .local/root-passphrase
if [ -e secrets/root_public_key ]; then
    if ! cmp -s .local/root-public.key secrets/root_public_key; then
        echo "secrets/root_public_key differs from .local/root-public.key; restore the matching trust anchor before initializing" >&2
        exit 1
    fi
else
    cp .local/root-public.key secrets/root_public_key
fi
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

# Upgrade ignored local configs only when this script is explicitly run.
# Keep existing Redis settings and trust keys intact.
if ! grep -Eq '^[[:space:]]*\[redis\][[:space:]]*(#.*)?$' .local/control.toml; then
    printf '\n%s\n' '[redis]' 'url = "redis://redis:6379/0"' \
        'password_file = "/run/secrets/redis_password"' >> .local/control.toml
fi

echo "local configuration and secrets are ready"
