#!/bin/sh
set -eu

test -f .local/caddy-local-root.crt || docker compose -f deploy/compose.yaml cp caddy:/data/caddy/pki/authorities/local/root.crt .local/caddy-local-root.crt
chmod 0644 .local/caddy-local-root.crt
echo "Caddy local CA copied to .local/caddy-local-root.crt"
echo "Install this certificate only on test devices; never use it for production."
