# Go Tunnels

Self-hosted homelab tunnel built around a Go modular monolith, WireGuard,
direct UDP discovery, and an encrypted relay fallback.

> [!WARNING]
> This repository is an early MVP foundation. It has not received an external
> security audit and is **not production-ready VPN software**.

## Implemented

- Go control-plane and relay entrypoints.
- PostgreSQL migrations and repositories for devices, credentials, routes,
  split DNS, policies, audit events, recovery codes, and WebAuthn credentials.
- Single-use enrollment tokens; device and WireGuard private keys stay local.
- Versioned JSON API and authenticated WebSocket coordination snapshots.
- Default-deny policy compiler and atomic nftables ruleset generator.
- WireGuard key/config adapters, STUN discovery, path selector, relay tickets,
  packet framing, and an in-memory live relay hub.
- HTMX device/route dashboard, structured logs, health endpoints, and metrics.
- Passkey bootstrap/login, signed server-side sessions, one-time recovery codes,
  strict Origin checks, CSRF protection, and identity audit events.
- Docker Compose/Caddy and Ansible deployment scaffolding.

## Not yet complete

- Device credential rotation and refresh before the 24-hour credential expiry.
- Full Linux interface/route lifecycle, nftables apply/rollback, and
  systemd-resolved split-DNS lifecycle.
- End-to-end live WireGuard transport and direct/relay roaming.
- PostgreSQL integration and Linux network-namespace acceptance tests.
- Android and iOS clients.

## Development

Requires Go 1.27.1+.

```sh
go test ./...
go vet ./...
go build ./cmd/...
```

Architectural conventions and the ordered next steps are documented in
[`docs/roadmap.md`](docs/roadmap.md). In particular, the planned HTTP router is
chi, while module consumers continue to depend on narrow interfaces rather than
a framework or a single god-service interface.

For a local deployment, copy `config/*.example.toml` to their non-example
names, create `secrets/postgres_password`, `secrets/relay_ticket_key`,
`secrets/session_signing_key`, and `secrets/ceremony_encryption_key`, then
run `docker compose -f deploy/compose.yaml up --build` with `CONTROL_DOMAIN`
and `RELAY_DOMAIN` set.

Both authentication key files must contain random values: at least 32 bytes for
the session signing key and exactly 32 bytes for the ceremony encryption key.
Open `/admin/login` on the configured HTTPS origin to register the first
passkey. Bootstrap closes after that credential is stored. Save the recovery
codes shown once by the bootstrap response; the database contains only their
hashes, and each code is consumed atomically on first use.

The control plane stores public keys, credential hashes, policies, and session
metadata. Private identity/WireGuard keys remain in local `0600` state files.
The relay forwards opaque WireGuard ciphertext. Default policy is deny.
