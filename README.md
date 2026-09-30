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
- Go-template device/route dashboard with self-hosted assets, structured logs,
  health endpoints, and metrics.
- Passkey bootstrap/login, signed server-side sessions, one-time recovery codes,
  strict Origin checks, CSRF protection, and identity audit events.
- Docker Compose/Caddy and Ansible deployment scaffolding.
- Thin `cmd/*` entrypoints with shared `internal/app/*` runtimes and a minimal
  `Run(context.Context) error` lifecycle contract.
- Signed invite proofs with device-key possession, trusted-companion approval,
  PostgreSQL pending state, and age-encrypted local root-key storage.
- Short-lived device credentials with atomic rotation and explicit trusted
  proxy handling for rate limits.
- Relay-only encrypted packet bridge with reconnect/backoff, live signed
  snapshot broadcast, strict snapshot-chain verification, and targeted
  authorized candidate messages.
- Local developer workflow: `make doctor`, `make dev-init`, `make dev-up`,
  `make dev-down`, `make vm-up`, `make relay-acceptance`, `make verify`.

## Not yet complete

- Privileged Linux network-namespace acceptance of the interface/route and
  nftables policy is wired in `internal/acceptance`; it still requires the
  Lima Linux VM (and root/CAP_NET_ADMIN) to execute.
- End-to-end LAN-service acceptance through the kernel WireGuard path; the
  current relay bridge is a transport slice, not yet the complete VPN product.
- Direct UDP handshake/path switching and STUN-driven roaming.
- PostgreSQL integration tests and the Linux network-namespace acceptance
  harness are present; they require an explicit database URL and Linux VM.
- Signed iOS target configuration, WireGuardKit integration, and physical-device
  Packet Tunnel verification. A native source scaffold is in `apps/ios/`.

## Development

Requires Go 1.27.1+.

```sh
go test ./...
go vet ./...
go build ./cmd/...
make lint       # check lint, imports, and formatting
make lint-fix   # apply the configured safe formatting fixes
```

The repository pins the golangci-lint v2 configuration in
[`.golangci.yml`](.golangci.yml). `gofumpt`, `gci`, and `goimports` are configured
as formatters so editors, local checks, and CI agree on spacing and import
groups. The regular `make lint` check never mutates the working tree.

Architectural conventions and the ordered next steps are documented in
[`docs/roadmap.md`](docs/roadmap.md). In particular, the planned HTTP router is
chi, while module consumers continue to depend on narrow interfaces rather than
a framework or a single god-service interface.

For a local deployment, run `make dev-init` and `make dev-up`. The Compose
stack runs migrations as a separate one-shot service before control starts.
Use `make dev-trust-ca` only for Linux test devices. Production certificates
must come from the reverse proxy's real DNS-01 setup.

`make relay-acceptance` runs the portable authenticated relay-only vertical
slice. `make acceptance` runs that test first and then executes the Linux
namespace scenario directly on Linux or through the `go-tunnels-vm` Lima
instance on macOS. Start that VM with `make vm-up`; set `LIMA_INSTANCE` when
using a different instance name.

Both authentication key files must contain random values: at least 32 bytes for
the session signing key and exactly 32 bytes for the ceremony encryption key.
Open `/admin/login` on the configured HTTPS origin to register the first
passkey. Bootstrap closes after that credential is stored. Save the recovery
codes shown once by the bootstrap response; the database contains only their
hashes, and each code is consumed atomically on first use.

The control plane stores public keys, credential hashes, policies, and session
metadata. Private identity/WireGuard keys remain in local `0600` state files.
The relay forwards opaque WireGuard ciphertext. Default policy is deny.
