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
- CSRF-protected admin forms for enrollment invites, device revoke, route
  advertisement/approval, service/access-profile creation, and advanced policy
  replacement.
- Read-only admin audit API (`/api/v1/admin/audit`) and recent-activity view;
  audit writes remain owned by durable domain/auth event consumers.
- Device-authenticated service catalog (`/api/v1/services/available`) filtered
  by explicit access-profile membership; an unassigned device receives no
  service tiles.
- Passkey bootstrap/login, signed server-side sessions, one-time recovery codes,
  strict Origin checks, CSRF protection, and identity audit events.
- Docker Compose/Caddy and Ansible deployment scaffolding.
- Thin `cmd/*` entrypoints with shared `internal/app/*` runtimes and a minimal
  `Run(context.Context) error` lifecycle contract.
- Agent and client now share `internal/app/node.App`; transport functions are
  adapted to the same lifecycle contract before the role-specific wiring runs.
- Signed invite proofs with device-key possession, trusted-companion approval,
  PostgreSQL pending state, atomic device/profile activation, and
  age-encrypted local root-key storage. The proof carries only the public
  WireGuard key; private keys remain on the enrolling node.
- Short-lived device credentials with atomic rotation and explicit trusted
  proxy handling for rate limits.
- Invite code approval is fail-closed after five invalid attempts. The CLI
  stores only an invite-ID counter in a local `0600` state file; the plaintext
  code and its digest never leave the trusted companion.
- Relay-only encrypted packet bridge with reconnect/backoff, live signed
  snapshot broadcast, strict snapshot-chain verification, and targeted
  authorized candidate messages.
- Versioned `udp_pair_v1` relay ingress with peer-bound tickets, bounded
  sessions, NAT rebinding, opaque forwarding, and WebSocket compatibility.
- Signed snapshot profiles can declare explicit `ACLRuleIDs`; trusted
  companion activation copies only those declared templates to the new device,
  while profiles without templates remain default-deny.
- Enrollment, route advertisements, invite proofs, signed snapshot routes, and
  policy rules reject malformed keys, default routes, unsafe DNS suffixes, and
  duplicate ACL identities at their respective trust boundaries.
- Overlay identities can be allocated from bounded RFC1918/CGNAT pools with
  collision, default-route, public-range, and exhaustion checks.
- Companion onboarding is explicitly two-step: `admin approve` activates the
  device, then repeatable `admin publish-snapshot` signs and publishes its
  profile diff through a single-use challenge-bound endpoint.
- Data-plane revoke is a separate trusted-companion operation: `admin
  revoke-device` signs an exact client removal and publishes it as the next
  snapshot revision. The web/API device revoke still disables credentials;
  run both operations when removing an already-connected client.
- Snapshot topology compilation now produces deterministic WireGuard peer
  allowed-prefixes while keeping relay/direct endpoint ownership separate.
- Local developer workflow: `make doctor-compose`, `make dev-init`, `make dev-up`,
  `make dev-down`, `make integration-local`, `make vm-up`,
  `make relay-acceptance`, `make verify`.

## Not yet complete

- External NAT traversal and roaming acceptance across two independent
  networks.
- PostgreSQL integration tests pass through `make integration-local` with
  Docker or through `make integration` with an explicit database URL; the
  Linux namespace acceptance covers kernel WireGuard plus allowed HTTP/SSH
  service reachability and forbidden-port default-deny behavior. The complete
  local Compose stack has also been verified through control, relay, Caddy,
  migrations, and readiness checks.
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
make vulncheck  # run the Go vulnerability database scan
make ios-source-check  # compile unsigned iOS package targets on a full Xcode host
```

After approval, publish the signed network diff with a configured overlay pool:

```sh
go run ./cmd/admin publish-snapshot \
  -endpoint https://control.example \
  -invite INVITE_ID \
  -overlay-pool 10.200.0.0/24 \
  -key state/root-key.age \
  -passphrase-file state/root-passphrase
```

To remove a client from the signed data-plane policy, use the trusted
companion while the control plane is reachable:

```sh
go run ./cmd/admin revoke-device \
  -endpoint https://control.example \
  -device DEVICE_ID \
  -key state/root-key.age \
  -passphrase-file state/root-passphrase
```

This command rejects gateway IDs and does not alter routes. It must be paired
with the normal admin/API device revoke so future credential authentication is
also stopped. A gateway applies the signed removal even if control later goes
offline, which closes the old-snapshot access window for that client.

The publish step is retryable and requires the trusted root key. The control
plane accepts snapshot reads only after a nonce-bound companion signature; it
does not expose the signed snapshot as a public endpoint.

The one-shot companion commands also accept `-config .local/admin.toml`; use
[`config/admin.example.toml`](config/admin.example.toml) as the starting point.
The passphrase remains a separate `0600` file referenced by
`passphrase_file`, never a TOML value or command-line argument.

On a fresh network, enroll the Linux gateway with a gateway enrollment token,
create the matching service and access profile in the admin UI, then copy its
public keys and the approved route/profile data into
[`config/initial-snapshot.example.toml`](config/initial-snapshot.example.toml).
Publish revision one from the trusted Mac companion:

```sh
go run ./cmd/admin init-snapshot \
  -config .local/admin.toml \
  -manifest config/initial-snapshot.toml
```

The command signs locally and the control plane accepts it only when no signed
snapshot exists. Later changes use the constrained invite/revoke commands, so
this bootstrap command cannot reset an established revision chain.

The repository pins the golangci-lint v2 configuration in
[`.golangci.yml`](.golangci.yml). `gofumpt`, `gci`, and `goimports` are configured
as formatters so editors, local checks, and CI agree on spacing and import
groups. The regular `make lint` check never mutates the working tree.

Architectural conventions and the ordered next steps are documented in
[`docs/roadmap.md`](docs/roadmap.md). In particular, the planned HTTP router is
chi, while module consumers continue to depend on narrow interfaces rather than
a framework or a single god-service interface.

For a local deployment, run `make dev-init` and `make dev-up`. The Compose
stack runs migrations as a separate one-shot service before control starts and
uses a Caddy internal CA selected only by the `dev-up` target. Use
`make dev-trust-ca` only for Linux test devices. Production Compose uses the
default Caddyfile, where certificates must come from the reverse proxy's real
DNS-01 setup.

`make dev-init` also creates the local age-encrypted companion root key and
mounts only its public key into control. The migration container receives only
the PostgreSQL password. `make compose-check` renders Compose and verifies
these secret boundaries before a developer starts the stack; initialization
also fails early when a local secret or the companion passphrase is truncated.
`make deploy-check` validates the Ansible bundle source paths and required
deployment files before a VPS rollout.

`make relay-acceptance` runs the portable authenticated relay-only vertical
slice through the production relay app and node bridge. `make acceptance` runs
those tests first and then executes the Linux namespace scenario directly on
Linux or through the `go-tunnels-vm` Lima instance on macOS. Start that VM with
`make vm-up`; set `LIMA_INSTANCE` when using a different instance name.

`make integration-local` creates a uniquely named, host-only PostgreSQL
Compose project on port `55432`, runs the migration/store integration tests,
and removes its volume on exit. `make integration` remains the CI/advanced
path and requires an explicit `TEST_DATABASE_URL`; it never guesses a database
or runs migrations against one implicitly.

The current direct-path preview accepts a validated, comma-separated candidate
list with `-direct-candidates`. Set `-stun stun:host:port` to run STUN on the
same UDP socket as `udp_pair_v1`; the relay also reports its observed source
endpoint as a `server_reflexive` candidate and republishes it over authenticated
coordination. A node installs one candidate at a time and marks the direct path
usable only after the WireGuard kernel reports a newer handshake than the
baseline captured before the change. If every candidate fails, the relay
endpoint is restored. External NAT traversal, roaming, and a two-network
acceptance test are still required.

When a control response contains `relay_udp_address`, agent/client prefer the
raw UDP pair transport when started with `-relay-udp` (or when the session was
issued by control). The UDP port is exposed directly by the relay container;
Caddy continues to terminate HTTPS/WebSocket traffic and does not proxy this
raw datagram protocol.

Both authentication key files must contain random values: at least 32 bytes for
the session signing key and exactly 32 bytes for the ceremony encryption key.
Open `/admin/login` on the configured HTTPS origin to register the first
passkey. Bootstrap closes after that credential is stored. Save the recovery
codes shown once by the bootstrap response; the database contains only their
hashes, and each code is consumed atomically on first use.

The control plane stores public keys, credential hashes, policies, and session
metadata. Private identity/WireGuard keys remain in local `0600` state files.
The relay forwards opaque WireGuard ciphertext. Control metrics use the
configured private `observability.metrics_address` rather than the public admin
listener. Docker builds exclude local state and secret directories from the
build context as an additional defense against accidental cache exposure.
Default policy is deny.
