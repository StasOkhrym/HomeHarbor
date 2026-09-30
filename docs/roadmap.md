# Go Tunnels Roadmap

This roadmap covers the next backend and web milestones. Security and a working
Linux vertical slice remain higher priority than mobile UI.

## 1. HTTP composition and routing

- Use `github.com/go-chi/chi/v5` with standard `net/http`; Gin is intentionally
  not part of the architecture because WebSockets, middleware, and existing
  handlers already use the standard interfaces.
- Keep every endpoint as a standard `http.Handler`/`http.HandlerFunc`. Chi owns
  route composition and middleware only; domain code must not depend on chi.
- Group `/api/v1`, `/admin`, `/healthz`, `/readyz`, and `/metrics` explicitly.
- Standardize middleware order: request ID, trusted proxy/IP extraction,
  structured access log, panic recovery, body limit, authentication,
  authorization, and endpoint handler.
- Prefer chi over Gin because the current code already uses `net/http`,
  `http.Request`, WebSockets, and standard middleware. Reconsider Gin only if a
  measured need for its binding/ecosystem outweighs framework coupling.

## 2. Unified application surface

- Do **not** create one large `Service` interface containing every operation.
  Such an interface couples unrelated modules and becomes harder to test and
  split when the monolith grows.
- Keep composition in `internal/app/control.App` and `internal/app/relay.App`.
  Agent and client use `internal/app/node.App` for the same reason. Each
  executable has a thin `cmd/*` entrypoint and implements the common lifecycle
  contract `Component.Run(context.Context) error`.
- Define small interfaces at the consumer boundary. For example,
  `DeviceReader`, `EnrollmentIssuer`, `PolicyProvider`, `PolicyEditor`,
  `RouteReader`, and `RouteApprover`.
- Expose a stable facade only for a complete use case that spans modules. The
  facade coordinates services; repositories remain private to their module.
- Keep request/response DTOs in the transport layer. Domain types must not
  acquire HTTP, chi, JSON-binding, or database concerns merely for convenience.

Target composition shape:

```go
type App struct {
    server *http.Server
    pool   *pgxpool.Pool
}

type DeviceReader interface {
    List(context.Context) ([]devices.Device, error)
}
```

`App` is the unified wiring surface; the narrow interfaces are the
contracts used by handlers, coordinators, jobs, and future extracted services.

## 3. Security and networking milestones

1. **Completed:** replace bootstrap bearer authentication with WebAuthn/passkey
   ceremonies, signed sessions, recovery codes, CSRF protection, and audit events.
2. **Completed:** add short-lived device credential rotation with atomic replacement.
3. **Completed:** make trusted-companion approval activate the device,
   credential, profile membership, and outbox events in one PostgreSQL
   transaction. Legacy pending invites without a WireGuard public key are
   retained for audit but cannot be activated.
4. **Completed:** enforce a five-attempt invite-code lockout. The companion
   persists only an invite-ID counter locally, while the domain store has an
   atomic PostgreSQL `blocked` transition for code-based compatibility paths.
5. **Completed:** constrain profile permission propagation to explicit signed
   snapshot `ACLRuleIDs`; an empty template list remains default-deny.
6. **Completed:** add bounded RFC1918/CGNAT overlay allocation with reserved
   network/broadcast addresses and deterministic collision handling.
7. **Completed:** add a challenge-bound, single-use companion snapshot read and
   an explicit retryable `publish-snapshot` flow after device activation.
   Fresh installations now have an explicit local-only `admin init-snapshot`
   bootstrap from a TOML manifest; it requires a gateway and can only publish
   revision one into an empty control-plane snapshot store.
8. **Completed:** add an exact signed client-removal diff. It removes the
   device, its profile memberships, and source ACLs while rejecting gateway or
   route removal; `admin revoke-device` publishes the next contiguous revision.
9. **Completed for the Linux VM gate:** snapshot topology now compiles deterministic WireGuard
   peer allowed-prefixes with gateway route scoping. The provisioned Lima run
   covers real kernel WireGuard handshakes, isolated routes, nftables
   default-deny behavior, rollback-sensitive application paths, and allowed or
   forbidden HTTP/SSH-like service reachability. The agent now reverts
   systemd-resolved split-DNS state on component shutdown; remaining work is
   host-level lifecycle acceptance on a real systemd-resolved machine.
10. **In progress:** relay sessions, reconnect, live snapshot delivery,
   encrypted packet forwarding, versioned `udp_pair_v1` ingress, relay-observed
   server-reflexive candidate publication, authenticated candidate exchange, and
   handshake-confirmed direct-to-relay switching exist. Candidate exchange and
   relay ticket issuance now share the signed snapshot route/ACL authorization
   boundary, the coordination broadcaster uses the live production hub, and
   control-issued tickets renew before expiry during reconnect loops.
   The Linux preview can provide candidates with `-direct-candidates` or
   same-socket `-stun` discovery; roaming and an external NAT traversal test are
   still required.
11. **Completed for the current local gate:** the Linux namespace/kernel
   WireGuard acceptance pass covers allowed HTTP/SSH-like service reachability,
   forbidden ports, and policy application in the provisioned Lima VM.
   Compose now waits for real control/relay readiness through static
   distroless healthcheck probes; the registry-backed ARM64 image build and
   full local Compose startup have been verified, including Caddy HTTPS
   health/readiness.
   PostgreSQL integration passes through the isolated `make integration-local`
   path; `TEST_DATABASE_URL` remains the CI/external-database contract.
12. **Started:** Android now has a controller boundary that rejects implicit
   default routes, delegates WireGuard lifecycle to the official engine, and keeps private key
   material behind an Android Keystore-wrapped storage boundary. Build tooling,
   official engine integration, and physical-device roaming tests remain. The
   pinned Gradle project now composes the official `GoBackend.VpnService`; the
   Android build still needs to run on a host with SDK/Gradle tooling.
   Finish the iOS Network Extension target and physical-device Packet Tunnel
   verification in the same mobile gate.

## 4. Self-documenting code standard

- Prefer precise names, small functions, typed state, and narrow interfaces over
  explanatory comments.
- Add comments for security invariants, ownership/lifetime, concurrency and
  locking decisions, transaction boundaries, fallback behavior, protocol
  compatibility, and intentionally ignored errors.
- Public APIs receive Go doc comments describing guarantees and failure modes.
- Avoid comments that merely restate the next line. Update or remove a comment
  in the same change whenever its invariant changes.
- Add package documentation for modules whose boundaries are not obvious:
  identity, devices, network, policy, coordination, relay, tunnel, and audit.
- During review, treat stale or misleading comments as correctness defects.

The first actionable admin surface is now implemented with same-origin HTML
forms, including route advertisement and explicit approval. Mutations reuse the
domain services directly, while the JSON API remains
the stable integration surface for the companion and future native clients.
The dashboard also exposes a bounded, read-only recent audit view; writes stay
in authentication and durable domain-event consumers.

Native clients use `GET /api/v1/services/available` with their short-lived
device credential. The endpoint expands only explicit access-profile
membership and returns an empty list by default; it is a convenience catalog,
not an authorization source. The gateway still enforces the signed snapshot
ACL, so a stale or compromised UI cannot grant network access.

## 5. Local development contract

- `make doctor` checks all local prerequisites; `make doctor-compose` checks the
  backend/Compose path without requiring Xcode, while `make doctor ios` checks
  the iOS toolchain.
- `make dev-init` creates ignored local config/secrets without overwriting them,
  including an age-encrypted trusted-companion root key whose public half is
  mounted into control only. It validates local secret lengths and refuses an
  incomplete companion key/passphrase set.
- `make compose-check` renders the stack and verifies control receives its
  runtime secrets while the migration process receives only the DB password;
  `make dev-up` runs this preflight automatically.
- `make deploy-check` validates that Ansible copies the repository deployment
  bundle from inside the checkout and that all required rollout files exist.
- `make integration-local` starts an isolated, uniquely named PostgreSQL
  Compose project for host-side migration/store tests and removes its volume
  on exit. `make integration` keeps the explicit `TEST_DATABASE_URL` contract
  for CI and externally managed databases.
- `make dev-up` starts PostgreSQL, the one-shot migration process, control,
  relay, and Caddy. `make dev-down` stops the stack.
- Control metrics bind to the configured `observability.metrics_address`; they
  are not mounted on the public admin listener. Keep that listener private to
  the host or an explicitly restricted monitoring network.
- `make dev-trust-ca` exports Caddy's local CA for Linux test devices only.
- `make vm-up` provisions the Ubuntu Lima VM with Docker, nftables, TUN tools,
  and `make vm-down` stops it.
- `make verify` runs formatting, tests, vet, and command builds.
- `make acceptance` runs the production relay-app test, the node bridge test,
  and the privileged namespace scenario directly on Linux or through the
  `go-tunnels-vm` Lima instance on macOS. The VM must be started with
  `make vm-up` first.

## 6. Maintainability gates

- New handlers use a narrow application interface and router-level middleware.
- New cross-module workflows document their transaction/event consistency model.
- New network state transitions include tests for rollback and stale revisions.
- Route, snapshot, enrollment, invite, and policy boundaries must reject
  default routes, unsafe DNS metadata, malformed public keys, and duplicate
  rule identities before persistence or kernel command generation.
- New protocol fields are capability-gated and backward-compatible within v1.
- Completion requires formatting, unit tests, race tests, vet, build, and the
  relevant integration or network-namespace scenario.
