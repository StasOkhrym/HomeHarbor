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
  Each executable has a thin `cmd/*` entrypoint and implements the common
  lifecycle contract `Component.Run(context.Context) error`.
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
4. **Completed:** constrain profile permission propagation to explicit signed
   snapshot `ACLRuleIDs`; an empty template list remains default-deny.
5. **Completed:** add bounded RFC1918/CGNAT overlay allocation with reserved
   network/broadcast addresses and deterministic collision handling.
6. **Completed:** add a challenge-bound, single-use companion snapshot read and
   an explicit retryable `publish-snapshot` flow after device activation.
7. **Completed:** add an exact signed client-removal diff. It removes the
   device, its profile memberships, and source ACLs while rejecting gateway or
   route removal; `admin revoke-device` publishes the next contiguous revision.
8. **In progress:** snapshot topology now compiles deterministic WireGuard
   peer allowed-prefixes with gateway route scoping. The provisioned Lima run
   now covers real kernel WireGuard handshakes, isolated routes, nftables
   default-deny behavior, rollback-sensitive application paths, and allowed or
   forbidden HTTP/SSH-like service reachability. The agent now reverts
   systemd-resolved split-DNS state on component shutdown; remaining work is
   host-level lifecycle acceptance on a real systemd-resolved machine.
9. **In progress:** relay sessions, reconnect, live snapshot delivery,
   encrypted packet forwarding, versioned `udp_pair_v1` ingress, relay-observed
   server-reflexive candidate publication, authenticated candidate exchange, and
   handshake-confirmed direct-to-relay switching exist. The Linux preview can
   provide candidates with `-direct-candidates` or same-socket `-stun` discovery;
   roaming and an external NAT traversal test are still required.
10. **Completed for the current local gate:** the Linux namespace/kernel
   WireGuard acceptance pass covers allowed HTTP/SSH-like service reachability,
   forbidden ports, and policy application in the provisioned Lima VM.
   PostgreSQL integration still requires an explicit test database, while the
   host Docker Compose runtime still needs a successful registry-backed image
   pull and startup verification.
11. **Started:** Android now has a `VpnService` boundary that rejects implicit
   default routes and requires an injected WireGuard engine. Build tooling,
   official engine integration, Android Keystore storage, and physical-device
   roaming tests remain. Finish the iOS Network Extension target and
   physical-device Packet Tunnel verification in the same mobile gate.

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
forms. Mutations reuse the domain services directly, while the JSON API remains
the stable integration surface for the companion and future native clients.

## 5. Local development contract

- `make doctor` checks Go, Docker Compose, Lima, and Xcode prerequisites.
- `make dev-init` creates ignored local config/secrets without overwriting them.
- `make dev-up` starts PostgreSQL, the one-shot migration process, control,
  relay, and Caddy. `make dev-down` stops the stack.
- `make dev-trust-ca` exports Caddy's local CA for Linux test devices only.
- `make vm-up` provisions the Ubuntu Lima VM with Docker, nftables, TUN tools,
  and `make vm-down` stops it.
- `make verify` runs formatting, tests, vet, and command builds.
- `make acceptance` runs the portable relay test and the privileged namespace
  scenario directly on Linux or through the `go-tunnels-vm` Lima instance on
  macOS. The VM must be started with `make vm-up` first.

## 6. Maintainability gates

- New handlers use a narrow application interface and router-level middleware.
- New cross-module workflows document their transaction/event consistency model.
- New network state transitions include tests for rollback and stale revisions.
- New protocol fields are capability-gated and backward-compatible within v1.
- Completion requires formatting, unit tests, race tests, vet, build, and the
  relevant integration or network-namespace scenario.
