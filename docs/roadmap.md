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
7. **In progress:** snapshot topology now compiles deterministic WireGuard
   peer allowed-prefixes with gateway route scoping. Complete privileged Linux
   interface, route, nftables, and
   systemd-resolved lifecycle acceptance with rollback to the last valid
   snapshot. The Linux namespace harness now exercises the isolated route and
   default-deny LAN policy path; it still needs to run in the provisioned Lima
   VM and be extended through the real kernel WireGuard interface.
8. **In progress:** relay sessions, reconnect, live snapshot delivery, and
   encrypted packet forwarding exist. Complete kernel WireGuard service
   reachability, STUN direct handshake, and direct-to-relay path switching.
9. **Partially completed:** PostgreSQL integration tests and the Linux
   namespace acceptance harness exist. Run them with `TEST_DATABASE_URL` and
   the provisioned Linux VM before calling the local E2E gate green.
10. Build the rough Android `VpnService` client, then finish the iOS Network Extension
   target and physical-device Packet Tunnel verification.

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
