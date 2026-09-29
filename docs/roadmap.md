# Go Tunnels Roadmap

This roadmap covers the next backend and web milestones. Security and a working
Linux vertical slice remain higher priority than mobile UI.

## 1. HTTP composition and routing

- Introduce `github.com/go-chi/chi/v5` when the API gains passkey, credential
  rotation, audit, and service-management route groups.
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
- Add an `application.Container` (or `App`) for composition. It holds concrete
  module services and shared infrastructure but contains no business logic.
- Define small interfaces at the consumer boundary. For example,
  `DeviceReader`, `EnrollmentIssuer`, `PolicyProvider`, `PolicyEditor`,
  `RouteReader`, and `RouteApprover`.
- Expose a stable facade only for a complete use case that spans modules. The
  facade coordinates services; repositories remain private to their module.
- Keep request/response DTOs in the transport layer. Domain types must not
  acquire HTTP, chi, JSON-binding, or database concerns merely for convenience.

Target composition shape:

```go
type Application struct {
    Devices *devices.Service
    Network *network.Service
    Policy  *policy.Service
    Audit   *audit.Service
}

type DeviceReader interface {
    List(context.Context) ([]devices.Device, error)
}
```

`Application` is the unified wiring surface; the narrow interfaces are the
contracts used by handlers, coordinators, jobs, and future extracted services.

## 3. Security and networking milestones

1. **Completed:** replace bootstrap bearer authentication with WebAuthn/passkey
   ceremonies, signed sessions, recovery codes, CSRF protection, and audit events.
2. Add short-lived device credential rotation and a grace window for reconnects.
3. Complete Linux interface, route, nftables, and systemd-resolved lifecycle
   with rollback to the last valid snapshot.
4. Issue relay sessions from the control plane and complete live WireGuard
   packet transport with direct-to-relay path switching.
5. Add PostgreSQL integration tests and Linux network-namespace acceptance tests.
6. Build the rough Android `VpnService` client, then the iOS Network Extension.

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

## 5. Maintainability gates

- New handlers use a narrow application interface and router-level middleware.
- New cross-module workflows document their transaction/event consistency model.
- New network state transitions include tests for rollback and stale revisions.
- New protocol fields are capability-gated and backward-compatible within v1.
- Completion requires formatting, unit tests, race tests, vet, build, and the
  relevant integration or network-namespace scenario.
