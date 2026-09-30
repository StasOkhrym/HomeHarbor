# Admin Passkey Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace bootstrap bearer access with passkey-first administrator authentication, signed sessions, one-time recovery codes, CSRF protection, and chi-based HTTP composition.

**Architecture:** A new `identity` module owns WebAuthn credentials, ceremony state, recovery codes, and admin sessions. The HTTP layer owns cookies, CSRF, chi routing, and browser DTOs through narrow consumer-defined interfaces. PostgreSQL stores credential material and hashes; transient WebAuthn challenges are server-side, one-time, and short-lived.

**Tech Stack:** Go 1.27.1, `go-webauthn/webauthn`, `go-chi/chi/v5`, PostgreSQL/pgx, standard `net/http`.

**Spec:** `docs/roadmap.md`

## Global Constraints

- Domain and application code must not depend on chi or HTTP types.
- No plaintext recovery code, session token, or WebAuthn challenge is persisted.
- Comments explain concrete invariants, lifetime/ownership, transaction boundaries, or failure behavior; they do not restate code.
- Bootstrap is available only while no WebAuthn credential exists.
- Authentication failures use generic client-facing errors and detailed structured server logs.

## Review Focus

- Replayed or expired WebAuthn ceremony state must fail and be consumed only once.
- A validly signed but expired/revoked session must fail authorization.
- Recovery codes must be single-use under concurrent requests.
- CSRF must reject missing, mismatched, or cross-origin state-changing admin requests.
- WebAuthn sign-count regression must reject login and preserve the previous stored counter.

---

### Task 1: Identity domain and recovery codes

**Files:**
- Create: `internal/control/identity/service.go`
- Create: `internal/control/identity/memory_store.go`
- Test: `internal/control/identity/service_test.go`

**Interfaces:**
- Produces: `NewService(Store, Clock, io.Reader)`, `GenerateRecoveryCodes`, `ConsumeRecoveryCode`, `CreateSession`, `ValidateSession`, `RevokeSession`.
- Produces: narrow `Store` operations with atomic consume semantics.

- [ ] Write failing tests for hashed-at-rest recovery codes, concurrent single use, session expiry, revocation, and generic invalid-token behavior.
- [ ] Run `go test ./internal/control/identity` and confirm missing-symbol failures.
- [ ] Implement the minimal domain types and service. Comment why hashes, expiry checks, and atomic consume belong at the store boundary.
- [ ] Run the package and full suites.
- [ ] Commit as `feat: add admin identity domain`.

### Task 2: PostgreSQL identity persistence

**Files:**
- Create: `migrations/000002_admin_identity.up.sql`
- Create: `migrations/000002_admin_identity.down.sql`
- Create: `internal/control/identity/storage_store.go`
- Test: `internal/control/identity/storage_store_test.go`

**Interfaces:**
- Consumes: Task 1 `identity.Store`.
- Produces: transactional one-time ceremony/recovery consumption and session lookup/revocation.

- [ ] Write PostgreSQL integration tests for concurrent recovery consumption, expired ceremony consumption, session revocation, and credential counter compare-and-update.
- [ ] Confirm tests fail before schema/adapter implementation.
- [ ] Evolve the existing `webauthn_credentials` and `recovery_codes` tables,
      then add ceremony/session tables; implement pgx adapter transactions
      without rewriting migration `000001` for already-deployed databases.
- [ ] Add comments at advisory/row locks and compare-and-update queries explaining the race they prevent.
- [ ] Run integration and full suites.
- [ ] Commit as `feat: persist admin identity state`.

### Task 3: WebAuthn ceremonies

**Files:**
- Create: `internal/control/identity/webauthn.go`
- Test: `internal/control/identity/webauthn_test.go`

**Interfaces:**
- Produces: `BeginBootstrap`, `FinishBootstrap`, `BeginLogin`, `FinishLogin` using transport-neutral ceremony IDs and JSON payloads.
- Consumes: Task 1 service/store and configured RP ID/origins.

- [ ] Write failing tests for bootstrap lockout after first credential, challenge expiry/replay, wrong RP origin, unknown credential, and sign-count regression.
- [ ] Implement `go-webauthn` adapter; persist only serialized server-side session data behind random ceremony IDs.
- [ ] Comment challenge ownership/lifetime and sign-counter compare-and-update behavior.
- [ ] Run package and full suites.
- [ ] Commit as `feat: add passkey ceremonies`.

### Task 4: Chi router and application container

**Files:**
- Create: `internal/control/application/application.go`
- Create: `internal/control/httpapi/router.go`
- Modify: `internal/control/httpapi/server.go`
- Modify: `cmd/control/main.go`
- Test: `internal/control/httpapi/router_test.go`

**Interfaces:**
- Produces: `application.Application` as wiring-only container.
- Produces: `httpapi.NewRouter(Dependencies) http.Handler`.
- Consumes: existing narrow device/network/policy contracts and Task 1/3 identity contracts.

- [ ] Write failing route/middleware tests for route groups, request IDs, body limits, recovery, and authorization boundaries.
- [ ] Add chi and migrate route composition while preserving standard `http.Handler` endpoint signatures.
- [ ] Split the current large server file by auth, devices, routes, policy, and admin dashboard responsibilities.
- [ ] Add comments only where middleware ordering or optional capability behavior is non-obvious.
- [ ] Run API and full suites.
- [ ] Commit as `refactor: compose control HTTP with chi`.

### Task 5: Browser auth, signed cookies, and CSRF

**Files:**
- Create: `internal/control/httpapi/auth.go`
- Create: `internal/control/httpapi/csrf.go`
- Create: `internal/control/httpapi/templates/login.html`
- Modify: `internal/control/httpapi/server.go`
- Test: `internal/control/httpapi/auth_test.go`

**Interfaces:**
- Consumes: identity ceremony/session interfaces.
- Produces: passkey bootstrap/login endpoints, recovery login, logout, session middleware, and double-submit CSRF middleware.

- [ ] Write failing browser-flow tests for Secure/HttpOnly/SameSite cookies, tampering, expiry, logout, recovery login, CSRF mismatch, and disallowed Origin.
- [ ] Implement signed opaque session cookies and CSRF tokens; remove bootstrap-secret login after a passkey exists.
- [ ] Add concise comments explaining cookie scope, signature comparison, and CSRF binding.
- [ ] Run API and full suites.
- [ ] Commit as `feat: add passkey admin sessions`.

### Task 6: Audit, configuration, docs, and migration safety

**Files:**
- Modify: `internal/platform/config/config.go`
- Modify: `config/control.example.toml`
- Modify: `internal/platform/events/audit.go`
- Modify: `README.md`
- Modify: `docs/roadmap.md`

**Interfaces:**
- Produces: configuration for RP origins/session/challenge TTLs and audit events for bootstrap, login, recovery, logout, and auth failures.

- [ ] Write failing config tests for insecure origins, RP mismatch, short signing keys, and invalid TTLs.
- [ ] Implement config validation and identity audit publishing without logging secrets or credential payloads.
- [ ] Document bootstrap/recovery operations and remove the temporary bearer instructions.
- [ ] Run `gofmt`, `go test -race ./...`, `go vet ./...`, `go build ./cmd/...`, migration tests, and Compose validation.
- [ ] Review all new comments against the self-documenting code standard; remove comments that only paraphrase code.
- [ ] Commit as `docs: document passkey administration`.
