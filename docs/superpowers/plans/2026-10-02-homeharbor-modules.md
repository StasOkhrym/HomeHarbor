# HomeHarbor Module Boundaries and Test Utilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make domain logic independent of server composition and provide honest reusable test repositories.

**Architecture:** Extract pure contracts and move responsibility owners before renaming protocols. Keep one Go module and explicit adapters; migrate imports with each move rather than adding permanent alias layers.

**Tech Stack:** Go, PostgreSQL, Redis, Cobra, Watermill, Go templates/HTMX, Docker Compose and native macOS adapters as scoped below.

**Spec:** [project-structure](../../reviews/2026-10-02-project-structure.md), [memory-store-audit](../../reviews/2026-10-02-memory-store-audit.md), [architecture-audit](../../reviews/2026-10-02-architecture-audit.md)

## Global Constraints

- Product name: HomeHarbor; Go module: `github.com/StasOkhrym/homeharbor`; keep one `go.mod`.
- Execute in the verified active checkout or a deliberately created isolated worktree. Reference baseline: `b66865b598e75efd291f357a923eae8c7b256a3d`; recheck HEAD and concurrent changes before execution.
- Seven separate executable roles: control, relay, agent, client, admin, migrate, healthcheck. Cobra stays in CLI adapters; configuration becomes immutable typed values.
- Shared memory repositories belong to `internal/testutil/control/<domain>`; non-test production code cannot import testutil. SQL owns durable state, Redis owns shared ephemeral security state.
- Full breaking removal of implementation/wire/config V2 suffixes; preserve actual cryptographic/schema versions and third-party `/v2` imports. No parallel legacy transport implementation.
- Browser stack: Go templates + self-hosted HTMX; Activity refresh every **4 seconds**. Preserve CSP with `allowEval:false`, CSRF and confirmation/revision checks. SSE and SPA are deferred.
- Watermill stays private to control event delivery. Authorization, invite consumption and policy confirmation remain authoritative synchronous/transactional operations.
- Sandbox is an **optional manual** workflow: Docker services plus native macOS system VPN/scoped DNS on the same laptop. Never invoke it from `verify`, `verify FULL=1`, CI, integration, existing acceptance or precommit.
- No silent dependency installation, trust-store mutation or root networking changes. Preflight and bounded explicit native apply are separate from help/config/enrollment.
- Each task gets a focused review and a green commit; do not commit unrelated user changes. A refactor uses characterization tests rather than contrived failures. New behavior/regressions use red → green.

## Review Focus

- Indirect forbidden imports: boundary checks traverse non-test dependencies, not only direct imports.
- Signed bytes after extraction: golden vectors remain byte-identical before the explicitly breaking rename.
- Memory repository aliases: external mutation cannot change persisted bytes/slices or rule defaults.
- Package test cycles: public-interface tests use domain_test; private tests keep narrow local stubs.
- Profile/workflow transaction failure: no partially attached device/profile/invite or outbox event.

---

### Task 1: Extract ACL, activation contracts and node path state

**Files:**

- Move: `internal/control/policy/compiler.go` → `internal/acl/compiler.go` and corresponding tests
- Move: mutable PathSelector from `internal/protocol` → `internal/node/path`
- Create: `internal/protocol/activation.go`, `activation_test.go`, `api/testdata/activation.json`
- Modify: `internal/app/control/workflows/activation.go`, node/companion consumers, `internal/architecture/boundaries_test.go`

**Interfaces:** Preserve current Rule/Action/Protocol/Snapshot and Compiler.Compile(revision uint64,rules []Rule)(Snapshot,error), now owned by acl. Move current ClaimChallenge/ClaimProof and SignClaim to protocol without changing canonical bytes; keep domain records out of protocol.

- [ ] **Step 1: Pin behavior.** Preserve compiler rejection/determinism tests and add TestActivationGoldenBytes and TestNodeAndCompanionHaveNoControlImports after migrating all domain DTO consumers. Characterize public wire JSON before extraction.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/acl ./internal/protocol ./internal/node/... ./internal/companion ./internal/architecture ./internal/control/policy ./internal/agent/nft`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Explicitly map devices/invites HTTP DTOs into domain values. Remove aliases once consumers move. Path selection becomes role state. Extend transitive architecture checks for pure packages and node/companion; remove stale forbidden network package reference.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/acl ./internal/protocol ./internal/node/... ./internal/companion ./internal/architecture ./internal/control/policy ./internal/agent/nft` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: extract shared protocol and access rules`.

### Task 2: Centralize bounded control API transport

**Files:**

- Create: `internal/controlclient/client.go`, `activation.go`, `credentials.go`, `invites.go`, `client_test.go`
- Modify: `internal/node/{activation,enroll}.go`, `internal/companion/{bootstrap,invites}.go`

**Interfaces:** Produce `controlclient.New(baseURL *url.URL, transport *http.Client) (*Client,error)` and `Challenge(ctx context.Context, inviteID string) (protocol.ClaimChallenge,error)` and `Claim(ctx context.Context, inviteID string, proof protocol.ClaimProof) (protocol.CredentialLease,error)`; recovery methods use the runtime task’s credential challenge DTOs and return protocol.CredentialLease. Invitation submission keeps its existing signed request shape, moved into protocol. Every method takes context first; credential supplied per request, not read from disk.

- [ ] **Step 1: Pin behavior.** Add TestCancellationBoundsRequest, TestOversizedResponseRejected (1 MiB maximum JSON body), TestUnexpectedRedirectRejected, TestStatusMapsToTypedError and TestClaimNotAutomaticallyRetried. Use httptest TLS; assert secrets absent in errors.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/controlclient ./internal/node/... ./internal/companion`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Require positive client timeout and disable redirects for signed operations; preserve TLS verification. Close bodies, bounded decode, reject trailing JSON. Move repeated transport only; signing, authorization decisions and credential ownership remain with callers.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/controlclient ./internal/node/... ./internal/companion` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: share typed bounded control API client`.

### Task 3: Move all seven memory repositories to testutil

**Files:**

- Move: `internal/control/{devices,identity,invites,policy,routes,services,snapshots}/memory_store.go` → `internal/testutil/control/<domain>/repository.go`
- Modify: domain tests, HTTP/workflow/companion/coordination fixture consumers and `internal/architecture/boundaries_test.go`
- Create: `internal/testutil/control/<domain>/repository_test.go` for adapters with identified behavioral gaps

**Interfaces:** Produce per-domain `NewRepository() *Repository`, implementing existing domain Repository interfaces. Device fixture method `SeedDevice(context.Context, devices.Device) error` replaces fixture-only SaveDevice; business interfaces retain only production operations. Existing internal/testutil/postgres.go stays focused integration support.

- [ ] **Step 1: Pin behavior.** Add TestPolicyEmptyDefaultsDeny, TestReturnedSlicesAndBytesAreIsolated, TestListMatchesSQLOrdering and TestCancelledContextReturnsError. Convert public tests to external package variants before imports; keep truly private stubs local. Compile-time interface assertions for seven adapters.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/control/... ./internal/testutil/... ./internal/companion ./internal/architecture`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Keep the adapters deterministic, deep-copy mutable data on input/output, preserve snapshot cloneEnvelope and match SQL defaults/order. Remove ConsumeEnrollmentToken and fixture-only SaveDevice from production contracts/SQL only after renewed call-site checks. Enforce no non-test testutil imports transitively. Do not relocate live sockets, limiter maps or mutable runtime plans here.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/control/... ./internal/testutil/... ./internal/companion ./internal/architecture` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: move memory repositories into testutil`.

### Task 4: Give workflows, transactions and profiles their own owners

**Files:**

- Move: `internal/app/control/workflows` → `internal/control/workflows`; `internal/app/control/storage` → `internal/control/transactions`
- Create: `internal/control/profiles/service.go`, `storage/repository.go`, `service_test.go`
- Modify: `internal/control/services/service.go`, its storage, activation transaction adapter, HTTP consumers and app wiring

**Interfaces:** Keep ActivationUnitOfWork.WithinActivation(context.Context,func(ActivationTransaction)error)error, with ports transaction scoped. Move AccessProfile and CreateProfile/Profiles to profiles: `(*Service).Create(context.Context,AccessProfile)(AccessProfile,error)` and `List(context.Context)([]AccessProfile,error)`. Catalog retains services only.

- [ ] **Step 1: Pin behavior.** Preserve activation rollback/idempotency tests; add TestProfileMembershipRollback and TestProfileRejectsInactiveDevice. SQL integration proves invite, device, profile membership and outbox commit together or none.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/control/... ./internal/app/control ./internal/architecture`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Extract profile repository methods without changing underlying schema or atomicity. Map HTTP adapters to profiles explicitly. Merge moved workflow files into the control/workflows directory introduced by Runtime Task 3; never overwrite credential recovery. Composition root constructs dependencies only. Include profiles in import guards and provide a profile test repository only when its existing tests need one.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/control/... ./internal/app/control ./internal/architecture` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: isolate profiles and transactional workflows`.

## Completion Gate

Run `go test -race ./internal/...` and real SQL activation/profile integration, then `make verify`. Inspect go list import graph and exported call sites; no node/companion imports of control or app/control, no production testutil imports. Pure extraction must preserve signed conformance vectors.
