# HomeHarbor: memory-store ownership audit

Date: 2026-10-02. Inspected source revision: `b66865b`. Runtime code unchanged. Scope: every control-domain memory_store.go, callers, actual control composition and other process-local state.

## Decision

User-selected target: move all seven domain memory adapters into shared test repository support under internal/testutil/control/<domain>. Keep them for fast deterministic domain/HTTP/workflow tests; business packages retain repository interfaces and domain behavior, without exporting MemoryStore constructors. Production domain persistence already uses SQL. Keep shared short-lived security state in Redis. Watermill belongs to asynchronous delivery, not to replacing queryable repositories or one-time transaction invariants.

All seven domain NewMemoryStore constructors are used by tests, with no production caller found. This does not mean every in-memory implementation is test-only: the general API rate limiter is process-local in production, and sockets, peer maps, endpoint selection and packet-plane ownership necessarily contain live memory state.

## Inventory

| Domain    | Current production owner                                         | Memory adapter purpose                                   | Recommendation                                                                 |
| --------- | ---------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------ |
| devices   | PostgreSQL adapter; atomic enrollment/rotation/revoke            | Identity/token/credential invariants and fixture seeding | Keep test fake; narrow unused repository methods                               |
| identity  | PostgreSQL recovery/passkeys + Redis browser sessions/ceremonies | Deterministic auth/WebAuthn tests                        | Keep test fake; split test responsibilities along actual repository interfaces |
| invites   | PostgreSQL + transactional activation workflow                   | Proof retry, approval/blocking unit tests                | Keep test fake; do not substitute for transactional SQL workflow               |
| policy    | PostgreSQL revisions/current rules                               | Revision conflict and compiler/service tests             | Keep test fake; repair initial snapshot and alias behavior                     |
| routes    | PostgreSQL advertisements                                        | Validation/approval unit tests                           | Keep test fake; align promised result order                                    |
| services  | PostgreSQL catalog/profile membership                            | Catalog/profile visibility and HTTP fixtures             | Keep test fake; clone profile slices                                           |
| snapshots | PostgreSQL immutable signed history                              | Snapshot lineage/cursor/conflict tests                   | Keep test fake; current cloneEnvelope is a good ownership example              |

Production wiring is explicit in internal/app/control/http.go: SQL devices/routes/policy/services/identity/snapshots/invites repositories, Redis sessions/ceremonies/challenges/replay/security quotas. These are existing adapters, not a proposed move from live memory to SQL.

## Actual quality gaps in test adapters

1. policy.MemoryStore starts with a zero Snapshot, whose DefaultAction is empty. SQL Latest on an empty table returns ActionDeny and an empty rules slice. Service.Latest forwards either result unchanged. Tests using memory therefore do not model the real empty-store contract.
2. policy Latest/Replace returns slices sharing stored snapshot data. Mutating a returned Rules slice can alter stored state outside the lock. services profiles contain DeviceIDs/ServiceIDs slices and are stored/returned without cloning. invites Record includes byte slices and nested permit/proof bytes and returns shallow copies. identity credentials are also only shallow-copied. Mutexes do not isolate references after a method returns.
3. devices/routes memory lists iterate maps; SQL queries specify created_at/id order. Define the ordering contract and align the fake if callers rely on it; do not make tests accidentally depend on random map iteration.
4. Memory methods broadly ignore context cancellation, while SQL/Redis operations can fail/cancel. Use targeted failure/cancellation adapters for orchestration tests; do not pretend a memory fake verifies SQL lock/transaction behavior.
5. identity.ContainsPlaintext is a test-only inspection helper checking recovery hash bytes, not a general proof that all storage/serialized output contains no secret. Keep such assertions in test support and scope their claims correctly.

These gaps were identified from source comparison; no permanent regression tests or fixes were added in this audit. Existing domain tests passing does not disprove untested contract differences. snapshots.cloneEnvelope already demonstrates appropriate byte ownership on insert/read.

## Remove unnecessary interface surface

No ConsumeEnrollmentToken caller was found beyond declarations/implementations. Production enrollment uses an atomic Enroll port; remove the standalone consumption method from the domain Repository and both adapters after confirming tests/contracts. It invites an unsafe split consume/save flow.

SaveDevice is used by memory fixture setup; no production call to SQL SaveDevice was found. Fixture insertion should not be a required business repository method. Move it behind a test fixture SeedDevice helper, keep atomic production enrollment/activation ports, and then remove the unused SQL implementation if no integration fixture requires it. Do not delete the fixture capability before migrating its consumers.

## Test-support structure

The selected shared test library is internal/testutil/control/{devices,identity,invites,policy,routes,services,snapshots}, with explicit fake repository factories and fixture seed helpers. It stays inside the existing Go module and is shared by domain, HTTP, companion and workflow tests; no independent library release or generic map-backed repository framework is required. Business packages define the interfaces; test adapters depend on those packages, never the reverse. Shared tests can exercise key interface semantics against memory and SQL adapters; SQL-only transaction/constraint/Redis TTL behavior remains in integration tests.

Do not mechanically rename all files to _test.go: sibling-package HTTP/workflow/companion tests currently import exported constructors. Conversely, same-package domain tests cannot import a testutil adapter that imports that domain without creating an import cycle. Migrate public-interface tests to package domain_test where practical; leave truly private tests with local narrow stubs. Do not export private production functions merely to move tests. Until that migration is ready, retaining the current files with explicit test-only documentation is safer than duplicate fakes or a broken test graph.

Add a production dependency check prohibiting cmd/app and other non-test production packages from importing testutil or constructing domain memory repositories. This keeps the runtime SQL/Redis requirement explicit, including the manual sandbox. The sandbox must use real storage and authentication; its optional nature does not justify fake production repositories.

## Other memory state

The production APILimiter at internal/app/control/http.go:129 uses NewRateLimiter; auth/onboarding limiters use NewSharedRateLimiter with Redis. The constructor comment claiming the memory limiter is test-only is inaccurate for the API limiter. A process-local API quota resets on restart and multiplies across replicas. Prefer the existing Redis adapter with a separate api bucket for an authoritative shared quota, or explicitly retain/document it as a local supplemental guard. Do not move quota enforcement into asynchronous Watermill events or relational writes on every request.

Live coordination WebSockets, UDP peer ownership, path state, worker cancellation and gateway reconciliation plans belong in memory with bounded lifecycle and cleanup. SQL can store durable metadata but cannot restore live sockets after a restart. Legacy relay Hub appears unused on the deployed UDP-pair path; remove it only with the already planned obsolete transport cleanup.

Relay used-ticket fingerprints are also process-local. Decide whether once-only ticket admission is scoped to one running relay or must survive restart/multiple replicas. If global anti-replay is required, a shared atomic expiring Redis record is appropriate. Persisting live packet-plane owners in SQL or broadcasting a used-ticket event would not atomically prevent duplicate admission.

## Watermill's role

State change + typed fact append occurs in one SQL transaction. Watermill delivers committed facts to projections/notifications; those consumers need idempotency and independent progress. A projection usually persists its queryable state in SQL. Queries, token consumption, credential rotation and authoritative policy validation stay behind explicit repository/application interfaces.

Thus the choices are complementary: SQL for durable domain state/history/projections; Redis for shared atomic TTL security state; Watermill for message delivery; memory fakes for tests; memory runtime owners for live resources. Avoid introducing event sourcing merely to remove a MemoryStore name.

## Verification

Fresh go test -race passed for all seven control domain packages: devices, identity, invites, policy, routes, services and snapshots. This run exercises their existing tests; it does not execute their SQL/Redis integration adapters or prove the identified gaps repaired. No runtime or test adapter was modified.

## Selected migration contract

1. Move each adapter into its purpose-named shared test-support package and expose NewRepository plus explicit fixture helpers such as SeedDevice.
2. Update cross-domain tests to import testutil. Convert public-interface domain tests to external domain_test packages where needed to avoid import cycles; retain narrow local stubs for genuinely private tests.
3. Repair the identified initial-state, cloning and ordering contract differences, then remove unused production repository methods independently of fixture seeding.
4. Enforce no non-test production imports of testutil. Production and the optional manual sandbox continue to use SQL/Redis. Live runtime maps and socket owners are outside this migration.
5. Validate migrated tests and SQL adapter contracts appropriate to the changed interface; do not add the manual macOS sandbox to required gates.

The test-support location is now a selected design decision. Source adapters have not yet been moved.
