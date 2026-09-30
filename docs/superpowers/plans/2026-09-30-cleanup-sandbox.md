# Cleanup, Docker sandbox and selective CI

Approved specification: the user's implementation request on 2026-09-30.
Work in `/Users/s.okhrym/personal_code/go-tunnels` on main; local commits only,
no pull requests or push. Preserve existing data, trust boundaries and regressions.

## Execution ledger

Baseline: `26c6182`; clean main, 128 commits ahead of origin.
The prior Local E2E ledger remains evidence of foundation work, not a completed VPN.

## Tasks

1. Structural cleanup: storage adapters, thin node entrypoints, explicit
   coordination dependencies and resource-based HTTP composition.
2. Redis browser sessions: separate durable identity and ephemeral session ports,
   TTL, fail-closed errors, no SQL fallback; preserve tunnel independence.
3. Traefik deployment: verified relay TLS, local CA and production DNS-01,
   data-preserving DB service rename and non-root secret ownership.
4. Python sandbox orchestration: idempotent development, isolated Linux topology,
   production signed enrollment and WireGuard relay, fixed-target browser viewer.
5. Full E2E/acceptance: positive, negative, replay, restart, outages, revoke,
   snapshot history, partial apply and DNS cleanup; missing coverage fails.
6. Extract mobile history to independent local repositories, verify builds before
   removing backend sources, and pin shared protocol contract fixtures.
7. Consolidate Makefile and selective GHA, with tested change classification,
   explicit full verification and no duplicated architecture/mobile jobs.

## Pre-flight

Tasks 1/2 share identity wiring; split the session port before selecting Redis.
Tasks 3/4 share verified TLS/config and resource ownership; sandbox must use the
same production adapters, never disable authentication or TLS verification.
Tasks 4/5/7 share one harness; manual and automated runs differ in lifecycle, not
in tunnel implementation. CI must report missing prerequisites as failures.
Task 6 must finish extraction and platform validation before deleting sources/jobs.

## Progress

Baseline `go test ./...` passed. Storage adapters renamed with an import-boundary
regression watched fail and pass. Full Go tests, correctness lint, 20 tooling
tests and real SQL/Redis/migration integration passed without required skips.
Task 1: shared node runtime and 29-line agent/client entrypoints implemented;
client unsigned-kernel regression and explicit coordination-reader regression
were watched fail and pass. Resource HTTP handlers and Chi groups separated;
neutral routes naming replaces network aliases. Full race suite and lint passed.
Task 2: browser sessions use a separate Redis port with hashed identifiers, TTL,
atomic revoke, no SQL fallback and explicit 503 on storage failures. Independent
Redis clients verify shared state, expiry and revocation. Full race suite, lint,
21 tooling tests and real SQL/Redis/migration integration passed without required
skips. Old SQL sessions are deliberately invalidated; durable recovery remains DB.
Task 3: Traefik deployment next. Full sandbox/E2E remains pending.
