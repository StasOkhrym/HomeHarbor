# HomeHarbor Events and Dynamic Admin UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver durable truthful audit facts and make the admin interface responsive with automatic Activity updates.

**Architecture:** Move event interpretation to control, make audit delivery atomic in SQL and isolate optional Watermill invalidation. Split browser adapters from JSON APIs before adding per-page queries and a single cancellation-aware polling controller.

**Tech Stack:** Go, PostgreSQL, Redis, Cobra, Watermill, Go templates/HTMX, Docker Compose and native macOS adapters as scoped below.

**Spec:** [watermill-research](../../reviews/2026-10-02-watermill-research.md), [viper-ui-research](../../reviews/2026-10-02-viper-ui-research.md), [project-structure](../../reviews/2026-10-02-project-structure.md), [runtime-architecture](../../reviews/2026-10-02-runtime-architecture.md)

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

- Pool maximum one and duplicate delivery: audit projection succeeds without a second connection or duplicate row.
- Poison/transient event: persisted retry state is visible; no silently green critical audit backlog.
- Lower ID committing after a higher ID: bounded recent-window refresh can still discover the row.
- Hidden tab, navigation and expired session: no overlapping/orphan requests or repeated login redirects.
- Background refresh while reading/filtering or editing: preserve focus/scroll/details/input; never expose secret metadata.

---

### Task 1: Own typed facts and atomic audit projection

**Files:**

- Move: `internal/platform/events` → `internal/control/events`
- Create: `internal/control/events/envelope.go`, `dispatcher.go`, `dispatcher_test.go`
- Modify: `internal/control/audit/storage/repository.go`, transaction outbox producers and `internal/app/control` wiring
- Create: `migrations/000013_outbox_delivery_state.up.sql`, corresponding down migration

**Interfaces:** Produce `events.Envelope` with EventID, Type, SchemaVersion, AggregateID, AggregateRevision, OccurredAt, ActorType/ID, TargetType/ID, CorrelationID and typed non-secret payload. Business-facing appender accepts facts in the existing transaction; it exposes no message.Message or Ack/Nack.

- [ ] **Step 1: Pin behavior.** Add TestSingleConnectionAuditDelivery, TestRedeliveryExactlyOneAuditRecord, TestInviteActorAndTargetAreNotDeviceByDefault, TestTransientRetryPersisted and TestPoisonEventDegradesReadiness. SQL tests set MaxConns=1 and exercise crash/restart around projection/completion.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/control/events ./internal/control/audit/... ./internal/control/transactions ./internal/app/control`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Insert audit and mark completion in one SQL transaction using one acquired connection. Eliminate context-carried GoChannel receipt. Persist attempts/next-attempt/last-error/quarantine outside rolled-back delivery transaction. Retry at 1,2,4…60 seconds; malformed/schema-invalid events quarantine immediately and expose degraded audit readiness. Sanitize stored errors. Preserve stable delivery IDs and existing outbox rows via explicit legacy decoder until drained; new facts use versioned envelope.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/control/events ./internal/control/audit/... ./internal/control/transactions ./internal/app/control` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: deliver typed audit facts atomically`.

### Task 2: Keep Watermill optional consumers independent

**Files:**

- Create: `internal/control/events/invalidation.go`, `invalidation_test.go`
- Modify: event wiring, health/readiness checks and event documentation

**Interfaces:** Provide private Watermill adapter for best-effort local invalidation; publish only after SQL commit. Future durable handlers require per-consumer persisted completion, never the single global published flag. No external broker is introduced now.

- [ ] **Step 1: Pin behavior.** Add TestOptionalSubscriberFailureDoesNotFailCommand, TestMissedHintRecoveredByReadQuery, TestCancelledSubscriberJoins and TestReadinessReportsAuditLagAndQuarantine.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/control/events ./internal/app/control ./internal/architecture`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Keep Watermill dependency behind this adapter; remove unused domain-topic publishes. Bound optional queues and coalesce hints. Polling requires no bus message. Expose pending count/oldest event age/quarantine; audit sink/database failure degrades readiness while dispatcher retries, not arbitrary process death. Do not implement a fictional notification consumer merely to justify the library.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/control/events ./internal/app/control ./internal/architecture` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: isolate optional watermill consumers`.

### Task 3: Separate browser adapters and Activity read model

**Files:**

- Move: browser files/templates/static from `internal/control/httpapi` into `internal/web/{admin,auth,session,assets}` by responsibility
- Create: `internal/control/audit/query.go`, `internal/web/admin/activity.go`, `activity_test.go`
- Modify: `internal/control/audit/storage/repository.go`, `internal/app/control/http.go`, Makefile/tooling asset paths

**Interfaces:** Produce `audit.Record { RecordID int64; Event Event }`, `audit.Query { Limit int; BeforeID int64; Action string; TargetID string }` and `ListRecords(context.Context,Query)([]Record,error)`. RecordID is storage identity; Event.ID remains optional delivery identity. Mount siblings via composition; session/CSRF contracts live in web/session.

- [ ] **Step 1: Pin behavior.** Add TestDirectAuthEventsHaveDistinctRecordIDs, TestLimitClampedTo200, TestActivityDoesNotQueryDevices, TestFragmentsRequireSessionAndNoStore and TestOutOfOrderCommitAppearsInRecentWindow. SQL ordering/pagination and filter tests use real rows; recent window limit defaults to 100.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/web/... ./internal/control/httpapi ./internal/control/audit/... ./internal/app/control ./internal/architecture`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Extract session/auth contracts first to prevent sibling adapter cycles. Give each page its own query/view model. Share full-page and fragment row templates. Recent window queries newest committed rows; historical pagination is separate, not exclusive id>cursor streaming. Allowlist action metadata; display explicit unknown actor/outcome where facts absent.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/web/... ./internal/control/httpapi ./internal/control/audit/... ./internal/app/control ./internal/architecture` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: separate admin web and activity queries`.

### Task 4: Implement four-second Activity polling and UI refinement

**Files:**

- Modify: `internal/web/assets/static/admin.js`, `admin.css`, templates under `internal/web/assets/templates/admin`
- Move/update: `internal/control/httpapi/tests/browser.test.cjs` → `internal/web/admin/tests/browser.test.cjs`
- Modify: page/form handlers, formatting/lint/browser-test path configuration

**Interfaces:** External JS owns one scheduler: 4000 ms live interval, hidden-tab pause, immediate visible resume, one request in flight, backoff 4/8/16/32 seconds. Authenticated Activity fragment route `/admin/activity/fragment` reuses query/templates; HTMX listens to plain custom event with allowEval:false.

- [ ] **Step 1: Pin behavior.** Browser tests assert exact 4000 interval, pause/resume, one in-flight, no timer after navigation, one login redirect on 401, last content retained on outage, stable-ID reconciliation, new-entry count while reading history, preserved filters/open-details/focus/scroll and mobile navigation. Form tests pin 422 validation and 409 revision conflict; private result flows cannot replay/cache secrets.
- [ ] **Step 2: Establish the baseline.** Run `node --test internal/web/admin/tests/browser.test.cjs`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Follow interface-design for spacing/type/color/status tokens, responsive shell and readable metadata details. Scope existing afterSwap heading focus/mobile close to navigation only. Add live/pause/fresh/stale indicators; announce new entries without moving history. Use same per-page query pattern for resource lists. Preserve non-JS forms, CSRF and confirmation. Show saved/signed/application-unknown truthfully; no fabricated health telemetry.
- [ ] **Step 4: Verify.** Run `node --test internal/web/admin/tests/browser.test.cjs` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: refresh activity and refine admin interface`.

## Completion Gate

Run `make verify`, real SQL outbox/audit tests and authenticated browser interaction at desktop and mobile sizes. Capture screenshots for Activity (live, paused, stale, filtered/details), Devices, Services, Access and Security. Verify CSP in the browser and keyboard behavior. JS unit tests alone do not prove rendered layout. SSE is deferred.
