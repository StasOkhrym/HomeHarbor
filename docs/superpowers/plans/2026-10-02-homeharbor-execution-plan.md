# HomeHarbor Architecture Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the approved architectural direction into independently reviewable changes that simplify business logic and produce a real manual macOS enrollment sandbox.

**Architecture:** Control becomes a stronger modular monolith inside a multi-executable product. Shared internal contracts/test utilities remain in one Go module. Runtime ownership and authorization are corrected before structural moves; UI consumes truthful read models and sandbox composes the actual product.

**Tech Stack:** Existing Go/PostgreSQL/Redis/WireGuard/nftables, Cobra across seven executables, private Watermill adapter, Go templates + HTMX, Docker Compose and native macOS utun/scoped DNS. Typed TOML initially; Viper evaluated privately, not automatically adopted.

**Spec:** [Project structure](../../reviews/2026-10-02-project-structure.md), [runtime architecture](../../reviews/2026-10-02-runtime-architecture.md), [MemoryStore decision](../../reviews/2026-10-02-memory-store-audit.md), [manual sandbox](../../reviews/2026-10-02-local-sandbox-design.md), plus the research documents linked by each subplan.

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

- Credentials/sessions remain authorized after startup only while their current lease/status allows it: Runtime Tasks 3–4.
- Pure extraction changes signed bytes or atomic workflows: Modules Tasks 1 and 4, CLI Task 4.
- Event retries duplicate or silently discard critical audit: Events/UI Tasks 1–2.
- Automatic UI updates disrupt reading/authentication or disclose secrets: Events/UI Tasks 3–4.
- Manual sandbox bypasses real private routing or changes unrelated host resources: Sandbox Tasks 2–4.

## Execution Order and Dependencies

| Order | Subplan                                                          | Dependency                                              | Reviewable outcome                                                                                      |
| ----- | ---------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 1     | [Runtime safety](2026-10-02-homeharbor-runtime.md)               | Current code                                            | Joined ownership, durable state, recoverable leases, current session authorization, early deny guard    |
| 2     | [Module boundaries / testutil](2026-10-02-homeharbor-modules.md) | Runtime contracts established                           | Pure shared packages; no node/server coupling; seven honest test repositories; profiles/workflows owned |
| 3     | [Cobra / config / tooling](2026-10-02-homeharbor-cli-tooling.md) | Module extraction                                       | All seven commands; strict precedence; dead-code/full V2 cleanup; portable scripts                      |
| 4     | [Events / dynamic UI](2026-10-02-homeharbor-events-ui.md)        | Transactions and canonical command/protocol layout      | Atomic audit delivery, isolated Watermill, browser adapter, attractive dynamic Activity                 |
| 5     | [Manual macOS sandbox](2026-10-02-homeharbor-manual-sandbox.md)  | Runtime + modules + CLI complete; truthful UI available | Native client outside Docker subnet completes signed invite and ordinary-browser private access         |

Execute sequentially by default. This split is by independently testable outcomes, not permission to concurrently edit shared contracts. The tooling harness regression (CLI Task 1) can be pulled forward before baseline verification without starting unrelated refactors. Each row is a separate plan because the scope spans independent subsystems.

## Before the First Code Change

- [ ] Confirm the active checkout, HEAD, worktrees, outstanding user changes and existing test infrastructure. Current planning baseline has only untracked `docs/reviews/`; this plan adds `docs/superpowers/plans/`.
- [ ] Preserve these design/plan documents in the execution checkout. Inspect repository guidance again; do not use the stale initial go-tunnels directory.
- [ ] Select execution approach with the user. At execution time use the git-worktrees skill if isolation is needed; no worktree is created just to write this plan.
- [ ] Fix bounded tooling fixture recursion first if inherited PYTHON makes the baseline unsafe. Run `make verify`; record actual output, not an older audit result.
- [ ] Check SQL/Redis integration and Linux/macOS prerequisites. Mark unavailable gates pending; never report complete from compilation alone.

## File and Interface Decisions

Subplans list exact source owners, new paths, interfaces and regression assertions. Package relocation preserves current exported signatures unless a task specifies a replacement. Relative paths resolve from the verified HomeHarbor checkout. New folder names are created only with implementation, never empty scaffolding.

One additional implementation decision is made concrete here: recover a lost credential-rotation response through a fresh single-use identity-signed challenge, with authoritative active-device checks. This avoids retaining an old bearer credential; record the chosen protocol in the runtime spec before coding both endpoints. No generic repository framework, service locator, external message broker or universal scripting framework is introduced.

The target `internal/testutil` already contains PostgreSQL test helpers; add per-domain adapters beneath it rather than inventing a second umbrella. Some moved test signatures depend on unexported domain members; those retain narrow local stubs. No production export is added just to make a fixture move possible.

## Cross-Plan Verification

- [ ] Per task: focused behavior tests → review → scoped commit. New behavior gets a meaningful red/green cycle; moves retain characterization coverage.
- [ ] Per subplan: portable `make verify` plus the named real SQL/Redis/Linux/browser checks relevant to it. Update Make/linter/test paths whenever assets/packages move.
- [ ] At integration: protocol golden vectors, actual relay session, credential response-loss recovery, cross-replica revoke, transaction/outbox deduplication, all seven help/version commands, desktop/mobile authenticated UI.
- [ ] Final manual sandbox: explicitly invoke it and record host/Docker capabilities, applied revision, routes/scoped DNS, packet evidence, positive/negative browser access and cleanup. Keep it excluded from mandatory gates.
- [ ] Final audit: verify production import graph, exported call sites, residual V2 occurrences, config/examples/deployment/CI invocations and documentation. Do not equate renamed directories with architecture compliance.

## Deferred Work

Windows integration, another physical LAN device, SSE, remote/live config reload, external broker and independent Go library releases remain deferred. Viper has a bounded adapter comparison, not a blanket adoption requirement. No deferred scenario is advertised as supported.

## Self-Review and Handoff

Coverage checked against all eleven review documents and the latest testutil correction. Every review-focus failure has an owning regression task. Configuration precedence, one-time enrollment, signing versions, test import cycles, native OS cleanup, event retry and manual gate exclusion are explicit. Tasks consume interfaces defined before their callers migrate; package moves retain current signatures. No runtime implementation or new runtime verification is claimed by this planning deliverable.

Recommended execution: subagent-driven, one implementation task and fresh review at a time, because credential/revocation/native network changes warrant independent review. Native execution is also available. Wait for the user's plan review and execution-method choice before implementation, as required by the writing-plans skill.
