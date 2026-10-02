# HomeHarbor CLI Configuration and Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give all seven binaries predictable side-effect-free commands and consistent validated configuration.

**Architecture:** A small Cobra host owns streams, signals, execution and errors. Role adapters load immutable typed configuration then call applications. Keep Make/scripts for development tasks; compare Viper privately against the same configuration contract.

**Tech Stack:** Go, PostgreSQL, Redis, Cobra, Watermill, Go templates/HTMX, Docker Compose and native macOS adapters as scoped below.

**Spec:** [cobra-runtime-research](../../reviews/2026-10-02-cobra-runtime-research.md), [viper-ui-research](../../reviews/2026-10-02-viper-ui-research.md), [project-structure](../../reviews/2026-10-02-project-structure.md), [runtime-architecture](../../reviews/2026-10-02-runtime-architecture.md)

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

- Help/version with missing config, secrets or unavailable servers: no filesystem/network/key side effects.
- Explicit false/zero/empty override: never confused with an absent flag/environment variable.
- Winning inline secret plus unreadable lower-priority file: read only the selected source.
- Cancelled finite operation or interrupted drain: return an explicit non-success status and run cleanup.
- Inherited PYTHON override in script tests: fixture subprocesses must not recursively launch the real suite.

---

### Task 1: Fix the tooling fixture environment contract

**Files:**

- Modify: `scripts/tooling.py`, `scripts/verify.sh`, `scripts/tests/test_tooling.py`, `test_processes.py`, `test_language_checks.py`

**Interfaces:** Keep existing Make/verify CLI contract; fixtures explicitly own their subprocess environment and fake tool executable selection.

- [ ] **Step 1: Pin behavior.** Add TestInheritedPythonDoesNotEscapeFixture and TestExplicitPythonOverrideRunsOnce, with a bounded child-process sentinel counter. Assert recursive suite execution is impossible and production override still selects the requested interpreter.
- [ ] **Step 2: Establish the baseline.** Run `python3 -m unittest discover -s scripts/tests`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Sanitize fixture-owned PYTHON before launching stubs; avoid globally deleting valid production overrides. Keep timeouts/owned process-group cleanup. Run the regression first in isolation so baseline recursion is bounded.
- [ ] **Step 4: Verify.** Run `python3 -m unittest discover -s scripts/tests` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: isolate tooling test interpreter overrides`.

### Task 2: Compose configuration sources before resolving secrets

**Files:**

- Modify: `internal/platform/config/{config,node,runtime}.go` and their tests
- Create: `internal/platform/config/sources.go`, `sources_test.go`
- Modify: `internal/app/node/config.go`, `cmd/admin/main.go`, `cmd/migrate/main.go`

**Interfaces:** Produce `type Sources struct { File string; Env func(string)(string,bool); Flags map[string]string }`; Flags contains only explicitly changed flags. Add `LoadControl(Sources)(Control,error)`, `LoadClient(Sources)(Node,error)`, `LoadAgent(Sources)(Node,error)` and `LoadDatabase(Sources)(Database,error)`. Database-only loading validates the full file schema but resolves only database secrets. Migrate existing path-only callers in the same task.

- [ ] **Step 1: Pin behavior.** Table tests pin defaults→strict file→present env→changed flags→selected secret→validate. Cases: false/0/empty, unknown TOML key, same-source inline/file conflict, higher inline overriding lower file, higher file overriding lower inline, unused missing secret, malformed final URL/TTL and database-only config.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/platform/config ./internal/app/node ./cmd/admin ./cmd/migrate`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Retain typed TOML first; use decoder metadata for unknown keys and LookupEnv presence. Resolve only the final selected secret. Preserve existing role structs; no domain getters or hot reload. Reuse conformance tests for a disposable private Viper implementation; record keep/adopt decision by binding-code reduction and all tests passing, then remove the losing adapter. Viper is not required to proceed.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/platform/config ./internal/app/node ./cmd/admin ./cmd/migrate` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: normalize config precedence and secret selection`.

### Task 3: Build Cobra host and migrate every executable

**Files:**

- Create: `internal/cli/host/host.go`, `signals.go`, `host_test.go`
- Create: `internal/cli/{control,relay,agent,client,admin,migrate,healthcheck}/command.go` and focused command tests
- Modify: all seven `cmd/<role>/main.go`; `go.mod`, `go.sum`

**Interfaces:** Produce `host.Execute(ctx context.Context, args []string, stdout,stderr io.Writer, root *cobra.Command) int`; each role exposes fresh `NewCommand() *cobra.Command`. main creates signal context, executes, and calls os.Exit only after execution/defers finish. Shared code does not construct SQL or privileged adapters.

- [ ] **Step 1: Pin behavior.** Add TestEveryRoleHelpAndVersionHaveNoEffects, TestCommandInstancesDoNotShareFlags, TestRunErrorClosesResources, TestFiniteCancellationNonzero and TestHealthcheckDeadlineTwoSeconds. Record current exit codes first and retain them except interrupted finite work now cannot report success.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/cli/... ./cmd/... ./internal/app/... ./internal/platform/config`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Use RunE with lexical cleanup, SilenceUsage/SilenceErrors and one error renderer. Do not use PostRunE for cleanup or MarkFlagRequired for file/env-backed values. Pass context to all admin/migration calls. First termination cancels; second signal exits immediately; drain timeout yields hard process exit without unsafe store teardown. Positive role-specific drain deadline defaults to 10 seconds; finite healthcheck stays 2 seconds.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/cli/... ./cmd/... ./internal/app/... ./internal/platform/config` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: unify executable commands with cobra`.

### Task 4: Remove proven dead paths and complete breaking transport cleanup

**Files:**

- Modify: `internal/relay`, `internal/node`, `internal/protocol`, `internal/platform/config`, `internal/app/relay`, command adapters
- Modify: `deploy/compose.yaml`, `deploy/compose.integration.yaml`, `config/*.example.toml`, `scripts`, deployment docs and integration fixtures
- Modify: `api/protocol.md`, golden vectors and `internal/architecture/boundaries_test.go`

**Interfaces:** Canonical surviving UDP transport endpoint: `/relay/udp`; replace `/relay/udp/v2` and implementation V2 names atomically across producers/consumers. Preserve cryptographic domain separators and genuine protocol version fields unless their semantics separately change.

- [ ] **Step 1: Pin behavior.** Add TestOldRelayEndpointRejected and TestCanonicalRelayRoundTrip; characterize signed bytes before/after rename. Call-site inventory records evidence for legacy Hub/WebSocket/Bridge/framed Packet and unused STUN configuration. Build-tagged Linux code and exported consumers count as reachability.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./cmd/... ./internal/... ./migrations/...`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Delete only proven obsolete code/tests after the current transport tests cover required behavior. Rename surviving V2 files/types/config fields; no compatibility aliases or duplicate transport. Update all invocations from old standard flag `-config` to Cobra `--config` and all docs/product naming. Retain third-party import versions and migrations. Review SQL history rather than deleting schema migrations.
- [ ] **Step 4: Verify.** Run `go test -race ./cmd/... ./internal/... ./migrations/...` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `refactor: remove obsolete transport and v2 implementation names`.

## Completion Gate

Run `make verify`, explicit integration and current relay acceptance. Validate both Compose files with compose config and build all seven binaries. Search V2/v2 results and classify each retained occurrence (schema/crypto/third-party/historical evidence). Re-run overridden-PYTHON fixture regression. No sandbox target enters the verification graph.
