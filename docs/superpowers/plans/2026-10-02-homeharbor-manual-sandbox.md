# HomeHarbor Manual macOS Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run a real invite-to-private-site flow on one Mac with Docker services and a native client outside their subnet.

**Architecture:** Use isolated Docker underlay/backend/private networks and a Linux gateway. Native macOS controller verifies signed state and delegates bounded utun/routes/scoped resolver changes to an elevated adapter with an ownership journal. No private-service publishing or browser proxy shortcut.

**Tech Stack:** Go, PostgreSQL, Redis, Cobra, Watermill, Go templates/HTMX, Docker Compose and native macOS adapters as scoped below.

**Spec:** [local-sandbox-design](../../reviews/2026-10-02-local-sandbox-design.md), [local-enrollment-contract](../../reviews/2026-10-02-local-enrollment-contract.md), [hostclient-research](../../reviews/2026-10-02-hostclient-research.md), [sandbox-research](../../reviews/2026-10-02-sandbox-research.md)

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

- Overlapping networks or missing Linux kernel capabilities: fail preflight before provisioning or host mutation.
- Pending/wrong/expired/replayed invitation: no credential or private access before real signed approval.
- Partial native apply or process crash: applied revision stays unchanged and journal enables scoped recovery.
- External route/resolver changes: cleanup reports conflict instead of overwriting another owner.
- Revoke/remove policy and credential expiry: ordinary browser access stops; restart preserves independent identities.

---

### Task 1: Expose real client join with safe bootstrap inputs

**Files:**

- Modify: `internal/cli/client/command.go`, `internal/node/enroll.go`, `internal/node/activation.go`, state bootstrap
- Create: `internal/cli/client/join_test.go`, client enrollment documentation

**Interfaces:** Produce `client join` followed by normal run using control origin, explicit CA, root public key/network fingerprint and private state path. Signed invite fragment and code use terminal prompts or stdin, never argv. Reuse EnrollByInvite, controlclient and credential owner.

- [ ] **Step 1: Pin behavior.** Add TestJoinRejectsWrongRootOrNetwork, TestInvalidOrExpiredInviteLeavesUnenrolled, TestPendingDoesNotApplyTunnel, TestClaimReplayRejected and TestPrivateInputNotPrinted. Real SQL/Redis approval/claim test uses independent generated gateway/client identities.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/cli/client ./internal/node/... ./internal/companion ./internal/control/workflows ./internal/control/httpapi`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Persist device keys before proof; show pending/approved/claimed/applied as distinct states. Trusted companion signs exact approval diff and snapshot; never auto-approve fixture data. Root private key stays with companion. TLS verification and signed lineage both required; no enrollment token shortcut.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/cli/client ./internal/node/... ./internal/companion ./internal/control/workflows ./internal/control/httpapi` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: expose signed invitation client join`.

### Task 2: Add native macOS network owner

**Files:**

- Create: `internal/tunnel/interface_darwin.go`, `interface_darwin_test.go`
- Create: `internal/node/networkplan/plan.go`, `plan_test.go`, `internal/client/macos/adapter.go`, `journal.go`, their tests
- Modify: `internal/tunnel/interface_unsupported.go`, `internal/node/{wireguard_reconciler,dns_reconciler}.go`, client CLI wiring

**Interfaces:** Produce validated `networkplan.Plan` containing interface peers, scoped route prefixes and suffix/resolver pairs from verified snapshot. macOS `Adapter.Apply(context.Context,Plan) error` and `Close(context.Context) error` own utun, routes and resolver journal. Narrow helper entrypoint is `client network-helper`, accepting versioned bounded JSON over local stdin, not arbitrary shell commands.

- [ ] **Step 1: Pin behavior.** Add TestPlanRejectsDefaultRouteAndForeignSuffix, TestPartialApplyKeepsRevision, TestCleanupPreservesExternalChanges, TestJournalRecoversInterruptedApply and TestNativeArgumentsCannotExecuteShell. Fake command runner tests exact arguments; actual utun/route/DNS acceptance is separately manual.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/node/... ./internal/client/macos ./internal/tunnel ./internal/cli/client`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Use preinstalled wireguard-go/wg with fixed resolved paths, native route/ifconfig operations and `/etc/resolver/sandbox.home.arpa`; no wg-quick global DNS. Controller runs unprivileged, helper verifies the signed snapshot against its explicitly provisioned trusted public root/network, checks owner UID/state path and bounded permitted subnet/suffix, and never reads root signing keys. Pass the signed envelope alongside the requested plan and reject a plan that differs from deterministic compilation; an unprivileged caller cannot supply arbitrary networking. Private helper journal under owned state is not replaceable via symlink. Prepare before mutations, cleanup in reverse order, report conflicts. Advance applied revision only after tunnel/routes/DNS all succeed.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/node/... ./internal/client/macos ./internal/tunnel ./internal/cli/client` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: own native macos tunnel routes and scoped dns`.

### Task 3: Provision isolated portable Docker fixtures

**Files:**

- Create: `deploy/compose.sandbox.yaml`, `deploy/sandbox/Dockerfile.gateway`, `Dockerfile.fixture`, `dns.conf`, `site/index.html`
- Create: `scripts/sandbox_init.py`, `scripts/sandbox_preflight.py`, `scripts/tests/test_sandbox_config.py`
- Modify: node/relay advertised endpoint mapping and focused tests as required

**Interfaces:** Produce independent Compose project `homeharbor-sandbox`, separate ignored state/volumes/CA. Defaults: underlay 172.28.40.0/24, private 172.29.50.0/24, overlay 10.200.0.0/24; private gateway .2, resolver .53, dummy site .80, suffix sandbox.home.arpa. Export only control/relay TLS plus bounded UDP 52000–52015 one-to-one.

- [ ] **Step 1: Pin behavior.** Add TestSandboxNetworksIsolated, TestPrivateServicesHaveNoPublishedPorts, TestUnderlayCannotReachPrivateFixture, TestRelayAllocatedPortMapsOneToOne and TestEndpointAudienceMatchesGatewayAndHost. Preflight rejects subnet overlap and probes Linux WireGuard/nft forwarding capability rather than inferring it from Docker availability.
- [ ] **Step 2: Establish the baseline.** Run `python3 -m unittest scripts.tests.test_sandbox_config`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Use distinct backend/underlay/internal private networks. Fixture overlay return route via .2; gateway nft denies untrusted underlay/private shortcut in addition to product WG policy. Grant only required NET_ADMIN/devices, no privileged blanket or Docker socket. Use role-specific control endpoint mapping for container and native host and correct relay ticket audience. Explicit local CA trust step; no silent host trust-store install. Reuse focused init functions, not dev state.
- [ ] **Step 4: Verify.** Run `python3 -m unittest scripts.tests.test_sandbox_config` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: provision isolated manual sandbox fixtures`.

### Task 4: Add optional manual workflow and demonstrate real access

**Files:**

- Create: `scripts/sandbox.sh`, `scripts/tests/test_sandbox_workflow.py`, `docs/manual-testing/macos-sandbox.md`
- Modify: `Makefile`, `.gitignore`, `scripts/doctor.sh`, README manual-testing links

**Interfaces:** Produce sandbox-up/client/status/logs/check/down/reset targets. down preserves identities and removes only owned network state; reset explicitly removes this stopped sandbox state. None of these targets is called by any mandatory verification target.

- [ ] **Step 1: Pin behavior.** Add TestSandboxExcludedFromEveryRequiredGate, TestDownPreservesState, TestResetRejectsActiveOrForeignProject, TestCommandsDoNotLogInviteCode and TestCleanupRequiresOwnership. Script tests use bounded stubs and never configure a real host.
- [ ] **Step 2: Establish the baseline.** Run `python3 -m unittest scripts.tests.test_sandbox_workflow scripts.tests.test_sandbox_config`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Document dependencies, explicit CA/browser trust, independent keys, companion approval and recovery. Manual sequence: up → denied private hostname → join/pending → companion signs approval → applied VPN/DNS → ordinary browser opens private site → denied non-profile service → revoke/remove access → denied again → run beyond 15-minute credential lifetime → restart → down. Capture route/scutil/dns and packet-path evidence without secrets. No hosts entry, HTTP/DNS host publishing, viewer proxy or Docker-subnet client can substitute for this flow.
- [ ] **Step 4: Verify.** Run `python3 -m unittest scripts.tests.test_sandbox_workflow scripts.tests.test_sandbox_config` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: add optional macos sandbox manual flow`.

## Completion Gate

Run `make verify` without provisioning the sandbox; compare targets/CI/acceptance to prove exclusion. Then explicitly execute the manual Mac flow on the actual available host, including interrupted apply/cleanup and credential rotation. If Docker VM lacks required kernel features, report that prerequisite and keep optional scenario pending; do not weaken the security contract. Windows and a second physical LAN device are deferred.
