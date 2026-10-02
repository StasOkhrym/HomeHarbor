# HomeHarbor Runtime Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep authorization current and give each worker, credential and local network resource a clear owner.

**Architecture:** Correct execution semantics before moving packages. Use one persisted credential owner and identity-proof recovery instead of keeping old bearer credentials valid. Essential workers are joined; an uncooperative drain is handled at the process boundary.

**Tech Stack:** Go, PostgreSQL, Redis, Cobra, Watermill, Go templates/HTMX, Docker Compose and native macOS adapters as scoped below.

**Spec:** [runtime-architecture](../../reviews/2026-10-02-runtime-architecture.md), [local-enrollment-contract](../../reviews/2026-10-02-local-enrollment-contract.md)

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

- Live sessions after revoke/expiry: sensitive messages must fail immediately on authoritative checks; idle sessions close within the configured recheck interval.
- Rotation response loss or local save failure: recover with the original device identity, never silently enroll a new device.
- Unexpected successful worker exit: cancel siblings and identify the stopped essential worker.
- Concurrent processes/state corruption: reject competing ownership and never replace damaged identity automatically.
- Gateway restart with old kernel rules and unavailable control: install owned deny rules before admission.

---

### Task 1: Own essential workers and shutdown

**Files:**

- Modify: `internal/platform/lifecycle/component.go`, `internal/platform/lifecycle/component_test.go`
- Modify: `internal/app/control/{app,server}.go`, `internal/app/node/{app,runtime}.go`, `internal/app/relay/app.go`, `internal/node/coordination.go`
- Create: `internal/platform/lifecycle/essential.go`, `essential_test.go`

**Interfaces:** Add `type Worker struct { Name string; Component Component }` and `RunEssential(context.Context, ...Worker) error`. Keep finite tasks outside this API; existing Component.Run remains unchanged.

- [ ] **Step 1: Pin behavior.** Add TestEssentialNilExitCancelsSiblings, TestEssentialErrorJoinsOwners, TestParentCancelIsOrderly, TestCandidatePublisherJoined and TestServerDoesNotCloseStoresBeforeHandlersExit. Use channels instead of sleep-based ordering; assert worker name appears in unexpected-exit errors.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/platform/lifecycle ./internal/app/... ./internal/node`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Cancel on any essential exit while parent is active; join workers and coordination publishers. Preserve explicit upgraded-socket ownership. Move control resource acquisition into Run, keeping New side-effect free; close resources in reverse ownership order. Carry configured drain deadline and second-signal termination to the CLI host in the CLI plan; do not return and close stores under live workers.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/platform/lifecycle ./internal/app/... ./internal/node` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: own essential runtime workers and resource shutdown`.

### Task 2: Persist and lock node state

**Files:**

- Modify: `internal/node/state.go`, `internal/node/state_test.go`, `internal/app/node/runtime.go`
- Create: `internal/node/localstate/store.go`, `store_test.go`, platform-specific lock files

**Interfaces:** Add `localstate.Open(path string) (*Store, error)`, `(*Store).Read() ([]byte,error)`, `(*Store).Replace([]byte) error`, `(*Store).Close() error`. Node keeps State decoding/key validation; store owns lifetime lock and private file writes.

- [ ] **Step 1: Pin behavior.** Add TestSecondOwnerRejected, TestReplaceSyncFailurePreservesOldState, TestPrivateMode, TestInvalidKeysFailClosed and TestRestartReusesIdentity. Inject filesystem failure points; assert no new identity is generated after corruption.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/node/... ./internal/app/node`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Acquire the lock before LoadOrCreate and retain through runtime. Write private temp, sync file, rename, sync parent directory. Reuse the snapshot persistence guarantees without copying trust logic. Reject symlink/unsafe parent paths and unsupported locking semantics explicitly.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/node/... ./internal/app/node` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: make node state durable and single owner`.

### Task 3: Define recoverable credential leases

**Files:**

- Modify: `internal/control/devices/service.go`, `internal/control/devices/storage/repository.go`, `internal/control/httpapi/devices.go`
- Modify: `internal/app/control/challenges.go`, `internal/app/control/http.go`, `internal/node/state.go`
- Create: `internal/protocol/credentials.go`, `credentials_test.go`, `internal/control/workflows/credential_recovery.go`, `credential_recovery_test.go`
- Create: `api/protocol.md`, `api/testdata/credential-recovery.json`

**Interfaces:** Produce `protocol.CredentialLease { DeviceID string; Credential string; ExpiresAt time.Time }`. Produce `protocol.CredentialChallenge { Version uint16; NetworkID string; DeviceID string; Nonce string; ExpiresAt int64 }` and `protocol.CredentialProof { Challenge CredentialChallenge; Signature string }` with explicit JSON/CBOR tags. Recovery uses a distinct canonical signed challenge binding network, device, nonce and expiry to the registered Ed25519 public key. No old-credential overlap. Document request/response DTOs and fixed signing domain before implementing either peer.

- [ ] **Step 1: Pin behavior.** Add TestRecoveryRequiresActiveDeviceIdentity, TestRecoveryChallengeConsumedOnceAcrossReplicas, TestRecoveryRejectsWrongNetworkAndExpiredNonce, TestRotationResponseIncludesExpiry and TestRecoveredCredentialInvalidatesOldCredential. Real Redis tests exercise single-use consumption; real SQL tests exercise status/credential atomicity.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/control/devices/... ./internal/control/workflows/... ./internal/control/httpapi ./internal/protocol ./internal/app/control`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Use 32 random nonce bytes, a 60-second challenge TTL and a separate signing domain `homeharbor/credential-recovery/v1\x00`. Challenge creation is rate limited and does not disclose device existence; completion verifies signature, consumes challenge and rechecks active status inside credential replacement transaction. Successful response loss is recoverable by requesting a new challenge. Never log credentials/proofs; retain the 15-minute credential cap. Record this selected recovery design in the runtime spec.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/control/devices/... ./internal/control/workflows/... ./internal/control/httpapi ./internal/protocol ./internal/app/control` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `feat: add identity proof recovery for credential leases`.

### Task 4: Refresh leases and revalidate live sessions

**Files:**

- Create: `internal/node/credentials/owner.go`, `owner_test.go`
- Modify: `internal/app/node/runtime.go`, `internal/node/{relay,relay_v2,coordination}.go`
- Modify: `internal/control/coordination/handler.go`, its session owner and tests

**Interfaces:** Produce `credentials.LeaseSource` with `Current(context.Context) (protocol.CredentialLease,error)`. Owner.Run(context.Context) is essential; inject clock, rotation/recovery calls and durable save. Coordination accepts an authoritative lease authenticator and current device reader.

- [ ] **Step 1: Pin behavior.** Add TestOneRotationUnderConcurrentConsumers, TestConsumersSeeOnlyDurablySavedLease, TestLostResponseRecoversWithIdentity, TestExpiryDoesNotExtendLocally, TestLiveSourceRevokeDenied, TestIdleSessionExpiryCloses and TestRotationReplacesSessionWithoutDuplicates. Fake clock covers a run longer than 15 minutes.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/node/... ./internal/control/coordination ./internal/app/node`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Rotate at 80% of lease lifetime; bound retry by expiry, then stop admission and recover using Task 3. Relay renewal reads Current per operation. Coordination reconnects on lease changes; bind socket to admission expiry, reauthenticate source on sensitive operations and every 5 seconds while idle, cancel on local revoke hint. Redis/SQL checks remain authoritative across replicas.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/node/... ./internal/control/coordination ./internal/app/node` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: refresh credentials and revoke live sessions`.

### Task 5: Install gateway deny guard before admission

**Files:**

- Modify: `internal/app/node/runtime.go`, `bootstrap_test.go`, `runtime_side_effects_test.go`, `internal/agent/nft/applier.go`
- Modify: `scripts/acceptance.sh` and its existing Linux fixture runner

**Interfaces:** Reorder existing bootstrap: read-only validation → owned deny guard → identity/admission → tunnel workers → signed complete apply. Client mode never installs forwarding guards.

- [ ] **Step 1: Pin behavior.** Add TestDenyPrecedesEnrollmentAndRelayAdmission and TestAdmissionFailureLeavesOwnedDeny. Linux scenario: retain previous allow state, stop/restart with control unavailable, probe private fixture and require denial without changing unrelated host forwarding.
- [ ] **Step 2: Establish the baseline.** Run `go test -race ./internal/app/node ./internal/agent/nft ./internal/node`. New regression tests must fail for the named behavior, not missing tooling; existing characterization tests must pass. Record the actual result.
- [ ] **Step 3: Implement.** Guard only HomeHarbor-owned interfaces/chains. Leave owned deny state on orderly gateway stop; partial apply never advances applied revision. Preserve Linux fail-closed contract and document actual crash behavior from packet-level acceptance.
- [ ] **Step 4: Verify.** Run `go test -race ./internal/app/node ./internal/agent/nft ./internal/node` again; require PASS, no races where `-race` is used, and the assertions from Step 1.
- [ ] **Step 5: Review and commit.** Review the task diff against its spec, stage only the Files above plus consumers discovered through imports, and commit as `fix: guard gateway traffic before network admission`.

## Completion Gate

Run focused tests, real SQL/Redis credential/revoke integration and existing Linux acceptance explicitly. Do not claim packet-level guard behavior from fake tests. Store unavailable platform checks as pending; runtime safety is not complete until required integration evidence exists. Run `make verify` after this subplan. No manual sandbox invocation.
