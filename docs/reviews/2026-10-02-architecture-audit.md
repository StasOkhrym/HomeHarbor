# HomeHarbor architecture audit — 2026-10-02

Reviewed checkout: `/Users/s.okhrym/personal_code/homeharbor`, `main`, `12130aa`.
This report distinguishes observed code from proposed changes. No runtime source
was changed during the audit. It is not a completed security or VPN E2E audit.

## Verdict

The control plane is a modular monolith: one application owns vertical domain
modules, explicit dependencies, module-owned storage and cross-module SQL
transactions. The whole product is a multi-process networking system containing
that monolith, a relay, a trusted companion and Linux nodes. Splitting control
into microservices would add operational complexity without addressing the
observed problems.

The useful structure already exists. Its weakest areas are shared protocol
ownership, obsolete relay paths, incomplete credential lifecycle and the gap
between audit storage and an operator-readable activity feed.

## Findings, ranked

### High: credential rotation is not owned by the running node

`internal/app/node/runtime.go:97–107` performs rotation only during startup when
`Refresh` is enabled. The relay ticket provider at lines 198–209 captures the
original `state.DeviceCredential`. Credentials have a maximum default lifetime
of 15 minutes (`internal/control/devices/service.go`). There is no supervised
credential rotation worker in the runtime assembly. An established data path
can survive, but subsequent admission/reconnect can fail after expiry.

Proposed fix: one credential owner shared by coordination and relay clients;
rotation before expiry, atomic state persistence, serialized rotations and
cancelable retries. Return expiry information from issuance/rotation instead of
making clients infer server configuration. An expired/revoked credential must
never silently become authorized again. Preserve the last valid signed network
state and existing packet plane during temporary control outages.

### High: audit records misidentify non-device events

`internal/platform/events/pipeline.go:93–112` decodes every outbox payload as
`devices.Event` and writes device actor/target identities. Activation emits
`invite.approved` with an invite aggregate ID. It therefore becomes an audit
record incorrectly describing a device. Even enrollment events cannot reliably
identify the initiating actor from the aggregate ID alone.

Proposed fix: a neutral event envelope containing event identity, action,
occurrence time, explicit actor and target, and producer-controlled safe
metadata. Write outbox entries in the mutation's SQL transaction. Keep delivery
idempotent and display unknown historical attribution honestly. Do not infer or
invent historical actors during migration.

### Medium: clients import server application implementation

`internal/node/activation.go:21` imports `internal/app/control/workflows` to use
claim DTOs, signing and lifetime/error constants. This makes node builds depend
on server workflow dependencies, including Redis-related code. The current
architecture test checks selected control domains but does not protect node
from application-package imports.

Proposed fix: move public claim protocol/signing/validation into a focused
`internal/protocol/activation` package. Keep orchestration, SQL transactions and
challenge storage in control workflows. Add directional import tests that also
prevent shared protocol from importing control/app/adapters. Do not move all
domain models into a generic shared package.

### Medium: obsolete relay implementation remains reachable in client code

The deployed relay registers only `/relay/udp/v2`. Nevertheless
`internal/app/relay/app.go` allocates and retains an unused old `Hub` and a
redundant ticket issuer. `internal/node/relay.go` still constructs the framed
WebSocket `Bridge` on legacy branches; the production relay does not register
its corresponding handler. Protocol negotiation still advertises `relay-v1`.
This is an unsupported runtime alternative, not a working fallback.

Proposed fix: retain one authenticated WSS admission/raw UDP relay path. Remove
legacy Hub/WebSocket handler/Bridge/framed Packet code after accounting for its
test and fuzz consumers. Replace old codec fuzzing with admission/control
message fuzzing. Retain cancellation, endpoint proof, nonce, renewal, resource
bounds and socket ownership tests for the surviving implementation.

### Medium: dead exported surface escapes the current unused linter

`ConsumeEnrollmentToken` has no callers, and production `storage.SaveDevice`
has no callers; atomic enrollment uses `Enroll`. `SaveDevice` on the memory
adapter is used by fixtures, so it is not equivalent to dead production code.
`DiscoverServerReflexive` has no call sites. The `--stun`/`stun_server` setting
is passed through configuration but is not used for discovery.

Proposed fix: remove obsolete repository requirements and PostgreSQL methods;
retain narrowly scoped test fixture helpers. Remove unused STUN configuration,
helper and its dependency if nothing remains. Memory repositories are used by
tests and should not be blindly deleted. No whole domain package is confirmed
unused by this pass. Audit exported reachability and build-tagged Linux sources
in addition to running the linter.

### Medium: Activity has no stable read cursor or automatic refresh

The Activity template has a manual refresh form only. Audit `List` sorts by
SQL row ID but returns neither that ID nor `event_id`. Auth events can omit the
outbox delivery ID. Timestamps alone therefore cannot safely deduplicate or
incrementally paginate the feed. New actions also fall back to “Other activity”.

Proposed fix: a dedicated read record with a stable cursor; keep row cursor and
outbox delivery identity separate. Add bounded filters and recent-page refresh.
SQL sequence allocation is not commit order: naïve `id > last_id` polling can
miss a delayed concurrent commit. For this pet project, refresh the bounded
filtered recent window every four seconds, reconcile by row identity and retain
read rows while displaying a new-events count. Older history uses keyset
pagination; document its concurrent-write semantics.

Expose an authenticated HTML fragment endpoint. Preserve filter/search state,
expanded details, scroll and focus. Pause when hidden or explicitly paused;
resume on visibility. One request at a time, cancel when leaving the page,
back off on network/server failures and keep the last successful rows visible.
Session expiry sends the browser to login. Status announcements never steal
focus. The existing global `htmx:afterSwap` listener focuses the page heading;
restrict that behavior to navigation before introducing background swaps.

### Medium: mutation coverage is narrower than the Activity name suggests

Current outbox producers primarily cover devices and activation, plus direct
auth auditing. Service/profile creation, route decisions and policy/snapshot
publication do not all have equivalent operator-readable records.

Proposed fix: record these durable mutations transactionally with explicit
actor/target and safe identifiers, outcome, revision and request correlation.
Render only allowlisted metadata. Do not log bearer credentials, recovery codes,
passphrases, invite codes, key material, raw auth responses or URL credentials.
Default display: time, action, outcome, actor, target; details show correlation,
revision and safe metadata. UI readiness must remain separate from actual
network/tunnel application status.

### Low/medium: CLI infrastructure is repeated inside a large entrypoint

`cmd/admin/main.go` contains six commands, manual dispatch, repeated config/key
flags, unlock helpers, precedence logic and direct stdout/stderr use. There are
no command tests for admin. Simple server binaries have substantially less need
for a CLI framework.

Initial proposal (superseded by the user-selected shared CLI direction): adopt Cobra for admin only; constructors return fresh command
instances, inject output and application dependencies, use command context and
preserve current command names. Keep explicit flags above TOML/defaults;
explicit empty values remain meaningful. Reject unexpected positional args,
provide consistent help/completion and test cancellation/errors. Keep secret
inputs file-based. Cobra does not require Viper; avoid migrating every daemon mechanically.
The follow-up [project structure proposal](2026-10-02-project-structure.md) and
[source-backed Viper/UI research](2026-10-02-viper-ui-research.md) define the
conditions for a bounded startup-only Viper adapter and the recommended typed-loader default.

### Tooling: sound baseline, some avoidable environment coupling

Make already scopes Go packages away from node_modules. CI calls current Make
gates, handles renamed/deleted paths conservatively and fails safe for unknown
files. Formatting is separate from read-only verification. Python already owns
complex local tooling; shell wrappers are small. Rewriting everything into Go
would not improve the observed contracts.

`doctor` checks binary presence and Python version, but not all required Python
imports or pinned runtime/tool compatibility. Make accepts `PYTHON`, while
`verify.sh` and other wrappers directly invoke `python3`. A manually selected
interpreter is therefore not used consistently. The first audit test invocation
used the system interpreter and failed on missing dependencies; the project
virtualenv passed all 64 tooling tests.

Proposed fix: consistently use the chosen interpreter, check Python imports and
supported tool versions early, share gate invocations between Make and wrappers,
and keep Linux privileged acceptance isolated. Preserve explicit CA trust,
secret boundaries, process-group cleanup and CI fail-safe classification.
Do not weaken heavy gates merely because the project is personal.

A concrete harness defect was reproduced during this audit: running verification
with an inherited absolute `PYTHON` override causes
`test_make_test_runs_browser_tests` to run the real Python suite in its copied
fixture, recursively. The fixture stubs `python3` in PATH but inherits `PYTHON`
and Make propagation variables. Stop only the invocation-owned process tree.
Fix fixture environment isolation and add a bounded subprocess timeout; verify
with deliberately inherited interpreter overrides. This is a harness defect,
not evidence that the ordinary production verification command recurses.

## Agreed direction and implementation order

User selected full breaking V2 cleanup, Go templates + HTMX and 3–5 second
polling. Recommended implementation sequence:

1. Establish shared activation contracts, complete import guards, remove dead
   surfaces and the unsupported relay path.
2. Rename surviving implementation to `UDPPair`/`UDPPairBridge`; use
   `/relay/udp`, capability `udp_pair`, and binding prefix `HHUP`. Update
   control/node/relay/config/docs/tooling/tests together. Retain genuine schema
   and cryptographic versioning and third-party `/v2` imports. Reject old relay
   names explicitly; no compatibility aliases. Coordinate local component
   restart; preserve keys/DB/state unless an explicit migration requires change.
3. Fix credential ownership and safe renewal; update protocol expiry fields and
   consumers together.
4. Correct audit events/transactional producers, then implement the bounded
   polling feed and metadata. Existing unattributed history remains unknown.
5. Refine the existing admin UI and migrate admin CLI to Cobra. UI direction:
   compact home-network console, restrained navy/teal palette, semantic status
   colors, clear typography and a Saved → Signed → Gateway unknown state strip.
   Prioritize services/devices and pending decisions over repeated warning cards;
   use responsive lists/tables, inline validation and accessible details. Do not
   invent online/healthy telemetry or expose signing keys to the browser.
6. Improve tooling diagnostics/interpreter consistency and validate the exact
   final tree. Commit boundaries should keep protocol cleanup, credential
   lifecycle, activity and visual changes independently reviewable.

These are proposed changes, not a claim that implementation is finished.

## Acceptance and verification

- Baseline: portable Go suite passed; some SQL/Redis tests intentionally skip
  without test services. Browser script tests: 6 passed. Tooling: 64 passed in
  existing project virtualenv. Linter: 0 issues. Standard `make verify` passed
  with exit 0, including formatting, lint, tooling/browser tests, the Go race
  suite and command builds. SQL/Redis integration, Linux acceptance, VPN E2E
  and authenticated visual UI QA were not run in this audit.
- Regression tests: old relay identifiers rejected, new admission/endpoint
  binding/renewal/data-plane cancellation succeed, peer constraints remain;
  protocol import guards reject server dependencies.
- Credential tests: renewal before expiry, readers receive new credential,
  concurrent rotations serialize, cancellation/persistence failure/revocation
  do not create false success, control outage preserves existing signed state.
- Audit integration: correct actors/targets, mutation+outbox rollback, duplicate
  delivery, legacy event handling, deterministic bounded filtering/history.
- Activity browser tests: delayed concurrent commits, deduplication, one timer,
  hidden/resumed tabs, navigation cleanup, retry, expiry, no focus/scroll loss,
  expanded details and malicious metadata rendered safely.
- UI visual QA: authenticated disposable records at 390 and 1440 pixels,
  keyboard access, reduced motion and empty/loading/stale/error states. Existing
  script tests do not establish visual quality or native passkey correctness.
- Run `make verify`, `make integration`, `make security` and isolated Linux
  `make acceptance` after implementation. Test signed onboarding through
  client/relay/gateway to dummy LAN separately; passing portable tests is not
  proof of that E2E path. Native clients remain deferred and need new contracts.

## Follow-up runtime design

The [runtime architecture review](2026-10-02-runtime-architecture.md) updates the target to Cobra across all executables and deeper shared CLI/config/lifecycle/credential libraries. It adds live-session revocation, credential renewal, startup-guard and supervisor findings at revision `b66865b`, plus a selective Watermill design for committed asynchronous facts. See also [Cobra research](2026-10-02-cobra-runtime-research.md) and [Watermill research](2026-10-02-watermill-research.md). Runtime findings include fresh focused race tests and isolated supervisor observations; the earlier full verification result belongs to its original audit snapshot.
