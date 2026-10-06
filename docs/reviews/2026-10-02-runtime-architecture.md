# HomeHarbor: runtime architecture and shared libraries

Date: 2026-10-02. Source revision inspected: `b66865b598e75efd291f357a923eae8c7b256a3d`. This extends the [structure proposal](2026-10-02-project-structure.md). The user accepts additional library complexity when it makes business logic simpler. This changes the earlier conservative Cobra recommendation: adopt it across all seven first-party executables, while preserving separate binaries and privilege boundaries. Runtime code has not been changed.

## Decisions

1. Standardize all command adapters on Cobra; keep configuration and application execution independent of Cobra.
2. Build focused shared libraries for process execution, configuration, supervision, control API transport, credentials and signed protocol/access rules. Prefer deep interfaces that hide real repetition over wrapper packages.
3. Keep Watermill as an implementation option behind a control-owned event module for genuine asynchronous consumers. Remove its current context-receipt hop from the critical audit write path when restructuring that path. Do not make all business interactions asynchronous.
4. Prioritize credential/session authority and startup/shutdown safety before cosmetic package moves.

## Cobra everywhere: one execution contract

```text
main -> CLI host -> role command -> typed config -> role application
                                          -> finite use case OR supervised daemon
```

Each `main` creates a fresh role command, delegates execution and exits once after owned cleanup has run. The host controls arguments, streams, signals, error presentation and exit classification. Commands parse once and call application operations using `cmd.Context()`. Help/version/completion must work without files, secrets, database or network. No global command trees, logger mutation or mutable config registry in business logic.

Keep `control`, `relay`, `agent`, `client`, `admin`, `migrate` and `healthcheck` as separate binaries. A one-command Cobra healthcheck is an acceptable consistency tradeoff; preserve its two-second deadline and avoid importing application runtimes. Existing single-dash multi-letter arguments in Compose/scripts must be migrated alongside the commands.

Configuration remains a separate typed module. Explicit CLI flags override environment/file values even when zero/false/empty; validate the final values. Resolve only selected secret files after overlays. Viper may implement those overlays but is not a dependency of application services. Required effective configuration must be checked after file/environment composition, rather than relying on required CLI-flag annotations.

Cleanup must use lexical `defer`, not `PostRunE`: Cobra skips post-run hooks after a `RunE` error. Persistent hook inheritance also requires deliberate design, so avoid making hooks an opaque startup framework. See [the pinned-source Cobra investigation](2026-10-02-cobra-runtime-research.md).

## Shared libraries that simplify callers

| Module                   | Small caller-facing interface                                    | Complexity it owns                                                                | Location                                         |
| ------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------ |
| CLI host                 | Execute command with context/arguments/streams; return exit code | Signal handling, usage/runtime errors, output policy                              | `internal/cli/host`                              |
| Configuration            | Load effective typed role config from source inputs              | Defaults, strict schema, source precedence, secret selection, validation          | `internal/platform/config`                       |
| Supervision              | Run named essential workers under cancellation                   | Unexpected termination, original error preservation, join and diagnostics         | `internal/platform/lifecycle`                    |
| HTTP runtime             | Serve with explicit drain/connection ownership                   | Listener teardown, bounded graceful drain, upgraded-session close/join            | `internal/platform/httpserver`                   |
| Control client           | Typed remote operations using current credential provider        | HTTP timeout/body limits, status errors, response validation                      | `internal/controlclient`                         |
| Credential owner         | Current credential lease; supervised rotation                    | Expiry, serialization, durable replacement, consumer notification, recovery state | `internal/node/credentials`                      |
| Local state              | Load/save/lock identity state                                    | Private file checks, atomic replacement, crash durability, single writer          | `internal/node/state`                            |
| Signed contracts and ACL | Validate/verify/compile explicit values                          | Canonical encoding, signatures, deterministic rule semantics                      | `internal/protocol`, `invite`, `snapshot`, `acl` |
| Control events           | Append fact in business transaction; register typed consumer     | Envelope mapping, durable delivery, retries, deduplication, observability         | `internal/control/events`                        |

A shared library need not be a separate Go module. Keep one `go.mod`; these packages are shared by actual roles. Only publish independently when an external consumer and compatibility lifecycle exist. Node credential/state behavior is shared between client and gateway, but is not neutral platform behavior. Concrete database/Redis adapters remain behind owning domain/application interfaces.

Business methods should expose operations such as approval/publication, not require callers to orchestrate credential refresh, decode HTTP errors, acknowledge Watermill messages or manage cleanup hooks. Hide those mechanisms within their owner. Keep transaction context and orchestration explicit when invariants cross domains; do not introduce a universal service locator, generic repository or reflection-driven application graph.

## Execution findings, prioritized

### High: live coordination sessions retain startup authorization

Evidence: `internal/control/coordination/handler.go:101` authenticates once. The message loop uses the captured `device`; candidate handling refreshes the destination at line 205 but not the source. `internal/app/control/http.go:70` authorizes based on the supplied source/destination status. No live sender revalidation/expiry timer or revoke-driven session closure was found in the inspected path.

Consequence: credential expiry/revocation rejects new requests, but an existing WebSocket can retain its old authorization and continue receiving broadcasts or sending candidate updates. This is a source-confirmed enforcement gap, not a claim of forged snapshots or arbitrary VPN access. Snapshot authority and packet-plane authorization remain separate.

Target: make session lifetime explicit. Bound a session by its credential lease, recheck device status during sensitive operations, and close active sessions on revoke with periodic checks as a recovery mechanism. A process-local invalidation bus alone cannot enforce revocation across multiple control replicas. Rotation must establish a fresh authorized session without overlapping duplicate device sessions.

### High: no long-lived credential owner

Evidence: `internal/control/devices/service.go:37` defaults credentials to 15 minutes; startup runtime config caps the issuance lifetime at 15 minutes. `internal/app/node/runtime.go:90` rotates only when startup refresh is requested. Relay renewal captures `state.DeviceCredential` at line 200; coordination gets the same static string at line 269. Enrollment/rotation responses do not provide a usable expiry field to the current node client, and persisted State contains no expiry.

Consequence: after expiry, reconnect/ticket renewal can fail indefinitely while loops retry with the same credential. An already-admitted packet plane has its own lifecycle; this finding does not mean every tunnel stops exactly at minute 15.

Target: return an explicit lease expiry in protocol responses, persist it, and have one owner rotate before expiry. Both transports obtain a current lease rather than capture strings. Serialize rotation and update consumers only after durable local save. The remote rotation currently invalidates the previous credential immediately, so a lost response or failed local save can strand the node; define bounded overlap/idempotent recovery or an identity-proof reauthentication protocol before promising crash-safe rotation. Never silently re-enroll or extend an expired credential locally.

### Medium/high: supervisor distinguishes only errors, not essential exits

Evidence: `internal/platform/lifecycle/component.go:50` cancels siblings only for a non-nil error. A long-lived worker returning nil while the parent is active leaves siblings running. Cancellation then waits indefinitely for a worker that does not return.

An isolated copy of the current supervisor reproduced both behaviors with controlled workers: nil exit leaves a sibling running; cancellation does not return before an uncooperative owner is released. This is not proof of a currently deployed worker hanging.

Target: keep finite bootstrap/tasks separate from named essential workers. Any unexpected essential exit cancels siblings and reports which owner stopped. Use role-specific shutdown deadlines and a hard process termination policy after a drain deadline; Go cannot safely kill an arbitrary goroutine. Do not return early and close shared stores while workers still use them. A second termination signal should allow an operator to end a stuck drain.

### Medium/high: gateway guard is late in startup preparation

Evidence: node startup prepares identity/enrollment and relay admission before returning the bootstrap guard (`internal/app/node/runtime.go:48,72`); `App.Run` invokes that guard only after startup finishes. The guard correctly precedes tunnel workers, and the staged snapshot applier correctly leaves the gateway denied after partial apply.

Consequence/inference: when restarting on a host retaining old kernel state, a control/enrollment failure can happen before the new deny guard is installed. The actual residual-state behavior needs Linux restart/kill verification; no packet-level exploit was reproduced here.

Target: after read-only config/trust preflight, establish the gateway's owned-interface deny guard before network admission or persistent enrollment work. Keep client startup non-forwarding. A guard must affect only HomeHarbor-owned traffic; do not reset host-wide firewall state. Define shutdown behavior explicitly: orderly shutdown leaves an owned deny state; crash/restart behavior must be tested.

### Medium: resource acquisition and shutdown contracts differ by role

Control `New` acquires stores and transfers ownership to `Run`; node construction defers startup and relay construction binds nothing. Control correctly closes on construction failure and listener failure, but a constructed, never-run app has no public Close. Prefer acquisition/cleanup inside a role Run function, or expose explicit Close for acquired apps. Constructors used for CLI help must remain side-effect free.

HTTP graceful shutdown and upgraded socket ownership are already handled separately, which should be preserved. On a drain timeout, closing the server is not proof every handler has returned; waiting for Serve does not join active handlers. Resource teardown must account for handler ownership and cancellation. The standard library documents that Shutdown excludes hijacked connections and Serve returns before Shutdown completes. [Go HTTP server contract](https://pkg.go.dev/net/http#Server.Shutdown)

`internal/node/coordination.go:313` launches a session candidate publisher without explicitly joining it. Its context is cancelled, but a shared lifecycle module should guarantee completion rather than only request cancellation. Add an owned join for that session worker.

`cmd/migrate/main.go:24` uses Background and exits directly after resource acquisition on failure. Admin remote operations also ignore process context. Cobra should route cancellation/deadlines into those operations; interrupted finite work must not be reported as success. `os.Exit` skips defers. [Go process exit](https://pkg.go.dev/os#Exit)

### Medium: state replacement is atomic but not crash-durable or single-owner

`internal/node/state.go:43` uses private temporary files and rename; Load validates file permissions and matching keys. These are good safeguards. Save does not sync file/directory and LoadOrCreate has no process lock. The signed snapshot persistence code already syncs both (`internal/node/snapshot_state.go:131,160`).

Target: reuse a focused state writer with file+directory sync and an explicit lock for the runtime lifetime. Concurrent processes configured with the same state path must fail clearly rather than generate/rotate competing identities. This is a source-derived concurrency/crash risk, not a reproduced data-loss incident.

## Event decoupling: where Watermill helps

The user's event-consumer direction is appropriate for facts that tolerate asynchronous delivery. Replace direct downstream calls with committed events for audit projection, Activity/read models, notifications and other independent reactions. Commands still own validation and atomic business state; events announce committed results.

| Interaction                                               | Recommended execution                                       | Why                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------- |
| Claim/replay checks, invite consumption, activation state | Explicit transactional workflow                             | Partial success must not grant access or consume a token inconsistently |
| Policy validation/revision confirmation                   | Synchronous command before commit                           | Caller needs authoritative success/conflict                             |
| Audit/read-model projection, notifications                | Durable asynchronous fact consumers                         | Independent downstream behavior and retries                             |
| Browser refresh hint                                      | Best-effort post-commit invalidation                        | Poll/requery repairs a missed hint                                      |
| Live-session revoke notification                          | Fast event reaction plus authoritative expiry/status checks | Missing a notification must not preserve authority forever              |

Decoupling requires meaningful typed facts. An event containing only an ID can force the consumer to call the original module and recreate the dependency. Prefer sufficient non-sensitive facts or a consumer-owned projection. Do not copy secret-bearing credentials or entire internal records into events. Use explicit event type/schema version, stable event ID, aggregate revision where ordering matters, occurred time, actor/target and correlation ID.

Watermill should remain behind `control/events`; business modules must not depend on `message.Message`, topic strings or Ack/Nack. Consume typed facts through small handlers. This hides broker mechanics without hiding the business fact vocabulary.

## Current Watermill path and target

See [the source-backed Watermill investigation](2026-10-02-watermill-research.md) for GoChannel, SQL consumer groups, Forwarder and migration caveats.

Current inspected path:

```text
business transaction -> PostgreSQL outbox
outbox transaction holds row locks -> GoChannel
    -> context-carried receipt -> audit INSERT on another pool connection
    -> domain-topic Publish with no production subscribers found
    -> mark outbox published -> commit
```

Durability comes from SQL outbox/audit idempotency, not the memory bus. The context-carried receipt couples publisher and subscriber inside one process, making broker replacement nontrivial. A single pool connection is structurally insufficient: the dispatcher holds it while the audit sink requests another; this wait scenario was inferred from code, not reproduced against PostgreSQL. Locks remain held through the consumer round trip.

For the current audit consumer, write the audit projection and delivery completion in one SQL transaction, removing the extra bus hop and second connection dependency. Preserve stable event IDs and unique deduplication constraints.

Retain Watermill as the messaging adapter for real asynchronous consumers. Decide delivery topology before adding a second durable consumer: GoChannel is suitable for local best-effort notifications, while independent durable consumers need persisted delivery/offset state or a durable broker with independently tracked consumer groups. One global published flag is not independent completion for multiple consumers. Do not introduce RabbitMQ/Kafka merely for internal UI updates; PostgreSQL-backed delivery is a viable option to investigate under the same conformance tests.

The dispatcher currently treats any delivery error as process-fatal. It does not implement per-event retry/backoff or persist failed attempts/last_error: the whole batch rolls back. Define transient retry, poison-event quarantine, critical-consumer readiness and outbox lag explicitly. Do not silently skip an audit event to keep readiness green. Separate required durability from optional notifications so an unavailable notification consumer does not stop the entire control service.

## Validation performed and remaining work

Fresh `go test -race` passed for `internal/platform/lifecycle`, `internal/app/node`, `internal/app/control` and `internal/control/coordination` on the inspected revision. The two isolated supervisor observations passed, confirming the observed gaps rather than fixes. No runtime code changes were made.

Still required before implementation completion: live WebSocket revoke/expiry test; controlled-clock credential rotation including lost response/save failure; SQL pool-size-one and replay/consumer-failure tests; Linux guard-before-admission and restart/crash verification; stopped-handler/worker ownership under drain timeout; CLI help/overrides/cancellation and deployment invocation migration.

Implement in that order of safety first, then shared CLI/config/runtime libraries, then event adapter/projections and broader module relocation. Folder structure alone does not repair these execution contracts.

### Selected credential recovery contract (Runtime Task 3)

Use identity-proof reauthentication, with no old-bearer overlap. The fixed
[credential protocol](../../api/protocol.md) binds a fresh 32-byte single-use
nonce, network, device and 60-second expiry under the distinct Ed25519 signing
domain `homeharbor/credential-recovery/v1\x00` (actual trailing NUL). Redis owns
shared challenge consumption and fail-closed onboarding quota. SQL locks the
device row, rechecks active identity, and atomically replaces credentials with
an outbox fact. Unknown devices receive ordinary challenges without lookup;
completion uses generic proof errors. A lost response or local persistence
failure requires a fresh challenge, never reenrollment. Leases expose actual
issuance expiry capped at 15 minutes and persist it with local identity state.

### Gateway startup and stop safety (Runtime Task 5, 2026-10-07)

Gateway startup now orders read-only configuration/trust validation, exclusive
local-state ownership, HomeHarbor-owned tunnel deny, identity loading/creation
and durable saves, enrollment/credential/relay admission, then supervised
workers. The state lock is an ownership prerequisite: a competing process or
filesystem ownership failure returns before firewall mutation. Successful deny
installation is required before identity work or admission. If nft installation
fails, startup returns its error and starts no admission or workers; it cannot
promise that a guard was established. Clients never install forwarding guards.

A complete verified signed snapshot remains the boundary for releasing deny.
Partial application does not advance the applied revision. Orderly gateway stop
joins all workers and their cleanup, then reinstalls owned deny using a bounded
fresh cleanup context before releasing the state owner. Worker, guard-cleanup
and state-close errors are joined. The guard changes only HomeHarbor's table and
tunnel-interface traffic; it does not disable unrelated host forwarding.

The Linux namespace packet fixture measured the crash limitation directly:
SIGKILL of a running runtime retained the previous kernel allow and private HTTP
remained reachable. Restart against unavailable control replaced that allow with
deny before credential admission, so private HTTP failed. SIGTERM shutdown also
left private HTTP denied. An unrelated forwarding path stayed reachable and a
separate owner's nft table remained identical after both transitions. An abrupt
crash therefore does not immediately revoke the last applied policy; denial
requires a successful restart guard (or an external owner intervention).

Evidence: `TestLinuxNamespaceGatewayRestartRetainedAllow` passed in the existing
disposable Linux arm64 VM, alongside both existing namespace policy/WireGuard
fixtures and `TestLinuxResolvedSplitDNSLifecycle`. The restart fixture runs the
production runtime and real nft commands, but explicitly seeds the retained
allow directly; it does not claim signed-snapshot delivery coverage. The focused
race suite for `internal/app/node`, `internal/agent/nft`, and `internal/node`
passed, including guard-before-enrollment/renewal/relay, failed admission,
failed guard, shutdown cleanup failure, and client isolation regressions.
