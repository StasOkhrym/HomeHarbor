# Watermill in HomeHarbor: current fit and future boundary

Date: 2026-10-02. Scope: existing `github.com/ThreeDotsLabs/watermill v1.5.3`, control outbox, audit pipeline, production subscriptions. Read-only review; no runtime changes or database reproduction.

## Decision

Retain Watermill as a private messaging adapter if HomeHarbor deliberately introduces explicit asynchronous consumers, and remove the GoChannel hop from the critical audit delivery path. Preserve durable recording, explicit failure semantics, supervision and tests. Hide transport behind an application-owned delivery boundary; do not make all services communicate only through events. Extra infrastructure complexity is worthwhile when it eliminates business complexity, but here the bus currently creates extra coordination around one database projection.

A modular monolith does not require an event bus. Business modules should expose typed commands, queries and events; they should not receive `*message.Message`, construct topic strings, coordinate Ack/Nack or depend on an implementation's context preservation.

## Verified current path

1. Domain storage appends events to `event_outbox` in the domain SQL transaction (`internal/app/control/storage/activation.go:51`; devices storage uses its explicit event-appender port).
2. The dispatcher holds a separate SQL transaction, locks up to 50 pending rows using `FOR UPDATE SKIP LOCKED`, and calls the publisher before marking rows (`internal/platform/events/audit.go:51-100`).
3. `AuditPipeline.Publish` adds a private receipt channel to the message context and publishes to `internal.audit.outbox`; it waits for a receipt (`internal/platform/events/pipeline.go:128-158`).
4. The subscriber decodes a `devices.Event`, writes an audit record through `audit/storage.Repository`, Acks even failed attempts, then sends the actual write error through the receipt. SQL owns retry identity; the Ack is not a durability guarantee (`pipeline.go:88-121`).
5. The audit repository uses the same pool independently, with `ON CONFLICT(event_id) DO NOTHING`; stable `outbox:<id>` identities make replays idempotent (`audit/storage/repository.go:17-38`).
6. The final publish uses the original domain topic. A source search found only one production `Subscribe`: the audit subscription. These final domain notifications currently have no production receivers.

`openStores` configures only `PreserveContext:true`: neither persistent replay nor blocking acknowledgements is enabled (`internal/app/control/stores.go:91-97`).

## What Watermill actually guarantees here

GoChannel is process-local and normally nonpersistent. Publish returns before subscriber processing; with no subscriber it succeeds without retaining the message. Its optional `Persistent` mode retains messages in memory, not durable disk storage, and can grow memory. Enabling blocking publication alone does not make delivery durable or turn Ack into an SQL commit. [Pinned GoChannel source](https://raw.githubusercontent.com/ThreeDotsLabs/watermill/v1.5.3/pubsub/gochannel/pubsub.go)

Ack/Nack express transport processing outcomes; a real subscriber must flush the appropriate broker/storage acknowledgement after processing. Publisher completion semantics depend on the implementation. [Watermill Publisher and Subscriber contract](https://watermill.io/docs/pub-sub/)

The current pipeline has correctly recognized asynchronous Publish and added a durable receipt. However that receipt is an in-process channel carried by context; it cannot survive serialization or travel to another process. `PreserveContext` is specifically a GoChannel behavior, unlike network pubsubs. Swapping this implementation for Redis, SQL or another broker is therefore not transparent. [Pinned GoChannel context implementation](https://raw.githubusercontent.com/ThreeDotsLabs/watermill/v1.5.3/pubsub/gochannel/pubsub.go)

## Execution and safety findings

**Pool acquisition cycle — code-confirmed mechanism, inferred reproduction.** The dispatcher holds one pooled connection while waiting for the subscriber, which calls `pool.Exec` and needs another connection from the same pool. With `pool_max_conns=1`, that write cannot acquire a connection until the dispatcher releases the first; the dispatcher cannot release it until the write completes. Cancellation can break the cycle, but the worker context has no per-delivery deadline. A one-connection deployment can consequently wait until shutdown. Multiple workers holding all available connections can create the same pattern. No live Postgres test was run to reproduce this case. Increasing pool size only mitigates this design; it does not remove the circular resource dependency.

**Failure policy differs from “retry queue” wording.** `RunOutboxDispatcher` returns on the first delivery/database error, and composition supervises it as critical. Pending rows remain replayable on restart, but there is no continuing in-process exponential retry loop. `attempts` only increments on successful processing; failed attempts roll back and `last_error` is never set in this path. Decide explicitly whether transient storage failures should temporarily remove readiness and retry, or terminate the service. Invalid event payloads should not cause an endless restart loop without a diagnosable quarantine/escalation policy.

**Locks span two transactions and subscriber scheduling.** The dispatcher keeps all claimed row locks while sequentially waiting for independently committed audit writes. A late error rolls back all outbox markers, even though earlier audit writes may already be committed. Existing idempotency handles replay, but the arrangement prolongs locks and requires coordination that one local SQL transaction could avoid.

**Audit semantics are domain-specific.** All payloads are decoded as `devices.Event` and actor/target are always labeled device, even when topics represent invitation activity. This is an audit projection owned by control, not a neutral platform library. Introduce a typed event envelope with event ID, type, schema version, actor and target where meaningful, timestamp, correlation and allowlisted metadata. Do not store credentials, session tokens, recovery codes or request bodies.

## Simpler recommended audit implementation

Keep the existing transactional outbox if delayed audit projection is intentional. Give the worker a transaction-aware audit projector:

```text
business transaction: change domain state + append typed event
projection transaction: lock pending rows + insert audit records + mark projected
commit projection transaction
optional best-effort UI invalidation after commit
```

Both projection writes use the same `pgx.Tx`; no second pool acquisition, subscriber goroutine or receipt channel is needed. Retain stable delivery IDs and uniqueness as defense against replay/migration mistakes. Keep transformation in a pure control-owned function; SQL implementation belongs to its adapter. Batch/deadline/backoff/quarantine/readiness policies remain explicit rather than being hidden in the projector.

Alternatively, if audit must exist at the moment a business operation succeeds, append its audit record in that business transaction. This changes visibility timing and failure behavior and should be chosen per use case. Authentication activity currently has its own direct audit sink; do not accidentally weaken its failure policy while simplifying domain events.

Polling the Activity read model does not require an in-memory event bus. A future SSE feed may carry coalesced invalidations only, with re-query on reconnect; browser refresh signals must never be the durable source of audit history.

## When Watermill becomes worthwhile

Revisit it when several independent consumers need durable work: external webhooks, notifications, snapshot distribution, integration projection, or separate worker processes. At that point standard routing, middleware, retries and transport integrations can replace bespoke dispatch machinery. Watermill provides handler middleware, but HomeHarbor currently uses a hand-written loop rather than the Router features. [Watermill middleware](https://watermill.io/docs/middlewares/)

Watermill Forwarder supports writing events into the same database transaction as business state, then forwarding them to a broker. It requires a transaction-scoped database publisher and a running forwarder with a database subscriber and destination publisher. This is a fit for a real external broker boundary, not a requirement for one local audit sink. [Official Forwarder documentation](https://watermill.io/advanced/forwarder/)

Its SQL integration provides durable storage and consumer groups, with configurable Ack deadlines and per-consumer offsets. It warns that PostgreSQL sequence IDs are assigned before commit: robust offsets need transaction-order handling, and long-lived transactions can delay delivery. Queue schema is a different option without consumer groups. Evaluate these semantics and migrations before replacing HomeHarbor's table. Delivery metadata remains distinct from exactly-once business effects; idempotent consumers are still needed across forwarding/crash boundaries. [Official SQL integration](https://watermill.io/pubsubs/sql/)

A future boundary should provide application-owned typed event/handler interfaces, versioned serialization, deduplication keys, per-consumer progress, bounded retries, dead-letter/quarantine handling, backlog/lag metrics and lifecycle ownership. Keep Watermill adapters under control integration infrastructure; do not export it through shared domain libraries or use pub/sub as a hidden synchronous command bus.

## Viable target retaining Watermill

The user's preference for simpler business modules and explicit event consumers is compatible with retaining Watermill, provided the dependencies are made visible at composition and the guarantees match each use case:

```text
control domain command
  -> transaction (state change + immutable fact in outbox)
  -> commit
control-owned event delivery adapter
  -> Watermill durable SQL subscriber/router or outbox Forwarder
  -> audit projection / notification consumer / integration consumer
```

Business services depend on a small transaction-owned event appender, not Watermill. Each registered consumer declares the fact types it handles, validates the schema, performs an idempotent effect and only then acknowledges its own delivery. Acknowledgement by consumer A must not suppress delivery to consumer B. Consumer identities/offsets, retry policy and retention are configured explicitly. Registration and lifecycle live in the composition root; named handlers should make the actual subscriber graph easy to inspect and test.

For current same-database audit, prefer projection plus completion marker in one transaction. If a durable Watermill SQL subscriber is chosen instead, preserve atomicity or stable inbox deduplication between effect and progress and integration-test a small pool; merely replacing GoChannel does not automatically fix nested connection acquisition. GoChannel can remain a local, best-effort invalidation mechanism whose missed messages cause a refresh, never lost durable work. A broker need not be added solely to imitate a modular monolith; choose durable SQL delivery for same-process consumers, or a broker-backed Forwarder when an actual process boundary is required.

Typed committed facts can decouple reactions that may happen later. They cannot replace commands or transactions for activation, invitation consumption, credential rotation, policy validation and other operations that must succeed together. Turning those invariants into eventual consumers produces intermediate states and additional compensation logic. Queries remain direct read ports. Whether to use asynchronous facts or a direct use-case call is determined by required consistency, failure and response timing, rather than a rule that all modules become event consumers.

## Required checks before an implementation is accepted

- A one-connection Postgres pool can project events successfully without acquiring another connection.
- Domain state and event append commit/roll back together.
- Audit projection and its completion marker commit/roll back together.
- Cancellation, failed insert, crash/restart and duplicate delivery retain pending work without duplicate audit rows.
- Transient failure, invalid payload and critical worker exit match the documented readiness/retry policy.
- Actor/target fields reflect invitation/device/auth semantics, and metadata contains no secrets.
- Optional notification failure cannot roll back or conceal successful durable audit processing.

Existing pipeline tests exercise delayed acknowledgements and stable delivery identity. Existing SQL outbox tests use a fake publisher, so they do not cover the actual cross-pool-acquisition cycle.
