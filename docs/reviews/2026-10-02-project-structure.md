# HomeHarbor: extensible project structure

Date: 2026-10-02. This is a proposed target architecture, grounded in the current checkout; runtime code has not been migrated. Read alongside [the architecture audit](2026-10-02-architecture-audit.md) and [the configuration/UI research](2026-10-02-viper-ui-research.md).

## Architectural verdict

HomeHarbor is a multi-executable product whose control service is an emerging modular monolith. The gateway, client and relay are separate runtime roles, so calling the entire repository one monolith obscures the actual deployment. The control service has useful vertical domains and private storage adapters, but boundaries remain porous: node and companion consume server-owned types, infrastructure owns domain event interpretation, and a large HTTP adapter owns both APIs and every browser page.

Directories are not sufficient module boundaries. A module needs a small application interface, owned state, explicit dependency direction and tests enforcing those rules. The goal is to deepen these existing modules, not add layers around every method.

## Decision: internal shared packages, one Go module

Keep one `go.mod`. Extract small, purpose-named packages under `internal/` when two real consumers need the same semantics. Do not introduce `shared`, `common`, `utils`, a generic repository framework or independently released libraries now. A second Go module introduces versioning and release coordination without solving an observed problem.

Externalize a library only when an independent consumer actually exists, its API is stable, and it has its own compatibility/test/release requirements. Go `internal` packages cannot be imported by arbitrary external projects. Native Swift/Kotlin clients need a language-neutral protocol specification and shared conformance vectors; moving Go DTOs into a library does not make them reusable in those languages.

| Package                                | Responsibility                                                                                    | Existing coupling it removes                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `internal/protocol`                    | Wire DTOs, capability names, activation proof canonicalization and validation, public error codes | Node importing `app/control/workflows`; companion importing control invite records |
| `internal/acl`                         | Pure access-rule values, validation and deterministic compilation                                 | Node/gateway importing `control/policy` for compiler/types                         |
| `internal/controlclient`               | Typed control API calls, transport configuration, bounded decoding, status-to-error translation   | Repeated HTTP/JSON code in node and companion                                      |
| `internal/invite`, `internal/snapshot` | Existing signed trust formats and verification                                                    | Already focused shared packages; retain their purpose                              |
| `internal/platform/config`             | Startup source composition, secret resolution and typed validation                                | Different overlay behavior in role loaders                                         |
| `internal/platform/lifecycle`          | Process cancellation and component lifecycle                                                      | Keep only infrastructure behavior shared across roles                              |

Protocol DTOs must not become aliases of domain/storage records. Map explicitly at HTTP boundaries. Keep transport errors distinct from domain errors. `controlclient` accepts an injected `http.Client` with a timeout/deadline contract and does not read credentials from disk, own SQL, or implicitly retry signed non-idempotent operations. The caller owns credentials and retry decisions.

Move mutable `protocol.PathSelector` into `internal/node/path`: it is node runtime state, not a wire contract. Keep privileged nftables/DNS/WireGuard adapters in their role-specific packages.

## Proposed tree

The tree shows responsibilities, not a requirement to create every directory immediately. Empty scaffolding and one-method wrappers are unnecessary.

```text
cmd/
  control/ relay/ agent/ client/ admin/ migrate/ healthcheck/
internal/
  app/
    control/                  # composition, server lifecycle, route mounting
    node/                     # client/gateway composition
    relay/                    # relay composition
  control/
    identity/ devices/ invites/ routes/ services/
    profiles/                 # profile membership and service/device assignments
    policy/ snapshots/ audit/
    workflows/                # cross-domain application operations
    transactions/             # SQL units of work for those operations
    events/                   # domain envelopes, outbox dispatch, audit mapping
    httpapi/                  # JSON API adapter, DTO/domain mapping
    .../storage/              # persistence private to each domain
  web/
    admin/                    # authenticated pages, fragments, view models
    auth/                     # browser login/passkey/recovery flows
    session/                  # shared browser session/CSRF contracts
    assets/                   # embedded CSS, external JS, templates
  node/
    path/                     # mutable path selection
    direct/ relay/            # node transports
  agent/
    nft/ dns/                 # gateway OS adapters
  companion/                  # root-key ownership and approval orchestration
  tunnel/                     # WireGuard/interface adapters
  protocol/ acl/ controlclient/
  invite/ snapshot/
  platform/
    config/ lifecycle/ redissecurity/
api/
  protocol.md                 # endpoints, signing bytes, public error semantics
  testdata/                   # language-neutral golden conformance vectors
scripts/
  lib/                        # actual script helpers, not application logic
  tests/
docs/
  architecture/               # boundaries, vocabulary, decisions
  reviews/                    # dated evidence and migration proposals
```

The existing `internal/app/control/workflows` should become control application logic rather than composition-root code. Move its transactional storage adapter alongside it. `app/control` then constructs dependencies and manages lifecycle. This keeps node imports out of server composition.

Split access profiles out of `services.Catalog`: a catalog describes services; a profile assigns devices and services. `profiles` owns profile membership and its repository. `policy` owns access policy publication/confirmation and consumes the pure `acl` package. Apply this split when changing those responsibilities, after mapping transactions; do not split services merely because a file is long.

Move the current `platform/events` into `control/events`: it imports control audit/devices and interprets domain operations, so it is not neutral infrastructure. Define a control-owned event envelope with explicit actor/target semantics rather than using `devices.Event` for every action. Keep outbox persistence and delivery idempotency. Do not remove durable delivery while simplifying the bus. With one real audit consumer, a direct outbox-to-audit sink may be sufficient; add generic pub/sub only when additional consumers require it.

## Dependency rules

- `cmd` calls the role application/CLI entry point; role composition imports domains and adapters.
- Control domains do not import HTTP handlers, CLI, composition roots, other domains' storage, or concrete SQL/Redis adapters.
- Cross-domain workflows use explicit domain application interfaces. A transaction adapter coordinates the repositories needed for an atomic operation; it does not scatter transaction ownership across handlers.
- `web/admin` and `control/httpapi` are sibling adapters. They call application interfaces and read queries; neither imports the other. Session/CSRF support must be extracted before moving handlers to avoid an adapter cycle.
- Node and companion may import `protocol`, `acl`, `controlclient`, `invite` and `snapshot`; they must not import `control` or `app/control`.
- Pure shared packages must not import process lifecycle, database, Redis, HTTP handlers or role-specific runtime state.
- Platform packages must not import control domains. Role-specific infrastructure should be named and located under that role.

Extend the existing architecture tests to enforce these directions, including node/companion and platform. The current checks primarily protect control domain imports and retain a stale forbidden network package name.

## Adding a capability without restructuring the product

For a new resource, first choose the domain that owns its lifecycle and invariants. Add service methods and a private storage adapter there. Add public request/response DTOs only if remote clients need the operation; then update protocol documentation and client methods. Add browser query/view models independently of those DTOs. A cross-domain operation belongs in a workflow with explicit transactional behavior.

Do not create a new package for every resource automatically. For example, service tags can remain in the service catalog until they gain independent rules and consumers. A new transport implementation belongs under node/relay composition, reusing signed protocol contracts without importing server business logic.

## Configuration: Cobra across executables, bounded Viper option

Use Cobra across all seven executables, preserving separate binaries. The user accepts a shared CLI library for consistent parsing, startup, cancellation and errors. Keep fresh command constructors and a small host; role application operations remain callable without Cobra. Healthcheck retains its two-second deadline and avoids importing server runtimes. See [the deeper runtime architecture](2026-10-02-runtime-architecture.md) and [Cobra research](2026-10-02-cobra-runtime-research.md), which supersede the earlier admin-only recommendation.

The recommended initial configuration change is to retain typed TOML loaders and fix their source ordering. Viper is optional, not a prerequisite for a good structure. Current requirements are one file format, explicit environment variables and startup configuration. The existing TOML dependency can detect unknown keys. Viper becomes attractive if all executables need a uniform flag/environment/file binding layer; its value is reducing overlay code, not domain abstraction.

```text
defaults -> strict file schema -> present environment values
         -> explicitly changed flags -> selected secret files
         -> semantic validation -> immutable role config
```

Use `LookupEnv` to distinguish absence from an explicitly empty value; distinguish unchanged flags from explicit zero/false. Reject invalid final values instead of silently replacing them with defaults. Define one secret-source rule: a winning inline source suppresses a lower-priority file reference, and a winning file reference suppresses a lower-priority inline value. Reject inline/file ambiguity within the same source. Resolve only the final selected file. Test this rule before migration because current database/Redis/relay behavior differs.

The node/admin loaders currently read some secret files before CLI overrides. Fix that regardless of whether Viper is adopted. Migration tooling must be able to load the database subtree without resolving unrelated server secrets.

If adopting Viper, keep it private to `platform/config`, instantiate it per load, explicitly bind supported environment keys/flags, configure tag/decoding behavior, validate unknown fields and return the same typed structs. Do not use global getters, remote configuration or `WatchConfig` in services. This is a replaceable adapter, not a dependency of every module. See [the detailed source-backed investigation](2026-10-02-viper-ui-research.md).

Dynamic UI does not require dynamic process configuration. Live reload would need a separately defined reloadable subset and fresh validated configuration published atomically; transport/trust/database construction remains startup-only initially.

## Dynamic UI: independent read models and scoped updates

Retain Go templates + HTMX and the selected four-second polling approach. The main improvement is a dedicated browser adapter with per-page queries. The current all-page model loads devices even for Activity/security; reusing that loader every four seconds would multiply unrelated work.

| Area             | Proposed behavior                                                                | Required boundary                                            |
| ---------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Activity         | Automatic refresh, filters, pause/live, readable metadata, freshness/error state | Audit read model + authenticated fragment query              |
| Devices/routes   | Search, filters, scoped refresh, clear pending approval states                   | Resource-specific queries, no universal page loader          |
| Forms            | Inline validation, scoped result updates, preserved input on errors              | Existing application validation and CSRF/confirmation checks |
| Policy/snapshots | Visible saved/signed state and revision conflicts                                | Authoritative server state, explicit 409 handling            |
| Navigation       | Responsive shell, consistent spacing/type/status tokens, predictable focus       | Shared templates and lifecycle-aware external JS             |

Activity records need a stable **storage record ID** separate from the optional outbox delivery ID, an action label, occurred time, outcome, actor/target identities and allowlisted operation metadata. Include request/correlation IDs only where producers actually record them. Never expose raw arbitrary metadata or secrets. Repair incorrect actor/target event production before rendering richer labels.

Use one cancellable external-JS scheduler: visible-tab updates, immediate resume, no overlapping requests, bounded failure backoff, stop on navigation/session expiry. The current `allowEval:false` means visibility-filter expressions in HTMX triggers cannot be used; dispatch a plain custom event instead. Keep current CSP intact.

Fetch a bounded recent window and reconcile stable row IDs. An `id > cursor` feed alone can miss a transaction that commits after a higher allocated ID. Keep historical pagination separate, disclose the current window limit and preserve filters, open details, reading position and keyboard focus. When reading history, announce a new-entry count rather than moving the list. A strictly complete event tail would require stronger replay semantics than this initial UI refresh.

Return authenticated `no-store` fragments from the same row templates used by the full page. On outage retain the last good content and show stale state. On authentication expiry stop refresh and navigate to login once. Background swaps must not invoke the existing global heading-focus/mobile-navigation handler.

Mutation forms keep server validation, CSRF and policy confirmation/revision checks. Handle known validation/conflict fragment responses explicitly, since default HTMX does not swap 4xx. Preserve normal form fallback. Secret-producing enrollment/recovery flows need explicit one-time presentation and must not be automatically replayed or cached in browser history.

Do not label gateways healthy or changes applied without real telemetry. The current saved/signed/application-unknown distinctions remain meaningful. A shared UI layer should consist of templates, visual tokens and a few scoped controllers, not a generic widget framework.

SSE is a later trigger replacement: authenticated coalesced invalidations prompt the same fragment fetch. It needs stream-specific timeout, reconnect/resync, bounded fanout and session-revocation behavior. Polling is sufficient for the chosen cadence and avoids adding a streaming lifecycle before the read models are sound.

## Tooling and migration order

Keep Make as the task entry point; Cobra belongs to the product CLI, not to replacing the script toolchain. Keep shell for orchestration and Python for existing substantial tooling. Extract script helpers only for repeated behavior; do not create a universal automation library. Update CI to use the same current targets and declared local runtime.

1. Expand dependency checks; map current call sites and atomic workflows. Add configuration precedence regression cases and preserve protocol golden vectors.
2. Extract pure ACL and activation/wire contracts; move node runtime state out of protocol; introduce the typed control API client. Keep payload/signature semantics unchanged until the separately authorized breaking cleanup.
3. Correct startup configuration ordering; restructure all command adapters with Cobra, starting with admin and shared node commands. Choose Viper only after the uniform binding requirement is demonstrated, and use the same config conformance tests for either implementation.
4. Move control workflows/events to their actual owner; separate profile responsibilities while preserving transaction/idempotency behavior.
5. Separate browser and JSON adapters; build Activity read models/fragments and the polling lifecycle, then improve remaining pages using the same tokens/components.
6. Remove proven dead paths and perform the selected full implementation/wire V2 cleanup across server, node, relay, CLI, configuration and tests together. Retain meaningful cryptographic/schema versions and third-party `/v2` imports.
7. Fix the existing tooling test harness environment leak before relying on overridden Python execution: inherited `PYTHON` can bypass fixture stubs and recursively invoke suites. Then align scripts/docs/CI with the resulting interfaces.

Validate meaningful behavior, not folder names alone: signed protocol conformance; configuration precedence/secret selection; SQL transactions and outbox duplicate delivery; real HTMX navigation/polling/expiry; mobile and desktop rendering. The earlier audit records passing `make verify`; database/Redis integration, VPN acceptance and authenticated visual UI verification remain separate environment-dependent gates. This document introduces no new runtime test result.

## Open implementation decisions

The target direction is concrete, but exact package exports should be designed while migrating their consumers. Do not prescribe a generic interface before inspecting its callers. Viper adoption is intentionally deferred; SSE is intentionally outside the initial polling implementation. Neither deferral blocks the module-boundary or dynamic-UI improvements.

## Shared test repositories

The user selected internal/testutil/control/<domain> as the shared library for the seven domain MemoryStore adapters. Keep business repository interfaces in their domain and make testutil depend on them; production must never import testutil. See [the migration contract](2026-10-02-memory-store-audit.md). Same-package tests require deliberate migration to avoid import cycles; merely moving files is insufficient.
