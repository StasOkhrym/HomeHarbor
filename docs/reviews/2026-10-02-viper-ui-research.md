# HomeHarbor: configuration and dynamic UI research

Research date: 2026-10-02. Runtime code was not changed. Recommendations below are architectural judgments; library behavior is backed by primary sources. Local evidence was read from `/Users/s.okhrym/personal_code/homeharbor`, module `github.com/StasOkhrym/homeharbor`. Viper 1.21.0 is the specifically analyzed version; do not infer future-version behavior from this note.

## Decisions

- Keep typed, validated configuration at every application/module boundary. Cobra is useful independently of Viper.
- Viper is a reasonable startup adapter if HomeHarbor chooses consistent flags + environment + TOML overlays across its executables. Its benefit is source composition, not type safety or secret lifecycle. Do not expose `*viper.Viper` to domain services.
- For the current pet project, improving the existing typed TOML loader is the smaller default. Avoid running two competing config systems permanently. Choose either a typed loader shared by all executables or a Viper-backed loader returning those same typed values.
- Keep Go templates + HTMX. Implement stable fragment endpoints and reliable polling first. SSE can later replace the refresh trigger without replacing the presentation/read-model design.

## Configuration facts and migration caveats

Viper's documented priority is explicit `Set`, flags, environment, configuration files, remote stores, defaults. Empty environment values are ignored unless `AllowEmptyEnv` is enabled. Keys are case insensitive, and ordinary complex-source overrides are not promised to deep merge. pflag/Cobra bindings are supported. These rules must be made explicit in HomeHarbor rather than assumed to match its current secret-file behavior. [Viper README](https://github.com/spf13/viper#putting-values-in-viper)

Source inspection of Viper 1.21.0 confirms: changed flags override even when their value is false/zero; unmarshalling enumerates registered keys, so `AutomaticEnv` alone misses fields existing only in environment; `UnmarshalExact` enables unknown-key rejection; weak input conversion is enabled by default; `WatchConfig` rereads into the same instance and invokes the callback even after a read error. Concurrent reads and writes are unsupported. [Pinned Viper source](https://raw.githubusercontent.com/spf13/viper/v1.21.0/viper.go)

The official README uses `mapstructure` tags for field names, so existing snake_case `toml` tags need deliberate mapping when introducing Viper. [Viper unmarshalling](https://github.com/spf13/viper#unmarshaling)

The existing BurntSushi dependency already provides `MetaData.Undecoded()` for strict unknown-key detection. No library replacement is needed to reject misspelled TOML keys. [BurntSushi strict decoding](https://pkg.go.dev/github.com/BurntSushi/toml#example-package-StrictDecoding)

Local findings:

- `internal/platform/config/runtime.go` seeds defaults before TOML decode and validates explicit zero as invalid. Preserve this behavior exactly.
- `config.go` discards TOML metadata, so unknown fields currently are not rejected.
- Environment overrides are explicit and incomplete. Relay/auth inline values win over secret files only when nonempty; Redis secret files overwrite configured inline values unless an environment password is present; database password files overwrite inline values. These differing precedence rules should be normalized and tested.
- `LoadDatabase` intentionally reads only the database section from a full control configuration. Blind global strict decoding would reject unrelated, valid sections. Validate the whole file schema once or restrict unknown-key checks to the requested subtree; do not require migration CLI to resolve auth/relay secrets.

Recommended typed-loader contract:

1. Process-specific defaults; strict TOML decode; allowlisted `HOMEHARBOR_*` environment overlay using `LookupEnv`; explicitly changed CLI flags; secret resolution; semantic validation; return an immutable typed struct.
2. Ordinary-value priority: changed CLI flag > present environment > TOML > default. For secrets, keep explicit inline values and `*_file` resolution in a separately documented resolver, rather than adding secret contents to a general map. Preserve existing compatibility until the selected rule is tested.
3. Choose empty semantics per field: invalid required endpoint/secret must fail; optional string can intentionally clear; explicit zero/false must not fall back. Never write `if value != zero { override }` as a general overlay rule.
4. No global singleton, remote config, broad reflective environment discovery, or live reload in the initial implementation. Configuration errors must not dump secret values.

Viper adoption contract:

- Explicit config path via `SetConfigFile`, without discovery; one `viper.New()` instance per load.
- Explicit allowlisted config-key to environment-name bindings via `BindEnv`; explicit Cobra `BindPFlag` mapping with changed-flag semantics, not a second zero-value-based flag pass.
- Process-specific defaults; `UnmarshalExact` configured with `TagName="toml"` to reuse existing tags, or one deliberate migration to consistent `mapstructure` tags; configured duration/slice hooks. Decoder configuration supports selecting the tag name. [Mapstructure DecoderConfig](https://pkg.go.dev/github.com/go-viper/mapstructure/v2#DecoderConfig)
- Resolve secrets and validate only after the final overrides. Existing node loading validates/resolves too early for a later flag pass; admin passphrase loading also precedes CLI file overrides. Correct this ordering regardless of library choice.
- No Viper instances or `WatchConfig` in domain services; return typed immutable values.

Strict source typing may need a separate file decode because environment strings necessarily require controlled conversion. Test this rather than assuming `UnmarshalExact` also makes conversions strict.

Hot reload is a separate feature: reload into a fresh candidate, resolve secrets and validate, then atomically publish only fields declared reloadable. Keep listeners, identity/crypto settings and connection construction startup-only initially. File watching cannot rotate credentials or rebuild consumers by itself.

## Dynamic HTMX design

HTMX supports interval polling and a visibility predicate such as `every 4s [!document.hidden]`. [Trigger documentation](https://htmx.org/attributes/hx-trigger/#polling) `hx-sync` can drop a new request while a matching request is in flight. [Request synchronization](https://htmx.org/attributes/hx-sync/) HTML fragments are native responses; 204 does not swap; 4xx/5xx raise errors and do not swap under default handling. [Response handling](https://htmx.org/docs/#response-handling)

However, trigger filters require evaluation and disabling `allowEval` disables them. [HTMX security configuration](https://htmx.org/docs/#security) HomeHarbor already sets `allowEval:false` and a CSP without `unsafe-eval`. Therefore the filtered polling example above must not be copied into this project. Use the existing external `admin.js` to dispatch a plain custom `activity-refresh` event only while visible, with one cancellable scheduler and explicit pause/resume/backoff; let `hx-trigger="activity-refresh"` handle the request. Keep CSP and disabled eval intact.

HTMX preserves focus for inputs with IDs, but plain replacement does not promise preservation of arbitrary disclosure state. Boosted links/forms scroll to the top by default; `show:none` disables it. [Swap/focus documentation](https://htmx.org/attributes/hx-swap/) `HX-Redirect` causes a full browser navigation, and HTMX does not process response headers on 3xx responses. [Redirect header](https://htmx.org/headers/hx-redirect/)

Local findings:

- Activity is a manually refreshed full-page list; navigation fetches full documents and selects `#admin-shell`.
- `admin.js` focuses the page heading after every swap and focuses global errors. Background refresh must use scoped events/status so it does not steal focus or collapse mobile navigation.
- Audit storage orders by numeric storage `id` but its `List` query does not SELECT that ID. `audit.Event.ID` is an optional outbox delivery identity; direct auth events intentionally omit it. Do not use it as UI identity or invent a timestamp hash. Add a separate read-model storage record ID.
- Metadata already exists as `map[string]any`, but activity only displays an inferred outcome and identities. Render an allowlist of useful facts; never blindly dump arbitrary metadata.

Recommended first implementation:

- Activity read model with storage record ID, occurred time, human action label, outcome, actor/target names and IDs, correlation/request ID where the producer actually records it; safe operation-specific metadata. Repair producer semantics before adding cosmetics.
- Authenticated no-store fragment endpoint rendering the same rows as the full page. Keep filters outside the replaced region. Use bounded newest-first query, stable row IDs and an explicit pause/live control.
- Poll every 4 seconds while visible using the external JS scheduler above; refresh immediately when becoming visible; drop overlap; do not mutate history. Re-fetch and reconcile a bounded recent window rather than querying only `id > lastSeen`: PostgreSQL sequence changes are visible independently of transaction rollback, so allocation is not a commit-order cursor (architectural inference). [PostgreSQL sequence functions](https://www.postgresql.org/docs/current/functions-sequence.html) Return 204 only when the complete selected view has not changed. Preserve open details and scroll anchor by record ID; if the operator is reading older entries, show a new-events count rather than jumping the view.
- Scope the existing heading focus handler to actual navigation. Use polite live status for connection/freshness and new-event count, not repeated full-feed announcements. Keep last successful content on errors, show stale state, and retry with bounded backoff.
- On 401, navigate once to login and stop polling. Do not swap a followed login page into the activity fragment. Keep ordinary full-page GET/manual refresh usable without JavaScript.

## SSE feasibility and trigger substitution

HTMX's separate SSE extension can swap named messages or trigger an HTTP fragment fetch, supports a named closing event and adds exponential reconnect behavior. [Official SSE extension](https://htmx.org/extensions/sse/) EventSource uses `text/event-stream`, reconnects and sends `Last-Event-ID` for streams with IDs; HTTP 204 can terminate reconnection. Its constructor provides URL and credentials mode, not arbitrary header options. [HTML SSE standard](https://html.spec.whatwg.org/multipage/server-sent-events.html)

Recommended SSE shape, if immediate updates become a real requirement: one authenticated same-origin stream per page emits coalesced `activity-changed` invalidations; existing fragment endpoint remains authoritative. Reconnect always fetches a full bounded current view, so missed invalidations do not imply missed displayed records. For a true append-only tail, add durable storage-ID replay and duplicate suppression; an in-memory hub alone is insufficient.

Current runtime defaults set a 30-second HTTP write timeout. SSE requires a deliberate stream-specific deadline policy and flushing; Go's `ResponseController.SetWriteDeadline` supports request-specific deadlines. [Go response controller](https://pkg.go.dev/net/http#ResponseController.SetWriteDeadline) Traefik documents immediate flushing when it recognizes a streaming response; verify the real route/middleware and timeout behavior, rather than disabling all proxy buffering globally. [Traefik response forwarding](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/#configuration-options)

Operational design must cover bounded subscribers/queues, cancellation on navigation/disconnect, bounded slow-client writes, heartbeat, fanout across control replicas, session revalidation during a long-lived stream and revoked-session termination. Ordinary request authentication only runs at stream establishment. Prefer post-commit invalidations over pre-commit domain notifications. SSE does not justify WebSockets or a SPA for this one-way operator feed.

## Acceptance evidence required before migration

- Config table tests: absent vs zero/false/empty; precedence combinations; environment-only nested fields; unknown keys; malformed duration; file permissions/error reporting; secret resolver conflicts; migration loader reads no irrelevant secrets; process tests share no global state.
- Browser tests: duplicate equal-time records remain distinct; focus/open details/scroll survive; hidden-tab resume; filters retained; no overlapping fetch; stale content retained on outage; recovery and login expiry; no-JS manual refresh; metadata escaping/redaction.
- SSE, if chosen: reconnect resync/replay; slow-client isolation; disconnect cleanup; long-lived session expiry/revocation; more than 30 seconds through deployed Traefik; no subscriber leak after repeated HTMX navigation; multi-replica behavior.

Source inspection establishes feasibility and caveats; no migration prototype or deployed SSE/browser experiment was executed for this research.
