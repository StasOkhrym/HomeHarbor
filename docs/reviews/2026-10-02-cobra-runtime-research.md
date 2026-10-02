# Cobra across HomeHarbor: command adapters and startup ownership

Research date: 2026-10-02. Repository inspected: `/Users/s.okhrym/personal_code/homeharbor`, HEAD `b66865b`. This is a design proposal; no runtime changes or dependency installation were performed. Cobra behavior was checked against pinned v1.10.1 source, rather than assuming a current latest release.

## Recommendation

Adopt Cobra for every first-party Go executable: control, relay, client, agent, admin, migrate, and healthcheck. Preserve separate binaries and deployment privileges. Uniform command parsing is valuable; collapsing all composition roots into one executable is a different decision and is unnecessary for that benefit.

Extract two focused shared libraries: a CLI host and runtime lifecycle tools. The CLI host owns arguments, streams, signals, build information and exit classification. Runtime tools own supervision and bounded HTTP draining. Each role remains responsible for dependencies, domain assembly, readiness and cleanup order. Business services receive typed options and interfaces; they never receive a Cobra command or a mutable config registry.

For the tiny healthcheck, a one-command Cobra adapter is a reasonable consistency tradeoff now that the user explicitly accepts library complexity. Keep its two-second probe deadline and minimal runtime dependencies; do not make the probe import the control or relay app. The current comment claiming a dependency-free probe must be updated if Cobra is added.

## Verified current code

| Evidence                                             | Current behavior                                                                                                   | Simplification or safety consequence                                                                                                                     |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/control/main.go:15-35`                          | Global standard flags, config load, logger, signal context, app construction and repeated exit blocks              | Move the flow into a command adapter; one process exit boundary                                                                                          |
| `cmd/relay/main.go:18-90`                            | Flag parsing before TOML, but loader validates TOML before overrides; empty/zero treated as absence at lines 52-65 | Overlay only explicit flags, then validate final effective config; explicit invalid zero must produce an error rather than silently selecting file value |
| `internal/platform/config/config.go:177-220`         | Relay validates TLS pairs/port range before command overrides                                                      | A valid override cannot currently repair an invalid unused file value                                                                                    |
| `internal/app/node/config.go:22-43`                  | Two-pass parsing around config load                                                                                | Parse once into CLI options, then load and overlay typed config                                                                                          |
| `internal/platform/config/node.go:107-125`           | Token/ticket files read and runtime checked before second CLI pass                                                 | Resolve only final selected secrets; validate only after overlays                                                                                        |
| `cmd/admin/main.go:21-47, 50-69, 133-155`            | Manual dispatch, repeated flag binding/config application                                                          | Native command tree, shared admin options, narrow per-command orchestration                                                                              |
| `internal/platform/config/config.go:150-170`         | Passphrase file eagerly resolved                                                                                   | Move secret resolution after final passphrase-file selection                                                                                             |
| `cmd/admin/main.go:89-92, 202-207, 249-252, 290-293` | Remote operations use `context.Background()`                                                                       | Pass command context with operation deadline through remote calls                                                                                        |
| `cmd/migrate/main.go:24-41`                          | Background context and error exit after pool acquisition                                                           | Use command context, bounded operation, deferred pool cleanup in function that returns                                                                   |
| `cmd/healthcheck/main.go:15-35`                      | Exactly one URL, two-second deadline, no shell assumption                                                          | Preserve probe semantics using `cobra.ExactArgs(1)` and contextual request                                                                               |
| `internal/app/node/runtime.go:21-30, 321-326`        | Runtime creation validates and defers startup to Run; constructor ignores context parameter                        | Keep side-effect-free construction; remove misleading constructor context when it is unused                                                              |
| `internal/app/control/app.go:34-81, 103-140`         | Constructor opens stores, Run owns closing; early construction errors clean up                                     | Document ownership transfer or unify acquisition in Run; do not disguise resource acquisition as a pure builder                                          |
| `internal/platform/lifecycle/component.go:26-56`     | First non-nil failure cancels siblings and waits; nil worker exit does not cancel siblings                         | Separate long-lived supervised workers from finite bootstrap/one-shot tasks                                                                              |

These observations concern inspected source paths, not memory-derived repo state. Existing lifecycle tests cover first-error sibling cancellation and join (`component_test.go:9-34`), but no unexpected successful daemon exit.

## Concrete shared boundaries

```text
cmd/{control,relay,client,agent,admin,migrate,healthcheck}/main.go
internal/cli/
  host/              # Cobra execution, streams, exit errors, build info
  control/           # role flags -> typed config -> app invocation
  relay/
  node/              # common client/gateway flags; explicit Role input
  admin/             # command constructors, presentation; companion use cases
  migrate/
  healthcheck/
internal/platform/
  config/            # typed loading/overlays/secret references/validation
  lifecycle/         # finite task vs supervised daemon contracts
  httpserver/        # bounded HTTP drain with explicit WebSocket close owner
internal/app/{control,relay,node}/
```

The host imports Cobra and standard library only. Each role CLI package imports its app package. App packages import shared runtime/config packages and domain/adapters; they do not import CLI. `internal/cli/node` moves flag parsing out of `internal/app/node`. A shared flag binder is allowed for node roles because they already share the configuration shape; avoid reflection-driven registrations for unrelated role settings.

Proposed small API:

```go
// host.Execute is testable and never exits the process.
func Execute(ctx context.Context, cmd *cobra.Command,
    args []string, streams Streams) int

// Each call returns a fresh command tree and option state.
func controlcmd.New() *cobra.Command
func nodecmd.New(role nodeapp.Role) *cobra.Command
```

The outer host/main installs signal handling and invokes `ExecuteContext`; only `main` calls `os.Exit`, after the host function's defers have executed. Every `RunE` calls application/use-case functions and returns errors. Set streams explicitly and avoid global logger mutation. `RunE` uses command stdout for intended output and stderr for diagnostics; secret-bearing invite output must not be mirrored into JSON logs.

The root constructor performs no file reads, DB opens, key unlocks or network connections. Help/version/completion stay usable with missing config and absent infrastructure. Use `Args: cobra.NoArgs` for daemon/migration commands. Admin commands retain local-only versus remote needs: `init-root` never loads control/relay secrets or connects to PostgreSQL.

## Cobra semantics that shape this design

`ExecuteContext` makes the supplied context accessible via `cmd.Context()`. It does not turn blocking operations into cancellable ones; consumers must use that context. Error-returning execution does not itself choose a process exit code. Set `SilenceErrors` and `SilenceUsage`, then centralize reporting. Default persistent hooks stop at the nearest matching hook. `PostRunE`/persistent post-run are skipped if `RunE` fails: use ordinary `defer` for cleanup, not hook cleanup. Help returns before runtime hooks. Fresh trees avoid sticky option values across repeated tests. [Pinned Cobra execution source](https://raw.githubusercontent.com/spf13/cobra/v1.10.1/command.go)

Use explicit-flag tracking rather than truthiness: false, zero, and empty can be meaningful overrides or invalid values that deserve validation. Cobra/pflag supports this through `Changed`; long flag syntax uses `--name`, unlike the standard Go flag package's single-dash multi-letter convention. [pflag source](https://raw.githubusercontent.com/spf13/pflag/v1.0.9/flag.go), [Cobra flags guide](https://cobra.dev/docs/how-to-guides/working-with-flags/)

Required flag/group checks are about supplied CLI flags. A value allowed from TOML/environment should be validated on the effective typed config, not rejected because its CLI flag was not changed. CLI-exclusive options can use required/mutually-exclusive groups. [Cobra flag groups](https://raw.githubusercontent.com/spf13/cobra/v1.10.1/flag_groups.go)

Do not use global `OnInitialize`, mutable command singletons, global hook traversal settings or dynamic command lookup as dependency injection. Compose explicit loader/run functions in `RunE`; this makes startup order reviewable.

## One startup pipeline

1. Build command tree and parse once.
2. Resolve config path and role-specific defaults.
3. Decode the role's allowed config section(s), reject unknown keys appropriately.
4. Overlay allowlisted environment values and explicitly changed flags.
5. Validate structural references, resolve the selected secret files, then validate semantic/runtime invariants.
6. Create logger/client/dependencies only for that command.
7. Execute finite task or run the app under cancellation.
8. Drain workers and active connections before closing stores; return an error/exit classification.

If Viper is adopted, it belongs only inside this startup/config adapter and returns typed values. Cobra does not require Viper. Neither package should own business workflows. Do not emit resolved config dumps: typed config currently contains decrypted secrets.

Proposed exit policy: 0 for successful command/help/version and graceful daemon shutdown; 2 for command syntax; 1 for operational/config failures; interruption of an incomplete finite admin/migration task has a distinct nonzero code. Never convert all `context.Canceled` errors into success: that would report an interrupted publication/migration as completed. `os.Exit` bypasses defers, which is why resource-owning functions must return before the process boundary. [Go os.Exit](https://pkg.go.dev/os#Exit)

## Execution ownership improvements worth doing alongside Cobra

A long-lived worker that unexpectedly returns nil currently leaves siblings running. Add a supervisor policy where any essential daemon termination triggers cancellation and a useful worker-named error. Keep finite bootstrap functions outside that group. Preserve the original failure rather than replacing it with sibling cancellation errors. This is an observed structural gap, not proof that a current concrete worker follows that path.

Keep acquisition/cleanup lexical. Control currently transfers opened-store ownership from New to Run; making `RunControl(ctx, cfg, deps)` own acquisition would remove the possibility of constructing an app and forgetting to Run/Close it. If retaining New, provide explicit Close for a constructed-but-unstarted app and tests for cancellation before listener creation. Node's lazy startup model is already closer to the desired boundary.

Reuse the established bounded HTTP shutdown helper where semantics match. Relay currently handles UDP ownership and hijacked WebSocket cleanup explicitly (`internal/app/relay/app.go:201-218`); a shared HTTP wrapper must accept an explicit upgraded-session close/join owner rather than relying on `http.Server.Shutdown` alone. Preserve explicit acquisition and teardown order in each composition root; do not build a service locator or opaque generic application graph.

Keep signal handling only at process boundary. After the first cancellation, restore the default handler so a second termination signal can stop a stuck graceful drain. Finite operations need their own deadlines; a command context without HTTP/network timeout is insufficient.

## Migration and verification

Migrate admin first, then shared node commands, then control/relay/migrate, then the small healthcheck. Keep binary names and separate permissions. Update single-dash invocations atomically: `deploy/compose.yaml:55,89,110` uses `-config`, and `scripts/dev_init.py:292` uses `-passphrase-file`.

Meaningful command tests must prove: help/version with missing config have no side effects; explicit false/zero overlays; obsolete secret paths overridden by valid ones are never read; relay final overrides are validated; stdin/stdout/stderr are injectable; finite interrupted jobs fail; canceled startup opens no listeners or modifies network; partial acquisition closes dependencies; unexpected daemon exit cancels siblings; HTTP/WebSocket workers join before storage close. Existing full verification is not rerun for this research-only change.
