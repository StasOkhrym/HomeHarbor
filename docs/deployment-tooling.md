# Local development checks

`make help` lists the public command surface. `make fmt` and `make lint` cover
owned Go, JavaScript, CSS, Go HTML templates, Python, shell, YAML, JSON, TOML,
Dockerfiles and SQL. Formatting is opt-in; `make verify` never rewrites sources.
The portable gate runs lint, Python/browser tests, Go race tests and builds. It
does not need Docker or a mobile SDK.

Use Node 24 (`npm ci --ignore-scripts`) and Python 3.11+ in an ignored virtual
environment (`pip install -r requirements-tooling.txt`). Go formatters and
correctness checks are pinned by `.golangci.yml` and the CI tool version.
Shell formatting and workflow validation use pinned Go modules. Install Hadolint
2.15.1 from its official release and verify the release checksum before execution;
the macOS ARM64 Python wrapper is not used because its wheel was corrupt.

`make integration` uses disposable DB/Redis containers. `make security` runs
bounded parser fuzzing and the pinned vulnerability scan. `FULL=1 make verify`
adds these gates, local Compose validation and Linux acceptance. These
acceptance tests are component tests, not the full invite-to-LAN product scenario.

`scripts/compose_check.py` validates rendered local and integration boundaries
without writing keys or state. Python remains limited to configuration parsing, fixtures and
process supervision; production signing, authorization and networking stay in Go.

Traefik verifies the relay backend certificate against the configured CA and DNS
identity `relay`. The loopback frontend uses a local test certificate. Its CA is not the companion signing
root. Private state and dependencies are excluded from the Docker build context.

The local initializer preserves existing private keys and fixes their permissions
to 0600. Runtime containers use the local operator's UID/GID to read mounted
secrets without widening permissions. Only the public companion root reaches the
control container. Never place secrets in committed configuration or command arguments.
Public certificate automation and VPS provisioning are deferred, not installed by this stack.

CI classifies both sides of renames and deleted paths. Documentation-only changes
do not build Go. Storage/Redis changes run integration; authorization/network
changes run Linux acceptance; parser changes fuzz. Shared dependencies, unknown
runtime changes or an unavailable base commit select every gate. A manual workflow
dispatch also selects everything. The single backend job avoids repeated tool
setup; each expensive step is conditional. Actions use immutable commit pins,
read-only repository permissions and bounded job timeouts. A release milestone
still requires a full gate on its exact commit, not merely a successful fast gate.

Categories overlap: identity/session/snapshot storage changes run durable contracts
and protected networking/security checks. Activation workflows live under
`internal/app/control/workflows`; their transaction contracts are mandatory.
Protected backend changes select both bounded fuzzing and vulnerability scanning.

Current limitations: TOML lint checks syntax; runtime validation rejects invalid
operational values at startup, but lint does not semantically load every example.
An existing unsigned initial-snapshot fixture is not rechecked for permissions or
symlinks during initialization. It contains no secret or active signed grant, but
this local-file hygiene remains follow-up work. The vulnerability scanner reports
reachable findings separately from uncalled vulnerable code in required modules;
a successful scan does not mean every dependency is free of known vulnerabilities.
