# Go Tunnels

Self-hosted access to home-network services: Go control plane, trusted companion,
WireGuard nodes, encrypted relay and a passkey-authenticated web admin.

This is unfinished security-sensitive software, not a security-audited VPN.
Backend/UI and component tests work locally. Full signed onboarding → Linux client
→ UDP relay → gateway → dummy LAN, and native-phone/Mom Test, remain unverified.

## Local backend and web UI

Runtime: Python 3.11+, OpenSSL and running Docker with Compose 2.23+. Initial
setup also needs Go 1.27.1 to create the encrypted companion signing root.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-tooling.txt
make dev-up
make dev-trust-ca # explicit test-CA trust, never automatic
```

Open <https://control.localhost:8443/admin/login> and use the real passkey flow.
No dummy admin token or auth bypass is enabled. Local certificates need no domain,
VPS or public IP. Containers are rebuilt and readiness checked; keys and DB volumes
survive. `make dev-down` stops them; `make dev-logs` follows logs.

Checks also need golangci-lint 2.14.0, Node 24 (`npm ci --ignore-scripts`) and
Hadolint 2.15.1 from its official checksummed release. Optional Ansible tooling
uses `requirements-deployment.txt`, not the daily development environment.

## Checks

```sh
make fmt           # opt-in formatting for owned languages
make lint          # read-only format, correctness and syntax checks
make test          # portable Go, Python and browser tests
make verify        # lint, tooling/browser tests, Go race tests and build
make integration   # disposable SQL/Redis contracts; no required skips
make security      # bounded parser fuzzing + pinned vulnerability scan
make acceptance    # isolated Linux namespace/WireGuard/resolved components
make verify FULL=1 # all above plus optional deployment checks
```

`make help` lists the supported surface. Import-boundary tests run once in the
regular Go suite. Linters cover owned Go, Python, shell, JS, CSS, Go HTML, SQL,
Dockerfiles and configuration formats; generated/vendor files are excluded.
CI selects gates conservatively; docs-only changes do not build Go. A milestone
requires the full gate on its exact commit, not just a successful fast job.

## Structure and trust

- Thin `cmd/*` entrypoints; explicit application wiring in `internal/app/*`.
- Vertical `internal/control/*` modules own small repository contracts and
  `storage` adapters. PostgreSQL remains the actual durable driver.
- Redis holds ephemeral security state, never LAN authorization or private keys.
- Chi/`net/http`, TOML and Watermill; Traefik owns HTTPS/WSS, not relay UDP.
- Companion signatures authorize network state; ACL is default-deny and partial
  runtime application must remain fail-closed.

Linux supplies TUN, routing and nftables; Docker does not replace its kernel.
See [architecture](docs/architecture.md), [local development](docs/local-development.md)
and [tooling](docs/deployment-tooling.md). Working plans belong to ignored `.superpowers/`.

## Native clients — deferred

Independent local repositories: `~/personal_code/go-tunnels-ios` and
`~/personal_code/go-tunnels-android`. Extraction preserved commit history and all
pending source changes; bytes and modes were verified before backend removal.
Neither repository depends on a neighboring backend checkout. Native development,
CI, signing and physical-device tests are deferred to the native-client/Mom Test
gate. This milestone does not claim a native build or a working phone VPN.
