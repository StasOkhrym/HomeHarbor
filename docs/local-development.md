# Local development

Run `make dev-up`, then open <https://control.localhost:8443/admin/login>.
The admin page uses the real passkey flow; there is no development auth bypass.
`make dev-trust-ca` explicitly trusts the test CA in the Mac login keychain. On
Linux it prints the CA path for installation in your browser/system.

`make dev-up` checks dependencies, domains, ports, TLS and rendered Compose, then
builds before recreating containers and remounting changed config files. It runs
migrations before control and waits for DB, Redis, control, relay and Traefik health.
A failed preflight or build leaves the running stack available.
It preserves volumes, node state and companion keys. No `--volumes` or implicit
reset is used. `make dev-down` stops the stack; `make dev-logs` follows its logs.
Use `make help` for the small command surface.

Configuration, certificates and the companion root live in ignored `.local/`
and `secrets/`. The private companion key is age-encrypted; Compose mounts only
its public half. Local apps run as the owner of bind-mounted secrets, avoiding
world-readable private keys on Linux. Do not commit or distribute private state.

HTTPS is bound to loopback on an unprivileged port, so Docker Desktop's privileged
port helper is unnecessary. The backend-only Mac overlay does not publish relay
UDP or grant network-admin capabilities. It is not a VPN demonstration.

`make integration` starts disposable authenticated DB/Redis containers, runs all
required adapter contracts and cleans only its own project on exit. Existing
development DB/state is untouched. `make acceptance` runs current relay and Linux
namespace and real systemd-resolved tests, starting the Lima test VM on Mac when
needed. `LIMA_INSTANCE=my-vm make acceptance` consistently selects another VM.
Native Linux acceptance requires root plus ip/nft/WireGuard/curl/Python and an
active systemd-resolved service in a disposable environment. These
are component tests, not yet the full signed-invite/browser-viewer sandbox.

Local initialization is a Python CLI: `python3 scripts/dev_init.py`. It validates
inputs before writing and stages generated keys/certificates privately. Existing
keys, CA, config comments and custom settings survive repeated runs. Private
files are restricted to mode 0600 even if an earlier run left broader permissions.
Incomplete or incompatible TLS material fails explicitly instead of rotating
trust. `DEV_HTTPS_PORT=9443 make dev-up` updates managed control/relay URLs;
`DEV_HTTP_PORT` defaults to 8088. Domains default to control/relay.localhost and
must be distinct valid lowercase names under `.localhost`. Changing domains
requires restoring a matching certificate/configuration; port changes reuse TLS.

Integration uses independent secrets, project and volumes. Its packages execute
serially because SQL fixtures share tables; concurrency tests inside packages
still run. `INTEGRATION_POSTGRES_PORT`/`INTEGRATION_REDIS_PORT` default to
55432/56379. Environment URLs are ignored unless explicitly authorized:

```sh
TEST_DATABASE_URL=postgres://... TEST_REDIS_URL=redis://... python3 scripts/integration.py --external
```

That command mutates the supplied test services. Skipped required contracts fail.
Failure and signal cleanup preserves the original exit code and removes only the
integration project's containers, volumes and temporary secrets.

The next network milestone must use isolated gateway, external client and dummy
LAN environments, a real signed invite/code and WireGuard relay, blocked direct
paths, and a browser viewer fetching only its fixed dummy target through the
client tunnel. The viewer must never become a general-purpose proxy.
