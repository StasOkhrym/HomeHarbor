# Local development

Run `make dev-up`, then open <https://control.localhost:8443/admin/login>.
The admin page uses email and password followed by a passkey or an authenticator
code. Existing passkey-only installations first finish the owner migration flow;
there is no development auth bypass.
`make dev-trust-ca` explicitly trusts the test CA in the Mac login keychain. On
Linux it prints the CA path for installation in your browser/system.

`make dev-up` checks dependencies, domains, ports, TLS and rendered Compose, then
builds before recreating containers and remounting changed config files. It runs
migrations before control and waits for DB, Redis, control, relay and Traefik health.
A failed preflight or build leaves the running stack available.
It preserves volumes, node state and companion keys. No `--volumes` or implicit
reset is used. `make dev-down` stops the stack; `make dev-logs` follows its logs.
Use `make help` for the small command surface.

The development stack captures account invitations, verification, password reset
and security notices in [Mailpit](http://127.0.0.1:8025). It never forwards them to
real recipients. `DEV_MAILPIT_PORT=9025 make dev-up` changes its loopback-only inbox
port; SMTP stays private to Docker. The development overlay explicitly selects
Mailpit, even if the application config contains another SMTP server. This overlay
is separate from the optional manual VPN sandbox.

`python3 scripts/dev_mail.py` initializes a dedicated SMTP CA, server certificate
and matching authentication files. These files survive repeated runs; partial or
mismatched sets fail instead of silently replacing them. This CA is used only by
the control container and is never installed in the Mac keychain. The inbox is
local and contains private account links: do not expose or share it. Messages
are ephemeral across container recreation.

Outside this development overlay, email is disabled by default. Enable `[smtp]`
in the control config and supply a verified STARTTLS or implicit-TLS SMTP server,
its credentials and a sender address. A hosted provider such as Mailgun is
optional: a properly operated SMTP relay works too. Configure a CA file only for
a private SMTP authority. Password reset changes the password and invalidates
old sessions; it keeps the account's existing MFA methods.

The configured authentication rate is per client IP and bounded stage: password,
MFA/proofs, account email, and logout. Password-bearing setup/reset aliases share
one password budget; query strings never create a fresh budget. This permits a
complete invitation and immediate normal sign-in without increasing the password
guessing allowance. Redis failure closes every stage; the overall API limit also
applies.

Configuration, certificates and the companion root live in ignored `.local/`
and `secrets/`. The private companion key is age-encrypted; Compose mounts only
its public half. Local apps run as the owner of bind-mounted secrets, avoiding
world-readable private keys on Linux. Do not commit or distribute private state.

HTTPS is bound to loopback on an unprivileged port, so Docker Desktop's privileged
port helper is unnecessary. The backend-only Mac stack does not publish relay
UDP or grant network-admin capabilities. It is not a VPN demonstration.

`make integration` starts disposable authenticated DB/Redis containers, runs all
required adapter contracts and cleans only its own project on exit. Existing
development DB/state is untouched. `make integration-mail` separately creates two
authenticated TLS Mailpit captures with temporary credentials, verifies real
STARTTLS and implicit TLS delivery plus password/CA/hostname rejection, then
removes only its own containers and temporary state. Both integration gates run
in CI when durable/backend changes require them, and in `make verify FULL=1`.
They never contact a real email provider. `make acceptance` runs current relay and Linux
namespace and real systemd-resolved tests, starting the Lima test VM on Mac when
needed. `LIMA_INSTANCE=my-vm make acceptance` consistently selects another VM.
Native Linux acceptance requires root plus ip/nft/WireGuard/curl/Python and an
active systemd-resolved service in a disposable environment. These
are component tests; the signed-invite/native-client/browser scenario is the
separately invoked [manual macOS sandbox](manual-testing/macos-sandbox.md).

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

The separate [manual macOS sandbox](manual-testing/macos-sandbox.md) uses isolated
gateway/private fixtures and a native host client, real signed invitation and
ordinary-browser private hostname access through WireGuard. It requires explicit
helper provisioning and browser CA trust. Its optional commands never run in the
required gates above; backend/UI development remains independent.
