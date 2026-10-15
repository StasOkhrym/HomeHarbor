# Manual macOS sandbox

This optional flow runs control, relay, a Linux gateway, PostgreSQL, Redis, DNS
and private HTTPS/HTTP fixtures in Docker Desktop. The macOS client stays on the host,
outside every Docker subnet. Ordinary browser access to
`https://site.sandbox.home.arpa:8080/` must travel through its native WireGuard
tunnel and the signed gateway ACL.

These commands never run from `verify`, `FULL=1`, CI, integration, acceptance or
precommit. Automated script tests use disposable state and stub external tools;
they do not prove the actual Mac packet flow. Windows and a second LAN laptop
remain separate follow-up scenarios.

## Prerequisites and ownership

Use a non-root macOS account, Go matching `go.mod`, Python 3.11+ with
`requirements-tooling.txt` dependencies, OpenSSL, Docker Desktop/Compose, and
preinstalled `wireguard-go` and `wg`. See the [official WireGuard installation
reference](https://www.wireguard.com/install/). The workflow installs no tools.
`make doctor PROFILE=sandbox` reports prerequisites, including native tools;
host helper provisioning and certificate trust remain explicit steps below.

The fixed Compose project is `homeharbor-sandbox`. Every container, network and
volume carries its canonical checkout path and owner UID. `.sandbox/` contains
private state; it is excluded from Git and Docker build contexts. Only one
checkout can own this named sandbox. All commands reject foreign or missing
ownership, including a matching Docker resource name without labels. Never add
ownership labels to unexplained legacy resources to bypass that refusal.

`sandbox-up` pins its Compose file, project and environment file; ambient
`COMPOSE_*` overrides cannot select another project, and inherited `HOMEHARBOR_*`
production settings cannot redirect sandbox clients or override their generated
configuration. Selected private/overlay
pools persist in `.sandbox/network.env`. Preflight rejects overlapping host/VPN
or Docker networks and probes WireGuard/nftables/forwarding in the Docker VM.
Pool overlap is checked before the probe image is built; its tag is scoped to
this checkout and owner. The full check repeats after the build.
An unsupported VM is a failed prerequisite, not permission to bypass the fence.

## Start and bootstrap the gateway

```sh
make sandbox-up
make sandbox-status
```

Up builds and starts the base stack and private fixtures; it does not start a
gateway or native client before enrollment. The login origin defaults to
`https://control.localhost:8443/admin/login`. Keep ordinary dev and sandbox
published ports separate; stop an occupying stack before this flow. Repeated
up requires down first, preserving selected pools, trust, database and identities.

Inspect `.sandbox/secrets/relay_tls_ca` and its SHA-256 fingerprint through a
trusted local operator channel. Then run the explicit trust scenario:

```sh
make sandbox-trust-ca
```

For a new certificate, the command requires a terminal and asks you to type its
displayed public fingerprint. Complete any macOS authentication prompt yourself.
It adds only SSL trust for `control.localhost` in your **login** keychain; it
does not alter system trust. Before/after user trust snapshots are kept privately
under `.sandbox/browser-trust/`. A matching repeated run verifies the existing
rule without rewriting it; a broader or different existing rule is refused.
The command also checks that native macOS trust accepts `control.localhost` and
rejects `relay.localhost` for the same frontend certificate.

Use **Safari** for this hostname-scoped CA trust. For Chrome, run the separate
explicit server-certificate mode:

```sh
make sandbox-trust-ca TRUST_BROWSER=chrome
```

Chrome skips hostname-scoped macOS trust entries. This mode instead verifies and
trusts only the current `CA:FALSE` frontend certificate for SSL. Its SANs must be
exactly `control.localhost`, `relay.localhost`, `control.sandbox` and
`relay.sandbox`. Confirm the displayed **server certificate** fingerprint; it
differs from the CA fingerprint. The existing CA rule is preserved. A renewed
server certificate needs explicit trust of its new fingerprint. Both modes
reject an unrelated hostname; when the explicit Chrome leaf is installed,
`relay.localhost` is also accepted for that exact certificate.

Do not bypass a browser warning. See the
[Chromium trust implementation](https://chromium.googlesource.com/chromium/src/+/2ec986dc720f5ce63b218a6ede134a29df4b726b/net/cert/internal/trust_store_mac.cc)
and [Apple's trust settings](https://support.apple.com/guide/keychain-access/kyca11871/mac).
The CLI uses its explicit CA file; it never changes browser or system trust.
Do not disable TLS verification, trust an arbitrary downloaded replacement root,
or capture secret token/passkey screens.

The private site has its own CA and a separate `CA:FALSE` certificate with the
single SAN `site.sandbox.home.arpa`. Before its browser acceptance, explicitly
trust that leaf through the same Make scenario:

```sh
make sandbox-trust-ca TRUST_BROWSER=chrome TRUST_TARGET=site
```

Confirm this site's displayed leaf fingerprint separately. This adds persistent
SSL trust for that exact certificate in the login keychain, available to the
user's SSL applications. It does not extend control's CA trust or trust the
site CA. `TRUST_TARGET=control` is the default. Site trust deliberately requires
leaf mode; it rejects a control certificate or extra SANs. This command checks
certificate identity locally and creates no route or DNS entry. Packet probes
use the explicit `.sandbox/secrets/site_tls_ca` instead of keychain trust.
Existing control/relay certificates and trust remain unchanged. Reinitialization
migrates only an exact generated unsigned HTTP manifest; edited manifests
require review. The companion still enforces HTTPS for catalog services.

Complete the actual [admin passkey flow](../admin-panel.md). On Invites, issue a
short-lived token with the gateway role. Then run:

```sh
make sandbox-gateway ACTION=enroll
go run ./cmd/admin init-snapshot --config .sandbox/admin.toml
```

Enter the gateway token at its hidden prompt. For deliberately piped input, use
a mode-0600 file and remove it after successful enrollment; never put the token
in argv, an environment variable or shell history. Enrollment saves independent
gateway keys in the gateway volume, exports only its three public identity
fields, and binds the initial manifest. The second command asks the trusted
companion to sign/publish that real gateway and its bounded routes/DNS/ACLs.
The signing private key remains on the host with the companion.

Before joining, verify denial:

```sh
make sandbox-check CHECK=denied
```

This also checks that the non-profile HTTP listener on private port 8081 is
actually alive inside the site container. Neither port 8080 nor 8081 nor private
DNS is published to the host. Control readiness alone does not prove denial.

## Join, approve and prepare the native pair

On the trusted companion terminal, obtain the root/network fingerprint:

```sh
sh scripts/sandbox.sh prepare fingerprint
```

Transfer that fingerprint through your trusted operator channel. Issue a signed
invitation with `go run ./cmd/admin invite --config .sandbox/admin.toml`; its
link/code are private output, so use an unrecorded operator terminal. Do not send
this output to shared logs or screenshots. In another terminal:

```sh
make sandbox-client ACTION=join
```

Supply the trusted fingerprint, then the signed link and separate code at the
client's hidden prompts. Observe **pending**. The join command applies no host
tunnel, DNS or routes. Before approving, verify the pending device/public keys
and intended profile in the operator UI.

For deliberate private piped/file input, supply the **public, independently
trusted** fingerprint separately so the launcher never reads ahead into the
private input. The file contains exactly the signed link and separate code on
two lines and must be mode 0600:

```sh
make sandbox-client ACTION=join TRUST_FINGERPRINT=PUBLIC_HEX_FINGERPRINT < .sandbox/private-join-input
# Equivalent explicit CLI, with a public fingerprint argument:
sh scripts/sandbox.sh client join --trust-fingerprint PUBLIC_HEX_FINGERPRINT < .sandbox/private-join-input
```

Make exports only `SANDBOX_TRUST_FINGERPRINT`; invite/code remain on stdin and are
never command arguments or environment values. Without an explicit fingerprint,
noninteractive join refuses before reading input. Terminal join still prompts
for the public fingerprint, then delegates hidden private prompts to Go. Delete
the private input file after a confirmed claim. The production client verifies
the supplied fingerprint against its root/network; the launcher never computes
and silently trusts a replacement.

After reviewing the pending device/profile, use only its non-secret invite ID
for the companion commands:

```sh
go run ./cmd/admin approve --config .sandbox/admin.toml --invite INVITE_ID
go run ./cmd/admin publish-snapshot --config .sandbox/admin.toml --invite INVITE_ID
```

Approval reads the private code from hidden stdin. It does not accept a `--code`
flag. The trusted companion signs the exact enrollment change. The waiting client
claims and saves its credential, then exports public metadata. Distinguish
pending, approved, claimed and applied; a saved credential is not LAN access.

```sh
make sandbox-prepare
```

Preparation writes matching client/gateway relay configs and a **public-only**
`.sandbox/network-helper.json` candidate. Review its owner UID, signing root,
network/device IDs, pinned client/gateway WireGuard public keys, selected
overlay/private pools, loopback ports and `sandbox.home.arpa` suffix. Repeated
preparation preserves the binding. A changed identity/scope requires old owned
network cleanup and explicit reprovisioning. See [join details](../client-join.md).

## Explicit privileged helper provisioning

Provision only after reviewing the candidate and the actual binaries. The
runtime invokes one fixed root-owned executable with `network-helper`; it sends
a bounded signed envelope, deterministic plan and local private WireGuard key
over stdin. The helper independently verifies signature, scope, owner and key
binding. It never reads the companion's private signing key.

| Item                                    | Required destination and ownership                                         |
| --------------------------------------- | -------------------------------------------------------------------------- |
| Reviewed host client                    | `/Library/PrivilegedHelperTools/homeharbor/client`, root:wheel, 0755       |
| Preinstalled reviewed wireguard-go copy | `/Library/PrivilegedHelperTools/homeharbor/wireguard-go`, root:wheel, 0755 |
| Preinstalled reviewed wg copy           | `/Library/PrivilegedHelperTools/homeharbor/wg`, root:wheel, 0755           |
| Reviewed public policy                  | `/private/etc/homeharbor/network-helper.json`, root:wheel, 0600            |
| Private ownership journal directory     | `/private/var/db/homeharbor`, root:wheel, 0700                             |

The tool and policy parent directories must be root:wheel, mode 0755; keep the
journal directory at 0700. Build `.sandbox/bin/client` from this exact checkout
if not already built by join.
Resolve the preinstalled tools to regular files; inspect architecture, source,
hashes and `otool -L` dependencies before copying. A root-owned executable that
loads a user-writable library is unsafe. Use binaries whose dependency chain is
trusted by root. Do not execute user-writable Homebrew paths through sudo or
grant sudo to a checkout binary. The entire destination executable path must be
root-owned and not group/world writable. Refuse existing HomeHarbor policy,
journal or tool destinations belonging to another installation.

Through an explicitly approved privileged terminal, create the directories and
copy the three reviewed binaries/public policy with the ownership/modes above.
This is a manual provisioning step, not a dependency installer or an automatic
side effect of up/join/prepare. No routes or resolvers should change during it.

Prepare a sudoers include for the **actual numeric owner UID**. For UID 501:

```sudoers
#501 ALL=(root) NOPASSWD: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: /Library/PrivilegedHelperTools/homeharbor/client network-helper
```

The exact argument is part of the authorization. Do not permit arbitrary client
arguments, another executable, `ALL`, shell commands or environment preservation.
Keep `NOSETENV` explicit so this command cannot opt into the `SETENV` bypass of
sudo's normal environment restrictions. The application also invokes the helper
with a minimal fixed environment; verify the installed host policy separately.
Disable sudo I/O capture for this command so private stdin is not copied into
sudo session recordings. Validate the candidate with `visudo -c -f CANDIDATE`,
then use a privileged `visudo` session to install a root-owned mode-0440 include
under the system's existing included directory. Validate the **whole** installed
sudoers policy as well. Syntax alone does not prove inclusion or effective
authorization: check the exact command with `sudo -n -l` and then the offline
close operation below. See the official [sudoers](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in)
and [visudo](https://www.sudo.ws/docs/man/visudo.man/) references. A temporary
`sudo -v` timestamp is insufficient for unattended renewal/cleanup past 15 minutes.

Run `.sandbox/bin/client network-close --config .sandbox/native-client.toml` as
the ordinary owner after provisioning. It must reach the exact installed helper
without an interactive password. Do not run the entire native client as root.

## Prove access, rotation and removal

```sh
make sandbox-gateway ACTION=run
make sandbox-client ACTION=run
```

Keep the native launcher foreground in its own terminal. In another terminal,
wait for signed network apply, then run `make sandbox-check CHECK=allowed` and
open `https://site.sandbox.home.arpa:8080/` in an ordinary browser. Port 8081 must
remain denied even though its private listener is alive. Never add a hosts entry,
host-publish DNS/site, attach the Mac client to a Docker subnet or use a browser
viewer/proxy to manufacture success.

The check first verifies HTTPS and the HTTP listener inside the site container,
so broken TLS cannot masquerade as denied access. Its second HTTPS probe uses
the selected private IP directly via `curl --resolve`, while retaining hostname
and CA verification. It therefore tests the packet route independently of DNS.

Capture non-secret evidence: selected pools; signed revision; the owned utun name;
`route -n get PRIVATE_SITE_IP`; `scutil --dns` scoped `sandbox.home.arpa` resolver;
`dscacheutil -q host -a name site.sandbox.home.arpa`; allowed/denied probe results;
and the private page in the browser. Observe traffic on the owned interface and
gateway WireGuard interface to confirm the relay/gateway path. Avoid packet
payloads, credentials, raw `wg showconf`, invite screens and private state dumps.

Keep the session alive for **more than 15 minutes**. Confirm credential renewal
using non-secret expiry/revision observations and fresh private requests; do not
infer rotation merely from an open page or an existing TCP connection. Stop and
restart the client, confirming unchanged public identities and a new successful
private request after authenticated snapshot catch-up. Repeat wrong-code,
expired invitation and replay attempts with disposable invitations; each must
leave the client unenrolled and unable to reach the private fixture.

To remove access, publish a signed device removal from the trusted companion:

```sh
go run ./cmd/admin revoke-device --config .sandbox/admin.toml --device CLIENT_DEVICE_ID
make sandbox-check CHECK=denied
```

Also revoke the disposable credential in the UI when testing authentication
removal. Credential revoke and signed LAN-grant removal are different actions;
neither can substitute for the other. Observe the newer signed revision, flush
only browser request caches as needed, and prove new connections fail.

## Stop, interrupted recovery and reset

`make sandbox-down` contacts only this launcher's private owner socket, requests
graceful native shutdown, waits for its lifetime lock and runs bounded offline
network-close before stopping owned Compose resources. It preserves identities,
trust and volumes. Cleanup failure prevents Docker teardown and keeps its
journal/identity for retry. There is no broad process kill or Docker prune.

The node's configured `shutdown_timeout` covers its full signal drain (10 seconds
by default, up to 60 seconds). The outer native launcher allows 65 seconds before
forcing a stuck child, then uses bounded offline recovery. Down allows that drain
plus recovery before declaring failure. Docker grants the gateway 70 seconds so
its own stop deadline does not preempt a valid node drain.

For a launcher crash, its child inherits the lifetime lock. If that child remains
alive but its owner socket cannot respond, down refuses to signal an unverified
PID. Stop that exact client in its original terminal, then run the offline close
command above and retry down. The root journal recovers intended partial effects;
externally replaced routes/resolvers produce a conflict and remain untouched.
Manually verify an interrupted apply/cleanup, same-head retry and offline cleanup
with an expired credential; record surviving journal state without private keys.

`make sandbox-reset` requires stopped, exactly owned Docker resources and no
active client. An installed native policy/journal blocks resetting its bound
identity. First complete offline close and inspect that owned utun/routes/resolver
are gone, then explicitly retire that installation's sudo rule, public policy
and closed root journal/revision fence in a reviewed privileged session. Never
delete an active or foreign journal merely to make reset pass.
The unprivileged launcher cannot inspect a child of the root-only
`/private/var/db/homeharbor` directory. After confirming that the closed
journal and any other installation's state are absent, remove the **empty**
directory in that privileged session too. Reset fails closed while the
directory is inaccessible, even if its journal file was already removed.

Reset removes only this project's volumes and archives previous local state
inside `.sandbox/archives/`, still excluded from Git/Docker contexts. Archives may
contain private keys; keep them private and explicitly remove them when no longer
needed. Dev `.local/` state and other Docker projects are untouched. Next up makes
fresh trust/identities. Remove the disposable browser CA trust when retiring it.

`sandbox-logs` exposes an allowlist of public structured diagnostics, dropping
free-text, request paths and credential-bearing fields. `sandbox-status` reports
ownership/resources; neither replaces packet, browser, rotation or recovery proof.
