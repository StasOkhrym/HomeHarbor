# HomeHarbor portable network sandbox research

Date: 2026-10-02. This is a proposed design, grounded in current source and official documentation. No network sandbox has been executed or runtime code changed in this research.

## Recommendation

Scope update: the user ultimately selected an independent MANUAL flow on the same macOS laptop: Docker server/private fixtures and native host system VPN/DNS client. It must not enter mandatory verify/CI/acceptance. The original simulated-client and second-device alternatives below are research context only. See [the updated selected proposal](2026-10-02-local-sandbox-design.md).

Use a separate Docker Compose project with Linux containers for control, relay, gateway and a simulated second device. Put those four on one user-defined bridge representing the local underlay LAN. Give gateway a second interface on an isolated service LAN containing an authoritative DNS fixture and a dummy HTTP site. Put PostgreSQL/Redis on a third private backend network accessible only to control. Keep the privileged network environment separate from the existing backend/UI developer stack.

Docker bridge networks provide network-scoped service discovery and separation between networks. Containers on one bridge can reach each other's listening ports, so the protected site must not join the underlay bridge. Compose allows explicit membership and `internal: true` service/backend networks. These are infrastructure isolation boundaries, not replacements for HomeHarbor's gateway ACL. [Docker bridge](https://docs.docker.com/engine/network/drivers/bridge/), [Compose networks](https://docs.docker.com/reference/compose-file/networks/)

```text
Host browser ── published HTTPS ── control ingress
                                  │
Underlay LAN: control ─ relay ─ gateway ─ client
                              │          │
                              └── WG overlay ─┘
                              │
Private service LAN: gateway ─ DNS ─ dummy site

Private backend: control ─ PostgreSQL ─ Redis
```

The diagram's encrypted overlay is implemented by HomeHarbor/WireGuard, not a fourth Docker network. Compose provisions the fixture's private service subnet. Current HomeHarbor approves/advertises routes and installs overlay routes, peers and firewall policy; it does not dynamically create Docker networks or run an authoritative DNS server. Avoid silently giving the production gateway access to the Docker daemon to imitate subnet creation.

## Proposed network and service contract

| Network           | Members                                                                          | Ownership and exposure                                                                                      |
| ----------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `underlay`        | control ingress, control as needed, relay, gateway, client, sandbox admin runner | One local Docker LAN; external networking only where needed; ordinary service aliases resolve control/relay |
| `services`        | gateway, DNS fixture, dummy site                                                 | `internal: true`; no published HTTP/DNS ports; client never attaches                                        |
| `backend`         | control, migration, PostgreSQL, Redis                                            | `internal: true`; no published DB/cache ports                                                               |
| WireGuard overlay | gateway/client kernel links                                                      | Addresses and peers authorized by signed topology; no Docker IPAM allocation                                |

Prefer project-scoped network and volume names, no `container_name`, no fixed globally named bridge, no host networking or macvlan. Example configurable pools: underlay `172.29.40.0/24`, service LAN `10.77.0.0/24`, overlay `10.78.0.0/24`. Preflight must reject overlaps with each other, Docker networks, host routes/VPN and any selected physical LAN. Example addresses are defaults for a disposable lab, not guaranteed conflict-free ranges.

On the private service LAN, gateway has a stable IP such as `.2`; site `.10`; DNS `.53`. Static fixture addresses make the approved route/DNS records reproducible. The underlay can use discovery except where direct candidate endpoints require explicit stable IPs.

The HTTP and DNS fixtures must return overlay replies through gateway. Current gateway policy is routed, with no NAT/SNAT owner. The simplest faithful setup installs an overlay-pool route via gateway `.2` in each private fixture namespace during fixture startup. A narrowly scoped init capability can be dropped before serving. A separate network-bootstrap helper is an alternative. Do not assume Docker's default bridge gateway knows the WireGuard overlay return path, and do not add broad masquerading rules just to hide this requirement.

Current gateway firewall drops decrypted tunnel traffic to gateway-local listeners (`internal/agent/nft/compiler.go`, input chain). Thus DNS/site belong in forwarded private containers, not on the gateway's own overlay address. Keep exact ACL rules: site TCP 8080, resolver UDP **and TCP** 53, exact `/32` destinations, with default deny for all other service ports.

## Real invitation flow, not a seeded success

1. Preflight capabilities, address pools and dependencies; initialize isolated test CA, encrypted companion root and state.
2. Start DB/Redis, migrations, control and relay; wait for actual readiness. Publish the initial root-signed topology through the supported companion API.
3. Enroll/approve the gateway using a supported control/companion operation. Publish its role, the approved private route with DNS metadata, and the dummy service/access profile. Only root public key enters control/node containers.
4. Start the client with persistent fresh identity keys. Before authorization, private IP fetch and private DNS must fail.
5. Create a real signed invite and independent code. Client submits proof; administrator/companion approves; companion publishes the resulting signed topology; client claims its credential by proving identity-key possession.
6. Client starts the production coordination and kernel WireGuard runtime. Wait for applied signed revision, working handshake and an exact dummy-site response, rather than treating process health as proof of access.
7. Verify private resolution and access, wrong-port denial, invite reuse rejection, unauthorized-client denial, then revoke the device/profile and verify an already established TCP flow is cut off.

Current approval transaction binds identity/profile/outbox together; claim requires an approved invite plus a matching trusted signed snapshot (`docs/activation.md`). Keep this real flow; seeding database records or passing the old raw enrollment token exercises a different contract.

**Current entrypoint gap:** `internal/node/activation.go` provides `EnrollByInvite`, but repository search found no caller in `cmd` or `internal/app/node`. `prepareIdentity` currently calls raw-token `Enroll` or `RefreshCredential`. Expose the existing signed-invite operation in client CLI/composition before claiming this is a one-command signed-invite sandbox. A narrow sandbox driver using the production function can prove the operation, but should not become a second implementation or be presented as completed normal client UX.

## DNS integration gap and preferred seam

`internal/agent/dns/manager.go` calls `resolvectl` to configure route-only domains on a link. An ordinary small Linux image lacks a running systemd-resolved/D-Bus environment. Putting a fake resolvectl in PATH would turn the demo into a test of a stub.

Also, `internal/app/node/runtime.go:280-288` returns from the client branch before constructing DNS ownership. Only the gateway branch receives `dns.Manager`. ClientReconciler validates snapshot DNS metadata but does not apply it. Therefore Docker DNS plus successful `dig @10.77.0.53 site.sandbox.home.arpa` does not prove automatic client system resolver integration.

Recommended staged boundary:

- Extract snapshot DNS planning from systemd-specific execution. Keep validation, selected suffix/resolver and staged cleanup rules common.
- Provide a client DNS owner behind a small interface; production Linux adapter remains systemd-resolved.
- For the Compose sandbox, use a namespace-local DNS forwarder with a dedicated generated config: forward only the chosen private suffix to the private fixture over WireGuard; forward unrelated bootstrap/control lookups to Docker's ordinary resolver. Bind only locally, isolate it inside client namespace, update from **verified snapshot** data and remove stale private forwarding on revoke/failure.
- Do not configure the client directly against a private DNS server before authorization or use Docker aliases for `site.sandbox.home.arpa`: either would bypass the behavior under test. DNS target/site addresses must be on the approved private route, and private lookups should prove that traffic traverses the tunnel.
- Keep the existing real systemd-resolved lifecycle acceptance in the disposable Linux VM. Compose verifies the shared DNS plan and container adapter; VM verifies Linux host integration.

A local forwarder can be a small established DNS process with explicitly generated configuration rather than new production DNS implementation. Its lifecycle is owned by the client namespace; choose a fixed runnable multiarch image only after checking that image's manifest. A first milestone may explicitly query the fixture resolver and clearly label normal application-name resolution incomplete.

## Browser demonstration without bypass

Publish control UI HTTPS to loopback by default. A host browser does not automatically join the client container's namespace or inherit its routes/DNS. A host-side iframe to the dummy container's published port would bypass the tunnel.

For a convenient visual demonstration, a fixed-target viewer can run with `network_mode: service:client`, fetching only the dummy site's configured private hostname/port through the client network. Publish its own UI port on the namespace-owning client service. No arbitrary URL parameter, redirects to other destinations, general CONNECT proxy or secret mounts. Display separately: invite pending/approved/claimed, verified revision, applied revision, actual fetch timestamp and response marker. A viewer proves access by the simulated client, not the host browser's own tunnel. Compose documents namespace sharing and disallows combining `network_mode` with separate `networks`. [Compose services](https://docs.docker.com/reference/compose-file/services/#network_mode)

## Portability boundaries

The portable baseline is Linux containers on rootful Docker Engine or Docker Desktop's Linux engine, native `linux/amd64` and `linux/arm64` images. Gateway/client need `CAP_NET_ADMIN` inside their own namespaces for WireGuard, routing and nftables; use no host network, Docker socket, `/lib/modules` mount, `SYS_MODULE` or blanket `privileged`. Control/relay/fixtures drop capabilities where practical. Docker supports selective capabilities; `NET_ADMIN` is preferable to privileged mode. [Docker runtime privileges](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)

Installing `wireguard-tools` does not guarantee the Docker daemon's kernel implements the WireGuard link type. Current code explicitly executes `ip link add ... type wireguard`. Preflight must create/delete a disposable link and exercise nftables inside a disposable container namespace. Kernel WireGuard exists in modern Linux, while userspace implementations are a separate path; HomeHarbor has no automatic userspace interface fallback today. Do not require `/dev/net/tun` for the current kernel path; a future userspace fallback would need it and an adapter, not merely a package installation. [WireGuard installation](https://www.wireguard.com/install/)

Docker Desktop runs containers in a Linux VM and forwards published TCP/UDP ports through its backend. Containers are not ordinary physical-LAN peers with directly assigned LAN IPs. Thus a simulated client on the Docker bridge is the easiest cross-platform reproducible default. [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)

A real second LAN device is an opt-in profile: publish the HTTPS control/coordination/relay admission endpoint and relay UDP on the chosen host LAN address; issue matching certificate names/IP SANs and bootstrap trust; use LAN-reachable URLs/candidates in invites/config. The remote client must use relay or a deliberately published direct UDP endpoint, not Docker-only gateway IPs. Do not publish private DNS/site ports or install routes that let the real client bypass HomeHarbor. This tests LAN access to the host's published endpoints; it does not recreate Docker containers as native LAN appliances.

Macvlan is Linux-only and unsupported on Docker Desktop Mac/Windows; it also has host communication and network-equipment constraints. Desktop host networking operates at TCP/UDP level, not native access to host interfaces. Neither is a portable shortcut for this sandbox. [Docker macvlan](https://docs.docker.com/engine/network/drivers/macvlan/), [Docker host networking limitations](https://docs.docker.com/engine/network/drivers/host/#limitations)

Rootless Docker is a separate compatibility tier. Its capabilities apply only to resources in its user namespace; global kernel operations can still fail. Do not categorically declare every rootless setup impossible, but do not advertise it as supported before the actual WireGuard+nft probes and end-to-end suite pass on the relevant daemon/kernel. A supported disposable Linux VM fallback is preferable to silently skipping network checks. [Docker rootless limitations](https://docs.docker.com/engine/security/rootless/troubleshoot/#known-limitations)

## Tooling surface and verification

Recommended surface: `make sandbox-up`, `sandbox-status`, `sandbox-logs`, `sandbox-test`, `sandbox-down`, and an explicit isolated `sandbox-reset`. Existing `dev-up` continues to serve backend/UI development. A single orchestrator handles generated state, Compose options, readiness and scenario execution; Make remains a thin discoverability layer. Use stable project identity for interactive runs and a unique project/temp state per automated run. Reset must remove only sandbox-owned volumes and secrets, never development state.

Do not use sleep-based happy-path sequencing. Have health/readiness probes, bounded scenario waits, exact service marker checks and JSON diagnostics containing public identities/revisions only. On failure preserve the original exit status and useful logs/namespace diagnostics; automated runs clean only their own resources. Never require trusting the CA in the host OS just to run container acceptance: client/admin fixtures can trust the mounted sandbox CA. Browser trust is a separate explicit convenience action.

The acceptance suite should include: private direct-IP denial before/after grant; invite/proof/approval/claim and snapshot lineage; DNS UDP/TCP; dummy fetch through client namespace; gateway ACL port denial; unknown device/key denial; established flow revocation; malformed/stale snapshot rejection; restart preserving identity and deny bootstrap; relay-only path; same-LAN direct path; relay failure followed by reconnect. Measure actual path/handshake so same-LAN direct success is not mistaken for working relay. Credential rotation must be exercised over a duration greater than the configured lifetime, or as a separately bounded test, because present runtime renewal/auth weaknesses may otherwise stay hidden.

No Docker capability probe, image manifest check, browser demonstration or full end-to-end flow was executed in this research. Current `deploy/Dockerfile` builds only control/relay/migrate/healthcheck, and distroless production images lack network tools; dedicated gateway/client sandbox targets remain to be added. `docs/local-development.md` explicitly says the existing stack is not a VPN demo and acceptance is not yet the full signed-invite/browser-viewer sandbox.
