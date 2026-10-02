# HomeHarbor host client outside Docker: macOS/Windows feasibility

Date: 2026-10-02. Final selected scope: a **manual independent macOS-only sandbox**, with Docker hosting Harbor/control/relay/gateway/private fixtures and a client running directly on the **same physical Mac**, outside Docker networks. This must not become a mandatory `verify`, CI or acceptance job. Windows and netstack sections are future/alternative research, not current deliverables.

## Decision

**Superseding decision after user confirmation:** the macOS sandbox must provide a full **system VPN with scoped private DNS**, so a normal host browser opens the dummy service's private hostname directly. Recommend a macOS utun adapter using preinstalled official WireGuard tools, with HomeHarbor owning signed onboarding, peer updates, specific routes, split DNS and cleanup. Do not build a custom driver installer. Concrete adapter and ownership stages appear in the final section below; Windows is reference for future work only.

The earlier netstack alternative is retained below only as optional diagnostics/CI research. It is application-scoped access and does **not** satisfy the selected ordinary-browser/system-DNS acceptance criterion. A localhost viewer or explicitly configured browser proxy cannot replace the native adapter work.

Official WireGuard includes an HTTP client example that creates an in-memory netstack TUN, connects it to a WireGuard device, and supplies netstack `DialContext` to `http.Transport`. That is concrete primary-source support for the approach rather than an invented transport. Its example keys/default route are demonstration data; HomeHarbor must derive its limited allowed routes from trusted snapshots and preserve real identity ownership. [Official netstack HTTP client](https://git.zx2c4.com/wireguard-go/tree/tun/netstack/examples/http_client.go)

## Current repository constraints

- `internal/tunnel/interface_unsupported.go` explicitly returns errors outside Linux for interface/forwarding lifecycle.
- `internal/tunnel/interface_linux.go` uses `ip link ... type wireguard`, Linux `ip route` and sysctl.
- `internal/tunnel/wireguard.go` applies peer config through `wgctrl.ConfigureDevice`; it is not an embedded userspace WireGuard engine.
- `internal/node/wireguard_reconciler.go` already separates pure peer validation/planning from an injected `wgtypes.Config` applier; this is a useful extraction seam.
- `internal/node/relay.go` `runKernelRelayBridge` always calls `EnsureLinuxInterface`, even with an injected endpoint updater. Reusing its wrapper unchanged still fails on macOS/Windows. Reuse relay bridge/admission/renewal and endpoint ownership below this Linux setup step.
- `internal/node/direct.go` handshake prober uses wgctrl; userspace mode needs a stats/handshake adapter backed by the embedded device.
- `EnrollByInvite` exists but is not wired into normal CLI/startup. Host mode must invoke the same operation rather than manually configure a private key extracted from an administrator/server fixture.
- Current client composition does not attach a DNS owner. Netstack mode needs an explicit verified-snapshot DNS plan and private lookup boundary.
- The repo already depends indirectly on wireguard-go `v0.0.0-20231211153847-12269c276173`; its netstack package imports gVisor, absent from the currently used app dependency graph/cache. Adding netstack means a substantive dependency/build-size increase. Do not claim the existing indirect dependency makes support free or already available.

## Optional netstack adapter research (not selected acceptance)

Keep one controller and signed configuration owner; vary the low-level transport/network adapter:

```text
Host client command
  identity / signed-invite enrollment / credential owner
  coordination + trusted snapshot and lineage verification
  pure network plan: local overlay IP / peer keys / allowed prefixes / private DNS
  tunnel adapter
    Linux kernel: wgctrl + ip + resolved
    Sandbox host: wireguard-go device + netstack
  relay/direct transport and narrow endpoint updater
  fixed localhost viewer -> private DNS + HTTP through netstack
```

The common controller must not leak `ip`, resolvectl, wgctrl device lookups or process-global state. First extract a prepared typed peer/network plan from snapshot ownership; adapters apply it. The existing wgtypes model can be a transitional config boundary, but avoid treating kernel function names and interface lifecycle as portable.

Embedded mode translates validated key/config data to WireGuard's in-process configuration API (`IpcSet`), using only serializer-owned strings from validated keys, numeric ports and canonical IP prefixes. It serializes endpoint updates with complete snapshot application, clears removed peers and closes/rebuilds resources on identity/DNS changes. Applying one owner's state is not proof the entire snapshot committed; preserve the existing staged success cursor semantics.

Use normal **host UDP sockets** for encrypted underlay; use netstack dialers only for private application traffic. Control/relay TLS and DNS lookup of their hostnames use the ordinary host HTTP transport. Routing those control connections through netstack would create a bootstrap dependency and tunnel all public traffic unnecessarily.

The netstack source constructs a gVisor NIC/address/routing table in memory, exposes UDP/TCP dialers and a resolver that queries its supplied DNS servers through that stack. Thus private-name lookup can traverse the tunnel without editing system DNS. Netstack creates an internal default route, but that is local to its in-memory stack; WireGuard peer allowed prefixes and the application destination allowlist still bound access. It is not a host default-route change. DNS servers are supplied at creation, so changing DNS/local address requires a controlled lifecycle/rebuild or a separate DNS client over netstack, not mutation of unexported fields. [Official netstack implementation](https://git.zx2c4.com/wireguard-go/plain/tun/netstack/tun.go)

Preferred scope: DNS and HTTP for the single configured dummy target. Verify signed hostname suffix, returned destination IP belongs to the approved service/route, port and redirect policy. Disable ambient HTTP proxy configuration for this private fetch so an environment proxy cannot bypass the netstack dialer. No fallback to ordinary host dialer when the tunnel/DNS fails.

## Host/Docker endpoint plan

On the same laptop, host client uses published HTTPS and UDP on loopback. Example HTTPS names `control.localhost` and `relay.localhost` retain the existing development trust/domain model. Gateway uses Docker-reachable aliases/private endpoint URLs, **not** host client `127.0.0.1`; loopback inside a container means that container itself.

Docker Desktop's engine lives in a Linux VM; published container ports are forwarded to the host, with bind address controlling whether they are loopback-only or LAN-accessible. A host process can access those published endpoints without being attached to a Docker subnet. [Docker Desktop published ports](https://docs.docker.com/desktop/features/networking/#how-exposed-ports-work)

Relay-specific current constraint:

1. `UDPPairV2.listenLocked` creates one allocated UDP ingress listener per admitted peer, from `UDPPortMin..UDPPortMax`, or ephemeral ports if the range is absent.
2. `udp_v2.go:245-256` offers **the actual listener port**, with host selection `AdvertiseHost`, then concrete `ListenIP`, then HTTP `req.Host` with its HTTPS port removed.
3. Therefore configure a small bounded UDP range and publish **every port with identical host/container numbers** (`127.0.0.1:port:port/udp`). Publishing only the initial `UDPListenAddress` or remapping range numbers breaks offers/renewal.
4. For split host/container DNS, leave `AdvertiseHost` empty and bind relay to unspecified `0.0.0.0`. Controlled admission URLs can then yield `relay.localhost:allocatedPort` to the host client and `relay:allocatedPort` to the gateway. A concrete Docker `ListenIP` wins over request host and leaks an unreachable container address to the host.
5. If TLS ingress rewrites HTTP Host, or config provides one global advertised host, this dual-name approach will fail. Preserve/validate the intended Host or explicitly design endpoint selection; do not let an arbitrary caller choose an unrestricted destination. Test actual returned offers and both packet directions on the deployed proxy/daemon.

A same-host relay-only milestone avoids publishing gateway WireGuard direct ports and avoids a container attempting to use the host client's loopback direct candidate. Later direct transport needs a host-reachable candidate and published gateway UDP endpoint; sharing one laptop does not make loopback addresses symmetric across namespaces. Both peers can initiate admission/binding to relay using endpoints reachable from their own namespace.

If the client moves to another physical LAN device later, loopback-published ports stop being reachable. That profile publishes only approved control/relay endpoints to the chosen host LAN address, supplies matching certificates/trust and advertises LAN-reachable endpoints. Private DNS/site remain unpublished. A macOS/Windows laptop is not automatically connected to Docker's bridge merely because both are on the same Wi-Fi.

## Native OS VPN alternative

| Mode                  | Benefits                                                                              | Required work/limits                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Embedded netstack     | One native host process, real cryptographic tunnel, no OS interface/route/DNS changes | Application-scoped viewer/dialer; add gVisor+device adapter; prove builds and runtime on actual Windows/macOS      |
| macOS native tunnel   | Arbitrary host apps/browser can reach private names/services                          | utun lifecycle, route ownership, native DNS policy, permissions/helper or app extension, rollback and cleanup      |
| Windows native tunnel | Arbitrary host apps/browser can reach private names/services                          | WireGuardNT/official tunnel service, driver/service packaging, elevation, route/DNS/firewall ownership and cleanup |

Wireguard-go officially supports macOS through utun, whose interface name must follow Darwin's naming rules; it also supports Windows but recommends the fuller Windows app. This does not supply HomeHarbor's cross-platform route/DNS ownership automatically. [Wireguard-go platform documentation](https://git.zx2c4.com/wireguard-go/about/)

Official Windows integration points developers to the embeddable tunnel service backed by WireGuardNT DLLs. The tunnel service creates/configures adapters and runs as Local System, so this is a packaged privileged integration rather than a zero-install sandbox utility. [Embeddable tunnel service](https://git.zx2c4.com/wireguard-windows/about/embeddable-dll-service/README.md), [Windows attack surface](https://git.zx2c4.com/wireguard-windows/about/docs/attacksurface.md)

Do not substitute an exported static `.conf` file from a shared administrator private key for a HomeHarbor client. Native app integration may temporarily consume a locally generated config, but key material belongs to the enrolled host identity, peer permissions derive from verified snapshots, and revoke/rotation/application of newer revisions must remain owned by HomeHarbor.

## Verification boundary

This research read primary source and repository code. It did not compile the netstack client on Windows/macOS or execute the mixed host/Docker UDP path. API/source compatibility with the selected pinned wireguard-go and gVisor versions needs an isolated smoke prototype before implementation commitment. Do not imply kernel and netstack performance/behavior are identical.

Required first proof: real signed onboarding; host-netstack DNS and exact private HTTP marker through encrypted relay; direct host ordinary fetch fails; no manual keys/DB seeds; wrong port denied; revoke closes existing flow; updated snapshot clears peers/DNS ownership; restart preserves enrolled identity; no host route/resolver mutation; Windows amd64/arm64 and macOS amd64/arm64 builds plus execution on available hosts. Linux gateway/real systemd-resolved acceptance remains a separate layer.

The preceding netstack proof is optional and insufficient for the now-selected system VPN. Native acceptance is defined below.

## Selected native system VPN implementation

### Common controller and privileged boundary

One host client controller owns local identity, real signed invitation/code enrollment, claim, credential rotation, coordination connection and trusted snapshot lineage. Its prepared network plan supplies local overlay address, peer keys/allowed prefixes, selected endpoints and private DNS suffix/resolver. The OS adapter implements link, peers, routes, DNS and applied-state reporting. Reuse the existing snapshot/peer validation; no parallel sandbox-only business flow and no server-derived client private key.

For the first sandbox, preflight detects an already installed supported official runtime and command tools. Report exact missing dependencies and installation instructions rather than automatically installing a driver or launching an elevated third-party installer. A narrow root/elevated helper applies only the validated host network plan; keep invitation secrets, control credential and HTTP operations outside that helper when practical. Whole-process elevation can be a temporary explicit disposable-sandbox mode, but not the eventual production privilege boundary.

### macOS adapter

Use installed `wireguard-go` plus `wg`, or embed wireguard-go with an OS utun rather than netstack. For a small sandbox choose the installed-tools path first: foreground-owned wireguard-go process, actual utun name reported by runtime, `wg` peer updates, native `ifconfig` address assignment and `route` for specific approved prefixes. Do not invent a fixed Linux interface name; Darwin's utun naming is documented by Wireguard-go. Avoid a dependency on wg-quick's Bash4 route monitor when the Go supervisor already owns lifecycle. [Wireguard-go macOS platform](https://git.zx2c4.com/wireguard-go/about/#platforms)

Use an owned `/etc/resolver/sandbox.home.arpa` file containing only the approved private resolver. macOS selects the best matching domain resolver and leaves unrelated names on the primary resolver. The OS-provided local `resolver(5)` was also read in this session; Apple's published source describes the same suffix matching and file naming. Do not edit `/etc/resolv.conf`. Treat an existing unmanaged suffix file, symlink or another VPN owning the namespace as a conflict, rather than replacing it. [Apple resolver manual source](https://github.com/apple-oss-distributions/libresolv/blob/main/resolver.5)

Do not use wg-quick `DNS=` for this scoped design without changing its adapter: the official Darwin implementation uses `networksetup -setdnsservers` on network services, which would broaden DNS ownership. The sandbox owns only its private suffix file and approved routes. [Official Darwin wg-quick source](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash)

Verify native resolution with the actual system resolver/normal browser and inspect `scutil --dns`; an explicit `dig @private-resolver` proves only server reachability, not correct OS suffix routing. Current macOS developer tooling can inspect state, but no privileged mutation has been performed by this research.

### Future Windows adapter reference (outside current scope)

Require the installed official WireGuard for Windows application/runtime. Create an owned tunnel with `wireguard /installtunnelservice <private generated config>`; uninstall only that tunnel's service at cleanup. The official service is backed by WireGuardNT and can be queried/updated by `wg` at runtime. This avoids maintaining driver download/signature/installation machinery in HomeHarbor. Generate initial config from the enrolled local device and verified snapshot, omit any global default route and `DNS=` directive, and restrict file ACL to the required controller/service accounts. [Official Windows enterprise integration](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)

Choose one route owner: the tunnel service can install initial allowed-prefix routes, while HomeHarbor must reconcile added/removed routes as signed snapshots change. Runtime `wg` peer changes alone do not prove Windows route/DNS updates. Use native NetTCPIP APIs/cmdlets for the dedicated tunnel's specific prefixes when needed; explicit interface index/alias prevents unrelated route ownership. Temporary sandbox routes belong to the active store and should not survive intentional teardown. [Microsoft New-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute)

For split DNS, add a local NRPT rule scoped to the private suffix (for example `.sandbox.home.arpa`) with its private resolver and an ownership display/comment marker. Use `-PassThru` to store the returned unique rule identifier in the ownership journal. Remove/update by that identifier, never remove all NRPT rules or rewrite all adapter DNS servers. Reject effective enterprise/VPN policy conflicts; NRPT cmdlet availability and suffix behavior need a preflight on supported Windows versions. [Microsoft Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule), [Microsoft Remove-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/remove-dnsclientnrptrule)

### Ordered execution and crash recovery

1. Preflight runtime/tools/elevation, address/route overlap, selected suffix ownership and control/relay reachability. Acquire a per-network/device OS-adapter lock.
2. Enroll/claim using the existing local identity; validate signed topology and construct the entire plan before privileged changes.
3. Prepare the dedicated interface/service with no unauthorized peers, assign overlay address, then apply authorized peer configuration and encrypted relay endpoint.
4. Install only approved private routes, including DNS-server reachability. Validate actual WireGuard handshake and gateway policy/application.
5. Publish private suffix DNS last; record committed applied revision only after all owners succeed. A partial failure removes newly owned routes/DNS/peers or keeps the dedicated path closed; never mark it applied because `wg` succeeded alone.
6. On newer snapshot/revoke, block/clear affected peers first, remove revoked routes and owned DNS, and terminate established access according to gateway ACL. Retaining cached DNS names must not retain authorized traffic.
7. On normal stop or recovered stale journal, remove only owned NRPT ID/resolver file, exact route+interface tuples, dedicated service/link/process and private temporary config. If a resource was edited by another owner, report conflict rather than overwrite/delete blindly.

Persist ownership journal atomically with OS interface/service identity, route tuples, resolver file content hash or NRPT GUID, current signed/applied revision and phase. Network resources/services can outlive a process crash, so a signal handler alone is insufficient. Initially require `sandbox-down`/client disconnect recovery to reconcile stale state; a service/helper watchdog is a later production lifecycle feature.

### Manual demonstration and limits

The normal host browser must open `http://site.sandbox.home.arpa:8080` directly after real enrollment+approval+signed publication+claim, without a viewer/proxy, hosts-file entry, private-site port publication or attaching the host client to Docker. Verify the host's system resolver selects the private DNS through the WireGuard route, unrelated DNS/default routes stay unchanged, another port/unauthorized device is denied, established traffic is cut on revoke, and teardown/crash recovery restores owned state.

Browsers with enforced external secure DNS/proxy policy may bypass system resolver behavior. Detect the actual browser/system settings during acceptance and report a specific incompatibility; do not claim arbitrary DoH profiles are supported or disable privacy settings globally. IP fetch and system-resolution checks separate DNS failure from tunnel failure.

Full system VPN needs elevation and OS-specific code; portability means a common controller plus separately verified native adapters, not one Linux binary working unchanged. No native tunnel, route, resolver or Windows service was created/tested here. Current scope is macOS only. Existing component test infrastructure remains separate; this optional manual sandbox is not added to `verify`, CI or mandatory acceptance.

## Selected manual user journey

1. User installs missing `wg`/`wireguard-go` dependencies separately; sandbox doctor reports their paths/versions, Docker readiness, network conflicts and existing suffix resources. It does not install software, trust a CA globally or change host networking during doctor.
2. User starts the dedicated Docker sandbox and opens the normal control admin UI. Initialization generates isolated encrypted companion root and public trust material; root private key remains local companion state and is never mounted into control/gateway. Bootstrap uses existing supported root/snapshot operations, not an auth bypass.
3. User adds/approves gateway, its private route/DNS and the dummy service/access profile through existing normal operations. Fixture bootstrap creates the private Docker subnet and return routes; it does not authorize the host client.
4. User creates a signed invite, obtains link and code through the intended channels, starts native client join on the same Mac and observes pending approval. User approves through companion and publishes the resulting root-signed topology. Client proves possession, claims credential and applies that topology.
5. A narrowly scoped elevated network operation creates the owned utun link/routes and suffix resolver. The ordinary client controller retains enrollment credentials and coordination; invitation/key/credential work does not need elevated shell execution.
6. User opens the private dummy hostname directly in the ordinary host browser, tries a disallowed port, revokes access and confirms it disappears. Status shows actual handshake and signed/applied revision, not merely running container health.
7. User disconnects/stops the manual sandbox; cleanup removes only its resolver file, routes, interface/runtime and project resources, with state preserved unless explicit sandbox reset. Interrupted runs have explicit recover/disconnect based on ownership journal.

Expose a small separate manual command surface such as sandbox doctor/up/status/down and host client join/connect/disconnect. Keep this out of the existing default validation graph. A local doctor/manual demo report can provide diagnostics when the user invokes it, without converting the exploratory workflow into an automated full acceptance program.
