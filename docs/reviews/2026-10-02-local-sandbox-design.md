# HomeHarbor: manual macOS Docker sandbox proposal

Date: 2026-10-02. Source revision: `b66865b`. Final user-selected scope: an independent manual testing flow on one physical macOS laptop. HomeHarbor/control/relay/gateway/private fixtures run in Docker; the native macOS client runs outside Docker and uses a real system tunnel plus scoped OS DNS. Windows and a second physical device are deferred. The sandbox must never become part of mandatory verify, CI or acceptance gates. This is a design/research artifact, not a running sandbox.

## Intent and recommendation

Provide a simple repeatable environment demonstrating genuine signed invitation, approval, credential claim, signed topology, encrypted service access, private DNS and revocation. A successful HTTP page must not be caused by directly publishing the dummy service or giving the client a private-network interface.

Selected target: Docker Compose for control/relay/Linux gateway/DNS/site, plus a native macOS host client with system VPN routing and scoped OS DNS. The user confirmed that direct ordinary-browser private hostname access is required. A userspace netstack/viewer can be a diagnostic mode, but cannot satisfy this acceptance criterion. Native tunnel/DNS integration needs platform-specific privileged operations; keep onboarding and business logic unprivileged.

Keep one production onboarding/coordination/snapshot controller with interchangeable data-plane adapters. Do not create a second simplified invite or fake authorization implementation for the sandbox.

## Topology

```text
Same macOS laptop

Browser -> private hostname -> native OS VPN adapter
                                  |
                    signed invite + coordination over HTTPS
                                  |
Host published localhost ports -> Docker proxy/control + relay
                                  |
                       real WireGuard packet plane
                                  |
                            Linux gateway
                                  |
                 private Docker service subnet (internal)
                         |                    |
                       DNS                dummy site

Private backend network: control/migrate -> PostgreSQL + Redis
```

Only control/relay endpoints are published. DNS and dummy site have no published ports, do not join the underlay network, and have no proxy path around gateway. The native client does not join any Docker network. A simulated client is outside this initial manual scope; any future simulation must not attach to private services/backend.

Suggested configurable pools: Docker underlay `172.28.40.0/24`, private services `172.29.50.0/24`, signed WireGuard overlay `10.200.0.0/24`. Preflight rejects overlaps with host/VPN/Docker networks. Gateway's private address `.2` differs from Docker's bridge gateway; DNS `.53` and site `.80` are stable fixtures. Private fixtures return overlay traffic via gateway `.2`, using a scoped startup route rather than product NAT.

Compose provisions the fixture subnet and DNS service. HomeHarbor currently configures overlay/routes/ACLs and split-DNS settings; it does not create Docker networks or run an authoritative DNS server. Do not give gateway the Docker socket to imitate that behavior.

## Endpoint addressing

The native host client uses loopback-published HTTPS and a small loopback-published relay UDP range, with host/container port numbers equal. Generate the local CA/certificates for chosen localhost names and use explicit client trust. Keep current host browser WebAuthn origin stable; no LAN origin is needed for this same-laptop baseline.

Container loopback is different from host loopback. Gateway must use a container-reachable control/relay endpoint; never copy `127.0.0.1` host-client URLs into gateway config. Relay must use truthful audience-specific endpoint resolution: host client sees a published loopback endpoint; gateway sees the internal Docker relay endpoint. Endpoint mapping must be an explicit transport concern, preserve authenticated session/device identity, validate allowed hosts/ports and never weaken TLS. Current relay can derive its advertised UDP host from the admission request Host when AdvertiseHost is empty and ListenIP is unspecified. Controlled host versus Docker admission URLs may therefore supply distinct reachable offers without a new global address setting. A concrete ListenIP overrides request Host. Gateway admission URL selection still needs explicit configuration because control currently returns one relay URL; verify both offers and proxy Host preservation.

A viable alternative is a shared host-reachable advertised endpoint, with gateway reaching Docker Desktop's host address; verify actual TCP/UDP hairpin behavior before choosing it. Do not depend on undocumented VM addresses. Relay advertises its actual allocated UDP port, so publish an explicit bounded identical-number range (e.g. `52000-52015/udp`) and set allocation to it. Do not publish 1024 ports by accident through the present derived default.

Use relay for the first baseline. Direct mode can later publish a fixed gateway UDP endpoint and advertise host-reachable candidates. Prove the packet path rather than relying on a configuration label. Docker Desktop forwards published TCP/UDP ports, while bridge addresses are not ordinary host/LAN peer addresses. [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)

## Host client choices

| Choice                                             | What the sandbox proves                                                                                              | Additional work                                                                       |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Userspace WireGuard/netstack + fixed-target viewer | Real signed flow, encrypted packets, private DNS within the client, gateway ACL, permitted/denied service and revoke | New userspace data-plane adapter; explicit private DNS/netstack dialer; scoped viewer |
| Native system VPN (macOS selected)                 | Above plus ordinary applications using OS routes and private DNS                                                     | macOS utun, owned routes/scoped DNS, privilege separation and cleanup                 |
| Client in container (deferred)                     | Linux composition and reproducible simulation                                                                        | Does not fulfill the selected native macOS client on its own                          |

For comparison only, the official wireguard-go HTTP example creates an in-memory network stack and dials HTTP through it. This supports the proposed architecture; it is not evidence that HomeHarbor currently supports it or that its dependency graph has passed a Windows build. [Official netstack example](https://git.zx2c4.com/wireguard-go/tree/tun/netstack/examples/http_client.go)

For userspace mode, DNS queries go to the signed private resolver through the same WireGuard stack. No host DNS fallback for private names, hosts-file shortcuts or direct host HTTP dialer. The viewer only requests the configured dummy target, blocks arbitrary URLs and redirects to unrelated endpoints, and binds loopback. It preserves an explicit unavailable/pending/denied state and never fetches before authorized signed topology applies. Host browser sees the viewer URL; the private service hostname is resolved and fetched inside the client. This distinction must be visible in diagnostics.

The selected system VPN mode permits opening the private hostname normally in host applications and must restore owned OS routing/DNS on failure/shutdown. A localhost viewer is only an optional diagnostic request facility. Neither host nor Linux gateway may silently degrade to a mode that does not meet the selected enforcement/OS integration contract.

## Native adapters for the selected full VPN mode

For this macOS sandbox, depend on preinstalled wireguard-go and wg tools; do not build a custom installer or install dependencies silently. Windows integration remains in the research reference only:

- macOS: wireguard-go/utun and wg runtime tools; scoped route owner; an owned resolver file for the signed suffix under `/etc/resolver/`. Avoid a blanket network-service DNS rewrite. Track allocated utun name and restore only routes/files actually created by HomeHarbor.

A narrow elevated adapter handles fixed validated tunnel/route/DNS operations. The ordinary controller verifies snapshots before calling it; the adapter validates the requested interface/prefix/suffix as well. No shell-interpolated commands, arbitrary executable paths, default routes or global resolver replacement. Help/invite proof does not require elevation; applying OS network state does.

Prepare and validate all owners before mutation, acquire a single-client state lock, apply tunnel/limited routes/scoped DNS, then advance the applied revision only after the complete plan succeeds. Persist an ownership journal for interrupted cleanup. Detect externally changed resources and report conflicts instead of restoring an old global snapshot over another program's settings.

Manual verification targets the available macOS host only. Windows support is deferred; the references do not imply it will be built or tested in this iteration. See [host-client research](2026-10-02-hostclient-research.md) for primary-source details.

## Shared execution design

```text
Client controller
  identity + signed invite + credential lease + coordination
  signed snapshot verification and revision persistence
                    |
       validated desired peer/route/DNS plan
                    |
  Linux kernel adapter OR userspace adapter OR native OS adapter
```

The controller owns trust, state, cancellation and command semantics. The data-plane adapter owns WireGuard lifecycle, peers/endpoints and dialing or system routes. Separate desired-state planning from concrete wgctrl/OS calls; reuse existing pure peer compilation, not the Linux command executor. Selected resolver/route settings come from verified snapshots.

Userspace mode needs an adapter that applies peer plans to wireguard-go and sets relay endpoint ownership consistently. The current reconciler produces wgtypes.Config; it is a useful internal migration seam, but business/controller interfaces should not permanently expose a kernel-specific config type. Preserve policy/revision invariants and removal behavior across adapters.

Use independent identities on the same machine: native client state and container gateway state must never share keys/credentials. Root signing authority remains with the trusted host companion, not control, relay, gateway or joining client. Include the previously proposed credential owner; a 30-second happy path must not hide expiry failures.

## Current prerequisites

- EnrollByInvite exists in `internal/node/activation.go` but has no production cmd/app caller. Add a real client join entrypoint using private input/prompt for invite fragment/code; do not seed client records or use raw tokens and call that the invite flow.
- `internal/tunnel/interface_unsupported.go` rejects the current interface lifecycle outside Linux. Existing client composition invokes Linux route reconciliation; simply building the client for macOS/Windows is insufficient.
- `internal/tunnel/wireguard.go` uses wgctrl; no wireguard-go device/netstack runtime is present. The userspace host adapter is new work, not an existing switch.
- Client composition currently omits DNS ownership, and gateway DNS depends on concrete systemd-resolved Manager. Extract DNS planning/application interfaces. Userspace private DNS is internal to the stack; system-wide DNS remains a separate native adapter requirement.
- Current Dockerfile builds server roles only. Add a dedicated gateway sandbox image with real ip/nft/WireGuard tools and a native macOS client build for the host architecture.
- Current dev initialization/output is not sandbox-scoped. Reuse focused generation helpers with independent Compose project, volumes, certificates and companion state.
- Credential rotation/live-session revoke and early gateway deny guard need the execution corrections in [the runtime review](2026-10-02-runtime-architecture.md).

## Real scenario

1. Preflight engine capabilities, pools, ports and platform; build without replacing a working environment on failure. Probe WireGuard/nft in disposable namespaces; image tools do not provide missing kernel support.
2. Start scoped DB/Redis/migrations/control/relay/private fixtures and gateway; use real authentication. Initialize gateway identity and publish root-signed revision one with its keys, private route, resolver, dummy service and profile ACL templates.
3. Start a fresh unapproved native client. Prove no permitted data-plane private DNS/site access. Private site has a unique response marker and a forbidden second port.
4. Companion issues signed invite plus separate code; native client sends proof and becomes pending. Operator checks/approves through companion; root-signed client addition is published.
5. Client claims credential, verifies/applies snapshot, establishes real WireGuard via relay and resolves/fetches dummy site through the authorized stack. ACL allows only site TCP and resolver UDP/TCP 53 at exact addresses.
6. Verify forbidden ports, unapproved identities, invitation reuse and any underlay bypass remain denied. Gateway needs a separate sandbox fence preventing non-WireGuard underlay forwarding to private fixtures; product nft policy only owns tunnel traffic.
7. Publish signed permission/device removal and prove both new and established service flows stop. Control credential revoke alone is not signed packet-plane removal.
8. Restart while preserving identities/revision cursor; test longer than credential lifetime after rotation exists. Record applied revision and actual packet-path evidence alongside Activity.

Step 5 must open the private hostname in the ordinary host browser with no proxy, custom hosts entry or viewer. Separately verify OS resolution and scoped route selection. Optional userspace diagnostics must be labeled and cannot mark this system VPN gate passed.

## Independent manual workflow

The entire flow is opt-in. No invocation from `make verify`, `make test`, `FULL=1`, existing acceptance scripts, pre-commit or CI. The regular development stack must remain usable with no sandbox tools, images, sudo permissions or private state. This flow may have its own manual diagnostic checks, but their result is not a required repository gate.

Proposed commands, not implemented:

| Command                           | Manual purpose                                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `sandbox-up`                      | Preflight/build/provision the isolated Docker environment; print UI and next step                              |
| `sandbox-client`                  | Run the native macOS client; prompt for signed invite/code and show pending/approved/applied state             |
| `sandbox-status` / `sandbox-logs` | Inspect this environment and show nonsensitive diagnostics                                                     |
| `sandbox-check`                   | Optional user-invoked reachability/denial diagnostics after a chosen scenario                                  |
| `sandbox-down`                    | Stop this native client and Compose project; revert only owned utun/routes/resolver state; preserve identities |
| `sandbox-reset`                   | Explicitly delete only this sandbox's persistent state after resources are stopped                             |

The human generates an invitation, observes pending, approves it through the trusted companion, opens the dummy service and performs signed revocation. Do not automatically approve invitations to conceal the manual steps. Environment bootstrap can be scripted, but the feature flow remains real and reviewable. An optional guided launcher can print the next action and wait for readiness without putting invitation codes/keys in logs or arguments.

Run ordinary orchestration as the user. Request elevation only for bounded native networking operations and report which owned resources will be changed. Do not silently add the CA to the system trust store; normal native CLI trust can use the generated CA explicitly, while browser trust is an explicit local setup step. State lives in a sandbox-specific ignored directory and Compose project, separate from dev and integration.

Native cleanup must target the recorded owned runtime/interface/routes/resolver file, not all wireguard-go processes or every VPN interface. Refuse to overwrite an existing suffix resolver not owned by this sandbox. Interrupted cleanup retains a private ownership journal and prints a targeted recovery command.

## Tooling and portability

Proposed, not implemented: sandbox up/status/invite/approve/check/logs/down and explicit reset. Keep Make for discoverability on macOS. A small Go sandbox orchestrator with Cobra can drive Compose and shared client/companion libraries; do not embed Docker provisioning into domain services. Return stage-specific nonsensitive diagnostics, bounded waits and original failure codes.

Normal down preserves project state; reset removes only the selected sandbox. Keep dev/integration/sandbox projects independent. Do not mount Docker socket, host D-Bus or host network state. Gateway uses only required namespace privileges; no blanket privileged mode. The selected full native VPN needs a controlled privilege step for tunnel/service/route/DNS ownership. Do not describe it as admin-free or promise that Docker alone supplies the host adapter. Optional userspace diagnostics have different privileges and acceptance scope.

Containers run on the engine Linux kernel. Verify WireGuard link creation and nft operations; rootless/alternate engines are separate tested compatibility tiers. Retain the existing Lima/Linux acceptance fallback for real systemd-resolved and kernel behavior. Neither a source example nor engine availability confirms end-to-end portability.

## Deferred scenarios

Windows, a client on another LAN device and a simulated container client are outside this iteration. If added later, they remain separate opt-in scenarios unless the user changes that policy. LAN-device access would need explicit LAN publication/trust rather than reusing loopback endpoints. Host-IP exposure is unnecessary for the selected same-macOS-laptop baseline.

See [platform/network research](2026-10-02-sandbox-research.md). No containers, tunnel, DNS adapter, native viewer or full invite flow were created or executed during this review. The selected client mode is full native system VPN/DNS; exact platform adapter integration still requires implementation and real-host acceptance.

## Related contracts

[Client enrollment prerequisites](2026-10-02-local-enrollment-contract.md) define trust, identity, invitation and native adapter requirements. [Memory-store audit](2026-10-02-memory-store-audit.md) confirms the sandbox uses actual SQL/Redis repositories rather than test fakes.
