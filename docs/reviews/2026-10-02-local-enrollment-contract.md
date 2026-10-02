# HomeHarbor: local client enrollment requirements

Date: 2026-10-02. Source revision: `b66865b`. Primary manual scenario: native macOS client on the same laptop as the Docker sandbox. Another LAN device is a later optional scenario. No enrollment setup or OS networking was executed in this review.

## What the enrolling device needs

The client needs a HomeHarbor client/controller, not SQL, Redis, Docker membership or administrator access to control. A browser invitation alone cannot run the current cryptographic client/tunnel operation. The present EnrollByInvite operation is a library function and still needs a normal join command/UI entrypoint.

Minimum bootstrap inputs:

| Input                                | Why                                                                           | Source                                                              |
| ------------------------------------ | ----------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Reachable HTTPS control origin       | Proof submission, pending status, possession challenge/claim and coordination | Sandbox setup publishes the address                                 |
| Trusted TLS CA/certificate chain     | Authenticate the HTTPS endpoint                                               | Explicit provisioned public sandbox CA; no insecure skip            |
| Trusted root public key + network ID | Verify invite/snapshot authority independently of control                     | Provision through trusted operator pairing/config, show fingerprint |
| Signed invitation link               | Profile/expiry-bound permit and invitation private authority in fragment      | Trusted companion issues it                                         |
| Separate invitation code             | Local proof/code confirmation in the real approval flow                       | Operator sends/shows separately                                     |
| Private local state location         | Preserve generated Ed25519/WireGuard identity and claimed credential          | Client chooses a scoped protected path                              |
| Supported tunnel/DNS adapter         | Access private service after signed approval                                  | Native macOS adapter for the selected sandbox                       |

Root private key stays with the trusted companion. Device identity/WireGuard private keys are generated on the joining device and never taken from a server fixture. Invite fragment/code are not loggable URLs/CLI arguments; use private input or a prompt. State is saved before proof transmission so retries reuse the same identity.

A convenience pairing bundle may contain control URL, network ID, root public key/fingerprint and TLS CA. It is an additional client UX artifact, not existing implementation. Trust that bundle through the operator channel; downloading a replacement root from the same untrusted endpoint is not independent pinning. A companion-signed invite does not eliminate the need to know which root to trust.

The client should generate a unique DeviceID automatically and show a readable name/identity fingerprint for approval. The current library requires the caller to supply DeviceID; the human should not invent identifiers or manipulate SQL.

## Native macOS prerequisites

For the selected full system VPN mode, preflight Docker only on the server host; the client needs supported wireguard-go/wg tools and the HomeHarbor controller. Normal proof submission does not require elevation. Applying an owned utun, private-prefix routes and scoped /etc/resolver suffix file requires a controlled privilege step. Keep default route, ordinary DNS and unrelated VPN state unchanged.

The current client calls a Linux-only interface/route lifecycle and omits DNS ownership. These adapters and join entrypoint are implementation prerequisites, not functionality supplied automatically by installing WireGuard. A generic WireGuard application alone cannot perform HomeHarbor proof/approval/claim or follow signed snapshot updates.

On the same laptop, client uses loopback-published control/relay endpoints, with explicit local certificate trust; its ordinary host process stays outside Docker's service subnet. Gateway uses namespace-reachable internal endpoints. The operator's host browser/admin WebAuthn origin can retain the existing localhost configuration. A private browser service hostname must be resolved by the configured OS suffix resolver after approval, not an ad hoc hosts entry or browser proxy.

## Exact flow

1. Preflight inputs, supported runtime, trust and private state; generate/reuse local keys and persistent DeviceID.
2. Locally parse the invitation fragment; verify canonical signed permit, expected root/network, profile and expiry. Prepare proof bound to device identity/WireGuard public keys and code digest.
3. Send only public signed proof material to control. Display pending status; client alone cannot approve itself.
4. Trusted companion validates the independent code and signs exact approval/device addition. Control commits approval/device/profile/outbox state atomically; companion publishes the authorized signed snapshot.
5. Client receives a fresh single-use challenge binding network/invite/device/nonce/expiry and signs it with its own identity key. Claim succeeds only when approved state and matching trusted snapshot exist; credential is returned only to the client and saved privately.
6. Verify snapshot lineage and apply owned peers/routes/private DNS. Obtain device-bound relay admission; establish encrypted packets to gateway; show actual applied revision and service result.
7. Reuse identity on retries/restarts, handle lost claim response through a fresh challenge as implemented, and maintain credential leases once the runtime owner is added. Invalid/expired/used invitations and wrong trust fail explicitly; do not silently switch to raw-token enrollment.

The endpoint/API prerequisites are read from internal/node/activation.go and docs/activation.md. Enrollment does not by itself prove tunnel or DNS access; step 6 is a separate observable state.

## Another physical LAN device later

It needs its own supported HomeHarbor client and independent protected identity, reachable LAN HTTPS and relay endpoints, provisioned public trust/root/network, invite and separate code. It does not require Docker. Loopback URLs on the server laptop cannot be used remotely; publish a selected LAN address and matching certificate identity. Keep a bounded relay UDP range reachable with matching advertised ports. Check host firewall and Wi-Fi client isolation; sharing Wi-Fi does not guarantee peer reachability.

No Internet router forwarding is necessary when both devices can reach the host within the same LAN. Do not expose private DNS/site/SQL/Redis to make onboarding easier. Private service routes and resolver only become available through the signed tunnel. A client on another OS needs that OS's actual tunnel/DNS adapter; Windows/mobile support remains outside the current macOS-only scope.

## Manual diagnostics, not mandatory gates

For the selected optional sandbox, report stages: trust configured, proof pending, approved, credential claimed, signed revision applied, DNS resolved, service reachable. Preserve nonsensitive diagnostics and distinguish control reachability from actual packet-plane access. Manually exercise wrong code, expired invite, replay, denial before approval, exact allowed port and signed revoke.

This flow stays opt-in and outside verify/CI/required acceptance as requested. It uses real SQL/Redis and actual signing/authentication despite being manual. See the [selected sandbox design](2026-10-02-local-sandbox-design.md) and [memory-store audit](2026-10-02-memory-store-audit.md).
