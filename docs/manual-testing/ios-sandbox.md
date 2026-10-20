# iPhone LAN sandbox

This is an optional manual flow on a Mac and an iPhone on the same trusted LAN/Wi-Fi. It is separate from `make verify` and the existing Mac-native sandbox. It uses `.sandbox-ios`, Compose project `homeharbor-ios-sandbox`, distinct certificate authorities and the admin origin `ios-admin.localhost`.

A full Xcode installation, iOS SDK and an Apple Developer Program team supporting Network Extension are required to install the real Packet Tunnel app. A free Personal Team cannot sign this capability; see [Apple DTS](https://developer.apple.com/forums/thread/128767). Simulator and unsigned builds do not prove physical VPN routing.

## Prepare and start infrastructure

Choose the Mac's current RFC1918 IPv4 address on the shared LAN (for example, Wi-Fi in System Settings → Network). Do not use a Docker, VPN or loopback address. Keep this address stable for the test.

```sh
make sandbox-ios-prepare LAN_IP=192.168.50.7
make sandbox-ios-up LAN_IP=192.168.50.7
make sandbox-ios-status
```

Replace the example address. The workflow verifies it is assigned to the Mac, selects a vetted network profile avoiding existing host/Docker pools, and refuses conflicting or foreign project resources. Startup checks the requested TCP/UDP bindings, probes Docker VM WireGuard/nftables support, then starts the database, Redis, migration, control, relay, proxy, private DNS and dummy site. Gateway enrollment and signed policy publication are still separate steps; infrastructure startup does not establish a client VPN.

Control HTTPS uses the selected address on TCP19443; relay WSS uses TCP19444 and UDP52120–52135. Admin HTTPS binds only `127.0.0.1:19445`, with `https://ios-admin.localhost:19445/admin/login`. The LAN control listener exposes only the enrollment/credential/coordination/relay admission API allowlist; admin/auth/companion endpoints are excluded. The private site and DNS have no published host ports. This flow does not alter the Mac's routes, DNS, VPN helper or installed trust.

Generated endpoint/profile metadata binds the stored identity to the chosen IP. Preparation preserves existing complete keys and certificates and refuses partial state or a changed endpoint. Preserve that state for review if the LAN address changes; do not delete individual files to force regeneration. A publication interrupted by a disk error may leave incomplete state, which is deliberately refused on retry.

## Certificate handoff

Preparation writes only public artifacts under `.sandbox-ios/public/`:

- `control-ca.pem` and `site-ca.pem`;
- `fingerprints.txt`, with SHA256 hashes of the DER certificates;
- `homeharbor-ios.mobileconfig`, a removable profile containing exactly those two root certificates.

Transfer only this public directory to the iPhone, for example with AirDrop, and compare both fingerprints before accepting the profile. Keep the rest of `.sandbox-ios` private on the Mac: it contains service secrets, private TLS keys and the encrypted companion root/passphrase. The public directory is inside a parent with mode `0700` to prevent accidental sharing of adjacent private state. Neither preparation nor startup installs or trusts a certificate.

Installing this profile and trusting its CAs is an explicit manual device security change. The profile contains no VPN, DNS, proxy or management enrollment settings. Root trust applies to certificates issued by these test CAs; it is not restricted to one hostname. Use it only for the isolated test, then remove it.

After installing the certificate profile in Settings, iOS requires separately enabling SSL trust under Settings → General → About → Certificate Trust Settings; see [Apple's manual trust instructions](https://support.apple.com/102390). Merely transferring or installing the profile does not establish SSL trust. Profile format follows [Apple's root certificate payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.root.yaml). Mac browser trust is separate; use the explicit command below for the admin browser.

## Admin browser and enrolled gateway

Use one explicit Mac browser trust mode after preparation:

```sh
make sandbox-ios-trust-ca
# Or, for Chrome:
make sandbox-ios-trust-ca TRUST_BROWSER=chrome
```

The default adds SSL CA trust only for `ios-admin.localhost` in the login keychain. Chrome requires a different mode: SSL `trustAsRoot` for the exact `CA:FALSE` frontend server certificate, including the selected numeric IP and three generated DNS SANs. This affects that user's SSL applications, not just Chrome. Each mode displays the actual public certificate SHA256 fingerprint and requires you to enter it and complete any macOS prompt yourself. A renewed Chrome leaf needs a new explicit confirmation. Existing different/broader rules are refused; before/after snapshots are saved privately in `.sandbox-ios/browser-trust`. Existing Mac sandbox trust entries are preserved. `TRUST_TARGET=site` is not supported by this Mac admin trust action; phone site trust comes from the separate public profile.

Open `https://ios-admin.localhost:19445/admin/login` on the Mac and complete the [initial owner/account setup](../admin-panel.md). This uses a distinct WebAuthn RP from the existing Mac sandbox. SMTP is disabled in this fixture; use a passkey or configured authenticator as the second factor. Production email-delivery acceptance is a separate flow.

Issue a gateway-role token in **Invites**, then use the hidden prompt:

```sh
make sandbox-ios-gateway ACTION=enroll
```

Never put that token in argv, an environment variable, screenshots or shared logs. The finite Go enrollment stores private gateway credentials only in its owned Docker volume and exports exactly the three public identity fields. The workflow binds those actual keys/ID into `.sandbox-ios/initial-snapshot.toml`, selected routes/DNS and ACLs allowing only DNS53 and the private HTTPS site8080. A running gateway, changed identity, incomplete binding or edited manifest is refused before overwrite. A failed public export after remote enrollment may require rerunning the finite command to recover the existing gateway identity; do not delete its volume.

In the authenticated panel, add service `Private sandbox site`, type `Web application`, URL `https://site.sandbox.home.arpa:8080`, advanced record ID `sandbox-site`. Create access profile `iPhone sandbox`, advanced record ID `ios-sandbox`, and select that site and the enrolled `iPhone sandbox gateway`. Reuse exact matching existing records. SQL catalog/profile membership and signed snapshot authorization are separate: both are required, and catalog membership alone grants no packet access.

Publish the initial signed scope, then start the gateway:

```sh
go run ./cmd/admin init-snapshot --config .sandbox-ios/admin.toml
make sandbox-ios-gateway ACTION=run
make sandbox-ios-fingerprint
```

Fingerprint output contains only the public root, network ID `ios-sandbox-network` and domain-separated network fingerprint. Transfer those through an independent trusted operator channel; the invite link is not a root-trust source. Do not confuse this fingerprint with either TLS CA fingerprint. Actual signed authorization and tunnel reachability are still unverified after a gateway start.

## Signed invitation and physical acceptance

With an eligible Development Team, install the real HomeHarbor app and its Packet Tunnel extension using the iOS repository's build/run instructions. Install/confirm the public CA profile as above. Keep both devices on the chosen LAN; allow the declared control/relay ports through the Mac firewall if it requests confirmation.

Issue the invitation in an unrecorded operator terminal:

```sh
go run ./cmd/admin invite --config .sandbox-ios/admin.toml
```

Treat its link and separate eight-digit code as private. In the iPhone app, paste/scan the signed link, enter the independently obtained network ID/public root, compare the full fingerprint and enter the code. Observe **pending**, then verify the intended device/public keys/profile in the operator panel. Use only the non-secret invite ID in the companion commands:

```sh
go run ./cmd/admin approve --config .sandbox-ios/admin.toml --invite INVITE_ID
go run ./cmd/admin publish-snapshot --config .sandbox-ios/admin.toml --invite INVITE_ID
```

Approval reads the separate code from a hidden prompt. Respect any rate-limit cooldown; do not issue replacement invitations for an already approved device. Saved enrollment and actual connection are separate states: after the app finishes claiming, press **Connect** explicitly. Confirm the real OS VPN state, then open `https://site.sandbox.home.arpa:8080/` in ordinary iPhone Safari. The service catalog comes from the provider's applied signed policy; a catalog refresh failure must not falsely disconnect the VPN.

Record actual results in the private review workspace, without credentials or private screenshots. Verify pre-enrollment/disconnected denial; allowed private DNS/site8080; denied site8081 while its fixture is actually alive; unrelated Internet/default-route behavior; background and foreground; more than 15 minutes of credential/ticket renewal; app/provider and gateway restart; remove while connected; fresh enrollment followed by signed revocation. Do not substitute a direct Docker/private-IP request for the iPhone tunnel path. For signed revocation, use the verified enrolled client device ID:

```sh
go run ./cmd/admin revoke-device --config .sandbox-ios/admin.toml --device CLIENT_DEVICE_ID
```

Confirm revoked traffic stops and removal disables/stops/removes only owned VPN preferences before deleting local protected keys. Simulator, protocol fixtures and unsigned bundles do not prove any physical result. A Personal Team is a failed prerequisite for this stage; do not remove Network Extension entitlements to bypass it.

## Stop and preserve state

```sh
make sandbox-ios-down
```

This removes only owned iPhone Compose containers/networks, waits for graceful shutdown and preserves identities, certificate material and volumes. It does not disable or remove the app's iPhone VPN profile or manually installed CA profile: disconnect/remove the owned HomeHarbor connection in the app and remove the certificate profile in iPhone Settings after testing. The existing `.sandbox` Mac flow remains separate.

An infrastructure start, TLS fixture, Simulator test or unsigned build must not be recorded as successful iPhone enrollment, split DNS, allowed/denied routing, background operation, credential renewal, restart, removal or revocation. Remove only this test profile/trust after acceptance; do not remove legacy Mac sandbox entries or other VPNs.
