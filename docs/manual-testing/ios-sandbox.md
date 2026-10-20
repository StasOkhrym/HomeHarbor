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

After installing the certificate profile in Settings, iOS requires separately enabling SSL trust under Settings → General → About → Certificate Trust Settings; see [Apple's manual trust instructions](https://support.apple.com/102390). Merely transferring or installing the profile does not establish SSL trust. Profile format follows [Apple's root certificate payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.root.yaml). Mac browser trust is separate and is not modified by these commands.

## Stop and preserve state

```sh
make sandbox-ios-down
```

This removes only owned iPhone Compose containers/networks, waits for graceful shutdown and preserves identities, certificate material and volumes. It does not disable or remove the app's iPhone VPN profile or manually installed CA profile: disconnect/remove the owned HomeHarbor connection in the app and remove the certificate profile in iPhone Settings after testing. The existing `.sandbox` Mac flow remains separate.

Full gateway enrollment, signed invitation and physical acceptance instructions will be added with those workflow stages. An infrastructure start, TLS fixture, Simulator test or unsigned build must not be recorded as successful iPhone enrollment, split DNS, allowed/denied routing, background operation, credential renewal, restart, removal or revocation.
