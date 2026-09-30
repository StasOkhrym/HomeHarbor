# Go Tunnels iOS preview

This directory is the native client boundary for the next product gate. It is
intentionally not part of the Go build: Apple requires an iOS application,
Network Extension entitlement, signing, and a physical-device test.

## Xcode setup

1. Create an iOS 17+ SwiftUI application target named `GoTunnels`.
2. Add the files from `GoTunnelsClient/` and `Shared/` to the application
   target. Add `Shared/KeychainStore.swift` to the Packet Tunnel target too.
3. Create a separate **Packet Tunnel Provider** target and add
   `PacketTunnelProvider/PacketTunnelProvider.swift` to that target.
4. Integrate the official WireGuardKit from
   [wireguard-apple](https://github.com/WireGuard/wireguard-apple) into the
   Packet Tunnel target. Its `wireguard-go-bridge` requires a separate Xcode
   external build target because Swift Package Manager cannot build that
   bridge automatically. Do not implement WireGuard cryptography here.
5. Enable the Network Extension capability and use an App Group for the
   application/provider hand-off. Store device and WireGuard private keys in
   Keychain with `ThisDeviceOnly` accessibility.

The source files are a deliberately small UX and lifecycle skeleton. The
Packet Tunnel provider requires `serverAddress`, an `overlayAddress`, at least
one explicit non-default `includedRoutes` entry, and complete WireGuard peer
fields (`peerPublicKey`, `peerEndpoint`, `peerAllowedIPs`) in its provider
configuration. The WireGuard private key is loaded from the shared Keychain,
not from `providerConfiguration`. Optional `dnsServers` and `dnsMatchDomains` are
validated as route-only settings; the provider never installs a default route
implicitly. A source-only build refuses to start when WireGuardKit is not
linked, rather than installing routes without encrypted transport. It is not a
signed VPN binary until the target is configured in Xcode, WireGuardKit and
the bridge are linked, and the result is exercised on a physical iPhone.
Simulator software-key fallback must remain debug-only.

Invite activation parses both fragment-only values emitted by the companion:
the signed permit and the 64-byte invite private key. The fragment is never
sent back to the control HTTP server; the app must move the decoded key into
the Keychain/App Group boundary before submitting a proof.

`KeychainStore.swift` is the shared App Group storage boundary for device
credentials and WireGuard private keys. It uses
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; do not replace it with
`UserDefaults`, logs, or exported backup data.

`Package.swift` provides unsigned source-only targets for CI and local API
checking. It intentionally excludes the `@main` app entrypoint; the eventual
Xcode project must add the app and Packet Tunnel targets, App Group, Network
Extension entitlement, and official WireGuardKit/`wireguard-go-bridge` build
target before any TestFlight or physical-device claim is made. On a Mac with
full Xcode, `make ios-source-check` runs the same unsigned package build as CI.
