# Go Tunnels iOS preview

This directory is the native client boundary for the next product gate. It is
intentionally not part of the Go build: Apple requires an iOS application,
Network Extension entitlement, signing, and a physical-device test.

## Xcode setup

1. Create an iOS 17+ SwiftUI application target named `GoTunnels`.
2. Add the files from `GoTunnelsClient/` to the application target.
3. Create a separate **Packet Tunnel Provider** target and add
   `PacketTunnelProvider/PacketTunnelProvider.swift` to that target.
4. Integrate the official WireGuardKit from
   [wireguard-apple](https://github.com/WireGuard/wireguard-apple) into the
   Packet Tunnel target. Do not implement WireGuard cryptography here.
5. Enable the Network Extension capability and use an App Group for the
   application/provider hand-off. Store device and WireGuard private keys in
   Keychain with `ThisDeviceOnly` accessibility.

The source files are a deliberately small UX and lifecycle skeleton. The
Packet Tunnel provider now requires `serverAddress`, an `overlayAddress`, and
at least one explicit non-default `includedRoutes` entry in its provider
configuration. Optional `dnsServers` and `dnsMatchDomains` are validated as
route-only settings; the provider never installs a default route implicitly.
They are not a signed VPN binary until the target is configured in Xcode,
WireGuardKit is linked, and the result is exercised on a physical iPhone.
Simulator software-key fallback must remain debug-only.

`KeychainStore.swift` is the shared App Group storage boundary for device
credentials and WireGuard private keys. It uses
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; do not replace it with
`UserDefaults`, logs, or exported backup data.
