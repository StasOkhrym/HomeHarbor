import Network
import NetworkExtension
#if canImport(WireGuardKit)
import WireGuardKit
#endif

// The provider owns the packet-flow socket and is the only process allowed to
// translate the signed control snapshot into a WireGuard interface. The
// source package intentionally compiles without WireGuardKit so CI can lint
// the configuration boundary; a signed app build must link the official
// package and its wireguard-go-bridge target, otherwise startup fails closed.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let keychain = KeychainStore()
#if canImport(WireGuardKit)
    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { _, _ in
            // Endpoint and key material must never be copied into logs.
        }
    }()
#endif

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = configuration.providerConfiguration,
              let tunnel = TunnelProviderConfiguration(values: providerConfiguration) else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnel.serverAddress)
        settings.ipv4Settings = NEIPv4Settings(addresses: [tunnel.overlayAddress], subnetMasks: [tunnel.overlayMask])
        settings.ipv4Settings?.includedRoutes = tunnel.routes
        if !tunnel.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: tunnel.dnsServers)
            dns.matchDomains = tunnel.dnsMatchDomains.map { "~\($0)" }
            settings.dnsSettings = dns
        }

#if canImport(WireGuardKit)
        guard let privateKey = try? keychain.load(account: Self.wireGuardPrivateKeyAccount),
              privateKey.count == 32,
              let wireGuardConfiguration = tunnel.wireGuardConfiguration(privateKey: privateKey) else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }
        // WireGuardAdapter owns the utun descriptor and handles path changes,
        // DNS resolution, and socket roaming. Apply network settings only
        // after all signed fields form a complete WireGuard configuration, so
        // malformed state cannot leave a half-configured tunnel behind.
        setTunnelNetworkSettings(settings) { error in
            guard error == nil else {
                completionHandler(error)
                return
            }
            self.adapter.start(tunnelConfiguration: wireGuardConfiguration) { adapterError in
                completionHandler(adapterError)
            }
        }
#else
        // Installing routes without the encrypted data plane would create a
        // dangerous black hole. The signed app must link WireGuardKit before
        // this provider can start.
        completionHandler(PacketTunnelError.wireGuardKitUnavailable)
#endif
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
#if canImport(WireGuardKit)
        adapter.stop { _ in
            // WireGuardKit teardown must finish before iOS reuses this
            // provider, otherwise the old packet socket may remain owned.
            completionHandler()
        }
#else
        completionHandler()
#endif
    }

    private static let wireGuardPrivateKeyAccount = "wireguard-private-key"
}

private enum PacketTunnelError: Error {
    case invalidConfiguration
    case wireGuardKitUnavailable
}

private struct TunnelProviderConfiguration {
    let serverAddress: String
    let overlayAddress: String
    let overlayMask: String
    let routes: [NEIPv4Route]
    let dnsServers: [String]
    let dnsMatchDomains: [String]
    let peerPublicKey: String
    let peerEndpoint: String
    let peerAllowedIPs: [String]
    let persistentKeepalive: UInt16?

    init?(values: [String: Any]) {
        guard let serverAddress = values["serverAddress"] as? String,
              let overlay = Self.parsePrefix(values["overlayAddress"] as? String),
              let routeValues = values["includedRoutes"] as? [String],
              !routeValues.isEmpty,
              let peerPublicKey = values["peerPublicKey"] as? String,
              let peerEndpoint = values["peerEndpoint"] as? String,
              let peerAllowedIPs = values["peerAllowedIPs"] as? [String],
              !peerAllowedIPs.isEmpty else {
            return nil
        }
        let parsedRoutes = routeValues.compactMap(Self.parseRoute)
        let parsedAllowedIPs = peerAllowedIPs.compactMap(Self.parsePrefixRange)
        guard parsedRoutes.count == routeValues.count,
              parsedAllowedIPs.count == peerAllowedIPs.count,
              Self.isBase64Key(peerPublicKey),
              !peerEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        let dnsServers = values["dnsServers"] as? [String] ?? []
        guard dnsServers.allSatisfy(Self.isIPAddress) else {
            return nil
        }
        let dnsMatchDomains = values["dnsMatchDomains"] as? [String] ?? []
        guard dnsMatchDomains.allSatisfy(Self.isDomainSuffix) else {
            return nil
        }
        self.serverAddress = serverAddress
        self.overlayAddress = overlay.address
        self.overlayMask = overlay.mask
        self.routes = parsedRoutes
        self.dnsServers = dnsServers
        self.dnsMatchDomains = dnsMatchDomains
        self.peerPublicKey = peerPublicKey
        self.peerEndpoint = peerEndpoint
        self.peerAllowedIPs = peerAllowedIPs
        self.persistentKeepalive = (values["persistentKeepalive"] as? NSNumber).map { $0.uint16Value }
    }

#if canImport(WireGuardKit)
    func wireGuardConfiguration(privateKey privateKeyData: Data) -> TunnelConfiguration? {
        guard let privateKey = PrivateKey(base64Key: privateKeyData.base64EncodedString()),
              let publicKey = PublicKey(base64Key: peerPublicKey),
              let endpoint = Endpoint(from: peerEndpoint),
              let address = IPAddressRange(from: overlayAddress),
              let allowedIPs = peerAllowedIPs.compactMap(IPAddressRange.init(from:)),
              allowedIPs.count == peerAllowedIPs.count else {
            return nil
        }
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = [address]
        interface.dns = dnsServers.compactMap(DNSServer.init(from:))
        guard interface.dns.count == dnsServers.count else { return nil }
        interface.dnsSearch = dnsMatchDomains

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = endpoint
        peer.allowedIPs = allowedIPs
        peer.persistentKeepAlive = persistentKeepalive
        return TunnelConfiguration(name: "Go Tunnels", interface: interface, peers: [peer])
    }
#endif

    private static func parsePrefix(_ value: String?) -> (address: String, mask: String)? {
        guard let value, value.contains("/") else { return nil }
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPv4Address(String(parts[0])),
              let bits = Int(parts[1]),
              (1...32).contains(bits) else { return nil }
        return (address.description, mask(bits: bits))
    }

    private static func parseRoute(_ value: String) -> NEIPv4Route? {
        guard let prefix = parsePrefix(value) else { return nil }
        return NEIPv4Route(destinationAddress: prefix.address, subnetMask: prefix.mask)
    }

    private static func parsePrefixRange(_ value: String) -> String? {
        // /0 is deliberately rejected: this is a LAN access tunnel, not an
        // exit-node VPN, so a default route must never be inferred.
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]), bits > 0 else { return nil }
        if IPv4Address(String(parts[0])) != nil {
            return bits <= 32 ? value : nil
        }
        if IPv6Address(String(parts[0])) != nil {
            return bits <= 128 ? value : nil
        }
        return nil
    }

    private static func isBase64Key(_ value: String) -> Bool {
        guard let data = Data(base64Encoded: value), data.count == 32 else { return false }
        return true
    }

    private static func mask(bits: Int) -> String {
        let value: UInt32 = bits == 32 ? UInt32.max : UInt32.max << UInt32(32 - bits)
        return "\((value >> 24) & 255).\((value >> 16) & 255).\((value >> 8) & 255).\(value & 255)"
    }

    private static func isIPAddress(_ value: String) -> Bool {
        IPv4Address(value) != nil || IPv6Address(value) != nil
    }

    private static func isDomainSuffix(_ value: String) -> Bool {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !value.isEmpty, !value.hasPrefix("."), !value.hasSuffix(".") else { return false }
        return value.split(separator: ".").allSatisfy { label in
            !label.isEmpty && label.first != "-" && label.last != "-" && label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
    }
}
