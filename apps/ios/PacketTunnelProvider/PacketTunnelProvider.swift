import Network
import NetworkExtension

// This target must link the official WireGuardKit implementation. The
// provider owns the packet-flow socket and is the only process allowed to
// translate the signed control snapshot into a WireGuard interface.
final class PacketTunnelProvider: NEPacketTunnelProvider {
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

        // WireGuardKit setup belongs here once the Xcode target is linked. The
        // provider must reject incomplete signed snapshots before applying any
        // route; it must never infer routes from UI values or install a default
        // route that was not explicitly authorized by the signed snapshot.
        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // WireGuardKit session teardown must happen before the completion call
        // so iOS does not reuse a provider whose packet socket is still owned.
        completionHandler()
    }
}

private enum PacketTunnelError: Error {
    case invalidConfiguration
}

private struct TunnelProviderConfiguration {
    let serverAddress: String
    let overlayAddress: String
    let overlayMask: String
    let routes: [NEIPv4Route]
    let dnsServers: [String]
    let dnsMatchDomains: [String]

    init?(values: [String: Any]) {
        guard let serverAddress = values["serverAddress"] as? String,
              let overlay = Self.parsePrefix(values["overlayAddress"] as? String),
              let routeValues = values["includedRoutes"] as? [String],
              !routeValues.isEmpty else {
            return nil
        }
        let parsedRoutes = routeValues.compactMap(Self.parseRoute)
        guard parsedRoutes.count == routeValues.count else {
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
    }

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
