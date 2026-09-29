import NetworkExtension

// This target must link the official WireGuardKit implementation. The
// provider owns the packet-flow socket and is the only process allowed to
// translate the signed control snapshot into a WireGuard interface.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              let serverAddress = configuration.providerConfiguration?["serverAddress"] as? String else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverAddress)
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["100.64.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["100.64.0.1"])

        // WireGuardKit setup belongs here once the Xcode target is linked. The
        // provider must reject incomplete signed snapshots before applying any
        // route; it must never infer routes from user-controlled UI values.
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
