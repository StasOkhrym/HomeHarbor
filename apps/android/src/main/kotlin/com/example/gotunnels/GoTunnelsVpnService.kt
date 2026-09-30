package com.example.gotunnels

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Owns the Android VPN lifecycle, while the WireGuard engine remains an
 * injected dependency. Keeping the engine out of this class prevents UI or
 * Android route code from becoming a second cryptographic implementation.
 */
class GoTunnelsVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var engine: WireGuardEngine = MissingWireGuardEngine

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return try {
            // Android may restart a sticky service without its original Intent.
            // Tear down the previous descriptor before treating that restart as
            // an invalid configuration; otherwise stale routes could survive
            // while the UI believes the tunnel is stopped.
            stopTunnel()
            val configuration = TunnelConfiguration.from(intent ?: return START_NOT_STICKY)
            val builder = Builder()
                .setSession("Go Tunnels")
                .addAddress(configuration.overlayAddress, configuration.overlayPrefixLength)

            // Adding only signed, non-default routes is intentional. Android's
            // Builder otherwise makes it easy to accidentally route all phone
            // traffic through a homelab gateway.
            configuration.routes.forEach { route ->
                builder.addRoute(route.address, route.prefixLength)
            }
            configuration.dnsServers.forEach(builder::addDnsServer)
            val establishedTunnel = builder.establish()
                ?: error("Android denied VPN interface creation")
            tunnel = establishedTunnel
            engine.start(
                establishedTunnel,
                configuration.endpoint,
                configuration.wireGuardPrivateKey,
                configuration.peerPublicKey,
            )
            START_STICKY
        } catch (error: IllegalArgumentException) {
            stopTunnel()
            START_NOT_STICKY
        } catch (error: IllegalStateException) {
            stopTunnel()
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun stopTunnel() {
        tunnel?.let { descriptor ->
            engine.stop()
            descriptor.close()
        }
        tunnel = null
    }
}

/** The production build supplies an official WireGuard-compatible adapter. */
interface WireGuardEngine {
    fun start(tunnel: ParcelFileDescriptor, endpoint: String, privateKey: String, peerPublicKey: String)
    fun stop()
}

private object MissingWireGuardEngine : WireGuardEngine {
    override fun start(tunnel: ParcelFileDescriptor, endpoint: String, privateKey: String, peerPublicKey: String) {
        error("WireGuard engine is not linked")
    }

    override fun stop() = Unit
}

private data class Route(val address: String, val prefixLength: Int)

private data class TunnelConfiguration(
    val overlayAddress: String,
    val overlayPrefixLength: Int,
    val routes: List<Route>,
    val dnsServers: List<String>,
    val endpoint: String,
    val wireGuardPrivateKey: String,
    val peerPublicKey: String,
) {
    companion object {
        fun from(intent: Intent): TunnelConfiguration {
            val overlay = parsePrefix(intent.requireString("overlay_address"), allowDefault = false)
            val routeValues = intent.getStringArrayListExtra("included_routes") ?: error("included_routes required")
            require(routeValues.isNotEmpty()) { "at least one route is required" }
            val routes = routeValues.map { parsePrefix(it, allowDefault = false) }
            val dnsServers = intent.getStringArrayListExtra("dns_servers") ?: arrayListOf()
            dnsServers.forEach { require(isIpAddress(it)) { "invalid DNS server" } }
            val endpoint = intent.requireString("endpoint")
            val privateKey = intent.requireString("wireguard_private_key")
            val peerKey = intent.requireString("peer_public_key")
            return TunnelConfiguration(overlay.address, overlay.prefixLength, routes, dnsServers, endpoint, privateKey, peerKey)
        }

        private fun parsePrefix(value: String, allowDefault: Boolean): Route {
            val parts = value.trim().split("/", limit = 2)
            require(parts.size == 2) { "CIDR is required" }
            val prefixLength = parts[1].toIntOrNull() ?: error("invalid CIDR prefix")
            require(prefixLength in 0..32) { "invalid CIDR prefix" }
            require(allowDefault || prefixLength > 0) { "default route is not allowed" }
            require(isIpv4Address(parts[0])) { "IPv4 CIDR is required" }
            return Route(parts[0], prefixLength)
        }

        private fun isIpAddress(value: String): Boolean = isIpv4Address(value) || value.contains(":")

        private fun isIpv4Address(value: String): Boolean =
            value.split(".").size == 4 && value.split(".").all { it.toIntOrNull()?.let { octet -> octet in 0..255 } == true }

        private fun Intent.requireString(key: String): String =
            getStringExtra(key)?.trim()?.takeIf { it.isNotEmpty() } ?: error("$key is required")
    }
}
