package com.example.gotunnels

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Owns the controller lifecycle, while the official WireGuard backend owns
 * the Android VPN service and TUN descriptor. Keeping those responsibilities
 * separate avoids two independent VpnService builders racing to install
 * routes for one tunnel.
 */
class GoTunnelsVpnService : Service() {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val keyMaterialStore by lazy { KeyMaterialStore(this) }
    private val engine by lazy { OfficialWireGuardEngine(applicationContext) }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val configuration = try {
            TunnelConfiguration.from(intent ?: return START_NOT_STICKY)
        } catch (_: IllegalArgumentException) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        } catch (_: IllegalStateException) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }

        // Serialize stop/start transitions. A network change can deliver a
        // second command while the first backend call is still resolving an
        // endpoint; ordering keeps the old configuration from being revived.
        executor.execute {
            try {
                engine.stop()
                val privateKey = keyMaterialStore.loadWireGuardPrivateKey(configuration.wireGuardKeyAlias)
                engine.start(configuration, privateKey)
            } catch (_: Exception) {
                engine.stop()
                stopSelfResult(startId)
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        executor.execute { engine.stop() }
        executor.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

/** The only tunnel-engine contract used by the Android lifecycle controller. */
internal interface WireGuardEngine {
    fun start(configuration: TunnelConfiguration, privateKey: String)
    fun stop()
}

internal data class Route(val address: String, val prefixLength: Int) {
    fun cidr(): String = "$address/$prefixLength"
}

internal data class TunnelConfiguration(
    val overlayAddress: String,
    val overlayPrefixLength: Int,
    val routes: List<Route>,
    val dnsServers: List<String>,
    val endpoint: String,
    val wireGuardKeyAlias: String,
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
            val keyAlias = intent.requireString("wireguard_key_alias")
            val peerKey = intent.requireString("peer_public_key")
            return TunnelConfiguration(overlay.address, overlay.prefixLength, routes, dnsServers, endpoint, keyAlias, peerKey)
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
