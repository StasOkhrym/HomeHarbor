package com.example.gotunnels

import android.content.Context
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

/**
 * Adapter around WireGuard's reviewed Android userspace backend. The adapter
 * translates only the already-validated topology values; it does not perform
 * cryptography or create a second Android VPN interface.
 */
internal class OfficialWireGuardEngine(context: Context) : WireGuardEngine {
    private val backend = GoBackend(context)
    private val tunnel = object : Tunnel {
        override fun getName(): String = "gotunnels"

        override fun onStateChange(newState: Tunnel.State) = Unit
    }

    @Synchronized
    override fun start(configuration: TunnelConfiguration, privateKey: String) {
        val config = Config.parse(configuration.asWireGuardConfig(privateKey).toByteArrayInputStream())
        backend.setState(tunnel, Tunnel.State.UP, config)
    }

    @Synchronized
    override fun stop() {
        backend.setState(tunnel, Tunnel.State.DOWN, null)
    }

    private fun TunnelConfiguration.asWireGuardConfig(privateKey: String): String = buildString {
        appendLine("[Interface]")
        appendLine("PrivateKey = $privateKey")
        appendLine("Address = $overlayAddress/$overlayPrefixLength")
        if (dnsServers.isNotEmpty()) {
            appendLine("DNS = ${dnsServers.joinToString(", ")}")
        }
        appendLine()
        appendLine("[Peer]")
        appendLine("PublicKey = $peerPublicKey")
        appendLine("AllowedIPs = ${routes.joinToString(", ") { it.cidr() }}")
        appendLine("Endpoint = $endpoint")
        appendLine("PersistentKeepalive = 25")
    }

    private fun String.toByteArrayInputStream(): ByteArrayInputStream =
        ByteArrayInputStream(toByteArray(StandardCharsets.UTF_8))
}
