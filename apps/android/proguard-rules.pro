# Keep the service entrypoints discoverable by Android's component loader.
-keep class com.example.gotunnels.GoTunnelsVpnService { *; }
-keep class com.wireguard.android.backend.GoBackend$VpnService { *; }
