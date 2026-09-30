# Go Tunnels Android preview

This is the Android-side boundary for the rough native client milestone. It
uses `VpnService` for OS integration but deliberately does not implement
WireGuard cryptography. A production build must provide a reviewed
WireGuard-compatible userspace engine behind `WireGuardEngine` and must obtain
its configuration from a verified, signed network snapshot.

The service rejects default routes. The control plane must provide explicit
overlay address, approved route prefixes, and optional DNS servers. This keeps
the rough client from silently becoming an exit node while the native
WireGuard integration is still being completed.

The service receives only a key alias in its start `Intent`; callers must first
enroll the key through `KeyMaterialStore`. The corresponding
WireGuard private key is wrapped with a non-exportable AES key in Android
Keystore and kept encrypted in private app storage; it is never passed as an
Intent extra. The reviewed WireGuard engine receives the plaintext only in
memory during startup.

The project now has a pinned Gradle application build and uses the official
`com.wireguard.android:tunnel` library. The custom service is only a lifecycle
controller; WireGuard's own `GoBackend.VpnService` owns the TUN descriptor and
route installation. Run `gradle -p apps/android assembleDebug` after installing
the Android SDK and Gradle, or import the directory into Android Studio; this
repository intentionally does not commit a generated wrapper binary.

Play signing and physical-device roaming tests remain part of the Android
milestone.
