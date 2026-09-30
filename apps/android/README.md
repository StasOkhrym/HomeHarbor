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

Build integration, Play signing, Android Keystore storage, and physical-device
roaming tests remain part of the Android milestone.
