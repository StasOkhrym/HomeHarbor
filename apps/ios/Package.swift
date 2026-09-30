// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "GoTunnelsIOS",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "GoTunnelsClient", targets: ["GoTunnelsClient"]),
        .library(name: "GoTunnelsPacketTunnel", targets: ["GoTunnelsPacketTunnel"]),
        .library(name: "GoTunnelsShared", targets: ["GoTunnelsShared"]),
    ],
    targets: [
        .target(
            name: "GoTunnelsShared",
            path: "Shared",
            linkerSettings: [.linkedFramework("Security")],
        ),
        // The app entrypoint is excluded because Swift Package Manager builds
        // a reusable client library here; the eventual Xcode app target owns
        // @main, entitlements, localization, and TestFlight signing.
        .target(
            name: "GoTunnelsClient",
            path: "GoTunnelsClient",
            dependencies: ["GoTunnelsShared"],
            exclude: ["GoTunnelsApp.swift"],
        ),
        .target(
            name: "GoTunnelsPacketTunnel",
            path: "PacketTunnelProvider",
            dependencies: ["GoTunnelsShared"],
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
            ],
        ),
    ],
)
