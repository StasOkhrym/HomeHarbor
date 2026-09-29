import SwiftUI

@main
struct GoTunnelsApp: App {
    @StateObject private var model = ClientModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: ClientModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label(statusText, systemImage: statusIcon)
                        .accessibilityLabel(statusText)
                }

                Section("Services") {
                    if model.services.isEmpty {
                        Text("No services are available yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.services) { service in
                        Link(destination: service.url) {
                            Label(service.name, systemImage: "arrow.up.right.square")
                        }
                    }
                }
            }
            .navigationTitle("Go Tunnels")
        }
    }

    private var statusText: String {
        switch model.state {
        case .connected: return "Access is available"
        case .connecting: return "Connecting…"
        case .actionRequired: return "Action required"
        case .disconnected: return "Disconnected"
        case .failed: return "Connection needs attention"
        }
    }

    private var statusIcon: String {
        switch model.state {
        case .connected: return "checkmark.circle.fill"
        case .connecting: return "arrow.triangle.2.circlepath"
        default: return "exclamationmark.circle"
        }
    }
}
