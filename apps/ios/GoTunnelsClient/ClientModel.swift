import Foundation
import SwiftUI

public enum ConnectionState: Equatable {
    case actionRequired
    case connecting
    case connected
    case disconnected
    case failed(String)
}

public struct ServiceTile: Identifiable, Equatable {
    public let id: String
    public let name: String
    public let url: URL
    public let nativeURL: URL?

    public init(id: String, name: String, url: URL, nativeURL: URL? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.nativeURL = nativeURL
    }
}

@MainActor
public final class ClientModel: ObservableObject {
    @Published public private(set) var state: ConnectionState = .actionRequired
    @Published public private(set) var services: [ServiceTile] = []

    public init() {}

    // The UI owns only user-visible state. Tunnel key material and provider
    // configuration stay in the App Group/Keychain boundary, never in SwiftUI.
    public func setServices(_ services: [ServiceTile]) {
        self.services = services
    }

    public func markConnecting() {
        state = .connecting
    }

    public func markConnected() {
        state = .connected
    }

    public func markActionRequired() {
        state = .actionRequired
    }
}
