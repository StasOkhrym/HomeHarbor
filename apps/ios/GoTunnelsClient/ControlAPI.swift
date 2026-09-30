import Foundation

public struct AvailableService: Codable, Equatable {
    public let id: String
    public let name: String
    public let kind: String
    public let url: URL
    public let nativeURL: URL?
    public let description: String?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case kind
        case url
        case nativeURL = "native_url"
        case description
    }
}

public enum ControlAPIError: Error {
    case invalidResponse
    case unauthorized
    case server(status: Int)
    case malformedPayload
}

/// ControlAPI is deliberately a small device-facing client. It knows only
/// stable `/api/v1` DTOs; signed snapshot verification and tunnel setup remain
/// inside the Packet Tunnel provider rather than being trusted to UI data.
public final class ControlAPI {
    private let endpoint: URL
    private let credential: String
    private let session: URLSession

    public init(endpoint: URL, credential: String, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.credential = credential
        self.session = session
    }

    public func availableServices() async throws -> [AvailableService] {
        let url = endpoint.appendingPathComponent("api/v1/services/available")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ControlAPIError.invalidResponse
        }
        switch http.statusCode {
        case 200:
            break
        case 401, 403:
            throw ControlAPIError.unauthorized
        default:
            throw ControlAPIError.server(status: http.statusCode)
        }
        struct Envelope: Decodable { let services: [AvailableService] }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else {
            throw ControlAPIError.malformedPayload
        }
        return envelope.services
    }
}
