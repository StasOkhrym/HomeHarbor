import Foundation

public enum InviteActivationError: Error {
    case invalidLink
    case missingCode
    case invalidInviteKey
}

public struct InviteActivation: Equatable {
    public let permit: String
    public let invitePrivateKey: Data
    public let code: String

    public init(url: URL, code: String) throws {
        guard let fragment = url.fragment, !fragment.isEmpty,
              let components = URLComponents(string: fragment),
              let permit = components.queryItems?.first(where: { $0.name == "permit" })?.value,
              let permitBytes = Self.decodeBase64URL(permit),
              !permitBytes.isEmpty else {
            throw InviteActivationError.invalidLink
        }
        guard let encodedInviteKey = components.queryItems?.first(where: { $0.name == "invite_key" })?.value,
              let invitePrivateKey = Self.decodeBase64URL(encodedInviteKey),
              invitePrivateKey.count == 64 else {
            throw InviteActivationError.invalidInviteKey
        }
        let normalizedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalizedCode.count == 8,
              normalizedCode.unicodeScalars.allSatisfy({ scalar in scalar.value >= 48 && scalar.value <= 57 }) else {
            throw InviteActivationError.missingCode
        }
        self.permit = permit
        self.invitePrivateKey = invitePrivateKey
        self.code = normalizedCode
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.contains("=") else {
            return nil
        }
        let standard = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padding = String(repeating: "=", count: (4 - standard.count % 4) % 4)
        return Data(base64Encoded: standard + padding)
    }
}
