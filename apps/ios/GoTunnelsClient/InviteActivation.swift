import Foundation

public enum InviteActivationError: Error {
    case invalidLink
    case missingCode
}

public struct InviteActivation: Equatable {
    public let permit: String
    public let code: String

    public init(url: URL, code: String) throws {
        guard let fragment = url.fragment, !fragment.isEmpty,
              let components = URLComponents(string: fragment),
              let permit = components.queryItems?.first(where: { $0.name == "permit" })?.value,
              !permit.isEmpty else {
            throw InviteActivationError.invalidLink
        }
        let normalizedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalizedCode.count == 8, normalizedCode.allSatisfy(\.isNumber) else {
            throw InviteActivationError.missingCode
        }
        self.permit = permit
        self.code = normalizedCode
    }
}
