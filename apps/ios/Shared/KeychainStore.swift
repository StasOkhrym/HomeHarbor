import Foundation
import Security

// KeychainStore is shared by the app and Packet Tunnel provider. Private
// credentials never enter NETunnelProviderProtocol.providerConfiguration,
// which is configuration transport rather than secret storage.
public final class KeychainStore {
    private let service: String
    private let accessGroup: String

    public init(service: String = "com.example.gotunnels", accessGroup: String = "group.com.example.gotunnels") {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func save(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData: data] as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw KeychainStoreError.status(updateStatus) }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainStoreError.status(addStatus) }
    }

    public func load(account: String) throws -> Data {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainStoreError.status(status)
        }
        return data
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.status(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
    }
}

public enum KeychainStoreError: Error {
    case status(OSStatus)
}
