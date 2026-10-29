import Foundation
import Security

/// Session and visitor IDs (spec §3): a prefix and 22 URL-safe characters,
/// 128 bits from the system's secure random source.
enum Identifiers {
    static func make(prefix: String) -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            // SecRandomCopyBytes does not fail in practice; fall back to UUID's randomness.
            withUnsafeBytes(of: UUID().uuid) { bytes = Array($0) }
        }
        let base64 = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return prefix + base64
    }
}

/// Where the visitor ID lives between launches.
protocol IdentifierStore: Sendable {
    func load(account: String) -> String?
    func save(_ value: String, account: String)
    func delete(account: String)
}

/// The Keychain, this device only. It survives a reinstall on the same device,
/// which is intended: a reinstall to get a fresh trial stays visible.
struct KeychainStore: IdentifierStore {
    static let service = "net.findip.shield"

    private func query(_ account: String) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: Self.service, kSecAttrAccount: account]
    }

    func load(account: String) -> String? {
        var q = query(account)
        q[kSecReturnData] = true
        q[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func save(_ value: String, account: String) {
        let data = Data(value.utf8)
        let update: [CFString: Any] = [kSecValueData: data]
        if SecItemUpdate(query(account) as CFDictionary, update as CFDictionary) == errSecItemNotFound {
            var add = query(account)
            add[kSecValueData] = data
            add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    func delete(account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }
}

/// For tests, and for apps that want nothing kept between launches.
final class MemoryStore: IdentifierStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]

    func load(account: String) -> String? { lock.sync { values[account] } }
    func save(_ value: String, account: String) { lock.sync { values[account] = value } }
    func delete(account: String) { lock.sync { _ = values.removeValue(forKey: account) } }
}
