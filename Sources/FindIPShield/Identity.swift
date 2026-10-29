import CryptoKit
import Foundation
import Security

/// identify() inputs. Raw values stay on the device (spec §5).
struct IdentityInput: Sendable, Equatable {
    var userId: String?
    var email: String?
    var plan: String?
    var salt: String?
    var custom: [String: ContextValue]?
}

/// Hashing and encryption of identity, matching the web SDK's
/// `sdk/src/core/identify.ts` byte for byte (identity.json).
enum Identity {
    /// RSA-OAEP-2048 with SHA-256 carries at most 190 bytes; longer values are hashed only.
    static let maxEncryptableBytes = 190

    static func clean(_ value: String?) -> String {
        value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    /// Trimmed and lower-cased; valid only with something on both sides of the last `@`.
    static func normalizeEmail(_ raw: String?) -> String {
        let email = clean(raw).lowercased()
        guard let at = email.lastIndex(of: "@") else { return "" }
        let afterAt = email.index(after: at)
        return at > email.startIndex && afterAt < email.endIndex ? email : ""
    }

    static func sha256Hex(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// The customer_context fields for an identity, before encryption.
    static func context(for input: IdentityInput) -> [String: Any] {
        var context: [String: Any] = [:]
        let userId = clean(input.userId)
        let email = normalizeEmail(input.email)
        let plan = clean(input.plan)
        let salt = clean(input.salt)
        let prefix = salt.isEmpty ? "" : "\(salt):"
        if !plan.isEmpty { context["plan"] = plan }
        if !email.isEmpty, let at = email.lastIndex(of: "@") {
            context["email_domain"] = String(email[email.index(after: at)...])
        }
        if !userId.isEmpty { context["user_id_hash"] = sha256Hex(prefix + userId) }
        if !email.isEmpty { context["email_hash"] = sha256Hex(prefix + email) }
        return context
    }

    /// The values to encrypt, keyed by the customer_context field they go into.
    static func encryptable(_ input: IdentityInput) -> [(field: String, value: String)] {
        var values: [(String, String)] = []
        let userId = clean(input.userId)
        let email = normalizeEmail(input.email)
        if !userId.isEmpty { values.append(("user_id_enc", userId)) }
        if !email.isEmpty { values.append(("email_enc", email)) }
        return values
    }
}

/// The site's identity public key, "fk1.<key id>.<base64 SPKI DER>".
struct IdentityKey: @unchecked Sendable {
    let keyId: String
    let key: SecKey

    private static let pattern = try! NSRegularExpression(pattern: "^fk1\\.(ik_[a-f0-9]{16})\\.([A-Za-z0-9+/]+={0,2})$")

    init?(_ formatted: String) {
        let text = formatted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let match = Self.pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let idRange = Range(match.range(at: 1), in: text),
              let keyRange = Range(match.range(at: 2), in: text),
              let spki = Data(base64Encoded: String(text[keyRange])),
              let pkcs1 = DER.rsaPublicKey(fromSPKI: spki)
        else { return nil }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, nil) else { return nil }
        self.keyId = String(text[idRange])
        self.key = key
    }

    /// RSA-OAEP with SHA-256 for both the digest and MGF1, as WebCrypto and
    /// the dashboard's Node decryption use. Nil when the value is too long.
    func encrypt(_ value: String) -> String? {
        let plain = Data(value.utf8)
        guard plain.count <= Identity.maxEncryptableBytes,
              SecKeyIsAlgorithmSupported(key, .encrypt, .rsaEncryptionOAEPSHA256),
              let cipher = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, plain as CFData, nil) as Data?
        else { return nil }
        return "fk1.\(keyId).\(cipher.base64EncodedString())"
    }
}

/// Just enough DER to take the RSAPublicKey out of a SubjectPublicKeyInfo:
/// Security framework imports RSA public keys as PKCS#1, not SPKI.
enum DER {
    static func rsaPublicKey(fromSPKI spki: Data) -> Data? {
        let bytes = [UInt8](spki)
        // SEQUENCE { SEQUENCE algorithm, BIT STRING subjectPublicKey }
        guard let outer = element(bytes, at: 0, tag: 0x30),
              let algorithm = element(bytes, at: outer.contentStart, tag: 0x30),
              let bitString = element(bytes, at: algorithm.end, tag: 0x03),
              bitString.contentStart < bitString.end,
              bytes[bitString.contentStart] == 0x00 // no unused bits
        else { return nil }
        return Data(bytes[(bitString.contentStart + 1)..<bitString.end])
    }

    private struct Element {
        let contentStart: Int
        let end: Int
    }

    private static func element(_ bytes: [UInt8], at offset: Int, tag: UInt8) -> Element? {
        guard offset + 2 <= bytes.count, bytes[offset] == tag else { return nil }
        var index = offset + 1
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7f
            guard count >= 1, count <= 4, index + count <= bytes.count else { return nil }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[index])
                index += 1
            }
        }
        guard index + length <= bytes.count else { return nil }
        return Element(contentStart: index, end: index + length)
    }
}
