import Foundation

/// The on-device privacy boundary for `custom` context (spec §4, context.json),
/// ported from the web SDK's `sdk/src/utils/safe.ts`. Ingest applies the same
/// rules again; nothing that fails them ever leaves the device.
enum ContextSanitizer {
    static let maxKeys = 20
    static let maxKeyLength = 64
    static let maxStringLength = 256

    private static let email = try! NSRegularExpression(pattern: "[^\\s@]+@[^\\s@]+\\.[^\\s@]+")
    private static let phone = try! NSRegularExpression(pattern: "^[+]?[\\d\\s().-]{7,}$")
    private static let card = try! NSRegularExpression(pattern: "\\b(?:\\d[ -]*?){13,19}\\b")

    static func containsSensitivePattern(_ value: String) -> Bool {
        let range = NSRange(value.startIndex..., in: value)
        if value.contains("@") && email.firstMatch(in: value, range: range) != nil { return true }
        if phone.firstMatch(in: value, range: range) != nil { return true }
        if card.firstMatch(in: value, range: range) != nil { return true }
        return false
    }

    static func isSensitiveKey(_ name: String) -> Bool {
        let lower = name.lowercased()
        return ["password", "passwd", "card", "cvv", "cvc", "ssn", "social", "secret"].contains { lower.contains($0) }
    }

    /// Keeps at most 20 keys, the first in sorted key order (a Swift dictionary
    /// has no insertion order), and drops sensitive keys and values.
    static func sanitize(_ input: [String: ContextValue]) -> [String: ContextValue] {
        var result: [String: ContextValue] = [:]
        for key in input.keys.sorted() {
            if result.count >= maxKeys { break }
            if key.utf16.count > maxKeyLength || isSensitiveKey(key) { continue }
            switch input[key]! {
            case .bool(let value):
                result[key] = .bool(value)
            case .int(let value):
                result[key] = .int(value)
            case .double(let value):
                if value.isFinite { result[key] = .double(value) }
            case .string(let value):
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty || trimmed.utf16.count > maxStringLength { continue }
                if containsSensitivePattern(trimmed) { continue }
                result[key] = .string(trimmed)
            }
        }
        return result
    }

    static func json(_ context: [String: ContextValue]) -> [String: Any] {
        context.mapValues { value -> Any in
            switch value {
            case .string(let v): return v
            case .int(let v): return v
            case .double(let v): return v
            case .bool(let v): return v
            }
        }
    }
}
