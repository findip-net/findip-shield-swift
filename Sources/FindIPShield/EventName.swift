import Foundation

/// Event-name rules shared with the web SDK (spec §4, events.json).
enum EventName {
    /// Mirrors VALID_EVENTS in the web SDK and ALLOWED_EVENTS at ingest.
    static let known: Set<String> = [
        "page_view", "session_start", "form_view", "form_submitted",
        "signup_view", "signup_attempt", "signup_success",
        "login_view", "login_attempt", "login_success", "login_failed",
        "password_reset_view", "password_reset_attempt",
        "checkout_view", "checkout_started", "payment_attempt", "payment_failed",
        "lead_form_view", "lead_submitted", "api_request", "custom",
    ]

    /// Retried once on a network failure (spec §6): the actions a backend
    /// is most likely to verify.
    static let sensitive: Set<String> = [
        "signup_attempt", "signup_success", "login_attempt", "login_failed",
        "payment_attempt", "checkout_started", "lead_submitted", "password_reset_attempt",
    ]

    private static let whitespace = try! NSRegularExpression(pattern: "\\s+")

    /// Trimmed, lower-cased, whitespace runs become one underscore; unknown names become `custom`.
    static func normalize(_ name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let range = NSRange(trimmed.startIndex..., in: trimmed)
        let joined = whitespace.stringByReplacingMatches(in: trimmed, range: range, withTemplate: "_")
        return known.contains(joined) ? joined : "custom"
    }
}
