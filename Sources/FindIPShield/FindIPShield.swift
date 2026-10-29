import Foundation

/// FindIP Shield for iOS: a verdict on each sensitive action in your app.
///
/// ```swift
/// try FindIPShield.configure(siteKey: "pub_…")
/// let verdict = try await FindIPShield.track(ShieldEvents.loginAttempt)
/// // Send FindIPShield.sessionId to your backend; it verifies before acting.
/// ```
///
/// The verdict is advice. Your backend confirms it with
/// `POST https://shield.findip.net/v1/shield/sessions/verify` and the site's
/// secret key before it allows, challenges or blocks.
public enum FindIPShield {
    public static let version = "1.0.1"
    static let sdkName = "findip-shield-ios"

    private static let lock = NSLock()
    nonisolated(unsafe) private static var client: ShieldClient?

    static var current: ShieldClient? { lock.sync { client } }

    /// Configures the SDK. Returns at once: nothing is sent and nothing runs on
    /// the main thread until the first `track`. Calling it again replaces the
    /// options; the visitor ID is kept.
    public static func configure(siteKey: String, options: ShieldOptions = ShieldOptions()) throws {
        let key = siteKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard key.hasPrefix("pub_") else { throw ShieldError.invalidSiteKey }
        install(ShieldClient(siteKey: key, options: options))
    }

    static func install(_ newClient: ShieldClient) {
        lock.sync { client = newClient }
    }

    /// Reports one event and returns Shield's verdict. Never throws for network
    /// or server problems: those return an `unknown` verdict, never `allow`.
    ///
    /// - Parameters:
    ///   - event: One of `ShieldEvents`, or any name (sent as `custom`).
    ///   - context: Up to 20 facts about the action. Sensitive keys and values
    ///     that look like an email, a phone or a card number never leave the device.
    ///   - screen: Optional screen name, sent as `/screen/<name>`.
    @discardableResult
    public static func track(_ event: String, context: [String: ContextValue]? = nil, screen: String? = nil) async throws -> Verdict {
        guard let client = current else { throw ShieldError.notConfigured }
        return try await client.track(event, context: context, screen: screen)
    }

    /// The completion-handler form of `track`, for UIKit code. The handler runs on the main queue.
    public static func track(
        _ event: String, context: [String: ContextValue]? = nil, screen: String? = nil,
        completion: @escaping @Sendable (Result<Verdict, Error>) -> Void
    ) {
        Task {
            let result: Result<Verdict, Error>
            do { result = .success(try await track(event, context: context, screen: screen)) } catch { result = .failure(error) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Who the user is, for every following event until `reset()`. Only SHA-256
    /// hashes leave the device, plus ciphertext only your Shield dashboard can open.
    public static func identify(
        userId: String? = nil, email: String? = nil, plan: String? = nil,
        salt: String? = nil, custom: [String: ContextValue]? = nil
    ) {
        current?.identify(IdentityInput(userId: userId, email: email, plan: plan, salt: salt, custom: custom))
    }

    /// With `consentRequired`, nothing is sent before `setConsent(true)`.
    public static func setConsent(_ granted: Bool) {
        current?.setConsent(granted)
    }

    /// The current Shield session ID, to send to your backend with the protected
    /// request. Starts a session when none is open. Nil before `configure`.
    public static var sessionId: String? {
        current?.currentSessionId
    }

    /// On logout: forgets the identity, keeps the session and visitor IDs.
    public static func reset() {
        current?.reset()
    }

    /// Rotates the visitor ID and ends the session.
    public static func resetVisitor() {
        current?.resetVisitor()
    }
}
