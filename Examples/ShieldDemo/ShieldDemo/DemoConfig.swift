import Foundation

/// The demo's two settings. Paste them here, or set them as environment
/// variables in the scheme (Product → Scheme → Edit Scheme → Run → Arguments).
enum DemoConfig {
    /// The public key of your Shield app site (`pub_...`). Empty: Shield stays off.
    private static let siteKeyHere = ""
    /// The demo backend (`server/server.mjs`). The Simulator reaches your computer at localhost.
    private static let backendHere = "http://localhost:8787"

    static var siteKey: String {
        ProcessInfo.processInfo.environment["SHIELD_SITE_KEY"] ?? siteKeyHere
    }

    static var backendURL: URL {
        URL(string: ProcessInfo.processInfo.environment["SHIELD_DEMO_BACKEND"] ?? backendHere)!
    }
}
