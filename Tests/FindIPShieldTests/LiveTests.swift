import Foundation
import Testing
@testable import FindIPShield

/// Against a real Shield ingest, only when pointed at one:
///   SHIELD_LIVE_ENDPOINT   e.g. http://localhost:3998/v1/shield/track
///   SHIELD_LIVE_SITE_KEY   a mobile app site's public key
///   SHIELD_LIVE_BUNDLE_ID  an app id registered on that site (iOS)
///   SHIELD_LIVE_OUT        optional file that receives the session ID
@Suite(.enabled(if: ProcessInfo.processInfo.environment["SHIELD_LIVE_ENDPOINT"] != nil))
struct LiveTests {
    let env = ProcessInfo.processInfo.environment

    @Test func sendsAnIdentifiedLoginAndGetsAVerdict() async throws {
        let endpoint = try #require(env["SHIELD_LIVE_ENDPOINT"].flatMap(URL.init(string:)))
        let client = ShieldClient(
            siteKey: try #require(env["SHIELD_LIVE_SITE_KEY"]),
            options: ShieldOptions(endpoint: endpoint, debug: true, timeout: 20),
            store: MemoryStore(),
            appInfo: AppInfo(bundleId: try #require(env["SHIELD_LIVE_BUNDLE_ID"]), version: "1.0.0", build: "1")
        )
        client.identify(IdentityInput(userId: "live-user-1", email: "Live.Tester@Example.com", plan: "trial"))
        let verdict = try await client.track(ShieldEvents.loginAttempt, context: ["method": "password"], screen: "login")
        #expect(verdict.transport == .delivered)
        #expect(verdict.risk.status == .available)
        if let out = env["SHIELD_LIVE_OUT"] {
            try verdict.sessionId.write(toFile: out, atomically: true, encoding: .utf8)
        }

        // An unregistered id is refused and named.
        let imposter = ShieldClient(
            siteKey: try #require(env["SHIELD_LIVE_SITE_KEY"]),
            options: ShieldOptions(endpoint: endpoint, timeout: 20), store: MemoryStore(),
            appInfo: AppInfo(bundleId: "com.imposter.app", version: nil, build: nil)
        )
        let refused = try await imposter.track(ShieldEvents.loginAttempt, context: nil, screen: nil)
        #expect(refused.transport == .dropped(.configuration))
        #expect(refused.risk.reasons == ["app_mismatch"])
    }
}
