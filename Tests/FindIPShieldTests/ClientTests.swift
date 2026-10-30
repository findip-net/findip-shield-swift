import Foundation
import Security
import Testing
@testable import FindIPShield

/// Answers requests from a closure and records them.
final class StubTransport: HTTPTransport, @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest) async throws -> (Int, [String: Any])
    private let lock = NSLock()
    private var handler: Handler
    private(set) var requests: [URLRequest] = []

    init(_ handler: @escaping Handler) { self.handler = handler }

    func setHandler(_ handler: @escaping Handler) { lock.sync { self.handler = handler } }

    var tracked: [[String: Any]] {
        lock.sync { requests }.filter { $0.httpMethod == "POST" }.compactMap {
            $0.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        }
    }

    var trackedNames: [String] { tracked.compactMap { ($0["event"] as? [String: Any])?["name"] as? String } }

    /// The tracked bodies other than `session_start`, which is sent alongside, in either order.
    var events: [[String: Any]] { tracked.filter { ($0["event"] as? [String: Any])?["name"] as? String != "session_start" } }

    func send(_ request: URLRequest) async throws -> (status: Int, body: Data) {
        let handler = lock.sync { () -> Handler in
            requests.append(request)
            return self.handler
        }
        let (status, object) = try await handler(request)
        return (status, try JSONSerialization.data(withJSONObject: object))
    }
}

extension ShieldClient {
    /// `track`, then waits for the `session_start` sent alongside it.
    func trackSettled(_ name: String, context: [String: ContextValue]?, screen: String?) async throws -> Verdict {
        let verdict = try await track(name, context: context, screen: screen)
        await settle()
        return verdict
    }
}

/// A clock tests move by hand.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var date = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { lock.sync { date } }
    func advance(_ seconds: TimeInterval) { lock.sync { date = date.addingTimeInterval(seconds) } }
}

@Suite struct ClientTests {
    static let allow: [String: Any] = [
        "request_id": "req_1", "session_id": "ignored",
        "risk": ["status": "available", "score": 12, "level": "low", "recommendation": "allow", "reasons": ["login_attempt"]],
        "ip": ["country": "GB", "asn": 2856, "asn_name": "BT", "is_vpn": false, "is_proxy": false, "is_tor": false,
               "is_relay": false, "is_hosting": false, "is_malicious": false],
    ]

    let device = DeviceInfo(
        platform: "ios", osVersion: "18.1", modelFamily: "iPhone", locale: "en-GB", timezone: "Europe/London",
        screen: .init(width: 393, height: 852, scale: 3), signals: .init(emulator: false, rooted: nil, debugger: false)
    )

    func makeClient(
        _ transport: StubTransport, options: ShieldOptions = ShieldOptions(),
        store: IdentifierStore = MemoryStore(), clock: TestClock = TestClock()
    ) -> ShieldClient {
        let device = self.device
        return ShieldClient(
            siteKey: "pub_test0000000000", options: options, store: store, transport: transport,
            appInfo: AppInfo(bundleId: "com.example.app", version: "4.2.1", build: "1021"),
            deviceProvider: { device }, now: { clock.now }, retryDelay: {}
        )
    }

    private func sessions(_ transport: StubTransport) -> [String] {
        transport.events.compactMap { ($0["session"] as? [String: Any])?["session_id"] as? String }
    }

    @Test func testAShortTripToTheBackgroundKeepsTheSession() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        client.didEnterBackground()
        clock.advance(60)
        client.willEnterForeground()
        _ = try await client.trackSettled("login_success", context: nil, screen: nil)

        #expect(Set(sessions(transport)).count == 1)
        #expect(transport.trackedNames.filter { $0 == "session_start" }.count == 1)
    }

    @Test func testALongTripToTheBackgroundEndsTheSession() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        client.didEnterBackground()
        clock.advance(31 * 60)
        client.willEnterForeground()
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)

        #expect(Set(sessions(transport)).count == 2)
        #expect(transport.trackedNames.filter { $0 == "session_start" }.count == 2)
    }

    @Test func testEventsSentInTheBackgroundDoNotKeepTheSessionOpen() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        client.didEnterBackground()
        clock.advance(20 * 60)
        _ = try await client.trackSettled("custom", context: nil, screen: nil)
        clock.advance(20 * 60)
        _ = try await client.trackSettled("custom", context: nil, screen: nil)
        clock.advance(60)
        _ = try await client.trackSettled("custom", context: nil, screen: nil)

        // 40 minutes in the background ends the first session; the second stays
        // open, its own background time having restarted when it opened.
        let seen = sessions(transport)
        #expect(seen[0] == seen[1])
        #expect(seen[1] != seen[2])
        #expect(seen[2] == seen[3])
    }

    @Test func testReadingTheSessionIdAfterTheTimeoutGivesOneNewSession() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        clock.advance(31 * 60)
        #expect(client.currentSessionId == client.currentSessionId)
    }

    @Test func testReadingTheSessionIdFirstStillSendsSessionStart() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let client = makeClient(transport)

        let read = client.currentSessionId
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        _ = try await client.trackSettled("login_success", context: nil, screen: nil)

        #expect(Set(sessions(transport)) == [read])
        #expect(transport.trackedNames.filter { $0 == "session_start" }.count == 1)
    }

    @Test func testReadingTheSessionIdAfterTheTimeoutStillSendsSessionStart() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        clock.advance(31 * 60)
        let read = client.currentSessionId
        _ = try await client.trackSettled("login_success", context: nil, screen: nil)

        #expect(sessions(transport).last == read)
        #expect(transport.trackedNames.filter { $0 == "session_start" }.count == 2)
    }

    @Test func testAnExplicitSessionStartIsNotSentTwice() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let client = makeClient(transport)

        _ = try await client.trackSettled("session_start", context: nil, screen: nil)
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)

        #expect(transport.trackedNames == ["session_start", "login_attempt"])
    }

    @Test func testDeliveredVerdictAndSessionStartOncePerSession() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)

        let verdict = try await client.trackSettled("login_attempt", context: nil, screen: "login")
        #expect(verdict.transport == .delivered)
        #expect(verdict.risk.recommendation == .allow)
        #expect(verdict.risk.score == 12)
        #expect(verdict.network?.country == "GB")
        _ = try await client.trackSettled("login_failed", context: nil, screen: nil)
        #expect(transport.trackedNames.sorted() == ["login_attempt", "login_failed", "session_start"])

        clock.advance(31 * 60)
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(Set(transport.trackedNames.suffix(2)) == ["session_start", "login_attempt"])
        let sessions = Set(transport.tracked.compactMap { ($0["session"] as? [String: Any])?["session_id"] as? String })
        #expect(sessions.count == 2, Comment(rawValue: "a new session after the timeout"))
    }

    @Test func testIdsHaveTheSpecFormatAndTheVisitorPersists() async throws {
        let store = MemoryStore()
        let transport = StubTransport { _ in (200, Self.allow) }
        _ = try await makeClient(transport, store: store).trackSettled("login_attempt", context: nil, screen: nil)
        _ = try await makeClient(transport, store: store).trackSettled("login_attempt", context: nil, screen: nil)
        let sessions = transport.tracked.compactMap { $0["session"] as? [String: Any] }
        let pattern = try NSRegularExpression(pattern: "^(sess|vis)_[A-Za-z0-9_-]{22}$")
        for s in sessions {
            for id in [s["session_id"] as? String, s["visitor_id"] as? String].compactMap({ $0 }) {
                #expect(pattern.firstMatch(in: id, range: NSRange(id.startIndex..., in: id)) != nil, Comment(rawValue: id))
            }
        }
        #expect(Set(sessions.compactMap { $0["visitor_id"] as? String }).count == 1, Comment(rawValue: "the visitor ID is kept across launches"))
    }

    @Test func testStrictModeSendsNoVisitorScreenSignalsOrFamily() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        _ = try await makeClient(transport, options: ShieldOptions(privacyMode: .strict)).trackSettled("signup_attempt", context: nil, screen: nil)
        let body = try #require(transport.events.last)
        let session = try #require(body["session"] as? [String: Any])
        let device = try #require(body["device"] as? [String: Any])
        #expect(session["visitor_id"] == nil)
        #expect(device["screen"] == nil)
        #expect(device["signals"] == nil)
        #expect(device["model_family"] == nil)
        #expect(device["os_version"] as? String == "18.1")
    }

    @Test func testConsentRequiredSendsNothingUntilGranted() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        let client = makeClient(transport, options: ShieldOptions(consentRequired: true))
        let refused = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(refused.transport == .dropped(.consent))
        #expect(refused.risk.recommendation == .monitor)
        #expect(transport.requests.isEmpty)
        client.setConsent(true)
        let sent = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(sent.transport == .delivered)
        #expect(transport.trackedNames.filter { $0 == "session_start" }.count == 1)
    }

    @Test func testRefusalsNeverReadAsAllow() async throws {
        let transport = StubTransport { _ in (403, ["error": "app_mismatch", "detected_app": "com.example.app"]) }
        let verdict = try await makeClient(transport).trackSettled("login_attempt", context: nil, screen: nil)
        #expect(verdict.transport == .dropped(.configuration))
        #expect(verdict.risk.status == .unknown)
        #expect(verdict.risk.recommendation == .monitor)
        #expect(verdict.risk.reasons == ["app_mismatch"])
    }

    @Test func testAnUnknownBodyNeverReadsAsAllow() {
        let body = try! JSONSerialization.data(withJSONObject: ["risk": ["status": "unknown", "level": "unknown", "recommendation": "allow", "reasons": []]])
        let verdict = ShieldClient.verdict(from: body, sessionId: "sess_x")
        #expect(verdict?.risk.recommendation == .monitor)
        #expect(verdict?.network == nil)
    }

    @Test func testQuotaStartsACooldown() async throws {
        let transport = StubTransport { _ in (429, ["error": "daily_quota_exceeded"]) }
        let clock = TestClock()
        let client = makeClient(transport, clock: clock)
        let first = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(first.transport == .dropped(.limited))
        let sentBefore = transport.requests.count
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(transport.requests.count == sentBefore, Comment(rawValue: "nothing is sent during the cooldown"))
        clock.advance(61)
        transport.setHandler { _ in (200, Self.allow) }
        let later = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(later.transport == .delivered)
    }

    @Test func testNetworkFailureRetriesSensitiveEventsOnce() async throws {
        struct Offline: Error {}
        let transport = StubTransport { _ in throw Offline() }
        let client = makeClient(transport)
        let sensitive = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(sensitive.transport == .dropped(.unreachable))
        #expect(sensitive.risk.reasons == ["shield_unreachable"])
        // session_start once (not sensitive), login_attempt twice.
        #expect(transport.trackedNames.sorted() == ["login_attempt", "login_attempt", "session_start"])
        _ = try await client.trackSettled("page_view", context: nil, screen: nil)
        #expect(transport.trackedNames.filter { $0 == "page_view" }.count == 1, Comment(rawValue: "not retried"))
    }

    @Test func testTooLargeDropsTheCustomContextAndRetries() async throws {
        let transport = StubTransport { request in
            let body = try JSONSerialization.jsonObject(with: request.httpBody ?? Data()) as? [String: Any]
            let hasCustom = (body?["customer_context"] as? [String: Any])?["custom"] != nil
            return hasCustom ? (413, ["error": "payload_too_large"]) : (200, Self.allow)
        }
        let client = makeClient(transport)
        let verdict = try await client.trackSettled("login_attempt", context: ["method": "password"], screen: nil)
        #expect(verdict.transport == .delivered)
        #expect((transport.events.last?["customer_context"] as? [String: Any])?["custom"] == nil)
    }

    @Test func testContextIsFilteredOnDevice() async throws {
        let transport = StubTransport { _ in (200, Self.allow) }
        _ = try await makeClient(transport).trackSettled("login_attempt", context: ["method": "password", "password": "x", "contact": "jane@example.com"], screen: nil)
        let custom = (transport.events.last?["customer_context"] as? [String: Any])?["custom"] as? [String: Any]
        #expect(custom as NSDictionary? == ["method": "password"] as NSDictionary)
    }

    @Test func testProgrammerErrorsThrow() async {
        #expect(throws: ShieldError.invalidSiteKey) { try FindIPShield.configure(siteKey: "sec_nope") }
        let client = makeClient(StubTransport { _ in (200, Self.allow) })
        do {
            _ = try await client.trackSettled("   ", context: nil, screen: nil)
            Issue.record("an empty name throws")
        } catch {
            #expect(error as? ShieldError == .emptyEventName)
        }
    }

    @Test func testScreenNamesBecomeScreenPaths() {
        #expect(PayloadBuilder.screenPath("Login") == "/screen/login")
        #expect(PayloadBuilder.screenPath("Sign Up") == "/screen/sign_up")
        #expect(PayloadBuilder.screenPath("checkout?step=2") == nil)
    }

    // MARK: Identity encryption

    @Test func testIdentityIsHashedAndEncryptedForTheDashboardOnly() async throws {
        let (identityKey, privateKey) = try Self.makeIdentityKey()
        let transport = StubTransport { request in
            if request.httpMethod == "GET" {
                #expect(request.url?.path == "/v1/shield/identity-key")
                return (200, ["key": identityKey])
            }
            return (200, Self.allow)
        }
        let client = makeClient(transport)
        client.identify(IdentityInput(userId: "42", email: " Jane@Example.com ", plan: "free"))
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)

        let context = try #require(transport.events.last?["customer_context"] as? [String: Any])
        #expect(context["email_domain"] as? String == "example.com")
        #expect(context["plan"] as? String == "free")
        #expect(context["email_hash"] as? String == Identity.sha256Hex("jane@example.com"))
        let body = try #require(transport.events.last.flatMap { try? JSONSerialization.data(withJSONObject: $0) }.flatMap { String(data: $0, encoding: .utf8) })
        #expect(!(body.contains("Jane@Example.com") || body.contains("jane@example.com")), Comment(rawValue: "no raw email leaves the device"))

        for (field, plain) in [("email_enc", "jane@example.com"), ("user_id_enc", "42")] {
            let formatted = try #require(context[field] as? String)
            #expect(formatted.hasPrefix("fk1.ik_0123456789abcdef."))
            let cipher = try #require(Data(base64Encoded: String(formatted.split(separator: ".")[2])))
            let decrypted = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, cipher as CFData, nil) as Data?
            #expect(decrypted.flatMap { String(data: $0, encoding: .utf8) } == plain)
        }
        #expect(transport.requests.filter { $0.httpMethod == "GET" }.count == 1, Comment(rawValue: "the key is fetched once and cached"))
    }

    @Test func testNoIdentityKeyMeansHashesOnly() async throws {
        let transport = StubTransport { request in request.httpMethod == "GET" ? (404, ["error": "no_identity_key"]) : (200, Self.allow) }
        let client = makeClient(transport)
        client.identify(IdentityInput(userId: "42"))
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        let context = try #require(transport.events.last?["customer_context"] as? [String: Any])
        #expect(context["user_id_hash"] != nil)
        #expect(context["user_id_enc"] == nil)
    }

    @Test func testIdentityKeyURLSitsNextToTheTrackEndpoint() {
        let client = makeClient(StubTransport { _ in (200, Self.allow) })
        #expect(client.identityKeyURL?.absoluteString == "https://shield.findip.net/v1/shield/identity-key?site_key=pub_test0000000000")
    }

    @Test func testASilentShieldAnswersUnknownAtTheDeadline() async throws {
        let transport = StubTransport { _ in
            try await Task.sleep(nanoseconds: 30_000_000_000)
            return (200, Self.allow)
        }
        let client = makeClient(transport, options: ShieldOptions(timeout: 0.3))
        let started = Date()
        let verdict = try await client.track("login_attempt", context: nil, screen: nil)
        #expect(Date().timeIntervalSince(started) < 5, Comment(rawValue: "answered at the deadline, not after the network"))
        #expect(verdict.transport == .dropped(.unreachable))
        #expect(verdict.risk.status == .unknown)
        #expect(verdict.risk.recommendation == .monitor)
        #expect(verdict.sessionId.hasPrefix("sess_"))
    }

    @Test func testTheFirstEventDoesNotWaitForSessionStart() async throws {
        let transport = StubTransport { request in
            let body = request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if (body?["event"] as? [String: Any])?["name"] as? String == "session_start" {
                try await Task.sleep(nanoseconds: 3_000_000_000)
            }
            return (200, Self.allow)
        }
        let client = makeClient(transport)
        let started = Date()
        let verdict = try await client.track("login_attempt", context: nil, screen: nil)
        #expect(verdict.transport == .delivered)
        #expect(Date().timeIntervalSince(started) < 2, Comment(rawValue: "answered without waiting for session_start"))
        await client.settle()
        #expect(transport.trackedNames.sorted() == ["login_attempt", "session_start"])
    }

    @Test func testASessionsFirstEventsShareOneIdentityKeyFetch() async throws {
        let (formatted, _) = try Self.makeIdentityKey()
        let transport = StubTransport { request in
            if request.httpMethod == "GET" {
                try await Task.sleep(nanoseconds: 100_000_000)
                return (200, ["key": formatted])
            }
            return (200, Self.allow)
        }
        let client = makeClient(transport)
        client.identify(IdentityInput(userId: "42", email: "jane@example.com", plan: nil))
        _ = try await client.trackSettled("login_attempt", context: nil, screen: nil)
        #expect(transport.requests.filter { $0.httpMethod == "GET" }.count == 1)
        #expect(transport.tracked.allSatisfy { ($0["customer_context"] as? [String: Any])?["email_enc"] != nil })
    }

    /// A fresh RSA-2048 key, its public half as "fk1.<id>.<base64 SPKI>" like the dashboard publishes it.
    static func makeIdentityKey() throws -> (String, SecKey) {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        let privateKey = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        let pkcs1 = try #require(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
        // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { rsaEncryption OID, NULL }, BIT STRING { 0x00, RSAPublicKey } }
        let algorithm: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
        let bitString = der(0x03, [0x00] + [UInt8](pkcs1))
        let spki = der(0x30, algorithm + bitString)
        return ("fk1.ik_0123456789abcdef.\(Data(spki).base64EncodedString())", privateKey)
    }

    private static func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let length = content.count
        if length < 0x80 { return [tag, UInt8(length)] + content }
        let bytes = withUnsafeBytes(of: UInt32(length).bigEndian, Array.init).drop { $0 == 0 }
        return [tag, 0x80 | UInt8(bytes.count)] + bytes + content
    }
}
