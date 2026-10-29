import Foundation

/// One configured SDK instance: its state and the send logic of spec §3 and §6.
/// State sits behind one lock; network work runs outside it. Every `track`
/// answers within `options.timeout`.
final class ShieldClient: @unchecked Sendable {
    static let maxInFlight = 50
    static let maxPayloadBytes = 32_768
    static let requestTimeout: TimeInterval = 5
    static let identityKeyTimeout: TimeInterval = 3
    static let identityKeyTTL: TimeInterval = 300
    static let cooldown: TimeInterval = 60

    let siteKey: String
    let options: ShieldOptions
    private let store: IdentifierStore
    private let transport: HTTPTransport
    private let appInfo: AppInfo
    private let deviceProvider: @Sendable () async -> DeviceInfo
    private let now: @Sendable () -> Date
    private let retryDelay: @Sendable () async -> Void
    private let log: Log

    private let lock = NSLock()
    private var consentGranted: Bool
    private var identity: IdentityInput?
    private var sessionId: String?
    private var lastEventAt: Date?
    private var visitorId: String?
    private var device: DeviceInfo?
    private var cooldownUntil: Date?
    private var inFlight = 0
    private var cachedKey: (key: IdentityKey?, fetchedAt: Date)?
    private var reportedConfigurationProblem = false
    private var lastSessionStart: Task<Void, Never>?
    private var keyFetch: Task<IdentityKey?, Never>?

    init(
        siteKey: String,
        options: ShieldOptions,
        store: IdentifierStore = KeychainStore(),
        transport: HTTPTransport = URLSessionTransport(),
        appInfo: AppInfo = .current(),
        deviceProvider: @escaping @Sendable () async -> DeviceInfo = { await DeviceInfo.current() },
        now: @escaping @Sendable () -> Date = { Date() },
        retryDelay: @escaping @Sendable () async -> Void = {
            // 2 seconds ±20 % (spec §6).
            try? await Task.sleep(nanoseconds: UInt64(Double.random(in: 1.6...2.4) * 1_000_000_000))
        }
    ) {
        self.siteKey = siteKey
        self.options = options
        self.store = store
        self.transport = transport
        self.appInfo = appInfo
        self.deviceProvider = deviceProvider
        self.now = now
        self.retryDelay = retryDelay
        self.log = Log(enabled: options.debug)
        self.consentGranted = !options.consentRequired
    }

    // MARK: State

    func setConsent(_ granted: Bool) { lock.sync { consentGranted = granted } }

    func identify(_ input: IdentityInput) { lock.sync { identity = input } }

    func reset() { lock.sync { identity = nil } }

    func resetVisitor() {
        lock.sync {
            store.delete(account: siteKey)
            visitorId = nil
            sessionId = nil
            lastEventAt = nil
        }
    }

    /// The current session ID, starting a session when none is open.
    var currentSessionId: String { lock.sync { touchSession(at: now(), recordActivity: false).id } }

    /// Starts a new session when none is open or the last event is older than the timeout.
    private func touchSession(at date: Date, recordActivity: Bool) -> (id: String, isNew: Bool) {
        var isNew = false
        if sessionId == nil || lastEventAt.map({ date.timeIntervalSince($0) > options.sessionTimeout }) ?? false {
            sessionId = Identifiers.make(prefix: "sess_")
            isNew = true
            lastEventAt = recordActivity ? date : (lastEventAt == nil ? date : lastEventAt)
        }
        if recordActivity || lastEventAt == nil { lastEventAt = date }
        return (sessionId!, isNew)
    }

    private func currentVisitorId() -> String? {
        if options.privacyMode == .strict { return nil }
        if let visitorId { return visitorId }
        if let stored = store.load(account: siteKey) {
            visitorId = stored
            return stored
        }
        let made = Identifiers.make(prefix: "vis_")
        store.save(made, account: siteKey)
        visitorId = made
        return made
    }

    // MARK: Track

    func track(_ rawName: String, context: [String: ContextValue]?, screen: String?) async throws -> Verdict {
        let trimmed = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { throw ShieldError.emptyEventName }
        let name = EventName.normalize(trimmed)
        return await Self.withDeadline(
            options.timeout,
            operation: { await self.trackNow(name, context: context, screen: screen) },
            fallback: { .unknown(sessionId: self.currentSessionId, transport: .dropped(.unreachable), reason: "shield_unreachable") }
        )
    }

    /// The operation's answer, or the fallback's once `seconds` pass; the operation is then cancelled.
    static func withDeadline(
        _ seconds: TimeInterval,
        operation: @escaping @Sendable () async -> Verdict,
        fallback: @escaping @Sendable () -> Verdict
    ) async -> Verdict {
        await withTaskGroup(of: Verdict?.self) { group in
            group.addTask { await operation() }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first ?? fallback()
        }
    }

    /// Waits for the last `session_start` sent in the background. For tests.
    func settle() async {
        await lock.sync { lastSessionStart }?.value
    }

    private func trackNow(_ name: String, context: [String: ContextValue]?, screen: String?) async -> Verdict {

        let (granted, session, visitor, identity) = lock.sync {
            (consentGranted, touchSession(at: now(), recordActivity: true), currentVisitorId(), self.identity)
        }
        guard granted else {
            log.debug("consent not given: \(name) not sent")
            return .unknown(sessionId: session.id, transport: .dropped(.consent), reason: "consent_required")
        }

        if session.isNew && name != "session_start" {
            // Not awaited: the event does not wait for a second round trip, and
            // ingest stores both in either order.
            let start = Task {
                _ = await self.send(name: "session_start", context: nil, screen: nil, sessionId: session.id, visitorId: visitor, identity: identity)
            }
            lock.sync { lastSessionStart = start }
        }
        return await send(name: name, context: context, screen: screen, sessionId: session.id, visitorId: visitor, identity: identity)
    }

    private func send(
        name: String, context: [String: ContextValue]?, screen: String?,
        sessionId: String, visitorId: String?, identity: IdentityInput?
    ) async -> Verdict {
        let sensitive = EventName.sensitive.contains(name)
        let admitted: DropReason? = lock.sync {
            if let until = cooldownUntil, now() < until { return .limited }
            if inFlight >= Self.maxInFlight && !sensitive { return .limited }
            inFlight += 1
            return nil
        }
        if let reason = admitted {
            return .unknown(sessionId: sessionId, transport: .dropped(reason), reason: "shield_rate_limited")
        }
        defer { lock.sync { inFlight -= 1 } }

        let device = await cachedDevice()
        let customerContext = await self.customerContext(identity: identity, context: context)
        let builder = PayloadBuilder(
            siteKey: siteKey, privacyMode: options.privacyMode,
            collectDeviceSignals: options.collectDeviceSignals, app: appInfo, device: device
        )
        var payload = builder.build(.init(
            name: name, timestamp: now(), screen: screen, sessionId: sessionId, visitorId: visitorId,
            customerContext: customerContext, consentGranted: true
        ))

        var retriedNetwork = false
        var retriedSize = false
        while true {
            guard let body = try? JSONSerialization.data(withJSONObject: payload) else {
                return .unknown(sessionId: sessionId, transport: .dropped(.invalid), reason: "invalid_payload")
            }
            if body.count > Self.maxPayloadBytes && !retriedSize, var context = payload["customer_context"] as? [String: Any] {
                retriedSize = true
                context.removeValue(forKey: "custom")
                payload["customer_context"] = context
                continue
            }

            var request = URLRequest(url: options.endpoint, timeoutInterval: Self.requestTimeout)
            request.httpMethod = "POST"
            request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
            request.httpBody = body

            let response: (status: Int, body: Data)
            do {
                response = try await transport.send(request)
            } catch {
                if sensitive && !retriedNetwork {
                    retriedNetwork = true
                    await retryDelay()
                    continue
                }
                log.debug("\(name) not delivered: \(error.localizedDescription)")
                return .unknown(sessionId: sessionId, transport: .dropped(.unreachable), reason: "shield_unreachable")
            }

            let errorCode = Self.errorCode(response.body)
            switch response.status {
            case 200:
                return Self.verdict(from: response.body, sessionId: sessionId)
                    ?? .unknown(sessionId: sessionId, transport: .dropped(.invalid), reason: "invalid_response")
            case 413 where !retriedSize:
                retriedSize = true
                if var context = payload["customer_context"] as? [String: Any] {
                    context.removeValue(forKey: "custom")
                    payload["customer_context"] = context
                }
                continue
            case 413:
                return .unknown(sessionId: sessionId, transport: .dropped(.tooLarge), reason: "payload_too_large")
            case 429:
                lock.sync { cooldownUntil = now().addingTimeInterval(Self.cooldown) }
                return .unknown(sessionId: sessionId, transport: .dropped(.limited), reason: errorCode ?? "rate_limited")
            case 400:
                log.debug("\(name) refused: \(errorCode ?? "bad request")")
                return .unknown(sessionId: sessionId, transport: .dropped(.invalid), reason: errorCode ?? "invalid_json")
            case 401, 403:
                reportConfigurationProblem(errorCode)
                return .unknown(sessionId: sessionId, transport: .dropped(.configuration), reason: errorCode ?? "forbidden")
            default:
                if sensitive && !retriedNetwork {
                    retriedNetwork = true
                    await retryDelay()
                    continue
                }
                return .unknown(sessionId: sessionId, transport: .dropped(.unreachable), reason: "shield_unreachable")
            }
        }
    }

    private func reportConfigurationProblem(_ code: String?) {
        let first = lock.sync { () -> Bool in
            defer { reportedConfigurationProblem = true }
            return !reportedConfigurationProblem
        }
        guard first else { return }
        let hint: String
        switch code {
        case "app_mismatch":
            hint = "Shield has no app registered as \(appInfo.bundleId). Add it under Settings → Apps & keys."
        case "integration_not_allowed":
            hint = "This site key belongs to a website site. Create a mobile app site for the app."
        default:
            hint = "Check the site key and that the site is enabled."
        }
        log.problem("FindIP Shield refused events (\(code ?? "forbidden")). \(hint)")
    }

    private func cachedDevice() async -> DeviceInfo {
        if let device = lock.sync({ self.device }) { return device }
        let fetched = await deviceProvider()
        lock.sync { device = fetched }
        return fetched
    }

    // MARK: Identity

    private func customerContext(identity: IdentityInput?, context: [String: ContextValue]?) async -> [String: Any] {
        var result: [String: Any] = [:]
        var custom: [String: ContextValue] = [:]
        if let identity {
            result = Identity.context(for: identity)
            custom = identity.custom ?? [:]
            let values = Identity.encryptable(identity)
            if !values.isEmpty, let key = await identityKey() {
                for (field, value) in values {
                    if let cipher = key.encrypt(value) { result[field] = cipher }
                }
            }
        }
        if let context { custom.merge(context) { _, new in new } }
        let sanitized = ContextSanitizer.sanitize(custom)
        if !sanitized.isEmpty { result["custom"] = ContextSanitizer.json(sanitized) }
        return result
    }

    var identityKeyURL: URL? {
        var components = URLComponents(url: options.endpoint, resolvingAgainstBaseURL: false)
        guard let path = components?.path, path.hasSuffix("/track") else { return nil }
        components?.path = String(path.dropLast("/track".count)) + "/identity-key"
        components?.queryItems = [URLQueryItem(name: "site_key", value: siteKey)]
        return components?.url
    }

    /// The site's identity key, cached 5 minutes; nil (hash only) when the site has none.
    /// A session's first event and its `session_start` share one fetch.
    private func identityKey() async -> IdentityKey? {
        let fetch = lock.sync { () -> Task<IdentityKey?, Never>? in
            if let cached = cachedKey, now().timeIntervalSince(cached.fetchedAt) < Self.identityKeyTTL { return nil }
            if let keyFetch { return keyFetch }
            let started = Task { await self.fetchIdentityKey() }
            keyFetch = started
            return started
        }
        guard let fetch else { return lock.sync { cachedKey?.key } }
        return await fetch.value
    }

    private func fetchIdentityKey() async -> IdentityKey? {
        defer { lock.sync { keyFetch = nil } }
        guard let url = identityKeyURL else { return nil }
        var request = URLRequest(url: url, timeoutInterval: Self.identityKeyTimeout)
        request.httpMethod = "GET"
        var key: IdentityKey?
        if let response = try? await transport.send(request), response.status == 200,
           let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
           let formatted = object["key"] as? String {
            key = IdentityKey(formatted)
        }
        let fetchedAt = now()
        lock.sync { cachedKey = (key, fetchedAt) }
        return key
    }

    // MARK: Responses

    static func errorCode(_ body: Data) -> String? {
        (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["error"] as? String
    }

    static func verdict(from body: Data, sessionId fallback: String) -> Verdict? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let risk = object["risk"] as? [String: Any] else { return nil }
        let status = RiskStatus(rawValue: risk["status"] as? String ?? "") ?? .unknown
        // Unknown never reads as allow, whatever the body says.
        var recommendation = Recommendation(rawValue: risk["recommendation"] as? String ?? "") ?? .monitor
        if status == .unknown && recommendation == .allow { recommendation = .monitor }
        let rule = (risk["rule"] as? [String: Any])?["name"] as? String
        var network: Verdict.Network?
        if status == .available, let ip = object["ip"] as? [String: Any] {
            network = Verdict.Network(
                country: ip["country"] as? String ?? "",
                asn: ip["asn"] as? Int ?? 0,
                asnName: ip["asn_name"] as? String ?? "",
                vpn: ip["is_vpn"] as? Bool ?? false,
                proxy: ip["is_proxy"] as? Bool ?? false,
                tor: ip["is_tor"] as? Bool ?? false,
                relay: ip["is_relay"] as? Bool ?? false,
                hosting: ip["is_hosting"] as? Bool ?? false,
                malicious: ip["is_malicious"] as? Bool ?? false
            )
        }
        return Verdict(
            requestId: object["request_id"] as? String,
            sessionId: object["session_id"] as? String ?? fallback,
            risk: Verdict.Risk(
                status: status,
                score: status == .available ? risk["score"] as? Int : nil,
                level: risk["level"] as? String ?? "unknown",
                recommendation: recommendation,
                reasons: risk["reasons"] as? [String] ?? [],
                ruleName: rule
            ),
            network: network,
            transport: .delivered
        )
    }
}
