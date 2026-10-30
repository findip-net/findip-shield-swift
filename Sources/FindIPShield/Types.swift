import Foundation

/// How much the SDK sends, as on the web SDK. `strict` sends no visitor ID and
/// no screen size, device signals or device family.
public enum PrivacyMode: String, Sendable, CaseIterable {
    case strict
    case balanced
    case advanced
}

/// Options for `FindIPShield.configure(siteKey:options:)`. Every option has the
/// default the specification gives, so `ShieldOptions()` is a complete setup.
public struct ShieldOptions: Sendable {
    public var privacyMode: PrivacyMode
    /// When true, nothing is sent until `FindIPShield.setConsent(true)`.
    public var consentRequired: Bool
    /// The track endpoint. The identity-key endpoint is derived from it.
    public var endpoint: URL
    /// A session ends after this long without an event, or after this long in the
    /// background. A shorter trip to the background keeps the session.
    public var sessionTimeout: TimeInterval
    /// Sends the emulator / jailbreak / debugger heuristics. Always off in `strict`.
    public var collectDeviceSignals: Bool
    /// Logs SDK activity to the unified log (subsystem `net.findip.shield`).
    public var debug: Bool
    /// The longest `track` waits for Shield; after it, an `unknown` verdict (`monitor`).
    public var timeout: TimeInterval

    public static let defaultEndpoint = URL(string: "https://shield.findip.net/v1/shield/track")!

    public init(
        privacyMode: PrivacyMode = .balanced,
        consentRequired: Bool = false,
        endpoint: URL = ShieldOptions.defaultEndpoint,
        sessionTimeout: TimeInterval = 30 * 60,
        collectDeviceSignals: Bool = true,
        debug: Bool = false,
        timeout: TimeInterval = 5
    ) {
        self.privacyMode = privacyMode
        self.consentRequired = consentRequired
        self.endpoint = endpoint
        self.sessionTimeout = sessionTimeout
        self.collectDeviceSignals = collectDeviceSignals
        self.debug = debug
        self.timeout = timeout
    }
}

/// A value in a `custom` context object: a string, a number or a boolean.
/// Literals work directly: `["method": "password", "seats": 3, "trial": true]`.
public enum ContextValue: Sendable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
}

extension ContextValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByBooleanLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

/// What Shield recommends for the action. Advice for the app; the backend
/// decides after verifying the session.
public enum Recommendation: String, Sendable {
    case allow
    case monitor
    case challenge
    case block
}

/// `available`: Shield scored the request. `unknown`: it could not, and the
/// verdict must never be read as safe.
public enum RiskStatus: String, Sendable {
    case available
    case unknown
}

/// Why an event did not reach Shield, or was refused by it.
public enum DropReason: String, Sendable {
    /// Consent is required and was not given.
    case consent
    /// Shield could not read the request.
    case invalid
    /// The site key, the site or the app registration is wrong.
    case configuration
    /// The request was too large even without the custom context.
    case tooLarge = "too_large"
    /// Rate limit, daily quota, capacity, or too many requests in flight.
    case limited
    /// No network, a timeout or a server error.
    case unreachable
}

/// Whether the event was delivered.
public enum Transport: Sendable, Equatable {
    case delivered
    case dropped(DropReason)
}

/// Shield's verdict for one event.
public struct Verdict: Sendable {
    public struct Risk: Sendable {
        public let status: RiskStatus
        /// 0 to 100; nil when `status` is `unknown`.
        public let score: Int?
        /// `low`, `medium`, `high`, `critical`, or `unknown`.
        public let level: String
        public let recommendation: Recommendation
        public let reasons: [String]
        /// Set when one of the site's custom rules decided.
        public let ruleName: String?
    }

    /// What Shield knows about the network the request came from. Nil when the
    /// risk is unknown: flags would otherwise claim knowledge.
    public struct Network: Sendable {
        public let country: String
        public let asn: Int
        public let asnName: String
        public let vpn: Bool
        public let proxy: Bool
        public let tor: Bool
        public let relay: Bool
        public let hosting: Bool
        public let malicious: Bool
    }

    public let requestId: String?
    /// Send this to your backend with the protected request.
    public let sessionId: String
    public let risk: Risk
    public let network: Network?
    public let transport: Transport

    /// The verdict returned when Shield gave no answer: unknown, never safe.
    static func unknown(sessionId: String, transport: Transport, reason: String) -> Verdict {
        Verdict(
            requestId: nil,
            sessionId: sessionId,
            risk: Risk(status: .unknown, score: nil, level: "unknown", recommendation: .monitor, reasons: [reason], ruleName: nil),
            network: nil,
            transport: transport
        )
    }
}

/// Programmer errors. Network and server problems never throw; they return an
/// unknown verdict instead.
public enum ShieldError: Error, Equatable, Sendable {
    /// `configure(siteKey:)` was not called first.
    case notConfigured
    /// The site key does not start with `pub_`.
    case invalidSiteKey
    /// The event name is empty.
    case emptyEventName
}

/// The event names Shield knows. Any other name is sent as `custom`.
public enum ShieldEvents {
    public static let pageView = "page_view"
    public static let sessionStart = "session_start"
    public static let signupView = "signup_view"
    public static let signupAttempt = "signup_attempt"
    public static let signupSuccess = "signup_success"
    public static let loginView = "login_view"
    public static let loginAttempt = "login_attempt"
    public static let loginSuccess = "login_success"
    public static let loginFailed = "login_failed"
    public static let passwordResetView = "password_reset_view"
    public static let passwordResetAttempt = "password_reset_attempt"
    public static let checkoutView = "checkout_view"
    public static let checkoutStarted = "checkout_started"
    public static let paymentAttempt = "payment_attempt"
    public static let paymentFailed = "payment_failed"
    public static let leadSubmitted = "lead_submitted"
    public static let apiRequest = "api_request"
    public static let custom = "custom"
}
