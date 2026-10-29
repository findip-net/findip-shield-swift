import Foundation

/// The app the SDK runs in, as the bundle reports it.
struct AppInfo: Sendable, Equatable {
    var bundleId: String
    var version: String?
    var build: String?

    static func current(_ bundle: Bundle = .main) -> AppInfo {
        AppInfo(
            bundleId: bundle.bundleIdentifier ?? "",
            version: bundle.infoDictionary?["CFBundleShortVersionString"] as? String,
            build: bundle.infoDictionary?["CFBundleVersion"] as? String
        )
    }
}

/// Builds the JSON body of one event (spec §2, payloads.json).
struct PayloadBuilder {
    var siteKey: String
    var sdkName: String = FindIPShield.sdkName
    var sdkVersion: String = FindIPShield.version
    var integration: String = "ios"
    var privacyMode: PrivacyMode
    var collectDeviceSignals: Bool
    var app: AppInfo
    var device: DeviceInfo

    struct Event {
        var name: String
        var timestamp: Date?
        var screen: String?
        var sessionId: String
        var visitorId: String?
        var customerContext: [String: Any]
        var consentGranted: Bool
    }

    /// ISO 8601, UTC, milliseconds. A formatter per call: ISO8601DateFormatter is not Sendable.
    static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }

    func build(_ event: Event) -> [String: Any] {
        let strict = privacyMode == .strict
        var payload: [String: Any] = [
            "site_key": siteKey,
            "sdk": ["name": sdkName, "version": sdkVersion, "integration": integration],
        ]

        var app: [String: Any] = ["bundle_id": self.app.bundleId]
        if let version = self.app.version, !version.isEmpty { app["version"] = version }
        if let build = self.app.build, !build.isEmpty { app["build"] = build }
        payload["app"] = app

        var eventBlock: [String: Any] = ["name": event.name, "source": "manual"]
        if let timestamp = event.timestamp { eventBlock["timestamp"] = Self.timestamp(timestamp) }
        payload["event"] = eventBlock

        if let screen = event.screen.flatMap(Self.screenPath) { payload["page"] = ["path": screen] }

        var session: [String: Any] = ["session_id": event.sessionId, "storage": "app"]
        if !strict, let visitorId = event.visitorId {
            session["visitor_id"] = visitorId
            session["visitor_storage"] = "app"
        }
        payload["session"] = session

        var device: [String: Any] = ["platform": self.device.platform]
        if let os = self.device.osVersion { device["os_version"] = os }
        if !strict, let family = self.device.modelFamily { device["model_family"] = family }
        if let locale = self.device.locale { device["locale"] = locale }
        if let timezone = self.device.timezone { device["timezone"] = timezone }
        if !strict, let screen = self.device.screen {
            device["screen"] = ["width": screen.width, "height": screen.height, "scale": screen.scale]
        }
        if !strict, collectDeviceSignals, let signals = self.device.signals {
            device["signals"] = [
                "emulator": signals.emulator as Any? ?? NSNull(),
                "rooted": signals.rooted as Any? ?? NSNull(),
                "debugger": signals.debugger as Any? ?? NSNull(),
            ]
        }
        payload["device"] = device

        if !event.customerContext.isEmpty { payload["customer_context"] = event.customerContext }
        payload["privacy"] = ["mode": privacyMode.rawValue, "consent": ["granted": event.consentGranted, "source": "app"]]
        return payload
    }

    private static let screenName = try! NSRegularExpression(pattern: "^[a-z0-9_-]{1,64}$")

    /// "Login" → "/screen/login". Names Shield would not store are left out.
    static func screenPath(_ name: String) -> String? {
        let lower = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            .replacingOccurrences(of: " ", with: "_")
        guard screenName.firstMatch(in: lower, range: NSRange(lower.startIndex..., in: lower)) != nil else { return nil }
        return "/screen/\(lower)"
    }
}
