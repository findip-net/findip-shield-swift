import Foundation
import Testing
@testable import FindIPShield

/// The shared contract (findip-sdk docs/shield/mobile-sdk-fixtures, copied
/// into Fixtures/). The same files run against ingest and the web SDK there.
@Suite struct FixtureTests {
    private func fixture(_ name: String) throws -> [String: Any] {
        let url = try #require(Bundle.module.resourceURL?.appendingPathComponent("Fixtures/\(name).json"))
        return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func cases(_ name: String) throws -> [[String: Any]] {
        try #require(fixture(name)["cases"] as? [[String: Any]])
    }

    /// JSON values from a fixture as ContextValue (JSON booleans are NSNumbers too).
    private func contextValues(_ object: [String: Any]) -> [String: ContextValue] {
        var result: [String: ContextValue] = [:]
        for (key, value) in object {
            if let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() {
                result[key] = .bool(number.boolValue)
            } else if let number = value as? NSNumber {
                result[key] = number.doubleValue == number.doubleValue.rounded() ? .int(number.intValue) : .double(number.doubleValue)
            } else if let string = value as? String {
                result[key] = .string(string)
            }
            // Nested objects and arrays have no ContextValue form: the API cannot even be called with them.
        }
        return result
    }

    @Test func testEventNames() throws {
        for c in try cases("events") {
            let input = try #require(c["input"] as? String)
            #expect(EventName.normalize(input) == c["expected"] as? String, Comment(rawValue: "event name \(input)"))
        }
    }

    @Test func testContextFilter() throws {
        for c in try cases("context") {
            let input = contextValues(try #require(c["input"] as? [String: Any]))
            let expected = contextValues(try #require(c["expected"] as? [String: Any]))
            #expect(ContextSanitizer.sanitize(input) == expected, Comment(rawValue: c["name"] as? String ?? ""))
        }
    }

    @Test func testIdentityHashes() throws {
        for c in try cases("identity") {
            let input = try #require(c["input"] as? [String: Any])
            let identity = IdentityInput(
                userId: input["userId"].map { "\($0)" },
                email: input["email"] as? String,
                plan: input["plan"] as? String,
                salt: input["salt"] as? String
            )
            let produced = Identity.context(for: identity) as NSDictionary
            #expect(produced == (c["expected"] as? NSDictionary) ?? [:], Comment(rawValue: c["name"] as? String ?? ""))
        }
    }

    /// The cases an SDK builds itself: the same inputs must give the same body.
    @Test func testPayloadsTheSDKBuilds() throws {
        let built = try cases("payloads").filter {
            ($0["sdk_builds"] as? Bool) == true
                && (($0["request"] as? [String: Any])?["sdk"] as? [String: Any])?["integration"] as? String == "ios"
        }
        #expect(!(built.isEmpty), Comment(rawValue: "the fixture has iOS cases to build"))
        for c in built {
            let request = try #require(c["request"] as? [String: Any])
            let sdk = try #require(request["sdk"] as? [String: Any])
            let app = try #require(request["app"] as? [String: Any])
            let session = try #require(request["session"] as? [String: Any])
            let device = try #require(request["device"] as? [String: Any])
            let privacy = try #require(request["privacy"] as? [String: Any])
            let screen = device["screen"] as? [String: Any]
            let signals = device["signals"] as? [String: Any]

            let builder = PayloadBuilder(
                siteKey: try #require(request["site_key"] as? String),
                sdkName: try #require(sdk["name"] as? String),
                sdkVersion: try #require(sdk["version"] as? String),
                integration: "ios",
                privacyMode: try #require(PrivacyMode(rawValue: privacy["mode"] as? String ?? "")),
                collectDeviceSignals: signals != nil,
                app: AppInfo(bundleId: try #require(app["bundle_id"] as? String), version: app["version"] as? String, build: app["build"] as? String),
                device: DeviceInfo(
                    platform: try #require(device["platform"] as? String),
                    osVersion: device["os_version"] as? String,
                    modelFamily: device["model_family"] as? String,
                    locale: device["locale"] as? String,
                    timezone: device["timezone"] as? String,
                    screen: screen.map { .init(width: $0["width"] as! Int, height: $0["height"] as! Int, scale: ($0["scale"] as! NSNumber).doubleValue) },
                    signals: signals.map { .init(emulator: $0["emulator"] as? Bool, rooted: $0["rooted"] as? Bool, debugger: $0["debugger"] as? Bool) }
                )
            )
            let page = request["page"] as? [String: Any]
            let screenName = (page?["path"] as? String).map { String($0.dropFirst("/screen/".count)) }
            let body = builder.build(.init(
                name: try #require((request["event"] as? [String: Any])?["name"] as? String),
                timestamp: nil,
                screen: screenName,
                sessionId: try #require(session["session_id"] as? String),
                visitorId: session["visitor_id"] as? String,
                customerContext: request["customer_context"] as? [String: Any] ?? [:],
                consentGranted: true
            ))
            #expect(body as NSDictionary == request as NSDictionary, Comment(rawValue: c["name"] as? String ?? ""))
        }
    }
}
