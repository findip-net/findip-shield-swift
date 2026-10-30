import FindIPShield
import SwiftUI

@main
struct ShieldDemoApp: App {
    init() {
        // Once, at launch. Nothing is sent until the first track.
        Shield.configure()
    }

    var body: some Scene {
        WindowGroup { LoginView() }
    }
}

/// Whether Shield is on in this run: off without a site key, and the login still works.
enum Shield {
    private(set) static var configured = false

    static func configure() {
        guard !DemoConfig.siteKey.isEmpty else { return }
        do {
            try FindIPShield.configure(siteKey: DemoConfig.siteKey, options: ShieldOptions(endpoint: DemoConfig.endpoint, debug: true))
            configured = true
        } catch {
            print("Shield is off: \(error)")
        }
    }
}
