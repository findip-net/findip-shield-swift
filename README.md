# FindIP Shield for iOS

A verdict on each sensitive action in your app: signups, logins, password
resets, checkouts. [FindIP Shield](https://www.findip.net/shield) scores the
network behind the request (VPN, proxy, Tor, hosting, known-malicious) and
recommends `allow`, `monitor`, `challenge` or `block`. Your backend confirms
the verdict before it acts.

- No dependencies, no tracking, no advertising IDs, no fingerprinting.
- Emails and user IDs are hashed and encrypted on the device; only your
  Shield dashboard can open them.
- Free Preview: 10,000 events a day per app site.

## Install

Swift Package Manager, iOS 15 or later:

```swift
.package(url: "https://github.com/findip-net/findip-shield-swift", from: "1.0.3")
```

In Xcode: **File → Add Package Dependencies…** and paste the URL.

## Set up

1. In the [Shield dashboard](https://www.findip.net/shield), create a **mobile
   app** site and register your bundle identifier.
2. Configure once at launch with the site's public key:

```swift
import FindIPShield

@main
struct MyApp: App {
    init() { try? FindIPShield.configure(siteKey: "pub_xxxxxxxxx") }
    var body: some Scene { WindowGroup { ContentView() } }
}
```

3. Call Shield before each sensitive action, and send the session ID with the
   request to your backend:

```swift
let verdict = try await FindIPShield.track(ShieldEvents.loginAttempt, screen: "login")
var request = URLRequest(url: loginURL)
request.setValue(verdict.sessionId, forHTTPHeaderField: "X-Shield-Session")
```

4. Your backend verifies that session with the site's **secret** key before it
   allows, challenges or blocks
   ([server verification](https://www.findip.net/docs/shield/server-verification)):

```bash
curl -X POST https://shield.findip.net/v1/shield/sessions/verify \
  -H "Authorization: Bearer sec_xxxxxxxxx" \
  -d '{"session_id":"sess_xxx"}'
```

The key in the app is public, like any key in an app binary. It identifies the
app and proves nothing; only your server's answer counts.

## The verdict

| `verdict.risk.recommendation` | In the app | In your backend |
|---|---|---|
| `allow` | Proceed. | Proceed. |
| `monitor` | Proceed. | Proceed; log it if you keep a review queue. |
| `challenge` | Proceed to your backend. | Ask for your own step-up: a code, a re-login, an email link. |
| `block` | Show a neutral "could not complete". | Refuse after verifying the session. |

`track` never throws for network or server problems. Without an answer from
Shield it returns `risk.status == .unknown` with `monitor`, never `allow`, and
`verdict.transport` says why (`.dropped(.unreachable)`, `.dropped(.configuration)`, …).
It answers within `timeout` (5 seconds by default) whatever the network does.

## Identify the user

```swift
FindIPShield.identify(userId: user.id, email: user.email, plan: "free")
// on logout
FindIPShield.reset()
```

The SDK sends SHA-256 hashes, the email domain, and RSA-OAEP ciphertext made
with your site's public identity key. The raw values never leave the device.

## Options

```swift
try FindIPShield.configure(siteKey: "pub_xxxxxxxxx", options: ShieldOptions(
    privacyMode: .balanced,      // .strict sends no visitor ID, screen, signals or device family
    consentRequired: false,      // true: nothing is sent until FindIPShield.setConsent(true)
    sessionTimeout: 30 * 60,
    collectDeviceSignals: true,  // simulator / jailbreak / debugger heuristics
    debug: false,                // logs to the unified log, subsystem net.findip.shield
    timeout: 5                   // the longest track waits; then unknown / monitor
))
```

Context facts travel with an event: `track(ShieldEvents.checkoutStarted, context: ["items": 3, "coupon": true])`.
Up to 20 keys; keys like `password` or `card`, and values that look like an
email, a phone or a card number, never leave the device.

## What is sent

| Sent | Never sent |
|---|---|
| Bundle id, app version and build | Anything the user typed |
| iOS version | IDFA, `identifierForVendor`, any cross-app ID |
| Device family (iPhone, iPad), never the model | Contacts, location, photos |
| Locale, time zone, screen size | A device fingerprint |
| A session ID per session and a visitor ID kept in the Keychain | Plain emails or user IDs |
| The event name | |

The visitor ID lives in the Keychain on this device only, so it survives a
reinstall: reinstalling to get a fresh trial stays visible. Use
`FindIPShield.resetVisitor()` or `.strict` mode if you do not want that.

**App Privacy answers** for this SDK: Device ID (the visitor ID) and Product
Interaction (event names), not linked to the user, not used for tracking,
purpose App Functionality (fraud prevention). The package ships a privacy
manifest. If you call `identify`, also declare the identifiers you pass.

## Events

`ShieldEvents` lists the names Shield understands: `signupAttempt`,
`signupSuccess`, `loginAttempt`, `loginSuccess`, `loginFailed`,
`passwordResetAttempt`, `checkoutStarted`, `paymentAttempt`, `paymentFailed`,
`leadSubmitted` and more. Any other name is stored as `custom`. Sensitive
actions are retried once when the network fails.

## Requirements

iOS 15, tvOS 15, visionOS 1, macOS 12. Swift 5.9 or later; clean in Swift 6
language mode.

## Demo app

[`Examples/ShieldDemo`](Examples/ShieldDemo) is a SwiftUI login screen with a
small Node backend that verifies the session: the whole flow from `track` to
the backend's decision, in one runnable project.

## License

MIT. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
