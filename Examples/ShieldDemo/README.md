# Shield demo for iOS

A fake login screen that shows the whole Shield flow in a SwiftUI app:

1. Shield is configured once, at launch, in `ShieldDemoApp`.
2. On **Log in**, the app optionally identifies the user (only hashes and
   ciphertext leave the device), then tracks `login_attempt`.
3. The app sends the Shield session ID to its backend in an `X-Shield-Session`
   header. The password never goes to Shield.
4. The backend ([`server/server.mjs`](server/server.mjs)) verifies the session
   with the site's secret key and decides: allow, ask for a step-up, or refuse
   with a neutral message.

The screen shows both sides: the verdict the app received, and what the
backend decided.

## Run it

You need Xcode 16 or later and Node 18 or later.

1. In the [Shield dashboard](https://www.findip.net/shield), create a **mobile
   app** site with the iOS bundle id `net.findip.shield.demo`.
2. Start the backend with the site's secret key:

   ```bash
   SHIELD_SECRET_KEY=sec_xxxxxxxxx node Examples/ShieldDemo/server/server.mjs
   ```

3. Open `Examples/ShieldDemo/ShieldDemo.xcodeproj`. Paste the site's public
   key into `DemoConfig.swift`, or tick `SHIELD_SITE_KEY` in **Product →
   Scheme → Edit Scheme → Run → Arguments** and set it there.
4. Run on an iPhone Simulator.

The Simulator reaches the backend on your computer at `http://localhost:8787`.
On a real device, set `SHIELD_DEMO_BACKEND` to `http://<your computer>.local:8787`;
the app allows plain HTTP only to local network hosts. To sign for a device,
choose your team under **Signing & Capabilities**, and register the bundle id
you sign with on the Shield site.

Without a site key the app still runs: Shield stays off and the screen says
so, so you can read the code path first.

## Try a verdict

Custom rules in the dashboard change the verdict at once. For example, add a
rule **App version or platform → iOS app, version below 2.0 → Block**: this
demo is version 1.0.0, so the next login is refused with a neutral message,
and the panel shows the rule's name.

## In your own app

The demo builds against this repository's source (a local package at `../..`).
Your app adds the published package:

```swift
.package(url: "https://github.com/findip-net/findip-shield-swift", from: "1.0.2")
```

## Tests

`ShieldDemoUITests` runs the whole flow on a Simulator against a stand-in for
Shield (`ci/fake-shield.mjs`). CI runs it on every pull request.

## Changing the project

`ShieldDemo.xcodeproj` is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen) and committed, so you can
open the demo without it. After editing `project.yml`, run `xcodegen` in this
folder.
