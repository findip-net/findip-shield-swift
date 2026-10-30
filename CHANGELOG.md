# Changelog

All notable changes to this package are documented here.

## 1.0.2 - 2026-10-30

### Fixed

- `sessionTimeout` now also counts time in the background: events sent in the
  background no longer keep a session open past the timeout. A shorter trip to
  the background keeps the session, so a user who leaves to read a code from
  their mail is still in the same login.
- Reading `FindIPShield.sessionId` after the timeout could return a different
  ID on every read.

## 1.0.1 - 2026-10-29

### Fixed

- The first event of a session no longer waits for its `session_start`: a
  fresh login made two round trips in a row in 1.0.0.
- That event and its `session_start` share one identity-key fetch.

### Added

- `ShieldOptions.timeout` (default 5 seconds): the longest `track` waits for
  Shield. After it, `track` returns an `unknown` verdict with `monitor` and
  `.dropped(.unreachable)`, and the request is cancelled; offline, 1.0.0
  could wait about 20 seconds.

## 1.0.0 - 2026-10-29

### Added

- `FindIPShield.configure(siteKey:options:)`, `track(_:context:screen:)`
  (async, plus a completion-handler form), `identify(userId:email:plan:salt:custom:)`,
  `setConsent(_:)`, `sessionId`, `reset()` and `resetVisitor()`, as in the
  FindIP Shield mobile SDK specification.
- Identity is hashed (SHA-256) and encrypted (RSA-OAEP, SHA-256) on the
  device; the raw email and user ID never leave it.
- Privacy manifest (`PrivacyInfo.xcprivacy`): no tracking, no tracking
  domains, no required-reason APIs.
- The shared contract fixtures of the specification run in the test suite.
