# Changelog

All notable changes to this package are documented here.

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
