# Contributing

Issues and pull requests are welcome.

- The behaviour of this SDK is defined by the
  FindIP Shield mobile SDK specification, kept by FindIP with the Shield API.
  A change in behaviour starts as a change to the specification.
- `swift test` must pass, including the fixture tests in
  `Tests/FindIPShieldTests/Fixtures`. Those files are shared with the
  Android SDK and the Shield API; do not edit them here.
- Keep the package free of dependencies and of required-reason APIs.
- Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).
