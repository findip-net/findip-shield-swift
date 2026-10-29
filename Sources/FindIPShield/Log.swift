import os

/// Debug logging to the unified log. Never logs identity values, a full site
/// key or a response body.
struct Log: Sendable {
    let enabled: Bool
    private static let logger = Logger(subsystem: "net.findip.shield", category: "sdk")

    func debug(_ message: @autoclosure () -> String) {
        guard enabled else { return }
        let text = message()
        Self.logger.debug("\(text, privacy: .public)")
    }

    /// Configuration problems are logged once whatever `debug` says: they mean every event is lost.
    func problem(_ message: String) {
        Self.logger.error("\(message, privacy: .public)")
    }
}
