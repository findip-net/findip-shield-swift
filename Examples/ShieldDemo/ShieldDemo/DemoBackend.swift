import Foundation

/// What the demo backend (server/server.mjs) decided after verifying the session.
struct BackendAnswer: Decodable, Sendable {
    struct ShieldPart: Decodable, Sendable {
        let recommendation: String?
    }

    /// allow, step_up or refuse; nil when the backend could not be reached.
    let decision: String?
    let message: String?
    let note: String?
    /// What Shield told the backend. Shown by the demo only; a real backend keeps it.
    let shield: ShieldPart?

    static func unreachable() -> BackendAnswer {
        BackendAnswer(decision: nil, message: nil, note: "Backend not reachable at \(DemoConfig.backendURL.absoluteString)", shield: nil)
    }
}

enum DemoBackend {
    /// POST /login with the Shield session in a header. The password never goes to Shield.
    static func login(email: String, shieldSessionId: String?) async -> BackendAnswer {
        var request = URLRequest(url: DemoConfig.backendURL.appendingPathComponent("login"), timeoutInterval: 5)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let shieldSessionId {
            request.setValue(shieldSessionId, forHTTPHeaderField: "X-Shield-Session")
        }
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["email": email])
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            return try JSONDecoder().decode(BackendAnswer.self, from: data)
        } catch {
            return .unreachable()
        }
    }
}
