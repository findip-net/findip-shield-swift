import FindIPShield
import SwiftUI

/// A fake login that shows the whole flow: identify (optional), track the
/// attempt, send the session to the backend, and let the backend decide.
@MainActor
final class LoginModel: ObservableObject {
    @Published var email = ""
    @Published var password = ""
    @Published var identifyUser = true
    @Published private(set) var busy = false
    @Published private(set) var verdict: Verdict?
    @Published private(set) var backend: BackendAnswer?
    @Published private(set) var signedIn = false

    func logIn() async {
        busy = true
        verdict = nil
        backend = nil
        let email = email.trimmingCharacters(in: .whitespaces)
        if Shield.configured {
            // Only hashes and ciphertext of the email leave the device.
            if identifyUser && !email.isEmpty {
                FindIPShield.identify(email: email, plan: "demo")
            }
            // Never throws for network or server problems: no answer is "unknown", never "allow".
            verdict = try? await FindIPShield.track(ShieldEvents.loginAttempt, context: ["method": "password"], screen: "login")
        }
        let answer = await DemoBackend.login(email: email, shieldSessionId: verdict?.sessionId ?? FindIPShield.sessionId)
        backend = answer
        signedIn = answer.decision == "allow"
        if signedIn && Shield.configured {
            _ = try? await FindIPShield.track(ShieldEvents.loginSuccess, screen: "login")
        }
        busy = false
    }

    func logOut() {
        // On logout: forget the identity, keep the session and visitor.
        FindIPShield.reset()
        signedIn = false
        password = ""
    }
}

struct LoginView: View {
    @StateObject private var model = LoginModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Shield demo").font(.title2.weight(.semibold))
                if !Shield.configured {
                    Note(text: "Shield is off. Set the site key in DemoConfig.swift or as SHIELD_SITE_KEY in the scheme. The login below still works without it.")
                }

                if model.signedIn {
                    Text("Signed in as \(model.email.isEmpty ? "demo user" : model.email).").font(.headline)
                    Button("Log out") { model.logOut() }.buttonStyle(.bordered)
                } else {
                    form
                }

                // What the user sees: neutral on a refusal, never the reason.
                if let answer = model.backend {
                    switch answer.decision {
                    case "refuse": Note(text: answer.message ?? "Could not complete the login. Try again later.")
                    case "step_up": Note(text: answer.message ?? "We need to confirm it is you.")
                    case nil: Note(text: answer.note ?? "Backend not reachable.")
                    default: EmptyView()
                    }
                }

                if let verdict = model.verdict { VerdictPanel(verdict: verdict) }
                if let answer = model.backend { BackendPanel(answer: answer) }
            }
            .padding(20)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("Email", text: $model.email)
                .textFieldStyle(.roundedBorder)
                .textContentType(.username)
                #if os(iOS)
                .keyboardType(.emailAddress)
                .textInputAutocapitalization(.never)
                #endif
                .disableAutocorrection(true)
            SecureField("Password (never sent to Shield)", text: $model.password)
                .textFieldStyle(.roundedBorder)
                .textContentType(.password)
            Toggle("Identify the user to Shield", isOn: $model.identifyUser)
            Button {
                Task { await model.logIn() }
            } label: {
                Text(model.busy ? "Checking…" : "Log in").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.busy)
        }
    }
}

/// The verdict as the app received it: advice for the app, not the decision.
struct VerdictPanel: View {
    let verdict: Verdict

    var body: some View {
        Panel(title: "Shield, in the app") {
            Fact(label: "Recommendation", value: verdict.risk.recommendation.rawValue + advice)
            Fact(label: "Risk", value: verdict.risk.score.map { "\($0) / 100, \(verdict.risk.level)" } ?? "unknown (never read as safe)")
            if !verdict.risk.reasons.isEmpty {
                Fact(label: "Reasons", value: verdict.risk.reasons.joined(separator: ", "))
            }
            if let rule = verdict.risk.ruleName {
                Fact(label: "Decided by rule", value: rule)
            }
            if let network = verdict.network {
                Fact(label: "Network", value: "\(network.country) · AS\(network.asn) \(network.asnName)")
            }
            Fact(label: "Delivery", value: delivery)
            Fact(label: "Session", value: verdict.sessionId, mono: true)
        }
    }

    private var advice: String {
        switch verdict.risk.recommendation {
        case .allow, .monitor: return " (proceed)"
        case .challenge: return " (your backend decides)"
        case .block: return " (show a neutral message)"
        }
    }

    private var delivery: String {
        switch verdict.transport {
        case .delivered: return "delivered"
        case .dropped(let reason): return "dropped: \(reason.rawValue)"
        }
    }
}

struct BackendPanel: View {
    let answer: BackendAnswer

    var body: some View {
        Panel(title: "Your backend") {
            Fact(label: "Decision", value: answer.decision ?? "no answer")
            if let recommendation = answer.shield?.recommendation {
                Fact(label: "Shield told it", value: recommendation)
            }
            if let note = answer.note {
                Fact(label: "Note", value: note)
            }
        }
    }
}

private struct Panel<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct Fact: View {
    let label: String
    let value: String
    var mono = false

    var body: some View {
        (Text("\(label): ").fontWeight(.medium) + Text(value).font(mono ? .system(.body, design: .monospaced) : .body))
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct Note: View {
    let text: String

    var body: some View {
        Text(text)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
    }
}
