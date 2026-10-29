import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// The device facts an event carries (spec §2). Nothing here identifies the
/// device: a family instead of the model, no hardware or advertising IDs.
struct DeviceInfo: Sendable, Equatable {
    var platform: String
    var osVersion: String?
    var modelFamily: String?
    var locale: String?
    var timezone: String?
    var screen: Screen?
    var signals: Signals?

    struct Screen: Sendable, Equatable {
        var width: Int
        var height: Int
        var scale: Double
    }

    struct Signals: Sendable, Equatable {
        var emulator: Bool?
        var rooted: Bool?
        var debugger: Bool?
    }

    /// The facts of the device the app runs on. Screen facts need the main actor.
    static func current() async -> DeviceInfo {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        var os = "\(version.majorVersion).\(version.minorVersion)"
        if version.patchVersion > 0 { os += ".\(version.patchVersion)" }
        return DeviceInfo(
            platform: "ios",
            osVersion: os,
            modelFamily: modelFamily(),
            locale: bcp47(Locale.current.identifier),
            timezone: TimeZone.current.identifier,
            screen: await screen(),
            signals: Signals(emulator: isSimulator, rooted: jailbroken(), debugger: debuggerAttached())
        )
    }

    /// "en_GB" or "en_GB@calendar=…" → "en-GB".
    static func bcp47(_ identifier: String) -> String {
        let base = identifier.split(separator: "@").first.map(String.init) ?? identifier
        return base.replacingOccurrences(of: "_", with: "-")
    }

    /// The letters before the first digit of the model identifier: "iPhone15,2" → "iPhone".
    static func family(fromModel model: String) -> String? {
        let letters = model.prefix { $0.isLetter }
        switch letters {
        case "iPhone", "iPad", "iPod": return String(letters)
        case "AppleTV": return "Apple TV"
        case "RealityDevice": return "Apple Vision"
        case "Mac", "MacBookPro", "MacBookAir", "iMac", "Macmini", "MacPro": return "Mac"
        default: return nil
        }
    }

    private static func modelFamily() -> String? {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
            return family(fromModel: simulated)
        }
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        #if os(macOS)
        return "Mac"
        #else
        return family(fromModel: machine)
        #endif
    }

    private static var isSimulator: Bool? {
        #if targetEnvironment(simulator)
        return true
        #elseif os(iOS) || os(tvOS) || os(visionOS)
        return false
        #else
        return nil
        #endif
    }

    /// A conservative file check. Nil where it cannot mean anything (simulator, macOS).
    private static func jailbroken() -> Bool? {
        #if targetEnvironment(simulator) || os(macOS)
        return nil
        #else
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/var/jb", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt"]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
        #endif
    }

    private static func debuggerAttached() -> Bool? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else { return nil }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private static func screen() async -> Screen? {
        #if canImport(UIKit) && !os(watchOS) && !os(visionOS)
        return await MainActor.run {
            let screen = UIScreen.main
            return Screen(width: Int(screen.bounds.width), height: Int(screen.bounds.height), scale: Double(screen.scale))
        }
        #else
        return nil
        #endif
    }
}
