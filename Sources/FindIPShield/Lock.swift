import Foundation

extension NSLock {
    /// `withLock` needs iOS 16; the SDK supports iOS 15.
    func sync<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
