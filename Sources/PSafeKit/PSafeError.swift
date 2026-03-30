import Foundation

public enum PSafeError: Error, Equatable, CustomStringConvertible {
    case argumentNil(String)
    case argumentOutOfRange(String, String)
    case notSupported(String)
    case duplicatePolicy(String)
    case formatMismatch(String)

    public var description: String {
        switch self {
        case let .argumentNil(name):
            return "\(name) cannot be null."
        case let .argumentOutOfRange(name, message):
            return "\(name): \(message)"
        case let .notSupported(message):
            return message
        case let .duplicatePolicy(name):
            return "Password policy with the name '\(name)' already existed in collection."
        case let .formatMismatch(message):
            return message
        }
    }
}