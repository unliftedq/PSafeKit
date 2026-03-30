import Foundation

public struct PasswordPolicyStyle: OptionSet, Sendable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    public static let useLowercase = PasswordPolicyStyle(rawValue: 0x8000)
    public static let useUppercase = PasswordPolicyStyle(rawValue: 0x4000)
    public static let useDigits = PasswordPolicyStyle(rawValue: 0x2000)
    public static let useSymbols = PasswordPolicyStyle(rawValue: 0x1000)
    public static let useHexDigits = PasswordPolicyStyle(rawValue: 0x0800)
    public static let useEasyVision = PasswordPolicyStyle(rawValue: 0x0400)
    public static let makePronounceable = PasswordPolicyStyle(rawValue: 0x0200)
}