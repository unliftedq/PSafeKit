import Foundation

open class PasswordPolicy {
    private var symbolSet: [Character] = []

    public init(_ passwordLength: Int) {
        self.totalPasswordLength = 1
        self.style = []
        self.totalPasswordLength = passwordLength
    }

    open func markPolicyAsChanged() {}
    open func markSymbolsAsChanged() {}

    public var style: PasswordPolicyStyle = [] {
        didSet {
            if style.rawValue & 0xFFFF0000 != 0 {
                style = oldValue
                return
            }
            if style.contains(.useHexDigits) {
                style = .useHexDigits
            }
            markPolicyAsChanged()
        }
    }

    public var totalPasswordLength: Int {
        didSet {
            if !(1...4095).contains(totalPasswordLength) {
                totalPasswordLength = oldValue
                return
            }
            markPolicyAsChanged()
        }
    }

    public var minimumLowercaseCount: Int = 0 {
        didSet {
            if !(0...4095).contains(minimumLowercaseCount) {
                minimumLowercaseCount = oldValue
                return
            }
            markPolicyAsChanged()
        }
    }

    public var minimumUppercaseCount: Int = 0 {
        didSet {
            if !(0...4095).contains(minimumUppercaseCount) {
                minimumUppercaseCount = oldValue
                return
            }
            markPolicyAsChanged()
        }
    }

    public var minimumDigitCount: Int = 0 {
        didSet {
            if !(0...4095).contains(minimumDigitCount) {
                minimumDigitCount = oldValue
                return
            }
            markPolicyAsChanged()
        }
    }

    public var minimumSymbolCount: Int = 0 {
        didSet {
            if !(0...4095).contains(minimumSymbolCount) {
                minimumSymbolCount = oldValue
                return
            }
            markPolicyAsChanged()
        }
    }

    public func getSpecialSymbolSet() -> [Character] {
        symbolSet
    }

    public func setSpecialSymbolSet(_ symbols: [Character] = []) {
        self.symbolSet = Array(Set(symbols)).sorted()
        markSymbolsAsChanged()
    }
}