import Foundation

public final class NamedPasswordPolicy: PasswordPolicy, CustomStringConvertible, Equatable {
    weak var owner: NamedPasswordPolicyCollection?

    public init(_ name: String, _ passwordLength: Int) {
        self.name = ""
        super.init(passwordLength)
        self.name = name
    }

    init(owner: NamedPasswordPolicyCollection?, name: String, style: PasswordPolicyStyle, totalPasswordLength: Int, minimumLowercaseCount: Int, minimumUppercaseCount: Int, minimumDigitCount: Int, minimumSymbolCount: Int, specialSymbolSet: [Character]) {
        self.name = name
        self.owner = owner
        super.init(totalPasswordLength)
        self.style = style
        self.totalPasswordLength = totalPasswordLength
        self.minimumLowercaseCount = minimumLowercaseCount
        self.minimumUppercaseCount = minimumUppercaseCount
        self.minimumDigitCount = minimumDigitCount
        self.minimumSymbolCount = minimumSymbolCount
        self.setSpecialSymbolSet(specialSymbolSet)
    }

    public var name: String {
        didSet {
            guard !name.isEmpty, name.count <= 255 else {
                name = oldValue
                return
            }
            owner?.markAsChanged()
        }
    }

    public override func markPolicyAsChanged() {
        owner?.markAsChanged()
    }

    public override func markSymbolsAsChanged() {
        owner?.markAsChanged()
    }

    public var description: String { name }

    public static func == (lhs: NamedPasswordPolicy, rhs: NamedPasswordPolicy) -> Bool {
        lhs.description == rhs.description
    }
}