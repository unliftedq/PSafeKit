import Testing
@testable import PSafeKit

struct PasswordPolicyTests {
    @Test("PasswordPolicy: New")
    func passwordPolicyNew() {
        let policy = PasswordPolicy(10)
        policy.style = .makePronounceable
        policy.minimumLowercaseCount = 1
        policy.minimumUppercaseCount = 2
        policy.minimumDigitCount = 3
        policy.minimumSymbolCount = 4

        #expect(policy.style.rawValue == 0x0200)
        #expect(policy.totalPasswordLength == 10)
        #expect(policy.minimumLowercaseCount == 1)
        #expect(policy.minimumUppercaseCount == 2)
        #expect(policy.minimumDigitCount == 3)
        #expect(policy.minimumSymbolCount == 4)
        #expect(String(policy.getSpecialSymbolSet()) == "")
    }

    @Test("PasswordPolicy: Single special symbols")
    func passwordPolicySingleSymbol() {
        let policy = PasswordPolicy(10)
        policy.setSpecialSymbolSet(["!"])
        #expect(String(policy.getSpecialSymbolSet()) == "!")
    }

    @Test("PasswordPolicy: Filter duplicate symbols")
    func passwordPolicyDuplicateSymbols() {
        let policy = PasswordPolicy(10)
        policy.setSpecialSymbolSet(["A", "B", "B", "A", "a", "b", "b", "a"])
        #expect(String(policy.getSpecialSymbolSet()) == "ABab")
    }

    @Test("PasswordPolicy: Empty special symbols")
    func passwordPolicyEmptySymbols() {
        let policy = PasswordPolicy(10)
        policy.setSpecialSymbolSet(["!"])
        policy.setSpecialSymbolSet([])
        #expect(String(policy.getSpecialSymbolSet()) == "")
    }
}