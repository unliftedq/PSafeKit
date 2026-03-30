import Testing
@testable import PSafeKit

struct NamedPasswordPolicyTests {
    @Test("NamedPasswordPolicy: New")
    func namedPasswordPolicyNew() {
        let policy = NamedPasswordPolicy("Test", 10)
        policy.style = .makePronounceable
        policy.minimumLowercaseCount = 1
        policy.minimumUppercaseCount = 2
        policy.minimumDigitCount = 3
        policy.minimumSymbolCount = 4

        #expect(policy.name == "Test")
        #expect(policy.style.rawValue == 0x0200)
        #expect(policy.totalPasswordLength == 10)
        #expect(policy.minimumLowercaseCount == 1)
        #expect(policy.minimumUppercaseCount == 2)
        #expect(policy.minimumDigitCount == 3)
        #expect(policy.minimumSymbolCount == 4)
        #expect(String(policy.getSpecialSymbolSet()) == "")
        #expect(policy.description == "Test")
    }

    @Test("NamedPasswordPolicy: Single special symbols")
    func namedPasswordPolicySingleSymbol() {
        let policy = NamedPasswordPolicy("Test", 10)
        policy.setSpecialSymbolSet(["!"])
        #expect(String(policy.getSpecialSymbolSet()) == "!")
    }

    @Test("NamedPasswordPolicy: Filter duplicate symbols")
    func namedPasswordPolicyDuplicateSymbols() {
        let policy = NamedPasswordPolicy("Test", 10)
        policy.setSpecialSymbolSet(["A", "B", "B", "A", "a", "b", "b", "a"])
        #expect(String(policy.getSpecialSymbolSet()) == "ABab")
    }

    @Test("NamedPasswordPolicy: Empty special symbols")
    func namedPasswordPolicyEmptySymbols() {
        let policy = NamedPasswordPolicy("Test", 10)
        policy.setSpecialSymbolSet(["!"])
        policy.setSpecialSymbolSet([])
        #expect(String(policy.getSpecialSymbolSet()) == "")
    }
}