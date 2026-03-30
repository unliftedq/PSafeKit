import Testing
@testable import PSafeKit

struct NamedPasswordPolicyCollectionTests {
    @Test("NamedPasswordPolicyCollection: New")
    func namedPasswordPolicyCollectionNewEmpty() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: ""))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 0)
    }

    @Test("NamedPasswordPolicyCollection: New a non-empty collection")
    func namedPasswordPolicyCollectionNewNonEmpty() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: "0104Test111101200100200300404@#$%"))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 1)

        let policy = passwordPolicies[0]
        #expect(policy.name == "Test")
        #expect(policy.style.rawValue == 0x1111)
        #expect(policy.totalPasswordLength == 18)
        #expect(policy.minimumLowercaseCount == 1)
        #expect(policy.minimumUppercaseCount == 2)
        #expect(policy.minimumDigitCount == 3)
        #expect(policy.minimumSymbolCount == 4)
        #expect(policy.getSpecialSymbolSet().count == 4)
    }

    @Test("NamedPasswordPolicyCollection: Clear")
    func namedPasswordPolicyCollectionClear() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: "0104Test111101200100200300404@#$%"))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 1)
        try passwordPolicies.clear()
        #expect(passwordPolicies.count == 0)
    }

    @Test("NamedPasswordPolicyCollection: Add")
    func namedPasswordPolicyCollectionAdd() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: ""))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 0)

        let policy = NamedPasswordPolicy("Test", 10)
        policy.style = PasswordPolicyStyle(rawValue: 0x111)
        policy.minimumLowercaseCount = 1
        policy.minimumUppercaseCount = 1
        policy.minimumDigitCount = 1
        policy.minimumSymbolCount = 1
        policy.setSpecialSymbolSet(["@"]) 

        try passwordPolicies.add(policy)
        #expect(passwordPolicies.count == 1)
        #expect(doc.headers[.namedPasswordPolicies].text == "0104Test011100A00100100100101@")
    }

    @Test("NamedPasswordPolicyCollection: Add (duplicate)")
    func namedPasswordPolicyCollectionAddDuplicate() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: "0104Test111101200100200300404@#$%"))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 1)

        let policy = NamedPasswordPolicy("Test", 10)
        #expect(throws: PSafeError.self) {
            try passwordPolicies.add(policy)
        }
    }

    @Test("NamedPasswordPolicyCollection: AddRange")
    func namedPasswordPolicyCollectionAddRange() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: ""))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        let policy = NamedPasswordPolicy("Test", 10)
        policy.style = PasswordPolicyStyle(rawValue: 0x111)
        policy.minimumLowercaseCount = 1
        policy.minimumUppercaseCount = 1
        policy.minimumDigitCount = 1
        policy.minimumSymbolCount = 1
        policy.setSpecialSymbolSet(["@"]) 

        try passwordPolicies.add(contentsOf: [policy])
        #expect(passwordPolicies.count == 1)
        #expect(doc.headers[.namedPasswordPolicies].text == "0104Test011100A00100100100101@")
    }

    @Test("NamedPasswordPolicyCollection: Remove")
    func namedPasswordPolicyCollectionRemove() throws {
        let doc = try Document(passphrase: "Password")
        try doc.headers.add(Header(.namedPasswordPolicies, text: "0104Test111101200100200300404@#$%"))

        let passwordPolicies = NamedPasswordPolicyCollection(document: doc)
        #expect(passwordPolicies.count == 1)
        try passwordPolicies.remove(passwordPolicies[0])
        #expect(passwordPolicies.count == 0)
    }
}