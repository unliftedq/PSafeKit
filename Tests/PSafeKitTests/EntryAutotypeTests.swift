import Testing
@testable import PSafeKit

struct EntryAutotypeTests {
    @Test("Entry: Autotype (default tokens)")
    func entryAutotypeDefault() {
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(nil)) == "UserName {Tab} Password {Enter}")
        #expect(joined(exampleEntry(nil).autotypeTokens) == "D e f a u l t {Tab} P a s s w 0 r d {Enter}")
    }

    @Test("Entry: Autotype (two-factor)")
    func entryAutotypeTwoFactor() {
        let autoTypeText = #"\u\t\p\t\2\t\n"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "UserName {Tab} Password {Tab} TwoFactorCode {Tab} {Enter}")
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == "D e f a u l t {Tab} P a s s w 0 r d {Tab} TwoFactorCode {Tab} {Enter}")
    }

    @Test("Entry: Autotype (credit card, tabbed Amex)")
    func entryAutotypeCreditCardTabbedAmex() {
        let autoTypeText = #"\ct\t\ce\t\cv\t\cp"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "CreditCardNumberTabbed {Tab} CreditCardExpiration {Tab} CreditCardVerificationValue {Tab} CreditCardPin")
        #expect(joined(exampleEntry(autoTypeText, amexCard: true).autotypeTokens) == "1 2 3 {Tab} 4 5 6 7 {Tab} 8 9 0 1 {Tab} 2 3 4 5 {Tab} 0 1 / 7 9 {Tab} 1 2 3 {Tab} 1 2 3 4")
    }

    @Test("Entry: Autotype (optional number, line 4)")
    func entryAutotypeOptionalNumberLine4() {
        let autoTypeText = #"\o4Test"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "Notes:4 T e s t")
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == "{^} T e s t")
    }

    @Test("Entry: Autotype (mandatory number, three digits)")
    func entryAutotypeMandatoryNumberThreeDigit() {
        let autoTypeText = #"\d123Test"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "Delay:123 T e s t")
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == "Delay:123 T e s t")
    }

    @Test("Entry: Autotype (example 2)")
    func entryAutotypeExample2() {
        let autoTypeText = #"\i\g\l\m"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "Title Group Url Email")
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == "E x a m p l e E x a m p l e s m e d o 6 4 . c o m t e s t @ e x a m p l e . c o m")
    }

    @Test("Entry: Autotype typo (hanging escape)")
    func entryAutotypeHangingEscape() {
        let autoTypeText = #"admin\"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == #"a d m i n \"#)
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == #"a d m i n \"#)
    }

    @Test("Entry: Autotype typo (mandatory number, no number)")
    func entryAutotypeMandatoryIncompleteCommand() {
        let autoTypeText = #"\W"#
        #expect(joined(AutotypeToken.getUnexpandedAutotypeTokens(autoTypeText)) == "W")
        #expect(joined(exampleEntry(autoTypeText).autotypeTokens) == "W")
    }

    private func exampleEntry(_ autotypeText: String?, amexCard: Bool = false) -> Entry {
        let entry = Entry()
        try? entry.setTitle("Example")
        try? entry.setGroup("Examples")
        try? entry.setUserName("Default")
        try? entry.setPassword("Passw0rd")
        try? entry.setCreditCardNumber(amexCard ? "123 4567 8901 2345" : "1234 5678 9012 3456")
        try? entry.setCreditCardExpiration("01/79")
        try? entry.setCreditCardVerificationValue("123")
        try? entry.setCreditCardPin("1234")
        try? entry.setTwoFactorKey([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        try? entry.setEmail("test@example.com")
        try? entry.setURL("medo64.com")
        try? entry.setNotes("1\r\n2\n3\r^\n")
        if let autotypeText { try? entry.setAutotype(autotypeText) }
        return entry
    }

    private func joined(_ tokens: [AutotypeToken]) -> String {
        tokens.map(\.description).joined(separator: " ")
    }
}