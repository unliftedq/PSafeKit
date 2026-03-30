import Foundation
import Testing
@testable import PSafeKit

struct EntryTests {
    @Test("Entry: New")
    func entryNew() {
        let entry = Entry()
        #expect(entry.records.count == 3)
        #expect(entry.records.contains(.uuid))
        #expect(entry.records.contains(.title))
        #expect(entry.records.contains(.password))
        #expect(entry.uuid != UUID())
        #expect(entry.title == "")
        #expect(entry.password == "")
    }

    @Test("Entry: New with Title")
    func entryNewWithTitle() {
        let entry = Entry("Test")
        #expect(entry.records.count == 3)
        #expect(entry.records.contains(.uuid))
        #expect(entry.records.contains(.title))
        #expect(entry.records.contains(.password))
        #expect(entry.uuid != UUID())
        #expect(entry.title == "Test")
        #expect(entry.password == "")
    }

    @Test("Entry: Clone")
    func entryClone() {
        let entry = Entry("Test")
        let clone = entry.clone()
        #expect(clone.records.count == 3)
        #expect(clone.records.contains(.uuid))
        #expect(clone.records.contains(.title))
        #expect(clone.records.contains(.password))
        #expect(clone.uuid == entry.uuid)
        #expect(clone.title == "Test")
        #expect(clone.password == "")
    }

    @Test("Entry: Change (read-only)")
    func entryReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries["Test"].setPassword("Old")
        doc.isReadOnly = true

        #expect(throws: PSafeError.self) {
            try doc.entries["Test"].setPassword("New")
        }
    }

    @Test("Entry: Indexer Get via Type")
    func entryAccessByRecordType() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries["Test"].setPassword("Old")
        #expect(doc.entries["Test"][.uuid].uuid != UUID())
        #expect(doc.entries["Test"][.password].text == "Old")

        try doc.entries["Test"][.password].setText("New")
        #expect(doc.entries["Test"][.password].text == "New")
    }

    @Test("Entry: Add")
    func entryTestNamed() throws {
        let guid = UUID()
        let doc = try Document(passphrase: "Password")
        doc.trackAccess = false
        doc.trackModify = false
        let entry = Entry()
        try doc.entries.add(entry)

        try entry.setUUID(guid)
        try entry.setGroup("Group")
        try entry.setTitle("Title")
        try entry.setUserName("UserName")
        try entry.setNotes("Notes")
        try entry.setPassword("Password")
        try entry.setCreationTime(Self.utc(2001, 1, 1))
        try entry.setPasswordModificationTime(Self.utc(2002, 1, 1))
        try entry.setLastAccessTime(Self.utc(2003, 1, 1))
        try entry.setPasswordExpiryTime(Self.utc(2004, 1, 1))
        try entry.setLastModificationTime(Self.utc(2005, 1, 1))
        try entry.setURL("http://example.com")
        try entry.setEmail("example@example.com")
        try entry.setTwoFactorKey([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        try entry.setCreditCardNumber("1234 5678 9012 3456")
        try entry.setCreditCardExpiration("Title")
        try entry.setCreditCardVerificationValue("0987")
        try entry.setCreditCardPin("6543")
        try entry.setQRCode("https://medo64.com/")

        #expect(entry.uuid == guid)
        #expect(entry.group.description == "Group")
        #expect(entry.title == "Title")
        #expect(entry.userName == "UserName")
        #expect(entry.notes == "Notes")
        #expect(entry.password == "Password")
        #expect(entry.creationTime == Self.utc(2001, 1, 1))
        #expect(entry.passwordModificationTime == Self.utc(2002, 1, 1))
        #expect(entry.lastAccessTime == Self.utc(2003, 1, 1))
        #expect(entry.passwordExpiryTime == Self.utc(2004, 1, 1))
        #expect(entry.lastModificationTime == Self.utc(2005, 1, 1))
        #expect(entry.url == "http://example.com")
        #expect(entry.email == "example@example.com")
        #expect(entry.getTwoFactorKey() == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        #expect(entry.creditCardNumber == "1234 5678 9012 3456")
        #expect(entry.creditCardExpiration == "Title")
        #expect(entry.creditCardVerificationValue == "0987")
        #expect(entry.creditCardPin == "6543")
        #expect(entry.qrCode == "https://medo64.com/")

        #expect(entry[.uuid].uuid == guid)
        #expect(entry[.group].text == "Group")
        #expect(entry[.title].text == "Title")
        #expect(entry[.userName].text == "UserName")
        #expect(entry[.notes].text == "Notes")
        #expect(entry[.password].text == "Password")
        #expect(entry[.creationTime].time == Self.utc(2001, 1, 1))
        #expect(entry[.passwordModificationTime].time == Self.utc(2002, 1, 1))
        #expect(entry[.lastAccessTime].time == Self.utc(2003, 1, 1))
        #expect(entry[.passwordExpiryTime].time == Self.utc(2004, 1, 1))
        #expect(entry[.lastModificationTime].time == Self.utc(2005, 1, 1))
        #expect(entry[.url].text == "http://example.com")
        #expect(entry[.emailAddress].text == "example@example.com")
        #expect(entry[.twoFactorKey].getBytes() == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        #expect(entry[.creditCardNumber].text == "1234 5678 9012 3456")
        #expect(entry[.creditCardExpiration].text == "Title")
        #expect(entry[.creditCardVerificationValue].text == "0987")
        #expect(entry[.creditCardPin].text == "6543")
        #expect(entry[.qrCode].text == "https://medo64.com/")
    }

    private static func utc(_ year: Int, _ month: Int, _ day: Int) -> Date {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: 0)
        components.year = year
        components.month = month
        components.day = day
        return components.date!
    }
}