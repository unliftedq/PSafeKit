import Foundation
import Testing
@testable import PSafeKit

struct DocumentBehaviorTests {
    @Test("Document: Load/Save new file")
    func documentNewSaveAndLoad() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        let data = try doc.saveData()

        let reloaded = try Document.load(data: data, passphrase: "Password")
        #expect(reloaded.entries.count == 1)
        #expect(reloaded.entries[0].title == "Test")
    }

    @Test("Document: Change password")
    func documentChangePassword() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        _ = try doc.saveData()
        #expect(!doc.hasChanged)
        #expect(doc.getPassphrase() == Array("Password".utf8))

        try doc.changePassphrase("Password2")
        #expect(doc.hasChanged)
        #expect(doc.getPassphrase() == Array("Password2".utf8))

        let data = try doc.saveData()
        #expect(!doc.hasChanged)

        let reloaded = try Document.load(data: data, passphrase: "Password2")
        #expect(reloaded.getPassphrase() == Array("Password2".utf8))
        #expect(reloaded.entries.count == 1)
        #expect(reloaded.entries[0].title == "Test")
    }

    @Test("Document: Change password (verify old)")
    func documentChangeOldPassword() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        _ = try doc.saveData()
        #expect(!doc.hasChanged)

        let result = try doc.tryChangePassphrase(old: "Password", new: "Password2")
        #expect(result)
        #expect(doc.hasChanged)
        #expect(doc.getPassphrase() == Array("Password2".utf8))
    }

    @Test("Document: Change password (verify failed)")
    func documentChangeOldPasswordFailed() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        _ = try doc.saveData()
        #expect(!doc.hasChanged)

        let result = try doc.tryChangePassphrase(old: "Password1", new: "Password2")
        #expect(!result)
        #expect(!doc.hasChanged)
        #expect(doc.getPassphrase() == Array("Password".utf8))
    }

    @Test("Document: Validate password")
    func documentValidatePassword() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        _ = try doc.saveData()
        #expect(!doc.hasChanged)

        #expect(!doc.validatePassphrase("Password2"))
        #expect(!doc.hasChanged)
        #expect(doc.validatePassphrase("Password"))
        #expect(!doc.hasChanged)
    }

    @Test("Document: SaveData uses default save application name")
    func documentSaveDataUsesDefaultSaveApplicationName() throws {
        let original = Document.defaultSaveApplicationName
        defer { Document.defaultSaveApplicationName = original }

        Document.defaultSaveApplicationName = "TestApp"

        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))

        let data = try doc.saveData()
        let reloaded = try Document.load(data: data, passphrase: "Password")

        #expect(reloaded.headers[.whatPerformedLastSave].text == "TestApp")
    }
}