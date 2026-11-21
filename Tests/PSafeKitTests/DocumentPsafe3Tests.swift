import Foundation
import Testing
@testable import PSafeKit

struct DocumentPsafe3Tests {
    @Test("Document: Load Empty.psafe3")
    func documentLoadEmptyPsafe3() throws {
        let doc = try Document.load(data: resourceData(named: "Empty", ext: "psafe3"), passphrase: "123")

        #expect(doc.headers.count == 7)
        #expect(doc.headers[.version].version == 0x030D)
        #expect(doc.headers[.uuid].uuid == UUID(uuidString: "472b873b-e9de-4f4c-ba63-4d93a86dfa4c"))
        #expect(doc.headers[.nonDefaultPreferences].text == "")
        #expect(doc.headers[.timestampOfLastSave].time == utcDate(2015, 12, 28, 5, 57, 23))
        #expect(doc.headers[.lastSavedByUser].text == "Josip")
        #expect(doc.headers[.lastSavedOnHost].text == "GANDALF")
        #expect(doc.headers[.whatPerformedLastSave].text == "Password Safe V3.37")
        #expect(doc.entries.count == 0)
    }

    @Test("Document: Load Empty.psafe3 (password mismatch)")
    func documentLoadEmptyPsafe3PasswordMismatch() throws {
        #expect(throws: PSafeError.formatMismatch("Password mismatch.")) {
            _ = try Document.load(data: resourceData(named: "Empty", ext: "psafe3"), passphrase: "XXX")
        }
    }

    @Test("Document: Load/Save Simple.psafe3")
    func documentLoadSaveSimplePsafe3() throws {
        let doc = try Document.load(data: resourceData(named: "Simple", ext: "psafe3"), passphrase: "123")
        doc.trackAccess = false
        doc.trackModify = false

        #expect(doc.headers.count == 8)
        #expect(doc.headers[.uuid].uuid == UUID(uuidString: "2438070b-06a4-4b2f-87b2-48656a6b5011"))
        #expect(doc.headers[.recentlyUsedEntries].text == "01a93b6ef7c5af4a5990bd5c20064cc62e")
        #expect(doc.entries.count == 2)
        #expect(doc.entries[0].title == "A")
        #expect(doc.entries[0].password == "A123")
        #expect(doc.entries[1].title == "B")
        #expect(doc.entries[1].password == "B123")

        let savedData = try doc.saveData()
        #expect(savedData.prefix(4) == Data([0x50, 0x57, 0x53, 0x33]))

        let reloaded = try Document.load(data: savedData, passphrase: "123")
        reloaded.trackAccess = false
        reloaded.trackModify = false

        #expect(reloaded.headers.count == 8)
        #expect(reloaded.headers[.uuid].uuid == UUID(uuidString: "2438070b-06a4-4b2f-87b2-48656a6b5011"))
        #expect(reloaded.headers[.recentlyUsedEntries].text == "01a93b6ef7c5af4a5990bd5c20064cc62e")
        #expect(reloaded.entries.count == 2)
        #expect(reloaded.entries[0].title == "A")
        #expect(reloaded.entries[0].password == "A123")
        #expect(reloaded.entries[1].title == "B")
        #expect(reloaded.entries[1].password == "B123")
    }

    @Test("Document: Load Simple.psafe3 (authentication mismatch)")
    func documentLoadSimplePsafe3AuthenticationMismatch() throws {
        var tampered = resourceData(named: "Simple", ext: "psafe3")
        tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF

        #expect(throws: PSafeError.formatMismatch("Authentication mismatch.")) {
            _ = try Document.load(data: tampered, passphrase: "123")
        }
    }

    private func resourceData(named name: String, ext: String) -> Data {
        let bundle = Bundle.module
        guard let url = bundle.url(forResource: name, withExtension: ext),
              let data = try? Data(contentsOf: url) else {
            Issue.record("Missing test resource \(name).\(ext)")
            return Data()
        }
        return data
    }

    private func utcDate(_ year: Int, _ month: Int, _ day: Int, _ hour: Int, _ minute: Int, _ second: Int) -> Date {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: 0)
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        return components.date ?? .distantPast
    }
}