import Testing
@testable import PSafeKit

struct RecordCollectionTests {
    @Test("RecordCollection: Add")
    func recordCollectionNew() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry())
        let groupRecord = Record(.group)
        try groupRecord.setText("Test")
        try doc.entries[0].records.add(groupRecord)
        #expect(doc.entries[0].group.description == "Test")
    }

    @Test("RecordCollection: Add (read-only document)")
    func recordCollectionReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry())
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries[0].records.add(Record(.group))
        }
    }

    @Test("RecordCollection: Indexer Get")
    func recordCollectionReadOnlyIndexerRead() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry())
        doc.isReadOnly = true
        #expect(doc.entries[0].records[.title].text == "")
    }

    @Test("RecordCollection: Indexer Set")
    func recordCollectionReadOnlyIndexerWrite() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry())
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries[0].records.remove(.title)
        }
    }
}