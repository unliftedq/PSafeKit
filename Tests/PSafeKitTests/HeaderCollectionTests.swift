import Testing
@testable import PSafeKit

struct HeaderCollectionTests {
    @Test("HeaderCollection: Add")
    func headerCollectionNew() throws {
        let doc = try Document(passphrase: "Password")
        let header = Header(.databaseName)
        try header.setText("Test")
        try doc.headers.add(header)
        #expect(doc.name == "Test")
    }

    @Test("HeaderCollection: Add (read-only document)")
    func headerCollectionReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.headers.add(Header(.databaseName))
        }
    }

    @Test("HeaderCollection: Indexer Get")
    func headerCollectionReadOnlyIndexerRead() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(doc.headers[.databaseName].text == "")
    }

    @Test("HeaderCollection: Indexer Set")
    func headerCollectionReadOnlyIndexerWrite() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.headers.remove(.databaseName)
        }
    }
}