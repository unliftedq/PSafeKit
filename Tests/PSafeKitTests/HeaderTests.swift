import Foundation
import Testing
@testable import PSafeKit

struct HeaderTests {
    @Test("Header: New")
    func headerNew() throws {
        let field = Header(.databaseName)
        try field.setText("Test")
        #expect(field.text == "Test")
    }

    @Test("Header: New (wrong type)")
    func headerNewWrongType() {
        let field = Header(.databaseName)
        #expect(throws: PSafeError.self) {
            try field.setUUID(UUID())
        }
    }

    @Test("Header: Add (read-only document)")
    func headerReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        let header = Header(.databaseName)
        try header.setText("Test")
        try doc.headers.add(header)

        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.headers[.databaseName].setText("NewName")
        }
    }

    @Test("Header: Indexer Get")
    func headerReadOnlyIndexerRead() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(doc.headers[.databaseName].text == "")
    }

    @Test("Header: Indexer Set")
    func headerReadOnlyIndexerWrite() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.headers.remove(.databaseName)
        }
    }
}