import Foundation
import Testing
@testable import PSafeKit

struct EntryCollectionTests {
    @Test("EntryCollection: Add")
    func entryCollectionNew() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("Test"))
        #expect(doc.entries[0].title == "Test")
    }

    @Test("EntryCollection: Add (read-only document)")
    func entryCollectionReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries.add(Entry())
        }
    }

    @Test("EntryCollection: Indexer Get (read-only document)")
    func entryCollectionReadOnlyIndexerRead() throws {
        let doc = try Document(passphrase: "Password")
        doc.isReadOnly = true
        #expect(doc.entries["Test"].title == "")
        #expect(doc.entries["Test", .title].text == "")
    }

    @Test("EntryCollection: Indexer Set 2 (read-only document)")
    func entryCollectionReadOnlyIndexerWrite2() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("A"))
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries.remove("A", .emailAddress)
        }
    }

    @Test("EntryCollection: Indexer Set 4 (read-only document)")
    func entryCollectionReadOnlyIndexerWrite4() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry(group: "X.Y", title: "A"))
        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries.remove("X.Y", "A", .emailAddress)
        }
    }

    @Test("EntryCollection: Indexer Get via Title (non-empty)")
    func entryCollectionIndexerReadByTitleNonEmpty() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries.add(Entry("A"))
        #expect(doc.entries["A"].title == "A")

        try doc.entries["A"].setTitle("B")
        #expect(doc.entries["B"].title == "B")
    }

    @Test("EntryCollection: Indexer Get via Title")
    func entryCollectionIndexerReadByTitle() throws {
        let doc = try Document(passphrase: "Password")
        #expect(doc.entries["A"].uuid != UUID())
        #expect(doc.entries["A"].title == "A")
    }

    @Test("EntryCollection: Indexer Get via Title and Type")
    func entryCollectionIndexerReadByTitleType() throws {
        let doc = try Document(passphrase: "Password")
        #expect(doc.entries["A", .uuid].uuid != UUID())
        #expect(doc.entries["A", .title].text == "A")
        #expect(doc.entries["A"][.uuid].uuid != UUID())
        #expect(doc.entries["A"][.title].text == "A")
    }

    @Test("EntryCollection: Indexer Get via Group, Title, and Type")
    func entryCollectionIndexerReadByGroupTitleType() throws {
        let doc = try Document(passphrase: "Password")
        #expect(doc.entries["X.Y", "A", .uuid].uuid != UUID())
        #expect(doc.entries["X.Y", "A", .group].text == "X.Y")
        #expect(doc.entries["X.Y", "A", .title].text == "A")
        #expect(doc.entries["X.Y", "A"][.uuid].uuid != UUID())
        #expect(doc.entries["X.Y", "A"][.title].text == "A")
    }
}