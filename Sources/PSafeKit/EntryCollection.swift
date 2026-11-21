import Foundation

public class EntryCollection {
    weak var document: Document?
    private var entries: [Entry] = []

    init(document: Document?) {
        self.document = document
    }

    init(document: Document?, entries: [Entry]) {
        self.document = document
        self.entries = entries
        for entry in entries {
            entry.owner = self
        }
    }

    public var count: Int { entries.count }
    public var isReadOnly: Bool { document?.isReadOnly ?? false }

    public func add(_ entry: Entry) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        entry.owner = self
        entries.append(entry)
        document?.markAsChanged()
    }

    public subscript(index: Int) -> Entry {
        entries[index]
    }

    public func entry(withUUID uuid: UUID) -> Entry? {
        entries.first(where: { $0.uuid == uuid })
    }

    public subscript(title: String) -> Entry {
        if let entry = entries.first(where: { $0.title.caseInsensitiveCompare(title) == .orderedSame }) {
            return entry
        }
        if isReadOnly { return Entry() }
        let entry = Entry(title)
        try? add(entry)
        return entry
    }

    public subscript(title: String, type: RecordType) -> Record {
        self[title][type]
    }

    public subscript(group: String, title: String) -> Entry {
        if let entry = entries.first(where: { $0.group == GroupPath(stringLiteral: group) && $0.title.caseInsensitiveCompare(title) == .orderedSame }) {
            return entry
        }
        if isReadOnly { return Entry() }
        let entry = Entry(group: group, title: title)
        try? add(entry)
        return entry
    }

    public subscript(group: String, title: String, type: RecordType) -> Record {
        self[group, title][type]
    }

    public func remove(_ title: String, _ type: RecordType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        if let index = entries.firstIndex(where: { $0.title.caseInsensitiveCompare(title) == .orderedSame }) {
            try entries[index].records.remove(type)
        }
    }

    public func remove(_ group: String, _ title: String, _ type: RecordType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        if let index = entries.firstIndex(where: { $0.group == GroupPath(stringLiteral: group) && $0.title.caseInsensitiveCompare(title) == .orderedSame }) {
            try entries[index].records.remove(type)
        }
    }

    func allEntries() -> [Entry] {
        entries
    }
}