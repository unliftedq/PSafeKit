import Foundation

public final class RecordCollection {
    fileprivate weak var entry: Entry?
    private var fields: [FieldSlot<Record>]

    init(entry: Entry?, records: [Record]) {
        self.entry = entry
        self.fields = records.map(FieldSlot.known)
        for record in records { record.owner = self }
    }

    init(wireFields: [WireField]) {
        fields = wireFields.map { field in
            guard let type = RecordType(rawValue: field.type) else { return .opaque(field) }
            return .known(Record(type: type, rawData: field.data))
        }
    }

    func attach(entry: Entry) {
        self.entry = entry
        for field in fields { field.known?.owner = self }
    }

    public var count: Int { fields.lazy.compactMap(\.known).count }
    var isReadOnly: Bool { entry?.owner?.document?.isReadOnly ?? false }
    var timeByteCount: Int { entry?.owner?.document?.format == .v4 ? 5 : 4 }

    public func contains(_ type: RecordType) -> Bool {
        fields.contains(where: { $0.known?.type == type })
    }

    /// Returns all occurrences of a record field, including repeated custom fields.
    public func values(for type: RecordType) -> [Record] {
        fields.compactMap { $0.known?.type == type ? $0.known : nil }
    }

    public func add(_ record: Record) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        guard record.type != .endOfEntry else {
            throw PSafeError.notSupported("End-of-entry is a file separator, not an entry field.")
        }
        record.owner = self
        fields.append(.known(record))
        markAsChanged(type: record.type)
    }

    public func remove(_ type: RecordType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        fields.removeAll {
            guard let record = $0.known, record.type == type else { return false }
            record.owner = nil
            return true
        }
        markAsChanged(type: type)
    }

    public subscript(index: Int) -> Record {
        Array(fields.lazy.compactMap(\.known))[index]
    }

    public subscript(type: RecordType) -> Record {
        if let record = fields.lazy.compactMap(\.known).first(where: { $0.type == type }) {
            return record
        }
        let record = Record(type)
        record.owner = self
        return record
    }

    func materialize(_ record: Record) {
        if !contains(record.type) {
            let index = fields.firstIndex {
                guard let type = $0.known?.type else { return false }
                return type != .uuid && type != .aliasUUID && type != .shortcutUUID && type > record.type
            } ?? fields.endIndex
            fields.insert(.known(record), at: index)
        }
    }

    func markAsChanged(type: RecordType) {
        entry?.owner?.document?.markAsChanged()
    }

    func markAsAccessed(type: RecordType) {
        if !isReadOnly, entry?.owner?.document?.trackAccess == true {
            entry?.owner?.document?.markAsChanged()
        }
    }

    func wireFields() -> [WireField] {
        fields.map {
            switch $0 {
            case let .known(record): WireField(type: record.type.rawValue, data: record.copyRawData())
            case let .opaque(field): field
            }
        }
    }
}