import Foundation

public final class RecordCollection {
    fileprivate weak var entry: Entry?
    private var records: [Record]

    init(entry: Entry?, records: [Record]) {
        self.entry = entry
        self.records = records
        for record in records { record.owner = self }
    }

    func attach(entry: Entry) {
        self.entry = entry
        for record in records { record.owner = self }
    }

    public var count: Int { records.count }
    var isReadOnly: Bool { entry?.owner?.document?.isReadOnly ?? false }

    public func contains(_ type: RecordType) -> Bool {
        records.contains(where: { $0.type == type })
    }

    public func add(_ record: Record) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        record.owner = self
        records.append(record)
        markAsChanged(type: record.type)
    }

    public func remove(_ type: RecordType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        records.removeAll(where: { $0.type == type })
        markAsChanged(type: type)
    }

    public subscript(index: Int) -> Record {
        records[index]
    }

    public subscript(type: RecordType) -> Record {
        if let record = records.first(where: { $0.type == type }) {
            return record
        }
        let record = Record(type)
        if !isReadOnly {
            record.owner = self
            var insertIndex = records.endIndex
            for (index, item) in records.enumerated() where item.type > type {
                insertIndex = index
                break
            }
            records.insert(record, at: insertIndex)
        }
        return record
    }

    func markAsChanged(type: RecordType) {
        entry?.owner?.document?.markAsChanged()
    }

    func markAsAccessed(type: RecordType) {
        if entry?.owner?.document?.trackAccess == true {
            entry?.owner?.document?.markAsChanged()
        }
    }

    func allRecords() -> [Record] {
        records
    }
}