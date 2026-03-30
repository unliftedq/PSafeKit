import Foundation

public extension UUID {
    static let empty = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
}

enum FieldDataType {
    case unknown
    case version
    case uuid
    case text
    case time
    case binary
}

open class Field {
    private var rawData = Data()

    public init() {}

    var isReadOnly: Bool { false }
    var dataType: FieldDataType { .unknown }

    func markAsChanged() {}
    func markAsAccessed() {}
    func willSetText(_ value: String) throws {}

    public var version: Int {
        guard dataType == .version || dataType == .unknown, rawData.count == 2 else { return -1 }
        return Int(rawData.withUnsafeBytes { $0.load(as: UInt16.self) })
    }

    public var uuid: UUID {
        guard dataType == .uuid || dataType == .unknown, rawData.count == 16 else { return .empty }
        let bytes = Array(rawData)
        return UUID(uuid: (
            bytes[3], bytes[2], bytes[1], bytes[0],
            bytes[5], bytes[4], bytes[7], bytes[6],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    public var text: String? {
        guard dataType == .text || dataType == .unknown else { return nil }
        markAsAccessed()
        return String(data: rawData, encoding: .utf8) ?? ""
    }

    public var time: Date {
        guard dataType == .time || dataType == .unknown else { return .distantPast }
        guard rawData.count == 4 else { return .distantPast }
        let seconds = rawData.withUnsafeBytes { $0.load(as: UInt32.self) }
        markAsAccessed()
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    public func getBytes() -> [UInt8] {
        markAsAccessed()
        return Array(rawData)
    }

    func copyRawData() -> Data {
        rawData
    }

    public func setVersion(_ value: Int) throws {
        try ensureType(.version)
        try ensureWritable()
        var v = UInt16(value)
        rawData = withUnsafeBytes(of: &v) { Data($0) }
        markAsChanged()
    }

    public func setUUID(_ value: UUID) throws {
        try ensureType(.uuid)
        try ensureWritable()
        let tuple = value.uuid
        rawData = Data([
            tuple.3, tuple.2, tuple.1, tuple.0,
            tuple.5, tuple.4, tuple.7, tuple.6,
            tuple.8, tuple.9, tuple.10, tuple.11, tuple.12, tuple.13, tuple.14, tuple.15
        ])
        markAsChanged()
    }

    public func setText(_ value: String) throws {
        try ensureType(.text)
        try ensureWritable()
        try willSetText(value)
        rawData = Data(value.utf8)
        markAsChanged()
    }

    public func setTime(_ value: Date) throws {
        try ensureType(.time)
        try ensureWritable()
        var seconds = UInt32(value.timeIntervalSince1970)
        rawData = withUnsafeBytes(of: &seconds) { Data($0) }
        markAsChanged()
    }

    public func setBytes(_ value: [UInt8]?) throws {
        guard let value else { throw PSafeError.argumentNil("Value") }
        try ensureWritable()
        rawData = Data(value)
        markAsChanged()
    }

    func setRawData(_ value: Data) {
        rawData = value
    }

    private func ensureType(_ expected: FieldDataType) throws {
        guard dataType == expected || dataType == .unknown else {
            throw PSafeError.formatMismatch("Field type mismatch.")
        }
    }

    private func ensureWritable() throws {
        if isReadOnly { throw PSafeError.notSupported("Object is read-only.") }
    }
}