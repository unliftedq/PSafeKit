import Foundation

public final class HeaderCollection {
    private weak var document: Document?
    private var fields: [FieldSlot<Header>]

    init(headers: [Header]) {
        fields = headers.map(FieldSlot.known)
    }

    init(wireFields: [WireField]) {
        fields = wireFields.map { field in
            guard let type = HeaderType(rawValue: field.type) else { return .opaque(field) }
            let header = Header(type)
            header.setRawData(field.data)
            return .known(header)
        }
    }

    func attach(document: Document) {
        self.document = document
        for field in fields {
            field.known?.owner = self
        }
    }

    public var count: Int { fields.lazy.compactMap(\.known).count }

    var isReadOnly: Bool { document?.isReadOnly ?? false }
    var timeByteCount: Int { document?.format == .v4 ? 5 : 4 }

    public func add(_ header: Header) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        header.owner = self
        if header.type != .emptyGroups,
           let index = fields.firstIndex(where: { $0.known?.type == header.type }) {
            fields[index].known?.owner = nil
            fields[index] = .known(header)
            header.owner = self
        } else {
            fields.append(.known(header))
        }
        markAsChanged()
    }

    public func contains(_ type: HeaderType) -> Bool {
        fields.contains(where: { $0.known?.type == type })
    }

    /// Returns all occurrences of a header, including repeated empty groups.
    public func values(for type: HeaderType) -> [Header] {
        fields.compactMap { $0.known?.type == type ? $0.known : nil }
    }

    public subscript(_ type: HeaderType) -> Header {
        get {
            if let header = fields.lazy.compactMap(\.known).first(where: { $0.type == type }) {
                return header
            }
            let header = Header(type)
            header.owner = self
            return header
        }
    }

    public func remove(_ type: HeaderType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        if type != .version {
            fields.removeAll {
                guard let header = $0.known, header.type == type else { return false }
                header.owner = nil
                return true
            }
        }
        markAsChanged()
    }

    func materialize(_ header: Header) {
        if !contains(header.type) {
            fields.append(.known(header))
        }
    }

    func markAsChanged() {
        document?.markAsChanged()
    }

    func wireFields() -> [WireField] {
        fields.map {
            switch $0 {
            case let .known(header): WireField(type: header.type.rawValue, data: header.copyRawData())
            case let .opaque(field): field
            }
        }
    }
}