import Foundation

public final class HeaderCollection {
    private weak var document: Document?
    private var headers: [Header]

    init(headers: [Header]) {
        self.headers = headers
    }

    func attach(document: Document) {
        self.document = document
        for header in headers {
            header.owner = self
        }
    }

    public var count: Int { headers.count }

    var isReadOnly: Bool { document?.isReadOnly ?? false }

    public func add(_ header: Header) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        header.owner = self
        if let index = headers.firstIndex(where: { $0.type == header.type }) {
            headers[index] = header
        } else {
            headers.append(header)
        }
        markAsChanged()
    }

    public func contains(_ type: HeaderType) -> Bool {
        headers.contains(where: { $0.type == type })
    }

    public subscript(_ type: HeaderType) -> Header {
        get {
            if let header = headers.first(where: { $0.type == type }) {
                return header
            }
            let header = Header(type)
            header.owner = isReadOnly ? nil : self
            headers.append(header)
            return header
        }
    }

    public func remove(_ type: HeaderType) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        headers.removeAll(where: { $0.type == type && $0.type != .version })
        markAsChanged()
    }

    func markAsChanged() {
        document?.markAsChanged()
    }

    func allHeaders() -> [Header] {
        headers
    }
}