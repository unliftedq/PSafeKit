import Crypto
import Foundation

public final class Document {
    public enum Format: Sendable {
        case v3
        case v4

        var majorVersion: Int { self == .v3 ? 3 : 4 }
        var currentVersion: Int { self == .v3 ? Header.defaultVersion : 0x0402 }
    }

    public nonisolated(unsafe) static var defaultSaveApplicationName = "PSafeKit"

    public init(passphrase: String, format: Format = .v3) throws {
        try Self.checkPassphrase(passphrase)
        self.passphrase = passphrase
        self.format = format
        self.iterations = Self.minimumV3Iterations
        self.v4 = format == .v4 ? try V4Codec.create() : nil

        let versionHeader = Header(.version)
        try versionHeader.setVersion(format.currentVersion)

        let uuidHeader = Header(.uuid)
        try uuidHeader.setUUID(UUID())

        self.headers = HeaderCollection(headers: [versionHeader, uuidHeader, Header(.nonDefaultPreferences)])
        self.entries = EntryCollection(document: nil)
        self.headers.attach(document: self)
        self.entries.document = self
        try self.headers[.lastPasswordChange].setTime(Date())
        self.hasChanged = false
    }

    private init(passphrase: String, format: Format, iterations: UInt32 = 0, v4: V4Codec? = nil,
                 headers: [WireField], records: [[WireField]]) {
        self.passphrase = passphrase
        self.format = format
        self.iterations = iterations
        self.v4 = v4
        self.headers = HeaderCollection(wireFields: headers)
        self.entries = EntryCollection(document: nil, entries: records.map { Entry(wireFields: $0) })
        self.headers.attach(document: self)
        self.entries.document = self
        self.hasChanged = false
    }

    private var passphrase: String
    private var iterations: UInt32
    private var v4: V4Codec?
    public let format: Format
    public var isReadOnly = false
    public let headers: HeaderCollection
    public let entries: EntryCollection
    public lazy var namedPasswordPolicies = NamedPasswordPolicyCollection(document: self)
    public var hasChanged = false
    public var trackAccess = true
    public var trackModify = true

    public var name: String {
        get { headers[.databaseName].text ?? "" }
        set { try? headers[.databaseName].setText(newValue) }
    }

    func markAsChanged() {
        hasChanged = true
    }

    public func save() throws {
        _ = try saveData()
    }

    public func getPassphrase() -> [UInt8] {
        Array(passphrase.utf8)
    }

    public func changePassphrase(_ newPassphrase: String) throws {
        guard !isReadOnly else { throw PSafeError.notSupported("Document is read-only.") }
        try Self.checkPassphrase(newPassphrase)
        guard !validatePassphrase(newPassphrase) else { return }
        try headers[.lastPasswordChange].setTime(Date())
        passphrase = newPassphrase
        markAsChanged()
    }

    public func tryChangePassphrase(old oldPassphrase: String, new newPassphrase: String) throws -> Bool {
        guard validatePassphrase(oldPassphrase) else { return false }
        try changePassphrase(newPassphrase)
        return true
    }

    public func validatePassphrase(_ candidate: String) -> Bool {
        candidate.utf8.elementsEqual(passphrase.utf8)
    }

    /// Returns the content of an inline V3 or referenced V4 attachment.
    public func attachmentContent(for entry: Entry) throws -> Data? {
        guard entry.owner === entries else { return nil }
        if format == .v3 {
            guard !entry[.attachmentMediaType].copyRawData().isEmpty else { return nil }
            return entry[.attachmentContent].copyRawData()
        }
        return try v4?.attachmentContent(id: entry[.attachmentReference].copyRawData())
    }

    /// Adds an attachment to an entry that does not already have one.
    public func addAttachment(_ content: Data, to entry: Entry, mediaType: String, fileName: String, title: String = "") throws {
        guard !isReadOnly else { throw PSafeError.notSupported("Document is read-only.") }
        guard entry.owner === entries, !mediaType.isEmpty else {
            throw PSafeError.argumentOutOfRange("Attachment", "An entry in this document and a media type are required.")
        }
        if var codec = v4 {
            guard !entry.records.contains(.attachmentReference) else {
                throw PSafeError.notSupported("The entry already references an attachment.")
            }
            let reference = Record(.attachmentReference)
            try reference.setUUID(UUID())
            try codec.addAttachment(id: reference.copyRawData(), content: content, title: title,
                                    mediaType: mediaType, fileName: fileName)
            try entry.records.add(reference)
            v4 = codec
        } else {
            guard !entry.records.contains(.attachmentMediaType) else {
                throw PSafeError.notSupported("The entry already has an inline attachment.")
            }
            try entry[.attachmentTitle].setText(title)
            try entry[.attachmentFileName].setText(fileName)
            try entry[.attachmentMediaType].setText(mediaType)
            try entry[.attachmentContent].setBytes(Array(content))
        }
    }

    public func saveData() throws -> Data {
        if !isReadOnly && trackModify {
            try headers[.timestampOfLastSave].setTime(Date())
            try headers[.whatPerformedLastSave].setText(Self.defaultSaveApplicationName)

            let environment = ProcessInfo.processInfo.environment
            let user = environment["USERNAME"] ?? environment["USER"] ?? ""
            let host = environment["COMPUTERNAME"] ?? environment["HOSTNAME"] ?? ""
            try headers[.lastSavedByUser].setText(user)
            try headers[.lastSavedOnHost].setText(host)
            if headers.contains(.whoPerformedLastSave) {
                if format == .v3 && headers[.version].version < 0x0302 {
                    try headers[.whoPerformedLastSave].setText(String(format: "%04x", user.unicodeScalars.count) + user + host)
                } else {
                    try headers.remove(.whoPerformedLastSave)
                }
            }
        }

        let wireHeaders = headers.wireFields()
        let records = entries.allEntries().map { $0.records.wireFields() }
        try Self.validateVersion(wireHeaders, format: format)
        let output: Data
        if var codec = v4 {
            output = try codec.save(headers: wireHeaders, records: records, passphrase: passphrase)
            v4 = codec
        } else {
            output = try saveV3(headers: wireHeaders, records: records)
        }
        hasChanged = false
        return output
    }

    private func saveV3(headers: [WireField], records: [[WireField]]) throws -> Data {
        let salt = randomBytes(count: 32)
        let iterationValue = max(iterations, Self.minimumV3Iterations)
        let stretchedKey = Self.getStretchedKey(passphrase: Array(passphrase.utf8), salt: salt, iterations: iterationValue)
        let stretchedKeyHash = Array(SHA256.hash(data: Data(stretchedKey)))

        let keyK = randomBytes(count: 32)
        let keyL = randomBytes(count: 32)
        let keyCipher = try Twofish(key: stretchedKey)
        let encryptedKeyK = try keyCipher.encrypt(keyK, mode: .ecb)
        let encryptedKeyL = try keyCipher.encrypt(keyL, mode: .ecb)

        let iv = randomBytes(count: 16)
        let payload = try Self.serializeV3(headers: headers, records: records, authenticationKey: keyL)
        let payloadCipher = try Twofish(key: keyK)
        let encryptedPayload = try payloadCipher.encrypt(payload.bytes, mode: .cbc(iv: iv))

        var output = Data()
        output.append(contentsOf: fileTag)
        output.append(contentsOf: salt)
        output.append(contentsOf: littleEndianBytes(of: iterationValue))
        output.append(contentsOf: stretchedKeyHash)
        output.append(contentsOf: encryptedKeyK)
        output.append(contentsOf: encryptedKeyL)
        output.append(contentsOf: iv)
        output.append(contentsOf: encryptedPayload)
        output.append(contentsOf: footerTag)
        output.append(contentsOf: payload.authenticationCode)
        return output
    }

    public static func load(data: Data, passphrase: String) throws -> Document {
        let bytes = Array(data)
        if !bytes.starts(with: fileTag) {
            let parsed = try V4Codec.load(bytes, passphrase: passphrase)
            try validateVersion(parsed.headers, format: .v4)
            return Document(passphrase: passphrase, format: .v4, v4: parsed.codec,
                            headers: parsed.headers, records: parsed.records)
        }
        return try loadV3(bytes, passphrase: passphrase)
    }

    private static let minimumV3Iterations: UInt32 = 327_680
    private static let maximumV3Iterations: UInt32 = 10_000_000

    private static func loadV3(_ bytes: [UInt8], passphrase: String) throws -> Document {
        guard bytes.count >= 232, (bytes.count - 200).isMultiple(of: 16),
              bytes[(bytes.count - 48)..<(bytes.count - 32)].elementsEqual(footerTag) else {
            throw PSafeError.formatMismatch("Unrecognized file format.")
        }

        let salt = Array(bytes[4..<36])
        let iterations = readUInt32LE(bytes, offset: 36)
        guard iterations <= maximumV3Iterations else {
            throw PSafeError.notSupported("V3 key stretching exceeds the supported iteration limit.")
        }
        let stretchedKey = getStretchedKey(passphrase: Array(passphrase.utf8), salt: salt, iterations: iterations)
        let expectedStretchedKeyHash = Array(bytes[40..<72])
        guard SHA256.hash(data: Data(stretchedKey)).withUnsafeBytes({ constantTimeEqual($0, expectedStretchedKeyHash) }) else {
            throw PSafeError.formatMismatch("Password mismatch.")
        }

        let keyCipher = try Twofish(key: stretchedKey)
        let keyK = try keyCipher.decrypt(Array(bytes[72..<104]), mode: .ecb)
        let keyL = try keyCipher.decrypt(Array(bytes[104..<136]), mode: .ecb)
        let iv = Array(bytes[136..<152])

        let encryptedPayload = Array(bytes[152..<(bytes.count - 48)])
        let payloadCipher = try Twofish(key: keyK)
        let payload = try payloadCipher.decrypt(encryptedPayload, mode: .cbc(iv: iv))

        var authentication = HMAC<SHA256>(key: SymmetricKey(data: Data(keyL)))
        let parsed = try parseV3(payload, authentication: &authentication)
        let expectedAuthenticationCode = Array(bytes[(bytes.count - 32)..<bytes.count])
        guard authentication.finalize().withUnsafeBytes({ constantTimeEqual($0, expectedAuthenticationCode) }) else {
            throw PSafeError.formatMismatch("Authentication mismatch.")
        }

        try validateVersion(parsed.headers, format: .v3)
        return Document(passphrase: passphrase, format: .v3, iterations: iterations,
                        headers: parsed.headers, records: parsed.records)
    }

    private static func validateVersion(_ headers: [WireField], format: Format) throws {
        guard let version = headers.first, version.type == HeaderType.version.rawValue,
              version.data.count == 2 || version.data.count == 4,
              Int(version.data[version.data.startIndex + 1]) == format.majorVersion,
              !headers.dropFirst().contains(where: { $0.type == HeaderType.version.rawValue }) else {
            throw PSafeError.formatMismatch("Unrecognized file format version.")
        }
    }

    private static func checkPassphrase(_ passphrase: String) throws {
        guard !passphrase.isEmpty, !passphrase.utf8.contains(0) else {
            throw PSafeError.argumentOutOfRange("Passphrase", "Expected a nonempty passphrase without NUL bytes.")
        }
    }

    private static func serializeV3(headers: [WireField], records: [[WireField]], authenticationKey: [UInt8]) throws
        -> (bytes: [UInt8], authenticationCode: [UInt8]) {
        var payload: [UInt8] = []
        var authentication = HMAC<SHA256>(key: SymmetricKey(data: Data(authenticationKey)))
        let end = WireField(type: 0xFF, data: Data())

        for fields in [headers] + records {
            for field in fields {
                guard field.type != end.type else { throw PSafeError.formatMismatch("Unexpected end-of-entry field.") }
                try appendV3Field(field, payload: &payload, authentication: &authentication)
            }
            try appendV3Field(end, payload: &payload, authentication: &authentication)
        }

        return (payload, Array(authentication.finalize()))
    }

    private static func appendV3Field(_ field: WireField, payload: inout [UInt8], authentication: inout HMAC<SHA256>) throws {
        guard let length = UInt32(exactly: field.data.count) else {
            throw PSafeError.argumentOutOfRange("Field", "Field is too large to serialize.")
        }
        authentication.update(data: field.data)
        let paddedLength = ((field.data.count + 4) / 16 + 1) * 16
        var block = Array(repeating: UInt8(0), count: paddedLength)
        block.replaceSubrange(0..<4, with: littleEndianBytes(of: length))
        block[4] = field.type
        let paddingStart = 5 + field.data.count
        block.replaceSubrange(5..<paddingStart, with: field.data)
        block.replaceSubrange(paddingStart..<paddedLength, with: randomBytes(count: paddedLength - paddingStart))

        payload.append(contentsOf: block)
    }

    private static func parseV3(_ payload: [UInt8], authentication: inout HMAC<SHA256>) throws
        -> (headers: [WireField], records: [[WireField]]) {
        var offset = 0
        var sections: [[WireField]] = []
        var fields: [WireField] = []

        while offset < payload.count {
            guard payload.count - offset >= 16 else { throw PSafeError.formatMismatch("Truncated V3 field.") }
            let fieldLength = Int(readUInt32LE(payload, offset: offset))
            let fullLength = ((fieldLength + 4) / 16 + 1) * 16
            guard fullLength <= payload.count - offset else {
                throw PSafeError.formatMismatch("Truncated V3 field.")
            }

            let fieldType = payload[offset + 4]
            let fieldData = Data(payload[(offset + 5)..<(offset + 5 + fieldLength)])
            authentication.update(data: fieldData)
            offset += fullLength

            if fieldType == 0xFF {
                guard fieldData.isEmpty else { throw PSafeError.formatMismatch("Invalid V3 end-of-entry field.") }
                guard !sections.isEmpty || !fields.isEmpty else {
                    throw PSafeError.formatMismatch("Missing V3 header.")
                }
                sections.append(fields)
                fields = []
            } else {
                fields.append(WireField(type: fieldType, data: fieldData))
            }
        }

        guard let headers = sections.first, fields.isEmpty else {
            throw PSafeError.formatMismatch("Missing V3 end-of-entry field.")
        }
        return (headers, Array(sections.dropFirst()))
    }

    private static func getStretchedKey(passphrase: [UInt8], salt: [UInt8], iterations: UInt32) -> [UInt8] {
        var hash = SHA256.hash(data: Data(passphrase + salt))
        for _ in 0..<iterations {
            hash = hash.withUnsafeBytes { SHA256.hash(data: $0) }
        }
        return Array(hash)
    }
}

private func constantTimeEqual(_ lhs: UnsafeRawBufferPointer, _ rhs: [UInt8]) -> Bool {
    guard lhs.count == rhs.count else { return false }
    return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
}

private let fileTag: [UInt8] = [0x50, 0x57, 0x53, 0x33]
private let footerTag: [UInt8] = [0x50, 0x57, 0x53, 0x33, 0x2D, 0x45, 0x4F, 0x46, 0x50, 0x57, 0x53, 0x33, 0x2D, 0x45, 0x4F, 0x46]

private func littleEndianBytes(of value: UInt32) -> [UInt8] {
    [
        UInt8(value & 0xFF),
        UInt8((value >> 8) & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 24) & 0xFF)
    ]
}

private func readUInt32LE(_ bytes: [UInt8], offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | (UInt32(bytes[offset + 1]) << 8)
        | (UInt32(bytes[offset + 2]) << 16)
        | (UInt32(bytes[offset + 3]) << 24)
}

private func randomBytes(count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
}