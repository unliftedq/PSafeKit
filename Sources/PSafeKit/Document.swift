import Crypto
import Foundation

public final class Document {
    public nonisolated(unsafe) static var defaultSaveApplicationName = "PSafeKit"

    public init(passphrase: String) throws {
        self.passphrase = passphrase
        self.iterations = 2048

        let versionHeader = Header(.version)
        try versionHeader.setVersion(Header.defaultVersion)

        let uuidHeader = Header(.uuid)
        try uuidHeader.setUUID(UUID())

        self.headers = HeaderCollection(headers: [versionHeader, uuidHeader])
        self.entries = EntryCollection(document: nil)
        self.headers.attach(document: self)
        self.entries.document = self
    }

    private init(passphrase: String, iterations: Int, headers: [Header], entries: [Entry]) {
        self.passphrase = passphrase
        self.iterations = iterations
        self.headers = HeaderCollection(headers: headers)
        self.entries = EntryCollection(document: nil, entries: entries)
        self.headers.attach(document: self)
        self.entries.document = self
        self.hasChanged = false
    }

    private var passphrase: String
    private var iterations: Int
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
        passphrase = newPassphrase
        markAsChanged()
    }

    public func tryChangePassphrase(old oldPassphrase: String, new newPassphrase: String) throws -> Bool {
        guard validatePassphrase(oldPassphrase) else { return false }
        try changePassphrase(newPassphrase)
        return true
    }

    public func validatePassphrase(_ candidate: String) -> Bool {
        passphrase == candidate
    }

    public func saveData() throws -> Data {
        if !isReadOnly && trackModify {
            try? headers[.timestampOfLastSave].setTime(Date())
            try? headers[.whatPerformedLastSave].setText(Self.defaultSaveApplicationName)

            let environment = ProcessInfo.processInfo.environment
            try? headers[.lastSavedByUser].setText(environment["USERNAME"] ?? environment["USER"] ?? "")
            try? headers[.lastSavedOnHost].setText(environment["COMPUTERNAME"] ?? environment["HOSTNAME"] ?? "")
        }

        let salt = randomBytes(count: 32)
        iterations = max(iterations, 2048)
        let iterationValue = UInt32(iterations)
        let stretchedKey = Self.getStretchedKey(passphrase: Array(passphrase.utf8), salt: salt, iterations: iterationValue)
        let stretchedKeyHash = Array(SHA256.hash(data: Data(stretchedKey)))

        let keyK = randomBytes(count: 32)
        let keyL = randomBytes(count: 32)
        let keyCipher = try Twofish(key: stretchedKey)
        let encryptedKeyK = try keyCipher.encrypt(keyK, mode: .ecb)
        let encryptedKeyL = try keyCipher.encrypt(keyL, mode: .ecb)

        let iv = randomBytes(count: 16)
        let payload = serializedPayload(authenticationKey: keyL)
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
        hasChanged = false
        return output
    }

    public static func load(data: Data, passphrase: String) throws -> Document {
        let bytes = Array(data)

        guard bytes.count >= 200,
              Array(bytes[0..<4]) == fileTag,
              Array(bytes[(bytes.count - 48)..<(bytes.count - 32)]) == footerTag else {
            throw PSafeError.formatMismatch("Unrecognized file format.")
        }

        let salt = Array(bytes[4..<36])
        let iterations = Int(readUInt32LE(bytes, offset: 36))
        let stretchedKey = getStretchedKey(passphrase: Array(passphrase.utf8), salt: salt, iterations: UInt32(iterations))
        let expectedStretchedKeyHash = Array(bytes[40..<72])
        guard Array(SHA256.hash(data: Data(stretchedKey))) == expectedStretchedKeyHash else {
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
        let parsed = try parsePayload(payload, authentication: &authentication)
        let actualAuthenticationCode = Array(authentication.finalize())
        let expectedAuthenticationCode = Array(bytes[(bytes.count - 32)..<bytes.count])
        guard actualAuthenticationCode == expectedAuthenticationCode else {
            throw PSafeError.formatMismatch("Authentication mismatch.")
        }

        guard let versionHeader = parsed.headers.first, versionHeader.type == .version, versionHeader.version >= 0x0300 else {
            throw PSafeError.formatMismatch("Unrecognized file format version.")
        }

        return Document(passphrase: passphrase, iterations: iterations, headers: parsed.headers, entries: parsed.entries)
    }

    private func serializedPayload(authenticationKey: [UInt8]) -> (bytes: [UInt8], authenticationCode: [UInt8]) {
        var payload: [UInt8] = []
        var authentication = HMAC<SHA256>(key: SymmetricKey(data: Data(authenticationKey)))

        for header in headers.allHeaders() {
            appendField(type: header.type.rawValue, rawData: Array(header.copyRawData()), payload: &payload, authentication: &authentication)
        }
        appendField(type: 0xFF, rawData: [], payload: &payload, authentication: &authentication)

        for entry in entries.allEntries() {
            for record in entry.records.allRecords() {
                appendField(type: record.type.rawValue, rawData: Array(record.copyRawData()), payload: &payload, authentication: &authentication)
            }
            appendField(type: RecordType.endOfEntry.rawValue, rawData: [], payload: &payload, authentication: &authentication)
        }

        return (payload, Array(authentication.finalize()))
    }

    private func appendField(type: UInt8, rawData: [UInt8], payload: inout [UInt8], authentication: inout HMAC<SHA256>) {
        authentication.update(data: Data(rawData))

        let paddedLength = ((rawData.count + 4) / 16 + 1) * 16
        var block = randomBytes(count: paddedLength)
        let fieldLengthBytes = littleEndianBytes(of: UInt32(rawData.count))
        block[0] = fieldLengthBytes[0]
        block[1] = fieldLengthBytes[1]
        block[2] = fieldLengthBytes[2]
        block[3] = fieldLengthBytes[3]
        block[4] = type
        for (index, byte) in rawData.enumerated() {
            block[5 + index] = byte
        }

        payload.append(contentsOf: block)
    }

    private static func parsePayload(_ payload: [UInt8], authentication: inout HMAC<SHA256>) throws -> (headers: [Header], entries: [Entry]) {
        var offset = 0
        var headers: [Header] = []

        while offset < payload.count {
            guard offset + 5 <= payload.count else { throw PSafeError.formatMismatch("Unrecognized file format.") }

            let fieldLength = Int(readUInt32LE(payload, offset: offset))
            let fullLength = ((fieldLength + 4) / 16 + 1) * 16
            guard offset + fullLength <= payload.count, offset + 5 + fieldLength <= payload.count else {
                throw PSafeError.formatMismatch("Unrecognized file format.")
            }

            let fieldType = payload[offset + 4]
            let fieldData = Array(payload[(offset + 5)..<(offset + 5 + fieldLength)])
            authentication.update(data: Data(fieldData))
            offset += fullLength

            if fieldType == 0xFF { break }
            guard let headerType = HeaderType(rawValue: fieldType) else { continue }

            let header = Header(headerType)
            header.setRawData(Data(fieldData))
            headers.append(header)
        }

        var entries: [Entry] = []
        var currentRecords: [Record] = []

        while offset < payload.count {
            guard offset + 5 <= payload.count else { throw PSafeError.formatMismatch("Unrecognized file format.") }

            let fieldLength = Int(readUInt32LE(payload, offset: offset))
            let fullLength = ((fieldLength + 4) / 16 + 1) * 16
            guard offset + fullLength <= payload.count, offset + 5 + fieldLength <= payload.count else {
                throw PSafeError.formatMismatch("Unrecognized file format.")
            }

            let fieldType = payload[offset + 4]
            let fieldData = Array(payload[(offset + 5)..<(offset + 5 + fieldLength)])
            authentication.update(data: Data(fieldData))
            offset += fullLength

            if fieldType == RecordType.endOfEntry.rawValue {
                if !currentRecords.isEmpty {
                    entries.append(Entry(records: currentRecords))
                    currentRecords = []
                }
                continue
            }

            guard let recordType = RecordType(rawValue: fieldType) else { continue }
            currentRecords.append(Record(type: recordType, rawData: Data(fieldData)))
        }

        return (headers, entries)
    }

    private static func getStretchedKey(passphrase: [UInt8], salt: [UInt8], iterations: UInt32) -> [UInt8] {
        var hash = Array(SHA256.hash(data: Data(passphrase + salt)))
        for _ in 0..<iterations {
            hash = Array(SHA256.hash(data: Data(hash)))
        }
        return hash
    }
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