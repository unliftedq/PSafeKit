import Crypto
import Foundation

struct V4Codec {
    private static let blockSize = 16
    private static let digestSize = 32
    private static let recipientSize = 116
    // Pinned core's MIN_HASH_ITERATIONS / HASH_FACTOR.
    private static let defaultIterations = 327_680 / 7
    private static let maxRecipientCount = 64
    private static let maxRecipientIterations = 2_097_152
    private static let maxTotalIterations = 4_194_304
    private static let maxFieldLength = 16 * 1_024 * 1_024
    private static let end: UInt8 = 0xff
    private static let attachmentID: UInt8 = 0x60
    private static let attachmentRef: UInt8 = 0x1a
    private static let contentKey: UInt8 = 0x70
    private static let contentMACKey: UInt8 = 0x71
    private static let contentIV: UInt8 = 0x72
    private static let contentLength: UInt8 = 0x73
    private static let contentMAC: UInt8 = 0x74

    private var encryptionKey: [UInt8]
    private var authenticationKey: SymmetricKey
    private var recipients: [Recipient]
    private var primary: PrimaryRecipient?
    // Keep attachment content encrypted in memory and preserve its independent CBC stream.
    private var attachments: [Attachment<Data>]

    private init(
        encryptionKey: [UInt8], authenticationKey: [UInt8], recipients: [Recipient] = [],
        primary: PrimaryRecipient? = nil, attachments: [Attachment<Data>] = []
    ) {
        self.encryptionKey = encryptionKey
        self.authenticationKey = SymmetricKey(data: authenticationKey)
        self.recipients = recipients
        self.primary = primary
        self.attachments = attachments
    }

    static func create() throws -> V4Codec {
        var rng = SystemRandomNumberGenerator()
        return V4Codec(encryptionKey: randomBytes(digestSize, using: &rng),
                       authenticationKey: randomBytes(digestSize, using: &rng))
    }

    static func load(_ data: [UInt8], passphrase: String) throws
        -> (codec: V4Codec, headers: [WireField], records: [[WireField]])
    {
        let password = try passwordBytes(passphrase)
        // One recipient, marker and MAC, IV, two header fields, and payload MAC.
        let suffixSize = 3 * digestSize + 3 * blockSize
        guard data.count >= digestSize + recipientSize + suffixSize else {
            throw PSafeError.formatMismatch("Truncated V4 container.")
        }

        let marker = Array(SHA256.hash(data: data.prefix(digestSize)))
        var cursor = digestSize
        var recipients: [Recipient] = []
        while !data[cursor ..< cursor + digestSize].elementsEqual(marker) {
            guard cursor <= data.count - suffixSize - recipientSize else {
                throw PSafeError.formatMismatch("Missing V4 key block terminator.")
            }
            guard recipients.count < maxRecipientCount else {
                throw PSafeError.notSupported("V4 key block count exceeds the supported limit.")
            }
            recipients.append(Recipient(bytes: Array(data[cursor ..< cursor + recipientSize])))
            cursor += recipientSize
        }
        let ciphertextStart = cursor + 2 * digestSize + blockSize
        let ciphertextEnd = data.count - digestSize
        guard ciphertextEnd - ciphertextStart >= 2 * blockSize,
              (ciphertextEnd - ciphertextStart).isMultiple(of: blockSize) else {
            throw PSafeError.formatMismatch("Invalid V4 ciphertext length.")
        }
        try validateRecipients(recipients)

        for (index, recipient) in recipients.enumerated() {
            let wrapper = try KeyWrap(key: deriveKey(password, recipient.salt, recipient.iterations))
            guard let encryptionKey = try wrapper.unwrap(recipient.wrappedEncryptionKey) else {
                continue
            }
            guard let rawAuthenticationKey = try wrapper.unwrap(recipient.wrappedAuthenticationKey) else {
                throw PSafeError.formatMismatch("Invalid V4 wrapped authentication key.")
            }
            let authenticationKey = SymmetricKey(data: rawAuthenticationKey)
            let endOfMarker = cursor + digestSize
            guard HMAC<SHA256>.isValidAuthenticationCode(
                data[endOfMarker ..< endOfMarker + digestSize],
                authenticating: data[digestSize ..< endOfMarker], using: authenticationKey
            ) else {
                throw PSafeError.formatMismatch("Invalid V4 key block authentication code.")
            }

            var reader = Reader(
                bytes: data, cursor: ciphertextStart, end: ciphertextEnd,
                cbc: CBC(cipher: try Twofish(key: encryptionKey),
                         iv: Array(data[ciphertextStart - blockSize ..< ciphertextStart])),
                mac: HMAC(key: authenticationKey)
            )
            let headers = try reader.readFields()
            var records: [[WireField]] = []
            var pending: [Attachment<Range<Int>>] = []
            var attachmentIDs: Set<Data> = []
            while reader.cursor != reader.end {
                let first = try reader.readField()
                if first.type == attachmentID {
                    guard first.data.count == 16, attachmentIDs.insert(first.data).inserted else {
                        throw PSafeError.formatMismatch("Invalid or duplicate V4 attachment UUID.")
                    }
                    pending.append(try reader.readAttachment(first: first))
                } else {
                    guard isRecordID(first.type) else {
                        throw PSafeError.notSupported("Unsupported V4 record type: \(first.type).")
                    }
                    records.append([first] + (try reader.readFields()))
                }
            }
            guard reader.mac.finalize().withUnsafeBytes({ equal($0, data[ciphertextEnd...]) }) else {
                throw PSafeError.formatMismatch("Invalid V4 payload authentication code.")
            }
            try validateHeaders(headers)
            try validateRecords(records, attachmentIDs: attachmentIDs)
            let attachments = try pending.map { try $0.verified(in: data) }
            let primary = PrimaryRecipient(index: index, proof: passwordProof(password, using: authenticationKey))
            return (V4Codec(encryptionKey: encryptionKey, authenticationKey: rawAuthenticationKey,
                            recipients: recipients, primary: primary, attachments: attachments),
                    headers, records)
        }
        throw PSafeError.formatMismatch("The passphrase did not unlock a V4 key block.")
    }

    mutating func save(headers: [WireField], records: [[WireField]], passphrase: String) throws -> Data {
        let password = try Self.passwordBytes(passphrase)
        try Self.validateHeaders(headers)
        try Self.validateRecords(records, attachmentIDs: Set(attachments.map { $0.fields[0].data }))
        var rng = SystemRandomNumberGenerator()
        let proof = Self.passwordProof(password, using: authenticationKey)
        var encryptionKey = self.encryptionKey
        var authenticationKey = self.authenticationKey
        var recipients = self.recipients
        let index = primary?.index ?? 0
        if primary?.proof != proof {
            // With other recipients present, only the supplied password can be rewrapped.
            if recipients.count == 1 {
                encryptionKey = Self.randomBytes(Self.digestSize, using: &rng)
                authenticationKey = SymmetricKey(data: Self.randomBytes(Self.digestSize, using: &rng))
            }
            let iterations = max(Self.defaultIterations, primary.map { recipients[$0.index].iterations } ?? 0)
            let otherIterations = recipients.enumerated().reduce(0) { total, entry in
                total + (entry.offset == index ? 0 : entry.element.iterations)
            }
            guard iterations <= Self.maxTotalIterations - otherIterations else {
                throw PSafeError.notSupported("Rotating the V4 primary key block would exceed the supported key derivation limit.")
            }
            let salt = Self.randomBytes(Self.digestSize, using: &rng)
            let wrapper = try KeyWrap(key: Self.deriveKey(password, salt, iterations))
            let wrappedAuthenticationKey = try authenticationKey.withUnsafeBytes { try wrapper.wrap(Array($0)) }
            let replacement = try Recipient(salt: salt, iterations: iterations,
                                            wrappedEncryptionKey: wrapper.wrap(encryptionKey),
                                            wrappedAuthenticationKey: wrappedAuthenticationKey)
            if recipients.isEmpty {
                recipients = [replacement]
            } else {
                recipients[index] = replacement
            }
        }
        try Self.validateRecipients(recipients)

        var nonce: [UInt8]
        repeat {
            nonce = Self.randomBytes(Self.digestSize, using: &rng)
        } while nonce.starts(with: "PWS3".utf8) // Avoid ambiguity with V3's format tag.
        let marker = SHA256.hash(data: nonce)
        var keyBlockSection = Data()
        for recipient in recipients { keyBlockSection.append(contentsOf: recipient.bytes) }
        keyBlockSection.append(contentsOf: marker)
        let iv = Self.randomBytes(Self.blockSize, using: &rng)
        var prefix = Data(nonce)
        prefix.append(keyBlockSection)
        prefix.append(contentsOf: HMAC<SHA256>.authenticationCode(for: keyBlockSection, using: authenticationKey))
        prefix.append(contentsOf: iv)

        var writer = Writer(
            data: prefix, cbc: CBC(cipher: try Twofish(key: encryptionKey), iv: iv),
            mac: HMAC(key: authenticationKey), rng: rng
        )
        try writer.writeRecord(headers)
        for record in records { try writer.writeRecord(record) }
        for attachment in attachments { try writer.writeAttachment(attachment) }
        writer.data.append(contentsOf: writer.mac.finalize())
        self.encryptionKey = encryptionKey
        self.authenticationKey = authenticationKey
        self.recipients = recipients
        primary = PrimaryRecipient(index: index, proof: Self.passwordProof(password, using: authenticationKey))
        return writer.data
    }

    func attachmentContent(id: Data) throws -> Data? {
        guard let attachment = attachments.first(where: { $0.fields[0].data == id }) else { return nil }
        let ciphertext = attachment.ciphertext
        var content = Data()
        try attachment.readContent(in: ciphertext.startIndex ..< ciphertext.endIndex, read: { ciphertext[$0] }) {
            content.append(contentsOf: $0)
        }
        return content
    }

    mutating func addAttachment(id: Data, content: Data, title: String, mediaType: String, fileName: String) throws {
        guard !content.isEmpty, let length = UInt32(exactly: content.count) else {
            throw PSafeError.argumentOutOfRange("Content", "V4 attachments require 1 to 4,294,967,295 bytes.")
        }
        var rng = SystemRandomNumberGenerator()
        let encryptionKey = Self.randomBytes(Self.digestSize, using: &rng)
        let authenticationKey = Self.randomBytes(Self.digestSize, using: &rng)
        let iv = Self.randomBytes(Self.blockSize, using: &rng)
        let tag = HMAC<SHA256>.authenticationCode(for: content, using: SymmetricKey(data: authenticationKey))
        var clear = Array(content)
        clear.append(contentsOf: Self.randomBytes(Self.padded(clear.count) - clear.count, using: &rng))
        let ciphertext = try Twofish(key: encryptionKey).encrypt(clear, mode: .cbc(iv: iv))
        let fields: [WireField] = [
            WireField(type: Self.attachmentID, data: id),
            WireField(type: 0x61, data: Data(title.utf8)),
            WireField(type: 0x63, data: Data(mediaType.utf8)),
            WireField(type: 0x64, data: Data(fileName.utf8)),
            WireField(type: Self.contentIV, data: Data(iv)),
            WireField(type: Self.contentKey, data: Data(encryptionKey)),
            WireField(type: Self.contentMACKey, data: Data(authenticationKey)),
            WireField(type: Self.contentLength, data: Data(Self.littleEndianBytes(length))),
            WireField(type: Self.contentMAC, data: Data(tag)),
        ]
        attachments.append(Attachment(fields: fields, ciphertext: Data(ciphertext)))
    }

    private struct PrimaryRecipient {
        let index: Int
        // Recognize the exact original UTF-8 bytes without retaining the password.
        let proof: HMAC<SHA256>.MAC
    }

    private struct Recipient {
        let bytes: [UInt8]
        var salt: [UInt8] { Array(bytes[..<32]) }
        var iterations: Int { Int(clamping: littleEndianWord(bytes[32 ..< 36])) }
        var wrappedEncryptionKey: ArraySlice<UInt8> { bytes[36 ..< 76] }
        var wrappedAuthenticationKey: ArraySlice<UInt8> { bytes[76 ..< 116] }

        init(bytes: [UInt8]) {
            self.bytes = bytes
        }

        init(salt: [UInt8], iterations: Int, wrappedEncryptionKey: [UInt8], wrappedAuthenticationKey: [UInt8]) {
            bytes = salt + littleEndianBytes(UInt32(iterations)) + wrappedEncryptionKey + wrappedAuthenticationKey
        }
    }

    private static func validateRecipients(_ recipients: [Recipient]) throws {
        guard !recipients.isEmpty else {
            throw PSafeError.formatMismatch("V4 container has no key blocks.")
        }
        var cumulative = 0
        for recipient in recipients {
            let iterations = recipient.iterations
            guard iterations > 0 else {
                throw PSafeError.formatMismatch("Invalid V4 key block iteration count.")
            }
            guard iterations <= maxRecipientIterations, iterations <= maxTotalIterations - cumulative else {
                throw PSafeError.notSupported("V4 key derivation work exceeds the supported limit.")
            }
            cumulative += iterations
        }
    }

    private struct Reader {
        let bytes: [UInt8]
        var cursor: Int
        let end: Int
        var cbc: CBC
        var mac: HMAC<SHA256>

        mutating func readField() throws -> WireField {
            let first = try cbc.decrypt(bytes[take(blockSize)])
            guard let length = Int(exactly: littleEndianWord(first.prefix(4))), length <= maxFieldLength else {
                throw PSafeError.notSupported("V4 field length exceeds the supported limit.")
            }
            let type = first[4]
            guard type != V4Codec.end || length == 0 else {
                throw PSafeError.formatMismatch("A V4 terminator must have an empty value.")
            }
            var data = Data(first.dropFirst(5).prefix(length))
            let remaining = length - data.count
            if remaining > 0 {
                let rest = try cbc.decrypt(bytes[take(padded(remaining))])
                data.append(contentsOf: rest.prefix(remaining))
            }
            let field = WireField(type: type, data: data)
            authenticate(field, using: &mac)
            return field
        }

        mutating func readFields() throws -> [WireField] {
            var fields: [WireField] = []
            while true {
                let field = try readField()
                if field.type == V4Codec.end { return fields }
                fields.append(field)
            }
        }

        mutating func readAttachment(first: WireField) throws -> Attachment<Range<Int>> {
            var fields = [first]
            var seen: Set<UInt8> = []
            var ciphertext: Range<Int>?
            while true {
                let field = try readField()
                switch field.type {
                case V4Codec.end:
                    guard let ciphertext, seen.contains(contentMAC), seen.contains(contentMACKey) else {
                        throw PSafeError.formatMismatch("Incomplete V4 attachment.")
                    }
                    return Attachment(fields: fields, ciphertext: ciphertext)
                case attachmentID:
                    throw PSafeError.formatMismatch("Multiple UUIDs in a V4 attachment.")
                case contentIV, contentKey, contentMACKey, contentMAC, contentLength:
                    let width = field.type == contentLength ? 4 : (field.type == contentIV ? blockSize : digestSize)
                    guard field.data.count == width, seen.insert(field.type).inserted else {
                        throw PSafeError.formatMismatch("Invalid or duplicate V4 attachment content field.")
                    }
                    if field.type == contentLength {
                        guard let length = Int(exactly: littleEndianWord(field.data)),
                              length > 0, length <= Int.max - (blockSize - 1),
                              seen.contains(contentIV), seen.contains(contentKey) else {
                            throw PSafeError.formatMismatch("Invalid V4 attachment content framing.")
                        }
                        ciphertext = try take(padded(length))
                    }
                default:
                    break
                }
                fields.append(field)
            }
        }

        private mutating func take(_ count: Int) throws -> Range<Int> {
            guard count <= end - cursor else {
                throw PSafeError.formatMismatch("Truncated V4 field or attachment.")
            }
            let range = cursor ..< cursor + count
            cursor += count
            return range
        }
    }

    private struct Writer {
        var data: Data
        var cbc: CBC
        var mac: HMAC<SHA256>
        var rng: SystemRandomNumberGenerator

        mutating func writeRecord(_ fields: [WireField]) throws {
            for field in fields { try writeField(field) }
            try writeField(WireField(type: end, data: Data()))
        }

        mutating func writeAttachment(_ attachment: Attachment<Data>) throws {
            for field in attachment.fields {
                try writeField(field)
                if field.type == contentLength {
                    // Do not advance the database CBC chain across the attachment ciphertext.
                    data.append(attachment.ciphertext)
                }
            }
            try writeField(WireField(type: end, data: Data()))
        }

        private mutating func writeField(_ field: WireField) throws {
            guard field.data.count <= maxFieldLength else {
                throw PSafeError.notSupported("V4 field length exceeds the supported limit.")
            }
            var clear = littleEndianBytes(UInt32(field.data.count))
            clear.append(field.type)
            clear.append(contentsOf: field.data)
            clear.append(contentsOf: randomBytes(padded(clear.count) - clear.count, using: &rng))
            let encrypted = try cbc.encrypt(clear)
            data.append(contentsOf: encrypted)
            authenticate(field, using: &mac)
        }
    }

    private struct Attachment<Ciphertext> {
        let fields: [WireField]
        let ciphertext: Ciphertext

        func verified(in source: [UInt8]) throws -> Attachment<Data> where Ciphertext == Range<Int> {
            try readContent(in: ciphertext, read: { source[$0] }) { _ in }
            return Attachment<Data>(fields: fields, ciphertext: Data(source[ciphertext]))
        }

        func readContent<Blocks: Collection>(
            in range: Range<Int>, read: (Range<Int>) -> Blocks, consume: (ArraySlice<UInt8>) -> Void
        ) throws where Blocks.Element == UInt8 {
            func value(_ type: UInt8) -> Data? { fields.first { $0.type == type }?.data }
            guard let encryptionKey = value(contentKey), let iv = value(contentIV),
                  let authenticationKey = value(contentMACKey), let length = value(contentLength),
                  let tag = value(contentMAC), let count = Int(exactly: littleEndianWord(length)) else {
                throw PSafeError.formatMismatch("Incomplete V4 attachment.")
            }
            var cbc = CBC(cipher: try Twofish(key: Array(encryptionKey)), iv: Array(iv))
            var mac = HMAC<SHA256>(key: SymmetricKey(data: authenticationKey))
            var remaining = count
            var offset = range.lowerBound
            while offset < range.upperBound {
                let end = offset + min(64 * 1_024, range.upperBound - offset)
                let clear = try cbc.decrypt(read(offset ..< end))
                let useful = clear.prefix(remaining)
                // The pinned core authenticates the unpadded content.
                mac.update(data: useful)
                consume(useful)
                remaining -= useful.count
                offset = end
            }
            guard remaining == 0, mac.finalize().withUnsafeBytes({ equal($0, tag) }) else {
                throw PSafeError.formatMismatch("Invalid V4 attachment authentication code.")
            }
        }
    }

    private struct CBC {
        let cipher: Twofish
        var iv: [UInt8]

        mutating func decrypt(_ blocks: some Collection<UInt8>) throws -> [UInt8] {
            let clear = try cipher.decrypt(Array(blocks), mode: .cbc(iv: iv))
            iv = Array(blocks.suffix(blockSize))
            return clear
        }

        mutating func encrypt(_ blocks: [UInt8]) throws -> [UInt8] {
            let encrypted = try cipher.encrypt(blocks, mode: .cbc(iv: iv))
            iv = Array(encrypted.suffix(blockSize))
            return encrypted
        }
    }

    private struct KeyWrap {
        let cipher: Twofish

        init(key: [UInt8]) throws {
            cipher = try Twofish(key: key)
        }

        // RFC 3394 with Twofish and four 64-bit words.
        func wrap(_ key: [UInt8]) throws -> [UInt8] {
            var a = Array(repeating: UInt8(0xa6), count: 8)
            var words = key
            for step in 0 ..< 24 {
                let offset = (step % 4) * 8
                var block = try cipher.encrypt(a + words[offset ..< offset + 8], mode: .ecb)
                block[7] ^= UInt8(step + 1)
                a = Array(block.prefix(8))
                words.replaceSubrange(offset ..< offset + 8, with: block.suffix(8))
            }
            return a + words
        }

        func unwrap(_ wrapped: ArraySlice<UInt8>) throws -> [UInt8]? {
            var a = Array(wrapped.prefix(8))
            var words = Array(wrapped.dropFirst(8))
            for step in (0 ..< 24).reversed() {
                let offset = (step % 4) * 8
                a[7] ^= UInt8(step + 1)
                let block = try cipher.decrypt(a + words[offset ..< offset + 8], mode: .ecb)
                a = Array(block.prefix(8))
                words.replaceSubrange(offset ..< offset + 8, with: block.suffix(8))
            }
            return equal(a, repeatElement(UInt8(0xa6), count: 8)) ? words : nil
        }
    }

    private static func deriveKey(_ password: [UInt8], _ salt: [UInt8], _ iterations: Int) -> [UInt8] {
        // PBKDF2-HMAC-SHA256, one output block. The initial HMAC state is reusable.
        let initial = HMAC<SHA256>(key: SymmetricKey(data: password))
        var first = initial
        first.update(data: salt + [0, 0, 0, 1])
        var previous = first.finalize()
        var output = Array(previous)
        for _ in 1 ..< iterations {
            var round = initial
            previous.withUnsafeBytes { round.update(data: $0) }
            previous = round.finalize()
            previous.withUnsafeBytes { bytes in
                for i in output.indices { output[i] ^= bytes[i] }
            }
        }
        return output
    }

    private static func passwordBytes(_ passphrase: String) throws -> [UInt8] {
        guard !passphrase.isEmpty, !passphrase.utf8.contains(0) else {
            throw PSafeError.formatMismatch("V4 requires a nonempty passphrase without NUL bytes.")
        }
        return Array(passphrase.utf8)
    }

    private static func passwordProof(_ password: [UInt8], using key: SymmetricKey) -> HMAC<SHA256>.MAC {
        var mac = HMAC<SHA256>(key: key)
        mac.update(data: Array("PSafeKit V4 primary recipient".utf8))
        mac.update(data: password)
        return mac.finalize()
    }

    private static func authenticate(_ field: WireField, using mac: inout HMAC<SHA256>) {
        // The pinned core authenticates type first, unlike the encrypted field's layout.
        mac.update(data: [field.type] + littleEndianBytes(UInt32(field.data.count)))
        mac.update(data: field.data)
    }

    private static func validateHeaders(_ headers: [WireField]) throws {
        guard let version = headers.first, version.type == 0x00,
              !headers.dropFirst().contains(where: { $0.type == 0x00 || $0.type == end }) else {
            throw PSafeError.formatMismatch("V4 headers require one leading version field.")
        }
        guard version.data.count == 2 || version.data.count == 4,
              version.data.dropFirst().first == 0x04, let minor = version.data.first, minor <= 2 else {
            throw PSafeError.notSupported("Unsupported V4 header version.")
        }
    }

    private static func validateRecords(_ records: [[WireField]], attachmentIDs: Set<Data>) throws {
        for record in records {
            guard let first = record.first, isRecordID(first.type), first.data.count == 16 else {
                throw PSafeError.formatMismatch("V4 records require a leading entry, alias or shortcut UUID.")
            }
            var attachmentRefs: Set<Data> = []
            for field in record.dropFirst() {
                guard field.type != end, !isRecordID(field.type),
                      !(attachmentID ... contentMAC).contains(field.type) else {
                    throw PSafeError.formatMismatch("Unexpected V4 record framing field.")
                }
                if field.type == attachmentRef {
                    guard field.data.count == 16, attachmentIDs.contains(field.data),
                          attachmentRefs.insert(field.data).inserted else {
                        throw PSafeError.formatMismatch("Invalid, missing or duplicate V4 attachment reference.")
                    }
                }
            }
        }
    }

    private static func isRecordID(_ type: UInt8) -> Bool {
        type == 0x01 || type == 0x42 || type == 0x43
    }

    private static func padded(_ count: Int) -> Int {
        (count + blockSize - 1) & ~(blockSize - 1)
    }

    private static func littleEndianWord(_ bytes: some Collection<UInt8>) -> UInt32 {
        bytes.enumerated().reduce(0) { $0 | (UInt32($1.element) << ($1.offset * 8)) }
    }

    private static func littleEndianBytes(_ value: UInt32) -> [UInt8] {
        (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    private static func randomBytes(_ count: Int, using rng: inout SystemRandomNumberGenerator) -> [UInt8] {
        (0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
    }

    private static func equal(_ lhs: some Collection<UInt8>, _ rhs: some Collection<UInt8>) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
