import Foundation

public final class Entry {
    public init() {
        let uuidRecord = Record(.uuid)
        try? uuidRecord.setUUID(UUID())
        let titleRecord = Record(.title)
        try? titleRecord.setText("")
        let passwordRecord = Record(.password)
        try? passwordRecord.setText("")
        self.records = RecordCollection(entry: nil, records: [uuidRecord, titleRecord, passwordRecord])
        self.records.attach(entry: self)
    }

    init(records: [Record]) {
        self.records = RecordCollection(entry: nil, records: records)
        self.records.attach(entry: self)
    }

    public convenience init(_ title: String) {
        self.init()
        try? setTitle(title)
    }

    public convenience init(group: GroupPath, title: String) {
        self.init()
        try? setGroup(group)
        try? setTitle(title)
    }

    public convenience init(group: String, title: String) {
        self.init(group: GroupPath(stringLiteral: group), title: title)
    }

    weak var owner: EntryCollection?
    public private(set) var records: RecordCollection

    public var uuid: UUID { records[.uuid].uuid }
    public var group: GroupPath { GroupPath(stringLiteral: records[.group].text ?? "") }
    public var title: String { records[.title].text ?? "" }
    public var userName: String { records[.userName].text ?? "" }
    public var notes: String { records[.notes].text ?? "" }
    public var password: String { records[.password].text ?? "" }
    public var creationTime: Date { records[.creationTime].time }
    public var passwordModificationTime: Date { records[.passwordModificationTime].time }
    public var lastAccessTime: Date { records[.lastAccessTime].time }
    public var passwordExpiryTime: Date { records[.passwordExpiryTime].time }
    public var lastModificationTime: Date { records[.lastModificationTime].time }
    public var url: String { records[.url].text ?? "" }
    public var email: String { records[.emailAddress].text ?? "" }
    public var creditCardNumber: String { records[.creditCardNumber].text ?? "" }
    public var creditCardExpiration: String { records[.creditCardExpiration].text ?? "" }
    public var creditCardVerificationValue: String { records[.creditCardVerificationValue].text ?? "" }
    public var creditCardPin: String { records[.creditCardPin].text ?? "" }
    public var qrCode: String { records[.qrCode].text ?? "" }
    public var autotype: String { records[.autotype].text ?? "" }
    public var autotypeTokens: [AutotypeToken] { AutotypeToken.getAutotypeTokens(autotype, entry: self) }
    public var passwordHistory: PasswordHistoryCollection { PasswordHistoryCollection(records: records) }

    public subscript(type: RecordType) -> Record { records[type] }

    public func setUUID(_ value: UUID) throws { try records[.uuid].setUUID(value) }
    public func setGroup(_ value: GroupPath) throws { try records[.group].setText(value.description) }
    public func setGroup(_ value: String) throws { try setGroup(GroupPath(stringLiteral: value)) }
    public func setTitle(_ value: String) throws { try records[.title].setText(value) }
    public func setUserName(_ value: String) throws { try records[.userName].setText(value) }
    public func setNotes(_ value: String) throws { try records[.notes].setText(value) }
    public func setPassword(_ value: String) throws { try records[.password].setText(value) }
    public func setCreationTime(_ value: Date) throws { try records[.creationTime].setTime(value) }
    public func setPasswordModificationTime(_ value: Date) throws { try records[.passwordModificationTime].setTime(value) }
    public func setLastAccessTime(_ value: Date) throws { try records[.lastAccessTime].setTime(value) }
    public func setPasswordExpiryTime(_ value: Date) throws { try records[.passwordExpiryTime].setTime(value) }
    public func setLastModificationTime(_ value: Date) throws { try records[.lastModificationTime].setTime(value) }
    public func setURL(_ value: String) throws { try records[.url].setText(value) }
    public func setEmail(_ value: String) throws { try records[.emailAddress].setText(value) }
    public func setTwoFactorKey(_ value: [UInt8]) throws { try records[.twoFactorKey].setBytes(value) }
    public func getTwoFactorKey() -> [UInt8] { records[.twoFactorKey].getBytes() }
    public func setCreditCardNumber(_ value: String) throws { try records[.creditCardNumber].setText(value) }
    public func setCreditCardExpiration(_ value: String) throws { try records[.creditCardExpiration].setText(value) }
    public func setCreditCardVerificationValue(_ value: String) throws { try records[.creditCardVerificationValue].setText(value) }
    public func setCreditCardPin(_ value: String) throws { try records[.creditCardPin].setText(value) }
    public func setQRCode(_ value: String) throws { try records[.qrCode].setText(value) }
    public func setAutotype(_ value: String) throws { try records[.autotype].setText(value) }

    public func clone() -> Entry {
        let cloned = Entry()
        cloned.records = RecordCollection(entry: nil, records: recordsSnapshot().map { $0.clone() })
        cloned.records.attach(entry: cloned)
        return cloned
    }

    private func recordsSnapshot() -> [Record] {
        (0..<records.count).map { records[$0] }
    }
}
