import Foundation

public final class Record: Field {
    public init(_ type: RecordType) {
        self.type = type
        super.init()
        if type == .autotype {
            try? setText(#"\u\t\p\n"#)
        }
    }

    init(type: RecordType, rawData: Data) {
        self.type = type
        super.init()
        setRawData(rawData)
    }

    public let type: RecordType
    weak var owner: RecordCollection?

    override var isReadOnly: Bool { owner?.isReadOnly ?? false }

    override var dataType: FieldDataType {
        switch type {
        case .uuid:
            return .uuid
        case .creationTime, .passwordModificationTime, .lastAccessTime, .passwordExpiryTime, .lastModificationTime:
            return .time
        case .twoFactorKey:
            return .binary
        case .group, .title, .userName, .notes, .password, .url, .autotype, .passwordHistory,
             .passwordPolicy, .runCommand, .emailAddress, .ownSymbolsForPassword,
             .passwordPolicyName, .creditCardNumber, .creditCardExpiration,
             .creditCardVerificationValue, .creditCardPin, .qrCode:
            return .text
        default:
            return .unknown
        }
    }

    override func markAsChanged() {
        owner?.markAsChanged(type: type)
    }

    override func markAsAccessed() {
        owner?.markAsAccessed(type: type)
    }

    override func willSetText(_ value: String) throws {
        guard type == .password,
              let owner,
              owner.contains(.passwordHistory),
              owner.contains(.password) else { return }

        let history = PasswordHistoryCollection(records: owner)
        guard history.enabled, let oldPassword = text, !oldPassword.isEmpty else { return }

        let timestamp: Date
        if owner.contains(.passwordModificationTime), owner[.passwordModificationTime].time != .distantPast {
            timestamp = owner[.passwordModificationTime].time
        } else {
            timestamp = Date()
        }

        history.addPasswordToHistory(time: timestamp, password: oldPassword)
    }

    public func clone() -> Record {
        Record(type: type, rawData: copyRawData())
    }
}