import Foundation

public enum RecordType: UInt8, Comparable, Sendable {
    case uuid = 0x01
    case group = 0x02
    case title = 0x03
    case userName = 0x04
    case notes = 0x05
    case password = 0x06
    case creationTime = 0x07
    case passwordModificationTime = 0x08
    case lastAccessTime = 0x09
    case passwordExpiryTime = 0x0A
    case lastModificationTime = 0x0C
    case url = 0x0D
    case autotype = 0x0E
    case passwordHistory = 0x0F
    case passwordPolicy = 0x10
    case passwordExpiryInterval = 0x11
    case runCommand = 0x12
    case doubleClickAction = 0x13
    case emailAddress = 0x14
    case protectedEntry = 0x15
    case ownSymbolsForPassword = 0x16
    case shiftDoubleClickAction = 0x17
    case passwordPolicyName = 0x18
    case entryKeyboardShortcut = 0x19
    case twoFactorKey = 0x1B
    case creditCardNumber = 0x1C
    case creditCardExpiration = 0x1D
    case creditCardVerificationValue = 0x1E
    case creditCardPin = 0x1F
    case qrCode = 0x20
    case endOfEntry = 0xFF

    public static func < (lhs: RecordType, rhs: RecordType) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}