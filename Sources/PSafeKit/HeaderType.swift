import Foundation

public enum HeaderType: UInt8, Sendable {
    case version = 0x00
    case uuid = 0x01
    case nonDefaultPreferences = 0x02
    case treeDisplayStatus = 0x03
    case timestampOfLastSave = 0x04
    case whoPerformedLastSave = 0x05
    case whatPerformedLastSave = 0x06
    case lastSavedByUser = 0x07
    case lastSavedOnHost = 0x08
    case databaseName = 0x09
    case databaseDescription = 0x0A
    case databaseFilters = 0x0B
    case recentlyUsedEntries = 0x0F
    case namedPasswordPolicies = 0x10
    case emptyGroups = 0x11
    case yubico = 0x12
}