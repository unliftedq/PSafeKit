import Foundation

public final class Header: Field {
    public static let defaultVersion = 0x030D

    public init(_ type: HeaderType, text: String = "") {
        self.type = type
        super.init()
        if !text.isEmpty {
            try? setText(text)
        }
    }

    public let type: HeaderType
    weak var owner: HeaderCollection?

    override var isReadOnly: Bool { owner?.isReadOnly ?? false }

    override var dataType: FieldDataType {
        switch type {
        case .version:
            return .version
        case .uuid:
            return .uuid
        case .timestampOfLastSave:
            return .time
        case .nonDefaultPreferences, .treeDisplayStatus, .whoPerformedLastSave,
             .whatPerformedLastSave, .lastSavedByUser, .lastSavedOnHost,
             .databaseName, .databaseDescription, .databaseFilters,
             .recentlyUsedEntries, .namedPasswordPolicies, .emptyGroups, .yubico:
            return .text
        }
    }

    override func markAsChanged() {
        owner?.markAsChanged()
    }
}