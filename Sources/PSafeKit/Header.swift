import Foundation

public final class Header: Field {
    public static let defaultVersion = 0x0311

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
    override var timeByteCount: Int { owner?.timeByteCount ?? 4 }
    override var acceptsLegacyHexTime: Bool { type == .timestampOfLastSave }

    override var dataType: FieldDataType {
        switch type {
        case .version:
            return .version
        case .uuid:
            return .uuid
        case .timestampOfLastSave, .lastPasswordChange:
            return .time
        case .yubico:
            return .binary
        case .nonDefaultPreferences, .treeDisplayStatus, .whoPerformedLastSave,
             .whatPerformedLastSave, .lastSavedByUser, .lastSavedOnHost,
             .databaseName, .databaseDescription, .databaseFilters,
             .recentlyUsedEntries, .namedPasswordPolicies, .emptyGroups:
            return .text
        }
    }

    override func markAsChanged() {
        owner?.materialize(self)
        owner?.markAsChanged()
    }
}