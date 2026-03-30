import Foundation

public struct GroupPath: CustomStringConvertible, ExpressibleByStringLiteral, Equatable, Hashable, Sendable {
    private let group: String

    public init(stringLiteral value: String) {
        self.group = value
    }

    public init(_ segments: String?...) {
        self.init(segments: segments)
    }

    public init(segments: [String?]) {
        var escapedSegments: [String] = []
        for segment in segments {
            guard let segment, !segment.isEmpty else { continue }
            escapedSegments.append(segment.replacingOccurrences(of: ".", with: #"\."#))
        }
        self.group = escapedSegments.joined(separator: ".")
    }

    private init(rawGroup: String) {
        self.group = rawGroup
    }

    public func getSegments() -> [String] {
        var escaped = false
        var segment = ""
        var segments: [String] = []

        for character in group {
            if character == "." {
                if escaped {
                    segment.removeLast()
                    segment.append(".")
                    escaped = false
                } else {
                    segments.append(segment)
                    segment.removeAll(keepingCapacity: true)
                }
            } else {
                if character == "\\" {
                    escaped = true
                }
                segment.append(character)
            }
        }

        segments.append(segment)
        return segments
    }

    public func append(_ segment: String?) -> GroupPath {
        guard let segment, !segment.isEmpty else { return self }
        guard !group.isEmpty else { return GroupPath(segments: [segment]) }

        var segments = getSegments().map(Optional.some)
        segments.append(segment)
        return GroupPath(segments: segments)
    }

    public func up() -> GroupPath {
        let segments = getSegments()
        guard segments.count > 1 else { return GroupPath(rawGroup: "") }
        return GroupPath(segments: Array(segments.dropLast()).map(Optional.some))
    }

    public subscript(index: Int) -> String? {
        let segments = getSegments()
        guard segments.indices.contains(index) else { return nil }
        return segments[index]
    }

    public var description: String { group }

    public static func == (lhs: GroupPath, rhs: GroupPath) -> Bool {
        lhs.group.caseInsensitiveCompare(rhs.group) == .orderedSame
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(group.lowercased())
    }
}