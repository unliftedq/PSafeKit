import Foundation

public final class NamedPasswordPolicyCollection {
    private weak var document: Document?
    private var items: [NamedPasswordPolicy] = []

    public init(document: Document) {
        self.document = document

        if document.headers.contains(.namedPasswordPolicies) {
            let text = document.headers[.namedPasswordPolicies].text ?? ""
            self.items = Self.parseMultiple(text, owner: self)
        }
    }

    public var count: Int { items.count }
    public var isReadOnly: Bool { document?.isReadOnly ?? false }

    public subscript(index: Int) -> NamedPasswordPolicy {
        items[index]
    }

    func markAsChanged() {
        guard let document else { return }

        var text = String(format: "%02X", items.count)
        for item in items {
            text += String(format: "%02X", item.name.count)
            text += item.name
            text += String(format: "%04X", item.style.rawValue)
            text += String(format: "%03X", item.totalPasswordLength)
            text += String(format: "%03X", item.minimumLowercaseCount)
            text += String(format: "%03X", item.minimumUppercaseCount)
            text += String(format: "%03X", item.minimumDigitCount)
            text += String(format: "%03X", item.minimumSymbolCount)
            let symbols = String(item.getSpecialSymbolSet())
            text += String(format: "%02X", symbols.count)
            text += symbols
        }

        try? document.headers[.namedPasswordPolicies].setText(text)
    }

    public func clear() throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        for item in items { item.owner = nil }
        items.removeAll()
        markAsChanged()
    }

    public func add(_ policy: NamedPasswordPolicy) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        if items.contains(where: { $0.name == policy.name }) {
            throw PSafeError.duplicatePolicy(policy.name)
        }
        items.append(policy)
        policy.owner = self
        markAsChanged()
    }

    public func add(contentsOf policies: [NamedPasswordPolicy]) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        for policy in policies {
            if items.contains(where: { $0.name == policy.name }) {
                throw PSafeError.duplicatePolicy(policy.name)
            }
        }
        for policy in policies {
            items.append(policy)
            policy.owner = self
        }
        markAsChanged()
    }

    public func remove(_ policy: NamedPasswordPolicy) throws {
        if isReadOnly { throw PSafeError.notSupported("Collection is read-only.") }
        items.removeAll(where: { $0 == policy })
        policy.owner = nil
        markAsChanged()
    }

    private static func parseMultiple(_ text: String, owner: NamedPasswordPolicyCollection) -> [NamedPasswordPolicy] {
        guard text.count >= 2, let count = Int(text.prefix(2), radix: 16) else { return [] }
        var remainder = String(text.dropFirst(2))
        var policies: [NamedPasswordPolicy] = []

        for _ in 0..<count {
            guard let policy = parseSingle(&remainder, owner: owner) else { break }
            policies.append(policy)
        }
        return policies
    }

    private static func parseSingle(_ text: inout String, owner: NamedPasswordPolicyCollection) -> NamedPasswordPolicy? {
        guard let nameLength = consumeHex(&text, length: 2) else { return nil }
        guard text.count >= nameLength else { return nil }
        let name = String(text.prefix(nameLength))
        text.removeFirst(nameLength)

        guard let styleFlags = consumeHex(&text, length: 4),
              let totalPasswordLength = consumeHex(&text, length: 3),
              let minimumLowercase = consumeHex(&text, length: 3),
              let minimumUppercase = consumeHex(&text, length: 3),
              let minimumDigits = consumeHex(&text, length: 3),
              let minimumSymbols = consumeHex(&text, length: 3),
              let symbolLength = consumeHex(&text, length: 2),
              text.count >= symbolLength else {
            return nil
        }

        let symbols = Array(String(text.prefix(symbolLength)))
        text.removeFirst(symbolLength)

        return NamedPasswordPolicy(
            owner: owner,
            name: name,
            style: PasswordPolicyStyle(rawValue: styleFlags),
            totalPasswordLength: totalPasswordLength,
            minimumLowercaseCount: minimumLowercase,
            minimumUppercaseCount: minimumUppercase,
            minimumDigitCount: minimumDigits,
            minimumSymbolCount: minimumSymbols,
            specialSymbolSet: symbols
        )
    }

    private static func consumeHex(_ text: inout String, length: Int) -> Int? {
        guard text.count >= length else { return nil }
        let part = String(text.prefix(length))
        text.removeFirst(length)
        return Int(part, radix: 16)
    }
}