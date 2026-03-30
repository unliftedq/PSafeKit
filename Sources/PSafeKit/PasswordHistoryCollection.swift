import Foundation

public final class PasswordHistoryCollection {
    init(records: RecordCollection) {
        self.records = records
        self.isInitializing = true

        if records.contains(.passwordHistory), let text = records[.passwordHistory].text, text.count >= 5 {
            let characters = Array(text)
            self.enabled = characters[0] != "0"
            self.maximumCount = Int(String(characters[1...2]), radix: 16) ?? Self.defaultMaximumCount

            if let count = Int(String(characters[3...4]), radix: 16) {
                var index = 5
                for _ in 0..<count {
                    guard text.count >= index + 12 else { break }
                    let timeStart = text.index(text.startIndex, offsetBy: index)
                    let timeEnd = text.index(timeStart, offsetBy: 8)
                    let lengthEnd = text.index(timeEnd, offsetBy: 4)
                    guard let unixTime = Int(text[timeStart..<timeEnd], radix: 16),
                          let passwordLength = Int(text[timeEnd..<lengthEnd], radix: 16) else { break }
                    index += 12
                    guard text.count >= index + passwordLength else { break }
                    let passwordStart = text.index(text.startIndex, offsetBy: index)
                    let passwordEnd = text.index(passwordStart, offsetBy: passwordLength)
                    items.append(PasswordHistoryItem(timeFirstUsed: Date(timeIntervalSince1970: TimeInterval(unixTime)), historicalPassword: String(text[passwordStart..<passwordEnd])))
                    index += passwordLength
                }
            }
        }

        self.isInitializing = false
    }

    private let records: RecordCollection
    private var items: [PasswordHistoryItem] = []
    private static let defaultMaximumCount = 3
    private var isInitializing = false

    public var enabled: Bool = false {
        didSet {
            if !enabled {
                items.removeAll()
            }
            markAsChanged()
        }
    }

    public var maximumCount: Int = defaultMaximumCount {
        didSet {
            if maximumCount < 1 { maximumCount = oldValue; return }
            if maximumCount > 255 { maximumCount = oldValue; return }
            markAsChanged()
        }
    }

    public var count: Int { items.count }

    public subscript(index: Int) -> PasswordHistoryItem {
        items[index]
    }

    public func clear() {
        items.removeAll()
        markAsChanged()
    }

    func addPasswordToHistory(time: Date, password: String) {
        guard enabled, !password.isEmpty else { return }
        items.append(PasswordHistoryItem(timeFirstUsed: time, historicalPassword: password))
        while items.count > maximumCount {
            items.removeFirst()
        }
        markAsChanged()
    }

    private func markAsChanged() {
        if isInitializing { return }
        var text = enabled ? "1" : "0"
        text += String(format: "%02x", maximumCount)
        text += String(format: "%02x", items.count)
        for item in items {
            let unixTime = max(0, Int(item.timeFirstUsed.timeIntervalSince1970))
            text += String(format: "%08x", unixTime)
            text += String(format: "%04x", item.historicalPassword.count)
            text += item.historicalPassword
        }
        try? records[.passwordHistory].setText(text)
    }
}