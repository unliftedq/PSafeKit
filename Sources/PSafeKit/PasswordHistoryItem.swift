import Foundation

public final class PasswordHistoryItem {
    init(timeFirstUsed: Date, historicalPassword: String) {
        self.timeFirstUsed = timeFirstUsed
        self.historicalPassword = historicalPassword
    }

    public let timeFirstUsed: Date
    public let historicalPassword: String
}