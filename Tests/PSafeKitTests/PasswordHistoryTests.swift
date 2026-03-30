import Foundation
import Testing
@testable import PSafeKit

struct PasswordHistoryTests {
    @Test("PasswordHistory: Parse existing history")
    func passwordHistoryParseExistingHistory() throws {
        let entry = Entry("Test")
        try entry[.passwordHistory].setText("10202576eea4f00011576eea5b00012")

        let history = entry.passwordHistory
        #expect(history.enabled)
        #expect(history.maximumCount == 2)
        #expect(history.count == 2)
        #expect(history[0].timeFirstUsed == Self.utc(2016, 6, 25, 20, 32, 15))
        #expect(history[0].historicalPassword == "1")
        #expect(history[1].timeFirstUsed == Self.utc(2016, 6, 25, 20, 32, 27))
        #expect(history[1].historicalPassword == "2")
    }

    @Test("PasswordHistory: Password change appends old password")
    func passwordHistoryPasswordChangeAppendsOldPassword() throws {
        let entry = Entry("Test")
        try entry[.passwordHistory].setText("10202576eea4f00011576eea5b00012")
        try entry.setPassword("3")
        try entry.setPasswordModificationTime(Self.utc(2016, 6, 25, 20, 32, 44))
        try entry.setPassword("4")

        let history = entry.passwordHistory
        #expect(history.enabled)
        #expect(history.maximumCount == 2)
        #expect(history.count == 2)
        #expect(history[0].timeFirstUsed == Self.utc(2016, 6, 25, 20, 32, 27))
        #expect(history[0].historicalPassword == "2")
        #expect(history[1].timeFirstUsed == Self.utc(2016, 6, 25, 20, 32, 44))
        #expect(history[1].historicalPassword == "3")
    }

    @Test("PasswordHistory: Change maximum count before password change")
    func passwordHistoryChangeMaximumCountBeforePasswordChange() throws {
        let entry = Entry("Test")
        try entry[.passwordHistory].setText("10202576eea4f00011576eea5b00012")
        entry.passwordHistory.maximumCount = 3
        try entry.setPassword("3")
        try entry.setPasswordModificationTime(Self.utc(2016, 6, 25, 20, 32, 44))
        try entry.setPassword("4")

        let history = entry.passwordHistory
        #expect(history.enabled)
        #expect(history.maximumCount == 3)
        #expect(history.count == 3)
        #expect(history[0].historicalPassword == "1")
        #expect(history[1].historicalPassword == "2")
        #expect(history[2].historicalPassword == "3")
    }

    @Test("PasswordHistory: Disable clears history")
    func passwordHistoryDisableClearsHistory() throws {
        let entry = Entry("Test")
        try entry[.passwordHistory].setText("10202576eea4f00011576eea5b00012")
        entry.passwordHistory.enabled = false
        try entry.setPassword("4")

        let history = entry.passwordHistory
        #expect(!history.enabled)
        #expect(history.maximumCount == 2)
        #expect(history.count == 0)
    }

    @Test("PasswordHistory: Clear")
    func passwordHistoryClear() throws {
        let entry = Entry("Test")
        try entry[.passwordHistory].setText("10202576eea4f00011576eea5b00012")
        entry.passwordHistory.clear()

        let history = entry.passwordHistory
        #expect(history.enabled)
        #expect(history.maximumCount == 2)
        #expect(history.count == 0)
    }

    private static func utc(_ year: Int, _ month: Int, _ day: Int, _ hour: Int, _ minute: Int, _ second: Int) -> Date {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: 0)
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        return components.date!
    }
}