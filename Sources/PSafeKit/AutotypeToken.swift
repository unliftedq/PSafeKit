import Foundation

public struct AutotypeToken: CustomStringConvertible, Sendable {
    public init(_ content: String, kind: AutotypeTokenKind = .key) {
        self.content = content
        self.kind = kind
    }

    public let content: String
    public let kind: AutotypeTokenKind
    public var description: String { content }

    public static func getUnexpandedAutotypeTokens(_ autotypeText: String?) -> [AutotypeToken] {
        guard let autotypeText, !autotypeText.isEmpty else {
            return [AutotypeToken("UserName", kind: .command), AutotypeToken("{Tab}"), AutotypeToken("Password", kind: .command), AutotypeToken("{Enter}")]
        }

        enum AutoTypeState {
            case `default`
            case escape
            case escapeCreditCard
            case escapeMandatoryNumber
            case escapeOptionalNumber
        }

        var tokens: [AutotypeToken] = []
        var state = AutoTypeState.default
        var command: String?
        var argument = ""

        for character in autotypeText {
            switch state {
            case .default:
                if character == "\\" {
                    state = .escape
                } else {
                    tokens.append(AutotypeToken(String(character)))
                }

            case .escape:
                switch character {
                case "u", "p", "2", "g", "i", "l", "m", "z":
                    tokens.append(getCommandToken(String(character), argument: nil))
                    state = .default
                case "c":
                    state = .escapeCreditCard
                case "b":
                    tokens.append(AutotypeToken("{Backspace}"))
                    state = .default
                case "t":
                    tokens.append(AutotypeToken("{Tab}"))
                    state = .default
                case "s":
                    tokens.append(AutotypeToken("+{Tab}"))
                    state = .default
                case "n":
                    tokens.append(AutotypeToken("{Enter}"))
                    state = .default
                case "d", "w", "W":
                    command = String(character)
                    state = .escapeMandatoryNumber
                case "o":
                    command = String(character)
                    state = .escapeOptionalNumber
                default:
                    tokens.append(AutotypeToken(String(character)))
                    state = .default
                }

            case .escapeCreditCard:
                switch character {
                case "n", "t", "e", "v", "p":
                    tokens.append(getCommandToken("c" + String(character), argument: nil))
                default:
                    tokens.append(contentsOf: getAutotypeTokensFromText("c" + String(character)))
                }
                state = .default

            case .escapeMandatoryNumber:
                if character.isNumber {
                    argument.append(character)
                    state = .escapeOptionalNumber
                } else {
                    tokens.append(contentsOf: getAutotypeTokensFromText((command ?? "") + argument + String(character)))
                    command = nil
                    argument = ""
                    state = .default
                }

            case .escapeOptionalNumber:
                if character.isNumber && argument.count < 3 {
                    argument.append(character)
                } else {
                    tokens.append(getCommandToken(command ?? "", argument: argument))
                    command = nil
                    argument = ""
                    if character == "\\" {
                        state = .escape
                    } else {
                        tokens.append(AutotypeToken(String(character)))
                        state = .default
                    }
                }
            }
        }

        if let command {
            if argument.isEmpty && (command == "d" || command == "w" || command == "W") {
                tokens.append(contentsOf: getAutotypeTokensFromText(command))
            } else {
                tokens.append(getCommandToken(command, argument: argument))
            }
        } else if state == .escape {
            tokens.append(AutotypeToken(#"\"#))
        }

        return tokens
    }

    public static func getAutotypeTokens(_ autotypeText: String?, entry: Entry) -> [AutotypeToken] {
        getAutotypeTokens(tokens: getUnexpandedAutotypeTokens(autotypeText), entry: entry)
    }

    public static func getAutotypeTokens(tokens: [AutotypeToken], entry: Entry) -> [AutotypeToken] {
        var expanded: [AutotypeToken] = []

        for token in tokens {
            guard token.kind == .command else {
                expanded.append(token)
                continue
            }

            let parts = token.content.split(separator: ":", maxSplits: 1).map(String.init)
            let command = parts[0]
            let argument = parts.count > 1 ? parts[1] : nil

            switch command {
            case "UserName":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.userName))
            case "Password":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.password))
            case "TwoFactorCode", "Delay", "Wait", "Legacy":
                expanded.append(token)
            case "CreditCardNumber":
                expanded.append(contentsOf: getAutotypeTokensFromText(trimCreditCardNumber(entry.creditCardNumber, isTabbed: false)))
            case "CreditCardNumberTabbed":
                expanded.append(contentsOf: getAutotypeTokensFromText(trimCreditCardNumber(entry.creditCardNumber, isTabbed: true)))
            case "CreditCardExpiration":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.creditCardExpiration))
            case "CreditCardVerificationValue":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.creditCardVerificationValue))
            case "CreditCardPin":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.creditCardPin))
            case "Group":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.group.description))
            case "Title":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.title))
            case "Url":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.url))
            case "Email":
                expanded.append(contentsOf: getAutotypeTokensFromText(entry.email))
            case "Notes":
                let lines = splitLines(entry.notes)
                if let argument, let lineNumber = Int(argument), lineNumber <= lines.count {
                    expanded.append(contentsOf: getAutotypeTokensFromText(lines[lineNumber - 1]))
                } else if argument == nil {
                    expanded.append(contentsOf: getAutotypeTokensFromText(lines.joined(separator: "\n")))
                }
            default:
                break
            }
        }

        return expanded
    }

    static func getAutotypeTokensFromText(_ content: String) -> [AutotypeToken] {
        var tokens: [AutotypeToken] = []
        for character in content {
            switch character {
            case "+", "^", "%", "~", "(", ")", "{", "}", "[", "]":
                tokens.append(AutotypeToken("{\(character)}"))
            case "\u{8}":
                tokens.append(AutotypeToken("{Backspace}"))
            case "\n", "\r":
                tokens.append(AutotypeToken("{Enter}"))
            case "\t":
                tokens.append(AutotypeToken("{Tab}"))
            default:
                tokens.append(AutotypeToken(String(character)))
            }
        }
        return tokens
    }

    private static func getCommandToken(_ command: String, argument: String?) -> AutotypeToken {
        switch command {
        case "u": return AutotypeToken("UserName", kind: .command)
        case "p": return AutotypeToken("Password", kind: .command)
        case "2": return AutotypeToken("TwoFactorCode", kind: .command)
        case "cn": return AutotypeToken("CreditCardNumber", kind: .command)
        case "ct": return AutotypeToken("CreditCardNumberTabbed", kind: .command)
        case "ce": return AutotypeToken("CreditCardExpiration", kind: .command)
        case "cv": return AutotypeToken("CreditCardVerificationValue", kind: .command)
        case "cp": return AutotypeToken("CreditCardPin", kind: .command)
        case "g": return AutotypeToken("Group", kind: .command)
        case "i": return AutotypeToken("Title", kind: .command)
        case "l": return AutotypeToken("Url", kind: .command)
        case "m": return AutotypeToken("Email", kind: .command)
        case "o": return AutotypeToken(argument.map { "Notes:\($0)" } ?? "Notes", kind: .command)
        case "d": return AutotypeToken(argument.map { "Delay:\($0)" } ?? "Delay", kind: .command)
        case "w": return AutotypeToken(argument.map { "Wait:\($0)" } ?? "Wait", kind: .command)
        case "W": return AutotypeToken(argument.map { "Wait:\($0)000" } ?? "Wait", kind: .command)
        case "z": return AutotypeToken("Legacy", kind: .command)
        default: return AutotypeToken(command)
        }
    }

    private static func trimCreditCardNumber(_ creditCardNumber: String, isTabbed: Bool) -> String {
        let digits = creditCardNumber.filter(\.isNumber)
        guard isTabbed else { return digits }

        var characters = Array(digits)
        var index = characters.count - 4
        while index > 0 {
            characters.insert("\t", at: index)
            index -= 4
        }
        return String(characters)
    }

    private static func splitLines(_ text: String) -> [String] {
        var result: [String] = []
        var current = ""
        let scalars = Array(text.unicodeScalars)
        var index = 0

        while index < scalars.count {
            let scalar = scalars[index]
            if scalar == "\r" {
                result.append(current)
                current = ""
                if index + 1 < scalars.count, scalars[index + 1] == "\n" {
                    index += 2
                } else {
                    index += 1
                }
                continue
            }
            if scalar == "\n" {
                result.append(current)
                current = ""
                index += 1
                continue
            }
            current.unicodeScalars.append(scalar)
            index += 1
        }

        result.append(current)
        return result
    }
}