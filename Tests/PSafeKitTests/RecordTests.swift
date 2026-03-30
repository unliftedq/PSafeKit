import Foundation
import Testing
@testable import PSafeKit

struct RecordTests {
    @Test("Record: New")
    func recordNew() throws {
        let field = Record(.title)
        try field.setText("Test")
        #expect(field.text == "Test")
    }

    @Test("Record: New (wrong type)")
    func recordNewWrongType() {
        let field = Record(.title)
        #expect(throws: PSafeError.self) {
            try field.setTime(Date())
        }
    }

    @Test("Record: New (auto-type)")
    func recordNewAutotype() {
        let field = Record(.autotype)
        #expect(field.text == #"\u\t\p\n"#)
    }

    @Test("Record: Change (read-only document)")
    func recordReadOnly() throws {
        let doc = try Document(passphrase: "Password")
        try doc.entries["Test"].setPassword("Old")

        doc.isReadOnly = true
        #expect(throws: PSafeError.self) {
            try doc.entries[0].records[.password].setText("New")
        }
    }

    @Test("Record: SetBytes")
    func recordSetBytes() throws {
        let field = Record(.title)
        try field.setBytes([0x00, 0xFF])
        #expect(field.getBytes().map { String(format: "%02X", $0) }.joined(separator: "-") == "00-FF")
    }

    @Test("Record: SetBytes (null)")
    func recordSetBytesNull() {
        let field = Record(.title)
        #expect(throws: PSafeError.self) {
            try field.setBytes(nil)
        }
    }
}