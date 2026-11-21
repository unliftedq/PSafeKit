import Foundation
import Testing
@testable import PSafeKit

struct CompatibilityTests {
    @Test(arguments: [Document.Format.v3, .v4])
    func preservesRawRecordsAndRespectsPasswordBytes(format: Document.Format) throws {
        let passphrase = "Fictitious e\u{301}"
        let document = try Document(passphrase: passphrase, format: format)
        document.trackModify = false
        let version = document.headers[.version]
        let originalVersion = version.version
        try version.setBytes(version.getBytes() + [0, 0])
        let entry = Entry("Fictitious")
        let id = try #require(UUID(uuidString: "01234567-89ab-4cde-8f01-23456789abcd"))
        try entry.setUUID(id)
        try entry.setPassword("Synthetic password")
        try document.entries.add(entry)
        let opaque = WireField(type: 0xEF, data: Data([0x00, 0xFF, 0x01]))
        var records = entry.records.wireFields()
        records.insert(opaque, at: 1)
        let parsedEntry = Entry(wireFields: records)
        try document.entries.add(parsedEntry.clone())
        #expect(!document.validatePassphrase(passphrase.precomposedStringWithCanonicalMapping))
        #expect(entry[.uuid].getBytes().prefix(8) == [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x4C, 0xDE])

        let time = Date(timeIntervalSince1970: 4_300_000_000)
        if format == .v4 {
            try entry.setCreationTime(time)
        } else {
            #expect(throws: PSafeError.self) { try entry.setCreationTime(time) }
        }
        let firstSave = try document.saveData()
        let loaded = try Document.load(data: firstSave, passphrase: passphrase)
        #expect(loaded.format == format)
        #expect(loaded.headers[.version].version == originalVersion)
        #expect(loaded.entries[1].uuid == id)
        #expect(loaded.entries[1].records.wireFields() == records)
        if format == .v4 { #expect(loaded.entries[0].creationTime == time) }

        // Reading absent fields does not materialize them in the saved stream.
        _ = loaded.entries[1].notes
        _ = loaded.entries[1].autotype
        _ = loaded.headers[.databaseDescription].text
        loaded.trackModify = false
        try loaded.changePassphrase("Synthetic replacement")
        let secondSave = try loaded.saveData()
        #expect(throws: PSafeError.self) { try Document.load(data: secondSave, passphrase: passphrase) }
        let updated = try Document.load(data: secondSave, passphrase: "Synthetic replacement")
        #expect(!updated.headers.contains(.databaseDescription))
        #expect(updated.entries[1].records.wireFields() == records)
    }

    @Test
    func rejectsInvalidV3ContainerAndHeader() throws {
        let document = try Document(passphrase: "Synthetic")
        try document.headers[.version].setVersion(0x0402)
        #expect(throws: PSafeError.self) { try document.saveData() }
        try document.headers[.version].setVersion(0x0311)
        var data = try document.saveData()
        data.replaceSubrange(36..<40, with: [0xFF, 0xFF, 0xFF, 0xFF])
        #expect(throws: PSafeError.notSupported("V3 key stretching exceeds the supported iteration limit.")) {
            try Document.load(data: data, passphrase: "Synthetic")
        }
    }

    #if os(macOS)
    @Test(.enabled(if: ProcessInfo.processInfo.environment["PSAFEKIT_UPSTREAM_FIXTURE"] != nil),
          arguments: [Document.Format.v3, .v4])
    func interoperatesWithPinnedUpstream(format: Document.Format) throws {
        let binary = try #require(ProcessInfo.processInfo.environment["PSAFEKIT_UPSTREAM_FIXTURE"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let version = format == .v3 ? "v3" : "v4"
        let passphrase = "Interop-fictitious-\u{00e9}-\u{6d4b}"
        let replacement = "Interop-replacement-fictitious"
        let input = directory.appendingPathComponent("upstream.psafe")
        let output = directory.appendingPathComponent("swift.psafe")
        func run(_ operation: String, _ file: URL) throws {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: binary)
            task.arguments = [operation, version, file.path]
            try task.run()
            task.waitUntilExit()
            try #require(task.terminationReason == .exit && task.terminationStatus == 0, "\(operation) \(version)")
        }

        try run("write", input)
        try run("read", input)
        let document = try Document.load(data: Data(contentsOf: input), passphrase: passphrase)
        document.trackModify = false
        #expect(document.format == format)
        #expect(document.name == "Fictitious database")
        #expect(document.headers.values(for: .emptyGroups).compactMap(\.text) == ["Unused.A", "Unused.B"])
        let opaqueHeader = try #require(document.headers.wireFields().first { $0.type == 0xDF })
        let id = try #require(UUID(uuidString: "01234567-89ab-4cde-8f01-23456789abcd"))
        let base = try #require(document.entries.entry(withUUID: id))
        #expect(base.title == "Base \u{6d4b}\u{8bd5}")
        let alias = try #require(document.entries.allEntries().first(where: { $0.title == "Alias" }))
        let shortcut = try #require(document.entries.allEntries().first(where: { $0.title == "Shortcut" }))
        let shortcutBase = try #require(document.entries.allEntries().first(where: { $0.title == "Shortcut base" }))
        #expect(alias.dependency == .alias(base: id) && alias.resolvedPassword == base.password)
        #expect(shortcut.dependency == .shortcut(base: shortcutBase.uuid) && shortcut.resolvedPassword == shortcutBase.password)
        let opaqueRecord = try #require(base.records.wireFields().first { $0.type == 0xE1 })
        #expect(try document.attachmentContent(for: base) == opaqueRecord.data)
        try alias.setGroup("Edited alias")

        document.name = "Edited by Swift"
        try document.changePassphrase(replacement)
        let serialized = try document.saveData()
        try serialized.write(to: output)
        try run("read-new", output)
        try run("read-old-rejected", output)
        if format == .v4 { try run("read-second", output) }

        let roundTrip = try Document.load(data: serialized, passphrase: replacement)
        #expect(roundTrip.headers.wireFields().contains(opaqueHeader))
        #expect(roundTrip.entries.entry(withUUID: id)?.records.wireFields().contains(opaqueRecord) == true)

        let fresh = try Document(passphrase: passphrase, format: format)
        fresh.name = "Edited by Swift"
        let newEntry = Entry("Swift-created entry")
        try newEntry.setUUID(id)
        try newEntry.setPassword("synthetic-password")
        try fresh.entries.add(newEntry)
        try fresh.addAttachment(opaqueRecord.data, to: newEntry, mediaType: "application/octet-stream",
                                fileName: "synthetic.bin", title: "Created by Swift")
        try fresh.saveData().write(to: output)
        try run("read-fresh", output)
    }
    #endif
}
