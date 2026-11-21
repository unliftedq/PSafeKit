# PSafeKit

PSafeKit is a Swift package for reading and writing Password Safe V3 (`.psafe3`) and V4 (`.psafe4`) databases.

This repository is a Swift port of the core model and file-format behavior from C# library `Medo.PasswordSafe`, adapted to Swift Package Manager and validated with package tests.

## Status

- Swift Package Manager library: `PSafeKit`
- Swift language mode: 6
- Default output is V3. Pass `format: .v4` to `Document(passphrase:format:)` to create a V4 database. Opening and saving an existing database keeps its format; there is no implicit conversion.
- V3 uses Twofish, SHA-256 key stretching, and HMAC-SHA256. V4 uses PBKDF2-HMAC-SHA256 and Twofish key wrap, plus separate authentication for key blocks, records, and attachment content.
- Unrecognized header and entry fields, repeated empty groups and custom fields, and V4 attachment records are retained when editing supported databases.

`.bimil` compatibility is not part of this package.

## Installation

Add PSafeKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/unliftedq/PSafeKit.git", branch: "main")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: ["PSafeKit"]
    )
]
```

## Quick Start

### Load an existing `.psafe3` file

```swift
import Foundation
import PSafeKit

let fileURL = URL(fileURLWithPath: "Secrets.psafe3")
let data = try Data(contentsOf: fileURL)
let document = try Document.load(data: data, passphrase: "123")

for index in 0..<document.entries.count {
    let entry = document.entries[index]
    print(entry.title, entry.userName, entry.password)
}
```

### Create a new document and save it

```swift
import Foundation
import PSafeKit

let document = try Document(passphrase: "StrongPassword")
document.name = "Personal Vault"

let entry = Entry("Email")
try entry.setUserName("alice@example.com")
try entry.setPassword("correct horse battery staple")
try entry.setURL("https://mail.example.com")
try document.entries.add(entry)

let data = try document.saveData()
try data.write(to: URL(fileURLWithPath: "PersonalVault.psafe3"))
```

### Change the default save application name

When a document is saved with `trackModify == true`, PSafeKit updates the Password Safe metadata field `whatPerformedLastSave`.

By default that value is `PSafeKit`, but you can override it for your application:

```swift
import PSafeKit

Document.defaultSaveApplicationName = "MyPasswordApp"
```

## API Notes

- `Document.load(data:passphrase:)` detects V3 or V4 and loads a database from memory.
- `Document.saveData()` returns the complete encrypted database as `Data`. To persist it, write it to your own URL (for example with `.atomic`). `save()` does not write a file.
- `Document.save()` runs the same serialization path and discards the returned `Data`.
- `Document.trackModify` controls whether save-related metadata is updated during save.
- `Document.trackAccess` exists for compatibility with document behavior, but access-tracking persistence is intentionally limited to the features currently implemented in this package.
- `Entry.dependency` and `Entry.resolvedPassword` expose alias and shortcut relationships without rewriting the original fields. `Document.addAttachment(_:to:mediaType:fileName:title:)` adds an inline V3 or independent V4 attachment; `attachmentContent(for:)` reads its bytes.
- `HeaderCollection.values(for:)` and `RecordCollection.values(for:)` expose repeated fields. Unrecognized fields are retained but not made editable through the typed API.

## Password Safe interoperability

Compared against [`pwsafe/pwsafe` at `5302acb`](https://github.com/pwsafe/pwsafe/tree/5302acb15b1b598898302261ab2fa669a550a869), including the V3/V4 format descriptions and the official core reader and writer.

| Format | Read/write scope | Verified against upstream core |
| --- | --- | --- |
| V3 | V3 major version, including the original four-byte version field. New files use `0x0311` and at least 327,680 SHA-256 rounds. The V3 MAC covers field values, not field type or length. | The official core read both a newly created PSafeKit database and an official `0x0311` database after editing and changing its passphrase in PSafeKit. Covers UTF-8, UUIDs, unknown fields, repeated empty groups, aliases, shortcuts, and inline attachment bytes. Older `0x030D` fixtures are covered by the package suite. |
| V4 | Twofish database container for versions through `0x0402`; verified key blocks, entries, aliases, shortcuts, and independent attachment records. Changing the active passphrase preserves other key blocks. | The official core read a newly created PSafeKit database with an independent attachment. For an official `0x0402` database edited and re-saved by PSafeKit, the core accepted the replacement and second passphrases, rejected the old passphrase, and verified attachment bytes and references. |

The input KDF work is bounded to avoid unbounded work from untrusted files: V3 accepts at most 10,000,000 rounds; V4 accepts 64 recipients, at most 2,097,152 rounds per recipient and 4,194,304 total, and up to 16 MiB per regular field. V4 attachment ciphertext is handled separately but the database itself is in memory. Unsupported V4 record kinds or unsupported versions are rejected instead of silently dropped. V4 does not provide an API for administering additional recipients; with multiple recipients, changing one passphrase cannot rotate the shared data keys without the other passphrases. It does not revoke keys already obtained from an older copy of the database.

## Development

Run the full test suite with:

```bash
swift test
```

The optional `PSAFEKIT_UPSTREAM_FIXTURE` environment variable enables cross-implementation tests using the [fixture driver](Tests/Interop/upstream-fixture.cpp) linked against the pinned official core. See [build instructions](Tests/Interop/README.md).

## Repository Layout

- `Sources/PSafeKit`: Swift library source
- `Tests/PSafeKitTests`: package tests and `.psafe3` test resources
