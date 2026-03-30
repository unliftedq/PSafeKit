# PSafeKit

PSafeKit is a Swift package for reading and writing Password Safe `.psafe3` files.

This repository is a Swift port of the core model and file-format behavior from C# library `Medo.PasswordSafe`, adapted to Swift Package Manager and validated with package tests.

## Status

- Swift Package Manager library: `PSafeKit`
- Swift language mode: 6
- File format currently supported: `.psafe3`
- Crypto currently implemented: Twofish, SHA-256 key stretching, HMAC-SHA256 payload authentication
- Tested behaviors include loading existing databases, saving new databases, round-tripping entries, password changes, password history, auto-type parsing, and named password policies

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

- `Document.load(data:passphrase:)` loads a `.psafe3` database from memory.
- `Document.saveData()` returns the full serialized `.psafe3` payload as `Data`.
- `Document.save()` runs the same serialization path and discards the returned `Data`.
- `Document.trackModify` controls whether save-related metadata is updated during save.
- `Document.trackAccess` exists for compatibility with document behavior, but access-tracking persistence is intentionally limited to the features currently implemented in this package.
- `Entry`, `Header`, `Record`, and their collection types keep the public surface close to the original library model.

## Development

Run the full test suite with:

```bash
swift test
```

At the time of writing, the package test suite covers 79 tests across 14 suites.

## Repository Layout

- `Sources/PSafeKit`: Swift library source
- `Tests/PSafeKitTests`: package tests and `.psafe3` test resources
