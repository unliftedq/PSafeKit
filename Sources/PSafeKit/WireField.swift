import Foundation

struct WireField: Equatable {
    let type: UInt8
    let data: Data
}

enum FieldSlot<Value> {
    case known(Value)
    case opaque(WireField)

    var known: Value? {
        if case let .known(value) = self { return value }
        return nil
    }
}
