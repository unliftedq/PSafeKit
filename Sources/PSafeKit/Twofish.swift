import Foundation

enum TwofishError: Error {
    case invalidKeySize
    case invalidIVSize
    case invalidDataLength
}

struct Twofish {
    enum Mode {
        case ecb
        case cbc(iv: [UInt8])
    }

    init(key: [UInt8]) throws {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw TwofishError.invalidKeySize
        }

        self.keyWords = stride(from: 0, to: key.count, by: 4).map { offset in
            leWord(from: key, offset: offset)
        }
        let schedule = Self.makeKeySchedule(keyWords: keyWords)
        self.sBoxKeys = schedule.sBoxKeys
        self.subKeys = schedule.subKeys
    }

    func encrypt(_ data: [UInt8], mode: Mode) throws -> [UInt8] {
        guard data.count.isMultiple(of: 16) else { throw TwofishError.invalidDataLength }
        var output = Array(repeating: UInt8(0), count: data.count)

        switch mode {
        case .ecb:
            var cbcState: [UInt32]? = nil
            for offset in stride(from: 0, to: data.count, by: 16) {
                encryptBlock(input: data, inputOffset: offset, output: &output, outputOffset: offset, cbcState: &cbcState)
            }
        case let .cbc(iv):
            guard iv.count == 16 else { throw TwofishError.invalidIVSize }
            var cbcState: [UInt32]? = words(from: iv)
            for offset in stride(from: 0, to: data.count, by: 16) {
                encryptBlock(input: data, inputOffset: offset, output: &output, outputOffset: offset, cbcState: &cbcState)
            }
        }

        return output
    }

    func decrypt(_ data: [UInt8], mode: Mode) throws -> [UInt8] {
        guard data.count.isMultiple(of: 16) else { throw TwofishError.invalidDataLength }
        var output = Array(repeating: UInt8(0), count: data.count)

        switch mode {
        case .ecb:
            var cbcState: [UInt32]? = nil
            for offset in stride(from: 0, to: data.count, by: 16) {
                decryptBlock(input: data, inputOffset: offset, output: &output, outputOffset: offset, cbcState: &cbcState)
            }
        case let .cbc(iv):
            guard iv.count == 16 else { throw TwofishError.invalidIVSize }
            var cbcState: [UInt32]? = words(from: iv)
            for offset in stride(from: 0, to: data.count, by: 16) {
                decryptBlock(input: data, inputOffset: offset, output: &output, outputOffset: offset, cbcState: &cbcState)
            }
        }

        return output
    }

    private let keyWords: [UInt32]
    private let sBoxKeys: [UInt32]
    private let subKeys: [UInt32]

    private static func makeKeySchedule(keyWords: [UInt32]) -> (sBoxKeys: [UInt32], subKeys: [UInt32]) {
        let key64Count = keyWords.count / 2
        var even = Array(repeating: UInt32(0), count: key64Count)
        var odd = Array(repeating: UInt32(0), count: key64Count)
        var sBoxKeys = Array(repeating: UInt32(0), count: 4)

        for index in 0..<key64Count {
            even[index] = keyWords[2 * index]
            odd[index] = keyWords[2 * index + 1]
            sBoxKeys[key64Count - 1 - index] = reedSolomonMdsEncode(even[index], odd[index])
        }

        var subKeys = Array(repeating: UInt32(0), count: 40)
        let keyLengthBits = keyWords.count * 32
        for index in 0..<(40 / 2) {
            let a = f32(UInt32(index) &* 0x02020202, keyWords: even, keyLengthBits: keyLengthBits)
            var b = f32(UInt32(index) &* 0x02020202 &+ 0x01010101, keyWords: odd, keyLengthBits: keyLengthBits)
            b = b.rotateLeft(8)
            subKeys[2 * index] = a &+ b
            subKeys[2 * index + 1] = (a &+ (2 &* b)).rotateLeft(9)
        }

        return (sBoxKeys, subKeys)
    }

    private func encryptBlock(input: [UInt8], inputOffset: Int, output: inout [UInt8], outputOffset: Int, cbcState: inout [UInt32]?) {
        var x = Array(repeating: UInt32(0), count: 4)
        for index in 0..<4 {
            x[index] = leWord(from: input, offset: inputOffset + index * 4) ^ subKeys[index]
            if cbcState != nil {
                x[index] ^= cbcState![index]
            }
        }

        let keyLengthBits = keyWords.count * 32
        for round in 0..<16 {
            let t0 = f32(x[0], keyWords: sBoxKeys, keyLengthBits: keyLengthBits)
            let t1 = f32(x[1].rotateLeft(8), keyWords: sBoxKeys, keyLengthBits: keyLengthBits)

            x[3] = x[3].rotateLeft(1)
            x[2] ^= t0 &+ t1 &+ subKeys[8 + 2 * round]
            x[3] ^= t0 &+ (2 &* t1) &+ subKeys[8 + 2 * round + 1]
            x[2] = x[2].rotateRight(1)

            if round < 15 {
                x.swapAt(0, 2)
                x.swapAt(1, 3)
            }
        }

        for index in 0..<4 {
            let outValue = x[index] ^ subKeys[4 + index]
            writeLEWord(outValue, to: &output, offset: outputOffset + index * 4)
            if cbcState != nil {
                cbcState![index] = outValue
            }
        }
    }

    private func decryptBlock(input: [UInt8], inputOffset: Int, output: inout [UInt8], outputOffset: Int, cbcState: inout [UInt32]?) {
        var x = Array(repeating: UInt32(0), count: 4)
        var encrypted = Array(repeating: UInt32(0), count: 4)

        for index in 0..<4 {
            encrypted[index] = leWord(from: input, offset: inputOffset + index * 4)
            x[index] = encrypted[index] ^ subKeys[4 + index]
        }

        let keyLengthBits = keyWords.count * 32
        for round in stride(from: 15, through: 0, by: -1) {
            let t0 = f32(x[0], keyWords: sBoxKeys, keyLengthBits: keyLengthBits)
            let t1 = f32(x[1].rotateLeft(8), keyWords: sBoxKeys, keyLengthBits: keyLengthBits)

            x[2] = x[2].rotateLeft(1)
            x[2] ^= t0 &+ t1 &+ subKeys[8 + 2 * round]
            x[3] ^= t0 &+ (2 &* t1) &+ subKeys[8 + 2 * round + 1]
            x[3] = x[3].rotateRight(1)

            if round > 0 {
                x.swapAt(0, 2)
                x.swapAt(1, 3)
            }
        }

        for index in 0..<4 {
            var outValue = x[index] ^ subKeys[index]
            if cbcState != nil {
                outValue ^= cbcState![index]
                cbcState![index] = encrypted[index]
            }
            writeLEWord(outValue, to: &output, offset: outputOffset + index * 4)
        }
    }
}

private let p8x8: [[UInt8]] = [
    [
        0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
        0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
        0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
        0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
        0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
        0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
        0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
        0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
        0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
        0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
        0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
        0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
        0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
        0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
        0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
        0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
    ],
    [
        0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
        0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
        0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
        0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
        0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
        0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
        0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
        0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
        0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
        0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
        0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
        0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
        0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
        0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
        0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
        0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
    ]
]

private let mdsTable: [[UInt32]] = {
    var table = Array(repeating: Array(repeating: UInt32(0), count: 256), count: 4)
    for index in 0..<256 {
        let m10 = p8x8[0][index]
        let m11 = p8x8[1][index]
        let mx0 = UInt8(mulX(UInt32(m10)))
        let mx1 = UInt8(mulX(UInt32(m11)))
        let my0 = UInt8(mulY(UInt32(m10)))
        let my1 = UInt8(mulY(UInt32(m11)))

        table[0][index] = composeWord(m11, mx1, my1, my1)
        table[1][index] = composeWord(my0, my0, mx0, m10)
        table[2][index] = composeWord(mx1, my1, m11, my1)
        table[3][index] = composeWord(mx0, m10, my0, mx0)
    }
    return table
}()

private func f32(_ value: UInt32, keyWords: [UInt32], keyLengthBits: Int) -> UInt32 {
    var b0 = byte0(value)
    var b1 = byte1(value)
    var b2 = byte2(value)
    var b3 = byte3(value)

    if keyLengthBits >= 256 {
        b0 = p8x8[1][Int(b0)] ^ byte0(keyWords[3])
        b1 = p8x8[0][Int(b1)] ^ byte1(keyWords[3])
        b2 = p8x8[0][Int(b2)] ^ byte2(keyWords[3])
        b3 = p8x8[1][Int(b3)] ^ byte3(keyWords[3])
    }
    if keyLengthBits >= 192 {
        b0 = p8x8[1][Int(b0)] ^ byte0(keyWords[2])
        b1 = p8x8[1][Int(b1)] ^ byte1(keyWords[2])
        b2 = p8x8[0][Int(b2)] ^ byte2(keyWords[2])
        b3 = p8x8[0][Int(b3)] ^ byte3(keyWords[2])
    }
    if keyLengthBits >= 128 {
        return mdsTable[0][Int(p8x8[0][Int(p8x8[0][Int(b0)] ^ byte0(keyWords[1]))] ^ byte0(keyWords[0]))]
            ^ mdsTable[1][Int(p8x8[0][Int(p8x8[1][Int(b1)] ^ byte1(keyWords[1]))] ^ byte1(keyWords[0]))]
            ^ mdsTable[2][Int(p8x8[1][Int(p8x8[0][Int(b2)] ^ byte2(keyWords[1]))] ^ byte2(keyWords[0]))]
            ^ mdsTable[3][Int(p8x8[1][Int(p8x8[1][Int(b3)] ^ byte3(keyWords[1]))] ^ byte3(keyWords[0]))]
    }

    return value
}

private func reedSolomonMdsEncode(_ k0: UInt32, _ k1: UInt32) -> UInt32 {
    var result: UInt32 = 0
    for index in 0..<2 {
        result ^= index > 0 ? k0 : k1
        for _ in 0..<4 {
            let b = UInt8((result >> 24) & 0xFF)
            let g2 = UInt8((UInt32(b) << 1) ^ (((b & 0x80) != 0) ? 0x14D : 0))
            let g3 = UInt8(((UInt32(b) >> 1) & 0x7F) ^ (((b & 0x01) != 0) ? (0x14D >> 1) : 0) ^ UInt32(g2))
            result = composeWord(b, byte0(result) ^ g3, byte1(result) ^ g2, byte2(result) ^ g3)
        }
    }
    return result
}

private func mulX(_ x: UInt32) -> UInt32 {
    x ^ lfsr2(x)
}

private func mulY(_ x: UInt32) -> UInt32 {
    x ^ lfsr1(x) ^ lfsr2(x)
}

private func lfsr1(_ x: UInt32) -> UInt32 {
    (x >> 1) ^ (((x & 0x01) != 0) ? (0x169 / 2) : 0)
}

private func lfsr2(_ x: UInt32) -> UInt32 {
    (x >> 2) ^ (((x & 0x02) != 0) ? (0x169 / 2) : 0) ^ (((x & 0x01) != 0) ? (0x169 / 4) : 0)
}

private func composeWord(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8) -> UInt32 {
    UInt32(b0) | (UInt32(b1) << 8) | (UInt32(b2) << 16) | (UInt32(b3) << 24)
}

private func leWord(from bytes: [UInt8], offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | (UInt32(bytes[offset + 1]) << 8)
        | (UInt32(bytes[offset + 2]) << 16)
        | (UInt32(bytes[offset + 3]) << 24)
}

private func writeLEWord(_ value: UInt32, to bytes: inout [UInt8], offset: Int) {
    bytes[offset] = byte0(value)
    bytes[offset + 1] = byte1(value)
    bytes[offset + 2] = byte2(value)
    bytes[offset + 3] = byte3(value)
}

private func words(from bytes: [UInt8]) -> [UInt32] {
    stride(from: 0, to: bytes.count, by: 4).map { offset in leWord(from: bytes, offset: offset) }
}

private func byte0(_ value: UInt32) -> UInt8 { UInt8(value & 0xFF) }
private func byte1(_ value: UInt32) -> UInt8 { UInt8((value >> 8) & 0xFF) }
private func byte2(_ value: UInt32) -> UInt8 { UInt8((value >> 16) & 0xFF) }
private func byte3(_ value: UInt32) -> UInt8 { UInt8((value >> 24) & 0xFF) }

private extension UInt32 {
    func rotateLeft(_ count: UInt32) -> UInt32 {
        (self << count) | (self >> (32 - count))
    }

    func rotateRight(_ count: UInt32) -> UInt32 {
        (self >> count) | (self << (32 - count))
    }
}