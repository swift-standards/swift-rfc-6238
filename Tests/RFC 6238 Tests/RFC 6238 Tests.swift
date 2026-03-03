// RFC 6238 Tests.swift
// swift-rfc-6238

import Testing

@testable import RFC_6238

@Suite
struct `RFC 6238 Tests` {

    // MARK: - Test HMAC Provider

    /// Mock HMAC provider for testing without crypto dependencies
    /// Uses test vectors from RFC 6238 Appendix B
    struct TestHMACProvider: RFC_6238.HMACProvider {
        func hmac(algorithm: RFC_6238.Algorithm, key: [UInt8], data: [UInt8]) -> [UInt8] {
            let testSecret20 = Array("12345678901234567890".utf8)
            let testSecret32 = Array("12345678901234567890123456789012".utf8)
            let testSecret64 = Array(
                "1234567890123456789012345678901234567890123456789012345678901234".utf8
            )

            if key == testSecret20 && algorithm == .sha1 {
                switch hexString(data) {
                case "0000000000000001":
                    return hexBytes("75a48a19d4cbe100644e8ac1397eea747a2d33ab")!
                case "00000000023523ec":
                    return hexBytes("278c02e53610f84c40bd9135acd4101012410a14")!
                case "00000000023523ed":
                    return hexBytes("b0092b21d048af209da0a1ddd498ade8a79487ed")!
                case "00000000023523ee":
                    return hexBytes("1c305c9694851807300bc28967778ed3db135a74")!
                case "000000000273ef07":
                    return hexBytes("907cd1a9116564ecb9d5d1780325f246173fe703")!
                case "0000000003f940aa":
                    return hexBytes("25a326d31fc366244cad054976020c7b56b13d5f")!
                case "0000000027bc86aa":
                    return hexBytes("ab07e97e2c1278769dbcd75783aabde75ed8550a")!
                default:
                    break
                }
            }

            if key == testSecret32 && algorithm == .sha256 {
                switch hexString(data) {
                case "0000000000000001":
                    return hexBytes(
                        "392514c9dd4165d4709456062c78e04e16e68718515951333bdb8b26caa3053c"
                    )!
                case "00000000023523ec":
                    return hexBytes(
                        "4eed729864525d771326c6049bc885629fb8813ebb417e5704df02358793f056"
                    )!
                case "00000000023523ed":
                    return hexBytes(
                        "cb48f7ef5cd98f6d7bfcb31ae7458ff692a015776205de7e1abfff29d6d48a9d"
                    )!
                case "000000000273ef07":
                    return hexBytes(
                        "3befb8821caef9df4e05790da0966163f4e38feee7f71fcd289c3de48d3486d9"
                    )!
                case "0000000003f940aa":
                    return hexBytes(
                        "a4e8eabbe549adfa65408945a9282cb93f394f06c0d4f122260963641bc3abe2"
                    )!
                case "0000000027bc86aa":
                    return hexBytes(
                        "1363cc0ee3557f092e5b55ea3ddb06bcd20f063ce393ccf670059e3ca44941f8"
                    )!
                default:
                    break
                }
            }

            if key == testSecret64 && algorithm == .sha512 {
                switch hexString(data) {
                case "0000000000000001":
                    return hexBytes(
                        "6f76f324230cefda1d3f65309a0badb36efce9528ada64967d71e4e9d74c4aa37fe7650f931ab86ddccc2d38962d720ee626a20feb311b485a92e3bb0796df28"
                    )!
                case "00000000023523ec":
                    return hexBytes(
                        "b3381250260d6a9e811ae58dfa406705e38c804c97528d5a7ed8ee533331f8c43cc3454911ad1d2761f9380170c0b180a657e3a944c796e05d09f2d1630b7505"
                    )!
                case "00000000023523ed":
                    return hexBytes(
                        "01713ed59e49948a4f0fffb7466baebac66362d90764a5a23df761636e1535c44b635339ec00a789b8ca45cd3d727acd6b995047547f6f68adc6f16a7436c331"
                    )!
                case "000000000273ef07":
                    return hexBytes(
                        "87d0cfb5d4e968d7d9041a5cf21dd7d460705784004f0244edb98004e6cf9942ace539d621c97dc0fb75f6f10d64af1f09ecae83ea7f1213c7fa187dfaf6b938"
                    )!
                case "0000000003f940aa":
                    return hexBytes(
                        "129baa738cfa1565a24297237bce282671ff6e261754eb7011e1e75bd2555b326313142a1f9fe2f31d9ce6cc95d3b16a0dee56f2492f2f76885702d98bfadc93"
                    )!
                case "0000000027bc86aa":
                    return hexBytes(
                        "562298a02af13e7522127adee3dc6678d53669ca2b7016186968f9a9c14f51d1e7098ba91293a01b5f3bab4207a2af5ce332a45f2c2ff2b9885aa42ff61cb426"
                    )!
                default:
                    break
                }
            }

            fatalError(
                "Unknown test vector: key=\(hexString(key)), algorithm=\(algorithm), data=\(hexString(data))"
            )
        }
    }

    // MARK: - RFC 6238 Test Vectors

    @Test
    func `RFC 6238 Test Vectors - SHA1`() throws {
        let secret = Array("12345678901234567890".utf8)
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha1,
            t0: 0
        )

        let testCases: [(Double, String)] = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ]

        let provider = TestHMACProvider()

        for (unixTime, expected) in testCases {
            let generated = totp.generate(at: unixTime, using: provider)
            #expect(generated == expected)
        }
    }

    @Test
    func `RFC 6238 Test Vectors - SHA256`() throws {
        let secret = Array("12345678901234567890123456789012".utf8)
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha256,
            t0: 0
        )

        let testCases: [(Double, String)] = [
            (59, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ]

        let provider = TestHMACProvider()

        for (unixTime, expected) in testCases {
            let generated = totp.generate(at: unixTime, using: provider)
            #expect(generated == expected)
        }
    }

    @Test
    func `RFC 6238 Test Vectors - SHA512`() throws {
        let secret = Array(
            "1234567890123456789012345678901234567890123456789012345678901234".utf8
        )
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha512,
            t0: 0
        )

        let testCases: [(Double, String)] = [
            (59, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ]

        let provider = TestHMACProvider()

        for (unixTime, expected) in testCases {
            let generated = totp.generate(at: unixTime, using: provider)
            #expect(generated == expected)
        }
    }

    // MARK: - Base32 Tests

    @Test
    func `Base32 Encoding`() {
        let testCases: [(String, String)] = [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
            ("Hello World", "JBSWY3DPEBLW64TMMQ======"),
        ]

        for (input, expected) in testCases {
            let bytes = Array(input.utf8)
            let encoded = RFC_6238.Base32.encode(bytes)
            #expect(encoded == expected)
        }
    }

    @Test
    func `Base32 Decoding`() {
        let testCases: [(String, String)] = [
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
            ("JBSWY3DPEBLW64TMMQ======", "Hello World"),
            // Test without padding
            ("MZXW6YTBOI", "foobar"),
            // Test with spaces and dashes (should be handled)
            ("MZXW 6YTB OI", "foobar"),
            ("MZXW-6YTB-OI", "foobar"),
        ]

        for (input, expected) in testCases {
            guard let decoded = RFC_6238.Base32.decode(input) else {
                Issue.record("Failed to decode base32 string: '\(input)'")
                continue
            }
            let decodedString = String(decoding: decoded, as: UTF8.self)
            #expect(decodedString == expected)
        }
    }

    @Test
    func `Base32 Round Trip`() {
        let testStrings = [
            "Hello, World!",
            "The quick brown fox jumps over the lazy dog",
            "1234567890",
            "!@#$%^&*()",
        ]

        for testString in testStrings {
            let originalBytes = Array(testString.utf8)
            let encoded = RFC_6238.Base32.encode(originalBytes)
            guard let decoded = RFC_6238.Base32.decode(encoded) else {
                Issue.record("Failed to decode base32 for round trip: '\(testString)'")
                continue
            }
            #expect(originalBytes == decoded)
        }
    }

    // MARK: - TOTP Configuration Tests

    @Test
    func `TOTP Initialization`() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let totp = try RFC_6238.TOTP(base32Secret: secret)

        #expect(totp.timeStep == 30)
        #expect(totp.digits == 6)
        #expect(totp.algorithm == .sha1)
        #expect(totp.t0 == 0)
    }

    @Test
    func `TOTP Provisioning URI`() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let totp = try RFC_6238.TOTP(base32Secret: secret, digits: 6, algorithm: .sha256)

        let uri = totp.provisioningURI(label: "user@example.com", issuer: "Example Corp")

        #expect(uri.contains("otpauth://totp/"))
        #expect(uri.contains("user@example.com"))
        #expect(uri.contains("secret=JBSWY3DPEHPK3PXP"))
        #expect(uri.contains("algorithm=SHA256"))
        #expect(uri.contains("digits=6"))
        #expect(uri.contains("period=30"))
        #expect(uri.contains("issuer=Example%20Corp"))
    }

    @Test
    func `Time Counter Calculation`() throws {
        let secret = [UInt8](repeating: 0, count: 20)
        let totp = try RFC_6238.TOTP(secret: secret, timeStep: 30)

        #expect(totp.counter(at: 0) == 0)
        #expect(totp.counter(at: 29) == 0)
        #expect(totp.counter(at: 30) == 1)
        #expect(totp.counter(at: 59) == 1)
        #expect(totp.counter(at: 60) == 2)
        #expect(totp.counter(at: 1_111_111_111) == 37_037_037)
    }

    @Test
    func `Time Remaining Calculation`() throws {
        let secret = [UInt8](repeating: 0, count: 20)
        let totp = try RFC_6238.TOTP(secret: secret, timeStep: 30)

        #expect(abs(totp.timeRemaining(at: 0) - 30) < 0.001)
        #expect(abs(totp.timeRemaining(at: 1) - 29) < 0.001)
        #expect(abs(totp.timeRemaining(at: 29) - 1) < 0.001)
        #expect(abs(totp.timeRemaining(at: 30) - 30) < 0.001)
    }

    @Test
    func `OTP Validation`() throws {
        let secret = Array("12345678901234567890".utf8)
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha1
        )

        let provider = TestHMACProvider()
        let testTime: Double = 1_111_111_111

        // Test exact match
        #expect(totp.validate("14050471", at: testTime, window: 0, using: provider))

        // Test with window
        #expect(totp.validate("14050471", at: testTime, window: 1, using: provider))

        // Test invalid OTP
        #expect(!totp.validate("00000000", at: testTime, window: 1, using: provider))
    }

    // MARK: - Error Handling Tests

    @Test
    func `TOTP Initialization Errors`() {
        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.TOTP(secret: [])
        }

        // Test invalid digits
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: [UInt8](repeating: 0, count: 20), digits: 5)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: [UInt8](repeating: 0, count: 20), digits: 9)
        }

        // Test invalid time step
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: [UInt8](repeating: 0, count: 20), timeStep: 0)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: [UInt8](repeating: 0, count: 20), timeStep: -10)
        }

        // Test invalid base32
        #expect(throws: RFC_6238.Error.invalidBase32String) {
            _ = try RFC_6238.TOTP(base32Secret: "INVALID!@#$%")
        }

        // Test empty base32
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(base32Secret: "")
        }
    }

    @Test
    func `HOTP Initialization Errors`() {
        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.HOTP(secret: [])
        }

        // Test invalid digits
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.HOTP(secret: [UInt8](repeating: 0, count: 20), digits: 5)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.HOTP(secret: [UInt8](repeating: 0, count: 20), digits: 9)
        }
    }
}

// MARK: - Hex Helpers

private func hexBytes(_ hex: String) -> [UInt8]? {
    guard hex.count % 2 == 0 else { return nil }

    var result = [UInt8]()
    var index = hex.startIndex

    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
        result.append(byte)
        index = nextIndex
    }

    return result
}

private let hexChars: [Character] = Array("0123456789abcdef")

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { byte in
        String(hexChars[Int(byte >> 4)]) + String(hexChars[Int(byte & 0x0F)])
    }.joined()
}
