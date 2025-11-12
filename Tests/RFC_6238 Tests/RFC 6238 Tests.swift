//
//  RFC 6238 Tests.swift
//  swift-rfc-6238
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Testing
import Foundation
@testable import RFC_6238
#if canImport(CryptoKit)
import CryptoKit
#endif

@Suite("RFC 6238 Tests")
struct RFC6238Tests {
    
    // MARK: - Test HMAC Provider
    
    /// Mock HMAC provider for testing without crypto dependencies
    /// Uses test vectors from RFC 6238 Appendix B
    struct TestHMACProvider: RFC_6238.HMACProvider {
        func hmac(algorithm: RFC_6238.Algorithm, key: Data, data: Data) -> Data {
            // For testing, we'll return pre-computed HMAC values from RFC 6238
            // This allows us to test the TOTP logic without a real HMAC implementation
            
            // Test vector secret (ASCII "12345678901234567890" repeated)
            let testSecret20 = "12345678901234567890".data(using: .ascii)!
            let testSecret32 = "12345678901234567890123456789012".data(using: .ascii)!
            let testSecret64 = "1234567890123456789012345678901234567890123456789012345678901234".data(using: .ascii)!
            
            // Check if this is one of our test vectors
            if key == testSecret20 && algorithm == .sha1 {
                // SHA1 test vectors from RFC 6238
                switch data.hexString {
                case "0000000000000001": // T = 1 (59 seconds)
                    return Data(hex: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")!
                case "00000000023523ec": // T = 37037036 
                    return Data(hex: "75a48a19d4cbe100644e8ac1397eea747a2d33ab")!
                case "00000000023523ed": // T = 37037037
                    return Data(hex: "0bacb7fa082fef30782211938bc1c5e70416ff44")!
                case "000000000273ef07": // T = 41152263
                    return Data(hex: "66c28227d03a2d5529262ff016a1e6ef76557ece")!
                case "0000000003f940aa": // T = 66666666
                    return Data(hex: "a904c900a64b35909874b33e61c5938a8e15ed1c")!
                case "0000000027bc86aa": // T = 666666666
                    return Data(hex: "a37e783d7b7233c083d4f62926c7a25f238d0316")!
                default:
                    break
                }
            }
            
            if key == testSecret32 && algorithm == .sha256 {
                // SHA256 test vectors
                switch data.hexString {
                case "0000000000000001":
                    return Data(hex: "32855612b2e7b6c0e4d8c43df51a652d154923670e93e532e299b8a13221fe6e")!
                case "00000000023523ec":
                    return Data(hex: "15266d14b4f62db7262dfbc09e5513998ff0bc1eede1507fae5e6161871cd524")!
                case "00000000023523ed":
                    return Data(hex: "055fceb559018c3db87308e6527cf765c6840b9990e1187797a079c9b48fe40e")!
                case "000000000273ef07":
                    return Data(hex: "11e65e295cf1dd27e701ccfd85a7f8e5b3c6424872c6d01a31e0729802ab72f3")!
                case "0000000003f940aa":
                    return Data(hex: "1c5129c7e7a56b71bc1dc7c30ab95e3c435c43e5e4c6eb23e17dcb5bb0b71019")!
                case "0000000027bc86aa":
                    return Data(hex: "99943326369823477794969992ceadb8cd34e20b91aa72e16e86efae37070e08")!
                default:
                    break
                }
            }
            
            if key == testSecret64 && algorithm == .sha512 {
                // SHA512 test vectors
                switch data.hexString {
                case "0000000000000001":
                    return Data(hex: "8efdc1305ac578a13ce1b2ec01eeb7b7e809aba9fd91229e4035793adde34e71ac089f3deea7c9ae37dd4f1e73713bc3e6ac96b70fcd3e8a5f9df96f7c8bc7a0")!
                case "00000000023523ec":
                    return Data(hex: "3213629ed04e6d2662f0dd88fbdf616ea00c6a684b9d5749eb928f23ebfc7867fc0a529e6c76c66f05fe29f92faa833e3ab5e72e7fbb488e30c15b3e8d9dc58b")!
                case "00000000023523ed":
                    return Data(hex: "e37709e104e4932bc592c85c32e094c839ba8f996c3e0ad9e22dd66e58af4b7fb2bb4e7f22c58a0e67a5730c45be89c75e87faaeff2e646b567a0797b413e618")!
                case "000000000273ef07":
                    return Data(hex: "2bde459bd53f8450f16a5c23afb699d7eb87fc387b96e039bb931f87c6f40008a12dd71d853c929a95e0159cf8fdcded6fb12e699c4616ba43f9ab965ee17199")!
                case "0000000003f940aa":
                    return Data(hex: "785472e4fb55b1a8c8c740e26b0df190a3ddacf768fcb18fb4959dc6e9103bb9b16e69b2eb7b103b95cfb6aa1dcb0fe16e7761f6f656727f616f9f4dce2e440f")!
                case "0000000027bc86aa":
                    return Data(hex: "77376e28618f2b82c5beab4d525b036e106e25d4e0431e779b8e1dd67a2e5b062f0fd785ba95e37311e54ad5d06b5f3e9ac3f5eb1a7bec6f03dc7a08a5e77b6e")!
                default:
                    break
                }
            }

            // Fall back to actual HMAC for test cases not in our known vectors
            #if canImport(CryptoKit)
            switch algorithm {
            case .sha1:
                return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key)))
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
            case .sha512:
                return Data(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
            }
            #else
            fatalError("Unknown test vector and CryptoKit not available: key=\(key.hexString), algorithm=\(algorithm), data=\(data.hexString)")
            #endif
        }
    }
    
    // MARK: - RFC 6238 Test Vectors
    
    @Test("RFC 6238 Test Vectors - SHA1")
    func testRFC6238TestVectorsSHA1() throws {
        // Test vectors from RFC 6238 Appendix B
        let secret = "12345678901234567890".data(using: .ascii)!
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha1,
            t0: 0
        )
        
        let testCases: [(Date, String)] = [
            (Date(timeIntervalSince1970: 59), "94287082"),
            (Date(timeIntervalSince1970: 1111111109), "07081804"),
            (Date(timeIntervalSince1970: 1111111111), "14050471"),
            (Date(timeIntervalSince1970: 1234567890), "89005924"),
            (Date(timeIntervalSince1970: 2000000000), "69279037"),
            (Date(timeIntervalSince1970: 20000000000), "65353130")
        ]
        
        let provider = TestHMACProvider()
        
        for (time, expected) in testCases {
            let generated = totp.generate(at: time, using: provider)
            #expect(generated == expected)
        }
    }
    
    @Test("RFC 6238 Test Vectors - SHA256")
    func testRFC6238TestVectorsSHA256() throws {
        // Test vectors from RFC 6238 Appendix B
        let secret = "12345678901234567890123456789012".data(using: .ascii)!
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha256,
            t0: 0
        )
        
        let testCases: [(Date, String)] = [
            (Date(timeIntervalSince1970: 59), "46119246"),
            (Date(timeIntervalSince1970: 1111111109), "68084774"),
            (Date(timeIntervalSince1970: 1111111111), "67062674"),
            (Date(timeIntervalSince1970: 1234567890), "91819424"),
            (Date(timeIntervalSince1970: 2000000000), "90698825"),
            (Date(timeIntervalSince1970: 20000000000), "77737706")
        ]
        
        let provider = TestHMACProvider()
        
        for (time, expected) in testCases {
            let generated = totp.generate(at: time, using: provider)
            #expect(generated == expected)
        }
    }
    
    @Test("RFC 6238 Test Vectors - SHA512")
    func testRFC6238TestVectorsSHA512() throws {
        // Test vectors from RFC 6238 Appendix B
        let secret = "1234567890123456789012345678901234567890123456789012345678901234".data(using: .ascii)!
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha512,
            t0: 0
        )
        
        let testCases: [(Date, String)] = [
            (Date(timeIntervalSince1970: 59), "90693936"),
            (Date(timeIntervalSince1970: 1111111109), "25091201"),
            (Date(timeIntervalSince1970: 1111111111), "99943326"),
            (Date(timeIntervalSince1970: 1234567890), "93441116"),
            (Date(timeIntervalSince1970: 2000000000), "38618901"),
            (Date(timeIntervalSince1970: 20000000000), "47863826")
        ]
        
        let provider = TestHMACProvider()
        
        for (time, expected) in testCases {
            let generated = totp.generate(at: time, using: provider)
            #expect(generated == expected)
        }
    }
    
    // MARK: - Base32 Tests
    
    @Test("Base32 Encoding")
    func testBase32Encoding() {
        let testCases: [(String, String)] = [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
            ("Hello World", "JBSWY3DPEBLW64TMMQ======")
        ]
        
        for (input, expected) in testCases {
            let data = input.data(using: .utf8)!
            let encoded = data.base32EncodedString()
            #expect(encoded == expected)
        }
    }
    
    @Test("Base32 Decoding")
    func testBase32Decoding() {
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
            ("MZXW-6YTB-OI", "foobar")
        ]
        
        for (input, expected) in testCases {
            guard let decoded = Data(base32Encoded: input) else {
                Issue.record("Failed to decode base32 string: '\(input)'")
                continue
            }
            let decodedString = String(data: decoded, encoding: .utf8) ?? ""
            #expect(decodedString == expected)
        }
    }
    
    @Test("Base32 Round Trip")
    func testBase32RoundTrip() {
        let testStrings = [
            "Hello, World!",
            "The quick brown fox jumps over the lazy dog",
            "1234567890",
            "!@#$%^&*()",
            "🎉 Unicode test 測試 テスト"
        ]
        
        for testString in testStrings {
            let originalData = testString.data(using: .utf8)!
            let encoded = originalData.base32EncodedString()
            guard let decoded = Data(base32Encoded: encoded) else {
                Issue.record("Failed to decode base32 for round trip: '\(testString)'")
                continue
            }
            #expect(originalData == decoded)
        }
    }
    
    // MARK: - TOTP Configuration Tests
    
    @Test("TOTP Initialization")
    func testTOTPInitialization() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let totp = try RFC_6238.TOTP(base32Secret: secret)
        
        #expect(totp.timeStep == 30)
        #expect(totp.digits == 6)
        #expect(totp.algorithm == .sha1)
        #expect(totp.t0 == 0)
    }
    
    @Test("TOTP Provisioning URI")
    func testTOTPProvisioningURI() throws {
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
    
    @Test("Time Counter Calculation")
    func testTimeCounter() throws {
        let secret = Data(repeating: 0, count: 20)
        let totp = try RFC_6238.TOTP(secret: secret, timeStep: 30)
        
        // Test specific time values
        #expect(totp.counter(at: Date(timeIntervalSince1970: 0)) == 0)
        #expect(totp.counter(at: Date(timeIntervalSince1970: 29)) == 0)
        #expect(totp.counter(at: Date(timeIntervalSince1970: 30)) == 1)
        #expect(totp.counter(at: Date(timeIntervalSince1970: 59)) == 1)
        #expect(totp.counter(at: Date(timeIntervalSince1970: 60)) == 2)
        #expect(totp.counter(at: Date(timeIntervalSince1970: 1111111111)) == 37037037)
    }
    
    @Test("Time Remaining Calculation")
    func testTimeRemaining() throws {
        let secret = Data(repeating: 0, count: 20)
        let totp = try RFC_6238.TOTP(secret: secret, timeStep: 30)
        
        // Test at exact boundaries
        #expect(abs(totp.timeRemaining(at: Date(timeIntervalSince1970: 0)) - 30) < 0.001)
        #expect(abs(totp.timeRemaining(at: Date(timeIntervalSince1970: 1)) - 29) < 0.001)
        #expect(abs(totp.timeRemaining(at: Date(timeIntervalSince1970: 29)) - 1) < 0.001)
        #expect(abs(totp.timeRemaining(at: Date(timeIntervalSince1970: 30)) - 30) < 0.001)
    }
    
    @Test("OTP Validation")
    func testValidation() throws {
        let secret = "12345678901234567890".data(using: .ascii)!
        let totp = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 8,
            algorithm: .sha1
        )
        
        let provider = TestHMACProvider()
        let testTime = Date(timeIntervalSince1970: 1111111111)
        
        // Test exact match
        #expect(totp.validate("14050471", at: testTime, window: 0, using: provider))
        
        // Test with window
        #expect(totp.validate("14050471", at: testTime, window: 1, using: provider))
        
        // Test invalid OTP
        #expect(!totp.validate("00000000", at: testTime, window: 1, using: provider))
    }
    
    // MARK: - Error Handling Tests
    
    @Test("TOTP Initialization Errors")
    func testTOTPInitializationErrors() {
        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.TOTP(secret: Data())
        }
        
        // Test invalid digits
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data(repeating: 0, count: 20), digits: 5)
        }
        
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data(repeating: 0, count: 20), digits: 9)
        }
        
        // Test invalid time step
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data(repeating: 0, count: 20), timeStep: 0)
        }
        
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data(repeating: 0, count: 20), timeStep: -10)
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
    
    @Test("HOTP Initialization Errors")
    func testHOTPInitializationErrors() {
        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.HOTP(secret: Data())
        }
        
        // Test invalid digits
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.HOTP(secret: Data(repeating: 0, count: 20), digits: 5)
        }
        
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.HOTP(secret: Data(repeating: 0, count: 20), digits: 9)
        }
    }
}

// MARK: - Helper Extensions

extension Data {
    init?(hex: String) {
        let hex = hex.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
    
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
