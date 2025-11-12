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
                    return Data(hex: "75a48a19d4cbe100644e8ac1397eea747a2d33ab")!
                case "00000000023523ec": // T = 37037036
                    return Data(hex: "278c02e53610f84c40bd9135acd4101012410a14")!
                case "00000000023523ed": // T = 37037037
                    return Data(hex: "b0092b21d048af209da0a1ddd498ade8a79487ed")!
                case "000000000273ef07": // T = 41152263
                    return Data(hex: "907cd1a9116564ecb9d5d1780325f246173fe703")!
                case "0000000003f940aa": // T = 66666666
                    return Data(hex: "25a326d31fc366244cad054976020c7b56b13d5f")!
                case "0000000027bc86aa": // T = 666666666
                    return Data(hex: "ab07e97e2c1278769dbcd75783aabde75ed8550a")!
                default:
                    break
                }
            }
            
            if key == testSecret32 && algorithm == .sha256 {
                // SHA256 test vectors
                switch data.hexString {
                case "0000000000000001":
                    return Data(hex: "392514c9dd4165d4709456062c78e04e16e68718515951333bdb8b26caa3053c")!
                case "00000000023523ec":
                    return Data(hex: "4eed729864525d771326c6049bc885629fb8813ebb417e5704df02358793f056")!
                case "00000000023523ed":
                    return Data(hex: "cb48f7ef5cd98f6d7bfcb31ae7458ff692a015776205de7e1abfff29d6d48a9d")!
                case "000000000273ef07":
                    return Data(hex: "3befb8821caef9df4e05790da0966163f4e38feee7f71fcd289c3de48d3486d9")!
                case "0000000003f940aa":
                    return Data(hex: "a4e8eabbe549adfa65408945a9282cb93f394f06c0d4f122260963641bc3abe2")!
                case "0000000027bc86aa":
                    return Data(hex: "1363cc0ee3557f092e5b55ea3ddb06bcd20f063ce393ccf670059e3ca44941f8")!
                default:
                    break
                }
            }
            
            if key == testSecret64 && algorithm == .sha512 {
                // SHA512 test vectors
                switch data.hexString {
                case "0000000000000001":
                    return Data(hex: "6f76f324230cefda1d3f65309a0badb36efce9528ada64967d71e4e9d74c4aa37fe7650f931ab86ddccc2d38962d720ee626a20feb311b485a92e3bb0796df28")!
                case "00000000023523ec":
                    return Data(hex: "b3381250260d6a9e811ae58dfa406705e38c804c97528d5a7ed8ee533331f8c43cc3454911ad1d2761f9380170c0b180a657e3a944c796e05d09f2d1630b7505")!
                case "00000000023523ed":
                    return Data(hex: "01713ed59e49948a4f0fffb7466baebac66362d90764a5a23df761636e1535c44b635339ec00a789b8ca45cd3d727acd6b995047547f6f68adc6f16a7436c331")!
                case "000000000273ef07":
                    return Data(hex: "87d0cfb5d4e968d7d9041a5cf21dd7d460705784004f0244edb98004e6cf9942ace539d621c97dc0fb75f6f10d64af1f09ecae83ea7f1213c7fa187dfaf6b938")!
                case "0000000003f940aa":
                    return Data(hex: "129baa738cfa1565a24297237bce282671ff6e261754eb7011e1e75bd2555b326313142a1f9fe2f31d9ce6cc95d3b16a0dee56f2492f2f76885702d98bfadc93")!
                case "0000000027bc86aa":
                    return Data(hex: "562298a02af13e7522127adee3dc6678d53669ca2b7016186968f9a9c14f51d1e7098ba91293a01b5f3bab4207a2af5ce332a45f2c2ff2b9885aa42ff61cb426")!
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
