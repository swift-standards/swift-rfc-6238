// ReadmeVerificationTests.swift
// swift-rfc-6238
//
// Verifies that README code examples actually work

import RFC_6238
import Testing

#if canImport(CryptoKit)
    import CryptoKit
#endif

@Suite
struct `README Verification` {

    #if canImport(CryptoKit)
        struct CryptoKitHMACProvider: RFC_6238.HMACProvider {
            func hmac(algorithm: RFC_6238.Algorithm, key: [UInt8], data: [UInt8]) -> [UInt8] {
                let symmetricKey = SymmetricKey(data: key)

                switch algorithm {
                case .sha1:
                    let mac = HMAC<Insecure.SHA1>.authenticationCode(
                        for: data, using: symmetricKey
                    )
                    return Array(mac)
                case .sha256:
                    let mac = HMAC<SHA256>.authenticationCode(
                        for: data, using: symmetricKey
                    )
                    return Array(mac)
                case .sha512:
                    let mac = HMAC<SHA512>.authenticationCode(
                        for: data, using: symmetricKey
                    )
                    return Array(mac)
                }
            }
        }

        @Test
        func `HMAC Provider implementation`() throws {
            let hmacProvider = CryptoKitHMACProvider()
            let key = Array("test".utf8)
            let data = Array("message".utf8)

            let result = hmacProvider.hmac(algorithm: .sha256, key: key, data: data)
            #expect(result.count == 32)
        }

        @Test
        func `Generating TOTP Codes`() throws {
            let totp = try RFC_6238.TOTP(
                base32Secret: "JBSWY3DPEHPK3PXP",
                timeStep: 30,
                digits: 6,
                algorithm: .sha1
            )

            let hmacProvider = CryptoKitHMACProvider()
            let now = Double(ContinuousClock.now.duration(to: .now).components.seconds)
                + 978_307_200  // Approximate unix time
            let otp = totp.generate(at: 1_111_111_111, using: hmacProvider)

            #expect(otp.count == 6)
            #expect(otp.allSatisfy { $0.isNumber })

            let remaining = totp.timeRemaining(at: 1_111_111_111)
            #expect(remaining > 0)
            #expect(remaining <= 30)
        }

        @Test
        func `Validating TOTP Codes`() throws {
            let totp = try RFC_6238.TOTP(
                base32Secret: "JBSWY3DPEHPK3PXP",
                timeStep: 30,
                digits: 6,
                algorithm: .sha1
            )

            let hmacProvider = CryptoKitHMACProvider()
            let testTime: Double = 1_111_111_109

            let otp = totp.generate(at: testTime, using: hmacProvider)
            let isValid = totp.validate(otp, at: testTime, window: 1, using: hmacProvider)
            #expect(isValid)

            let isValidExact = totp.validate(otp, at: testTime, window: 0, using: hmacProvider)
            #expect(isValidExact)
        }

        @Test
        func `Generating Provisioning URIs`() throws {
            let totp = try RFC_6238.TOTP(
                base32Secret: "JBSWY3DPEHPK3PXP",
                timeStep: 30,
                digits: 6,
                algorithm: .sha1
            )

            let uri = totp.provisioningURI(
                label: "user@example.com",
                issuer: "Example Corp"
            )

            #expect(uri.starts(with: "otpauth://totp/"))
            #expect(uri.contains("secret=JBSWY3DPEHPK3PXP"))
            #expect(uri.contains("algorithm=SHA1"))
            #expect(uri.contains("digits=6"))
            #expect(uri.contains("period=30"))
            #expect(uri.contains("issuer=Example"))
        }

        @Test
        func `Using HOTP (Counter-Based)`() throws {
            let hmacProvider = CryptoKitHMACProvider()

            let hotp = try RFC_6238.HOTP(
                secret: Array("12345678901234567890".utf8),
                digits: 6,
                algorithm: .sha1
            )

            let counterOTP = hotp.generate(counter: 42, using: hmacProvider)

            #expect(counterOTP.count == 6)
            #expect(counterOTP.allSatisfy { $0.isNumber })
        }

        @Test
        func `TOTP Configuration`() throws {
            let secret = Array("test secret".utf8)

            let totp1 = try RFC_6238.TOTP(
                secret: secret,
                timeStep: 30,
                digits: 6,
                algorithm: .sha1,
                t0: 0
            )
            #expect(totp1.digits == 6)
            #expect(totp1.timeStep == 30)

            let totp2 = try RFC_6238.TOTP(
                base32Secret: "JBSWY3DPEHPK3PXP",
                timeStep: 30,
                digits: 6,
                algorithm: .sha1,
                t0: 0
            )
            #expect(totp2.digits == 6)
        }

        @Test
        func `HOTP Configuration`() throws {
            let secret = Array("test secret".utf8)

            let hotp = try RFC_6238.HOTP(
                secret: secret,
                digits: 6,
                algorithm: .sha1
            )

            #expect(hotp.digits == 6)
            #expect(hotp.algorithm == .sha1)
        }

    #endif

    @Test
    func `Supported Algorithms`() throws {
        #expect(RFC_6238.Algorithm.sha1.rawValue == "SHA1")
        #expect(RFC_6238.Algorithm.sha256.rawValue == "SHA256")
        #expect(RFC_6238.Algorithm.sha512.rawValue == "SHA512")

        let allCases = RFC_6238.Algorithm.allCases
        #expect(allCases.count == 3)
    }

    @Test
    func `Error Handling`() throws {
        #expect(throws: RFC_6238.Error.invalidBase32String) {
            _ = try RFC_6238.TOTP(base32Secret: "invalid!@#$")
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Array("test".utf8), digits: 5)
        }

        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Array("test".utf8), timeStep: -1)
        }

        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.TOTP(secret: [])
        }
    }
}
