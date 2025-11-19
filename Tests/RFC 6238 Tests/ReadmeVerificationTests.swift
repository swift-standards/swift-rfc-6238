//
//  ReadmeVerificationTests.swift
//  swift-rfc-6238
//
//  Verifies that README code examples actually work
//

#if canImport(CryptoKit)
import CryptoKit
#endif
import RFC_6238
import Testing

@Suite("README Verification")
struct ReadmeVerificationTests {

#if canImport(CryptoKit)
    // HMAC Provider implementation for tests
    struct CryptoKitHMACProvider: RFC_6238.HMACProvider {
        func hmac(algorithm: RFC_6238.Algorithm, key: Data, data: Data) -> Data {
            let symmetricKey = SymmetricKey(data: key)

            switch algorithm {
            case .sha1:
                return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetricKey))
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
            case .sha512:
                return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
            }
        }
    }

    @Test("README Line 50-68: HMAC Provider implementation")
    func hmacProviderImplementation() throws {
        // Test that the HMAC provider example compiles and works
        let hmacProvider = CryptoKitHMACProvider()
        let key = Data("test".utf8)
        let data = Data("message".utf8)

        let result = hmacProvider.hmac(algorithm: .sha256, key: key, data: data)
        #expect(result.count == 32)  // SHA256 produces 32 bytes
    }

    @Test("README Line 72-89: Generating TOTP Codes")
    func generatingTOTPCodes() throws {
        // Create TOTP instance from base32 secret
        let totp = try RFC_6238.TOTP(
            base32Secret: "JBSWY3DPEHPK3PXP",
            timeStep: 30,
            digits: 6,
            algorithm: .sha1
        )

        // Generate current OTP
        let hmacProvider = CryptoKitHMACProvider()
        let otp = totp.generate(using: hmacProvider)

        #expect(otp.count == 6)
        #expect(otp.allSatisfy { $0.isNumber })

        // Check remaining time
        let remaining = totp.timeRemaining()
        #expect(remaining > 0)
        #expect(remaining <= 30)
    }

    @Test("README Line 93-101: Validating TOTP Codes")
    func validatingTOTPCodes() throws {
        let totp = try RFC_6238.TOTP(
            base32Secret: "JBSWY3DPEHPK3PXP",
            timeStep: 30,
            digits: 6,
            algorithm: .sha1
        )

        let hmacProvider = CryptoKitHMACProvider()

        // Generate and validate current OTP
        let otp = totp.generate(using: hmacProvider)
        let isValid = totp.validate(otp, window: 1, using: hmacProvider)
        #expect(isValid)

        // Validate at specific time
        let testDate = Date(timeIntervalSince1970: 1_111_111_109)
        let otpAtTime = totp.generate(at: testDate, using: hmacProvider)
        let isValidAtTime = totp.validate(otpAtTime, at: testDate, window: 0, using: hmacProvider)
        #expect(isValidAtTime)
    }

    @Test("README Line 105-114: Generating Provisioning URIs")
    func generatingProvisioningURIs() throws {
        let totp = try RFC_6238.TOTP(
            base32Secret: "JBSWY3DPEHPK3PXP",
            timeStep: 30,
            digits: 6,
            algorithm: .sha1
        )

        // Generate URI for authenticator apps
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

    @Test("README Line 118-129: Using HOTP (Counter-Based)")
    func usingHOTP() throws {
        let hmacProvider = CryptoKitHMACProvider()

        // Create HOTP instance
        let hotp = try RFC_6238.HOTP(
            secret: Data("12345678901234567890".utf8),
            digits: 6,
            algorithm: .sha1
        )

        // Generate OTP for specific counter value
        let counterOTP = hotp.generate(counter: 42, using: hmacProvider)

        #expect(counterOTP.count == 6)
        #expect(counterOTP.allSatisfy { $0.isNumber })
    }

    @Test("README Line 135-152: TOTP Configuration")
    func totpConfiguration() throws {
        let secret = Data("test secret".utf8)

        // Test default initialization
        let totp1 = try RFC_6238.TOTP(
            secret: secret,
            timeStep: 30,
            digits: 6,
            algorithm: .sha1,
            t0: 0
        )
        #expect(totp1.digits == 6)
        #expect(totp1.timeStep == 30)

        // Test base32 initialization
        let totp2 = try RFC_6238.TOTP(
            base32Secret: "JBSWY3DPEHPK3PXP",
            timeStep: 30,
            digits: 6,
            algorithm: .sha1,
            t0: 0
        )
        #expect(totp2.digits == 6)
    }

    @Test("README Line 156-165: HOTP Configuration")
    func hotpConfiguration() throws {
        let secret = Data("test secret".utf8)

        let hotp = try RFC_6238.HOTP(
            secret: secret,
            digits: 6,
            algorithm: .sha1
        )

        #expect(hotp.digits == 6)
        #expect(hotp.algorithm == .sha1)
    }

#endif

    @Test("README Line 169-175: Supported Algorithms")
    func supportedAlgorithms() throws {
        #expect(RFC_6238.Algorithm.sha1.rawValue == "SHA1")
        #expect(RFC_6238.Algorithm.sha256.rawValue == "SHA256")
        #expect(RFC_6238.Algorithm.sha512.rawValue == "SHA512")

        // Verify all cases exist
        let allCases = RFC_6238.Algorithm.allCases
        #expect(allCases.count == 3)
    }

    @Test("README Line 179-186: Error Handling")
    func errorHandling() throws {
        // Test invalid base32
        #expect(throws: RFC_6238.Error.invalidBase32String) {
            _ = try RFC_6238.TOTP(base32Secret: "invalid!@#$")
        }

        // Test invalid digits
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data("test".utf8), digits: 5)
        }

        // Test invalid time step
        #expect(throws: RFC_6238.Error.self) {
            _ = try RFC_6238.TOTP(secret: Data("test".utf8), timeStep: -1)
        }

        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try RFC_6238.TOTP(secret: Data())
        }
    }
}
