// RFC 6238.swift
// swift-rfc-6238
//
// Implementation of RFC 6238: TOTP: Time-Based One-Time Password Algorithm
// Pure Swift implementation with no Foundation dependencies.

public import Dependency_Primitives

/// Implementation of RFC 6238: TOTP: Time-Based One-Time Password Algorithm
///
/// See: https://www.rfc-editor.org/rfc/rfc6238.html
public enum RFC_6238 {

    /// Represents a Time-Based One-Time Password (TOTP) configuration
    public struct TOTP: Codable, Hashable, Sendable {
        /// The shared secret key
        public let secret: [UInt8]

        /// The time step in seconds (default: 30)
        public let timeStep: Double

        /// The number of digits in the generated OTP (default: 6, range: 6-8)
        public let digits: Int

        /// The HMAC algorithm to use
        public let algorithm: Algorithm

        /// The initial counter time (T0) - Unix time to start counting time steps (default: 0)
        public let t0: Double

        /// Creates a TOTP configuration
        /// - Parameters:
        ///   - secret: The shared secret key
        ///   - timeStep: The time step in seconds (default: 30)
        ///   - digits: The number of digits in the OTP (default: 6, must be 6-8)
        ///   - algorithm: The HMAC algorithm (default: SHA1)
        ///   - t0: The initial counter time (default: 0)
        /// - Throws: `Error.invalidDigits` if digits is not between 6-8, `Error.invalidTimeStep` if timeStep is not positive, `Error.emptySecret` if secret is empty
        public init(
            secret: [UInt8],
            timeStep: Double = 30,
            digits: Int = 6,
            algorithm: Algorithm = .sha1,
            t0: Double = 0
        ) throws(Error) {
            guard !secret.isEmpty else {
                throw Error.emptySecret
            }
            guard (6...8).contains(digits) else {
                throw Error.invalidDigits("Digits must be between 6 and 8, got \(digits)")
            }
            guard timeStep > 0 else {
                throw Error.invalidTimeStep("Time step must be positive, got \(timeStep)")
            }

            self.secret = secret
            self.timeStep = timeStep
            self.digits = digits
            self.algorithm = algorithm
            self.t0 = t0
        }

        /// Creates a TOTP configuration from a base32 encoded secret
        /// - Parameters:
        ///   - base32Secret: The base32 encoded secret
        ///   - timeStep: The time step in seconds (default: 30)
        ///   - digits: The number of digits in the OTP (default: 6)
        ///   - algorithm: The HMAC algorithm (default: SHA1)
        ///   - t0: The initial counter time (default: 0)
        /// - Throws: `Error.invalidBase32String` if base32 decoding fails, or other validation errors
        public init(
            base32Secret: Swift.String,
            timeStep: Double = 30,
            digits: Int = 6,
            algorithm: Algorithm = .sha1,
            t0: Double = 0
        ) throws(Error) {
            guard let secret = Base32.decode(base32Secret) else {
                throw Error.invalidBase32String
            }

            try self.init(
                secret: secret,
                timeStep: timeStep,
                digits: digits,
                algorithm: algorithm,
                t0: t0
            )
        }

        /// Calculates the time-based counter value T
        /// - Parameter unixTime: Unix timestamp in seconds since epoch
        /// - Returns: The counter value T
        public func counter(at unixTime: Double) -> UInt64 {
            UInt64((unixTime - t0) / timeStep)
        }

        /// Generates an OTP for a given time using the provided HMAC implementation
        /// - Parameters:
        ///   - unixTime: Unix timestamp in seconds since epoch
        ///   - hmacProvider: The HMAC provider implementation
        /// - Returns: The generated OTP as a string with leading zeros if necessary
        public func generate(at unixTime: Double, using hmacProvider: any HMACProvider) -> Swift.String {
            let counter = self.counter(at: unixTime)
            let hotp = HOTP(validatedSecret: secret, digits: digits, algorithm: algorithm)
            return hotp.generate(counter: counter, using: hmacProvider)
        }

        /// Validates an OTP within a time window
        /// - Parameters:
        ///   - otp: The OTP to validate
        ///   - unixTime: Unix timestamp in seconds since epoch
        ///   - window: The number of time steps to check before and after current time (default: 1)
        ///   - hmacProvider: The HMAC provider implementation
        /// - Returns: True if the OTP is valid within the window
        public func validate(
            _ otp: Swift.String,
            at unixTime: Double,
            window: Int = 1,
            using hmacProvider: any HMACProvider
        ) -> Bool {
            let currentCounter = counter(at: unixTime)

            for offset in -window...window {
                let testCounter = UInt64(Int64(currentCounter) + Int64(offset))
                let hotp = HOTP(validatedSecret: secret, digits: digits, algorithm: algorithm)
                let expectedOTP = hotp.generate(counter: testCounter, using: hmacProvider)

                if constantTimeCompare(otp, expectedOTP) {
                    return true
                }
            }

            return false
        }

        /// Generates the remaining seconds until the next OTP
        /// - Parameter unixTime: Unix timestamp in seconds since epoch
        /// - Returns: Seconds remaining until next OTP
        public func timeRemaining(at unixTime: Double) -> Double {
            let elapsedInStep = (unixTime - t0).truncatingRemainder(dividingBy: timeStep)
            return timeStep - elapsedInStep
        }

        /// Generates a URI for provisioning the TOTP in authenticator apps
        /// - Parameters:
        ///   - label: The account label (e.g., "user@example.com")
        ///   - issuer: The service issuer (e.g., "Example Corp")
        /// - Returns: The otpauth URI string
        public func provisioningURI(label: Swift.String, issuer: Swift.String? = nil) -> Swift.String {
            let encodedLabel = percentEncode(label)
            var uri = "otpauth://totp/\(encodedLabel)"
            uri += "?secret=\(Base32.encode(secret))"
            uri += "&algorithm=\(algorithm.rawValue.uppercased())"
            uri += "&digits=\(digits)"
            uri += "&period=\(Int(timeStep))"
            if let issuer {
                uri += "&issuer=\(percentEncode(issuer))"
            }
            return uri
        }
    }

    /// Represents an HMAC-Based One-Time Password (HOTP) configuration
    /// This is the base algorithm used by TOTP (RFC 4226)
    public struct HOTP: Codable, Hashable, Sendable {
        /// The shared secret key
        public let secret: [UInt8]

        /// The number of digits in the generated OTP
        public let digits: Int

        /// The HMAC algorithm to use
        public let algorithm: Algorithm

        /// Creates an HOTP configuration
        /// - Parameters:
        ///   - secret: The shared secret key
        ///   - digits: The number of digits in the OTP (default: 6)
        ///   - algorithm: The HMAC algorithm (default: SHA1)
        /// - Throws: `Error.invalidDigits` if digits is not between 6-8, `Error.emptySecret` if secret is empty
        public init(
            secret: [UInt8],
            digits: Int = 6,
            algorithm: Algorithm = .sha1
        ) throws(Error) {
            guard !secret.isEmpty else {
                throw Error.emptySecret
            }
            guard (6...8).contains(digits) else {
                throw Error.invalidDigits("Digits must be between 6 and 8, got \(digits)")
            }

            self.secret = secret
            self.digits = digits
            self.algorithm = algorithm
        }

        /// Internal initializer that doesn't throw - used when we know parameters are valid
        /// This is used internally by TOTP where parameters have already been validated
        internal init(
            validatedSecret secret: [UInt8],
            digits: Int,
            algorithm: Algorithm
        ) {
            self.secret = secret
            self.digits = digits
            self.algorithm = algorithm
        }

        /// Generates an OTP for a given counter value
        /// - Parameters:
        ///   - counter: The counter value
        ///   - hmacProvider: The HMAC provider implementation
        /// - Returns: The generated OTP as a string with leading zeros if necessary
        public func generate(counter: UInt64, using hmacProvider: any HMACProvider) -> Swift.String {
            // Convert counter to big-endian bytes
            let counterBytes: [UInt8] = unsafe withUnsafeBytes(of: counter.bigEndian) { Array($0) }

            // Calculate HMAC
            let hmac = hmacProvider.hmac(algorithm: algorithm, key: secret, data: counterBytes)

            // Dynamic truncation (RFC 4226 Section 5.3)
            let truncated = dynamicTruncate(hmac)

            // Compute OTP value
            var divisor: UInt32 = 1
            for _ in 0..<digits { divisor *= 10 }
            let otp = truncated % divisor

            // Format with leading zeros
            return zeroPadded(otp, width: digits)
        }

        /// Performs dynamic truncation as specified in RFC 4226
        /// - Parameter hmac: The HMAC value to truncate
        /// - Returns: The truncated 31-bit integer
        private func dynamicTruncate(_ hmac: [UInt8]) -> UInt32 {
            guard hmac.count >= 20 else {
                fatalError("HMAC too short: \(hmac.count) bytes")
            }

            let offset = Int(hmac[hmac.count - 1] & 0x0f)

            guard offset + 4 <= hmac.count else {
                fatalError("Invalid offset \(offset) for HMAC length \(hmac.count)")
            }

            var value: UInt32 = 0
            for i in offset..<(offset + 4) {
                value = (value << 8) | UInt32(hmac[i])
            }

            return value & 0x7fff_ffff
        }
    }

    /// Supported HMAC algorithms
    public enum Algorithm: Swift.String, Codable, Hashable, CaseIterable, Sendable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"

        /// The expected HMAC output length in bytes
        public var hashLength: Int {
            switch self {
            case .sha1: 20
            case .sha256: 32
            case .sha512: 64
            }
        }
    }

    /// Protocol for providing HMAC implementations
    /// This allows the RFC implementation to remain crypto-library agnostic
    public protocol HMACProvider: Sendable {
        /// Computes HMAC for the given algorithm, key, and data
        /// - Parameters:
        ///   - algorithm: The HMAC algorithm to use
        ///   - key: The secret key
        ///   - data: The data to authenticate
        /// - Returns: The HMAC value
        func hmac(algorithm: Algorithm, key: [UInt8], data: [UInt8]) -> [UInt8]
    }

    /// Errors that can occur during TOTP/HOTP operations
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidBase32String
        case invalidDigits(Swift.String)
        case invalidTimeStep(Swift.String)
        case emptySecret
    }
}

// MARK: - HMAC Witness + Dependency.Key

extension RFC_6238 {
    /// Witness struct for HMAC provision, conforming to both HMACProvider and Dependency.Key.
    public struct HMAC: Sendable {
        @usableFromInline
        let _hmac: @Sendable (Algorithm, [UInt8], [UInt8]) -> [UInt8]

        @inlinable
        public init(
            hmac: @escaping @Sendable (Algorithm, [UInt8], [UInt8]) -> [UInt8]
        ) {
            self._hmac = hmac
        }
    }
}

extension RFC_6238.HMAC: RFC_6238.HMACProvider {
    @inlinable
    public func hmac(
        algorithm: RFC_6238.Algorithm,
        key: [UInt8],
        data: [UInt8]
    ) -> [UInt8] {
        _hmac(algorithm, key, data)
    }
}

extension RFC_6238.HMAC: Dependency.Key {
    public typealias Value = RFC_6238.HMAC

    #if canImport(CryptoKit)
    public static var liveValue: RFC_6238.HMAC {
        RFC_6238.HMAC { algorithm, key, data in
            // Platform-specific: use CryptoKit HMAC
            fatalError(
                "RFC_6238.HMAC.liveValue: CryptoKit HMAC integration required. "
                + "Inject a provider via Dependency.Scope.with { $0[RFC_6238.HMAC.self] = ... }"
            )
        }
    }
    #else
    public static var liveValue: RFC_6238.HMAC {
        RFC_6238.HMAC { _, _, _ in
            fatalError(
                "RFC_6238.HMAC.liveValue unavailable on this platform. "
                + "Inject a provider via Dependency.Scope.with { $0[RFC_6238.HMAC.self] = ... }"
            )
        }
    }
    #endif

    public static var testValue: RFC_6238.HMAC {
        RFC_6238.HMAC { algorithm, key, data in
            // Deterministic: truncate/pad key+data to expected hash length
            let combined = key + data
            var result = [UInt8](repeating: 0, count: algorithm.hashLength)
            for i in 0..<min(combined.count, result.count) {
                result[i] = combined[i]
            }
            return result
        }
    }
}

// MARK: - Error Description

extension RFC_6238.Error: CustomStringConvertible {
    public var description: Swift.String {
        switch self {
        case .invalidBase32String:
            "Invalid base32 encoded string"
        case .invalidDigits(let message):
            "Invalid digits: \(message)"
        case .invalidTimeStep(let message):
            "Invalid time step: \(message)"
        case .emptySecret:
            "Secret key cannot be empty"
        }
    }
}

// MARK: - Helper Functions

/// Performs constant-time string comparison to prevent timing attacks
private func constantTimeCompare(_ a: Swift.String, _ b: Swift.String) -> Bool {
    guard a.count == b.count else { return false }

    var result = 0
    for (charA, charB) in zip(a, b) {
        result |= Int(charA.asciiValue ?? 0) ^ Int(charB.asciiValue ?? 0)
    }

    return result == 0
}

/// Formats an integer with leading zeros to the specified width.
private func zeroPadded(_ value: UInt32, width: Int) -> Swift.String {
    var s = Swift.String(value)
    while s.count < width { s = "0" + s }
    return s
}

/// Percent-encodes a string for use in URIs (RFC 3986 unreserved characters).
private func percentEncode(_ string: Swift.String) -> Swift.String {
    var result = ""
    for scalar in string.unicodeScalars {
        if scalar.isASCII,
           (scalar.value >= 0x41 && scalar.value <= 0x5A)   // A-Z
            || (scalar.value >= 0x61 && scalar.value <= 0x7A) // a-z
            || (scalar.value >= 0x30 && scalar.value <= 0x39) // 0-9
            || scalar == "-" || scalar == "_" || scalar == "." || scalar == "~"
            || scalar == "@"  // safe in otpauth label
        {
            result.append(Character(scalar))
        } else {
            for byte in Swift.String(scalar).utf8 {
                result += "%"
                result.append(hexChar(byte >> 4))
                result.append(hexChar(byte & 0x0F))
            }
        }
    }
    return result
}

private func hexChar(_ nibble: UInt8) -> Character {
    let chars: [Character] = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "A", "B", "C", "D", "E", "F",
    ]
    return chars[Int(nibble)]
}

// MARK: - Base32 (RFC 4648)

extension RFC_6238 {
    /// Base32 encoding/decoding per RFC 4648.
    public enum Base32 {
        private static let alphabet: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

        /// Decodes a base32-encoded string to bytes.
        /// - Parameter base32: The base32 encoded string (padding, spaces, dashes tolerated)
        /// - Returns: Decoded bytes, or nil if the string contains invalid characters.
        public static func decode(_ base32: Swift.String) -> [UInt8]? {
            let cleaned = base32.uppercased().filter { char in
                char != " " && char != "-" && char != "="
            }

            var bits = 0
            var value = 0
            var output = [UInt8]()

            for char in cleaned {
                guard let idx = alphabet.firstIndex(of: char) else {
                    return nil
                }
                value = (value << 5) | alphabet.distance(from: alphabet.startIndex, to: idx)
                bits += 5

                if bits >= 8 {
                    output.append(UInt8((value >> (bits - 8)) & 0xFF))
                    bits -= 8
                }
            }

            return output
        }

        /// Encodes bytes to a base32 string with padding.
        /// - Parameter bytes: The bytes to encode
        /// - Returns: Base32-encoded string with padding
        public static func encode(_ bytes: [UInt8]) -> Swift.String {
            var result = ""
            var bits = 0
            var value = 0

            for byte in bytes {
                value = (value << 8) | Int(byte)
                bits += 8

                while bits >= 5 {
                    let index = (value >> (bits - 5)) & 0x1F
                    result.append(alphabet[index])
                    bits -= 5
                }
            }

            if bits > 0 {
                let index = (value << (5 - bits)) & 0x1F
                result.append(alphabet[index])
            }

            while result.count % 8 != 0 {
                result.append("=")
            }

            return result
        }
    }
}

// MARK: - Convenience (Dependency-resolved)

extension RFC_6238.TOTP {
    /// Generates an OTP using the HMAC provider from dependency scope.
    ///
    /// - Parameter unixTime: Unix timestamp in seconds since epoch
    /// - Returns: The generated OTP string
    public func generate(at unixTime: Double) -> Swift.String {
        generate(at: unixTime, using: Dependency.Scope.current[RFC_6238.HMAC.self])
    }

    /// Validates an OTP using the HMAC provider from dependency scope.
    ///
    /// - Parameters:
    ///   - otp: The OTP to validate
    ///   - unixTime: Unix timestamp in seconds since epoch
    ///   - window: The number of time steps to check (default: 1)
    /// - Returns: True if the OTP is valid within the window
    public func validate(
        _ otp: Swift.String,
        at unixTime: Double,
        window: Int = 1
    ) -> Bool {
        validate(otp, at: unixTime, window: window, using: Dependency.Scope.current[RFC_6238.HMAC.self])
    }
}

extension RFC_6238.HOTP {
    /// Generates an OTP using the HMAC provider from dependency scope.
    ///
    /// - Parameter counter: The counter value
    /// - Returns: The generated OTP string
    public func generate(counter: UInt64) -> Swift.String {
        generate(counter: counter, using: Dependency.Scope.current[RFC_6238.HMAC.self])
    }
}
