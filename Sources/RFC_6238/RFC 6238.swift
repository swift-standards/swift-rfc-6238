//
//  RFC 6238.swift
//  swift-rfc-6238
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Foundation

/// Implementation of RFC 6238: TOTP: Time-Based One-Time Password Algorithm
///
/// See: https://www.rfc-editor.org/rfc/rfc6238.html
public enum RFC_6238 {
    
    /// Represents a Time-Based One-Time Password (TOTP) configuration
    public struct TOTP: Codable, Hashable, Sendable {
        /// The shared secret key
        public let secret: Data
        
        /// The time step in seconds (default: 30)
        public let timeStep: TimeInterval
        
        /// The number of digits in the generated OTP (default: 6, range: 6-8)
        public let digits: Int
        
        /// The HMAC algorithm to use
        public let algorithm: Algorithm
        
        /// The initial counter time (T0) - Unix time to start counting time steps (default: 0)
        public let t0: TimeInterval
        
        /// Creates a TOTP configuration
        /// - Parameters:
        ///   - secret: The shared secret key
        ///   - timeStep: The time step in seconds (default: 30)
        ///   - digits: The number of digits in the OTP (default: 6, must be 6-8)
        ///   - algorithm: The HMAC algorithm (default: SHA1)
        ///   - t0: The initial counter time (default: 0)
        /// - Throws: `Error.invalidDigits` if digits is not between 6-8, `Error.invalidTimeStep` if timeStep is not positive, `Error.emptySecret` if secret is empty
        public init(
            secret: Data,
            timeStep: TimeInterval = 30,
            digits: Int = 6,
            algorithm: Algorithm = .sha1,
            t0: TimeInterval = 0
        ) throws {
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
            base32Secret: String,
            timeStep: TimeInterval = 30,
            digits: Int = 6,
            algorithm: Algorithm = .sha1,
            t0: TimeInterval = 0
        ) throws {
            guard let secret = Data(base32Encoded: base32Secret) else {
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
        /// - Parameter time: The time to calculate for (defaults to current time)
        /// - Returns: The counter value T
        public func counter(at time: Date = Date()) -> UInt64 {
            let unixTime = time.timeIntervalSince1970
            return UInt64((unixTime - t0) / timeStep)
        }
        
        /// Generates an OTP for a given time using the provided HMAC implementation
        /// - Parameters:
        ///   - time: The time to generate OTP for (defaults to current time)
        ///   - hmacProvider: The HMAC provider implementation
        /// - Returns: The generated OTP as a string with leading zeros if necessary
        public func generate(at time: Date = Date(), using hmacProvider: HMACProvider) -> String {
            let counter = self.counter(at: time)
            let hotp = HOTP(validatedSecret: secret, digits: digits, algorithm: algorithm)
            return hotp.generate(counter: counter, using: hmacProvider)
        }
        
        /// Validates an OTP within a time window
        /// - Parameters:
        ///   - otp: The OTP to validate
        ///   - time: The time to validate against (defaults to current time)
        ///   - window: The number of time steps to check before and after current time (default: 1)
        ///   - hmacProvider: The HMAC provider implementation
        /// - Returns: True if the OTP is valid within the window
        public func validate(
            _ otp: String,
            at time: Date = Date(),
            window: Int = 1,
            using hmacProvider: HMACProvider
        ) -> Bool {
            let currentCounter = counter(at: time)
            
            // Check within the time window
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
        /// - Parameter time: The current time (defaults to now)
        /// - Returns: Seconds remaining until next OTP
        public func timeRemaining(at time: Date = Date()) -> TimeInterval {
            let unixTime = time.timeIntervalSince1970
            let elapsedInStep = (unixTime - t0).truncatingRemainder(dividingBy: timeStep)
            return timeStep - elapsedInStep
        }
        
        /// Generates a URI for provisioning the TOTP in authenticator apps
        /// - Parameters:
        ///   - label: The account label (e.g., "user@example.com")
        ///   - issuer: The service issuer (e.g., "Example Corp")
        /// - Returns: The otpauth URI string
        public func provisioningURI(label: String, issuer: String? = nil) -> String {
            var components = URLComponents()
            components.scheme = "otpauth"
            components.host = "totp"
            components.path = "/\(label)"
            
            var queryItems = [
                URLQueryItem(name: "secret", value: secret.base32EncodedString()),
                URLQueryItem(name: "algorithm", value: algorithm.rawValue.uppercased()),
                URLQueryItem(name: "digits", value: String(digits)),
                URLQueryItem(name: "period", value: String(Int(timeStep)))
            ]
            
            if let issuer = issuer {
                queryItems.append(URLQueryItem(name: "issuer", value: issuer))
            }
            
            components.queryItems = queryItems
            
            return components.string ?? ""
        }
    }
    
    /// Represents an HMAC-Based One-Time Password (HOTP) configuration
    /// This is the base algorithm used by TOTP (RFC 4226)
    public struct HOTP: Codable, Hashable, Sendable {
        /// The shared secret key
        public let secret: Data
        
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
            secret: Data,
            digits: Int = 6,
            algorithm: Algorithm = .sha1
        ) throws {
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
            validatedSecret secret: Data,
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
        public func generate(counter: UInt64, using hmacProvider: HMACProvider) -> String {
            // Convert counter to big-endian bytes
            var counterBigEndian = counter.bigEndian
            let counterData = Data(bytes: &counterBigEndian, count: 8)
            
            // Calculate HMAC
            let hmac = hmacProvider.hmac(algorithm: algorithm, key: secret, data: counterData)
            
            // Dynamic truncation (RFC 4226 Section 5.3)
            let truncated = dynamicTruncate(hmac)
            
            // Compute OTP value
            let otp = truncated % UInt32(pow(10.0, Double(digits)))
            
            // Format with leading zeros
            return String(format: "%0\(digits)d", otp)
        }
        
        /// Performs dynamic truncation as specified in RFC 4226
        /// - Parameter hmac: The HMAC value to truncate
        /// - Returns: The truncated 31-bit integer
        private func dynamicTruncate(_ hmac: Data) -> UInt32 {
            // Ensure HMAC is long enough (RFC 4226 requires at least 20 bytes for SHA-1)
            guard hmac.count >= 20 else {
                fatalError("HMAC too short: \(hmac.count) bytes")
            }

            // Get the offset from the last 4 bits of the HMAC
            let offset = Int(hmac[hmac.count - 1] & 0x0f)

            // Ensure we can read 4 bytes from the offset
            guard offset + 4 <= hmac.count else {
                fatalError("Invalid offset \(offset) for HMAC length \(hmac.count)")
            }

            // Extract 4 bytes starting at the offset
            let truncatedBytes = hmac[offset..<(offset + 4)]

            // Convert to UInt32 (big-endian) and mask the most significant bit
            var value: UInt32 = 0
            for byte in truncatedBytes {
                value = (value << 8) | UInt32(byte)
            }

            // Clear the most significant bit to ensure a 31-bit positive integer
            return value & 0x7fffffff
        }
    }
    
    /// Supported HMAC algorithms
    public enum Algorithm: String, Codable, CaseIterable, Sendable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
        
        /// The expected HMAC output length in bytes
        public var hashLength: Int {
            switch self {
            case .sha1: return 20
            case .sha256: return 32
            case .sha512: return 64
            }
        }
    }
    
    /// Protocol for providing HMAC implementations
    /// This allows the RFC implementation to remain crypto-library agnostic
    public protocol HMACProvider {
        /// Computes HMAC for the given algorithm, key, and data
        /// - Parameters:
        ///   - algorithm: The HMAC algorithm to use
        ///   - key: The secret key
        ///   - data: The data to authenticate
        /// - Returns: The HMAC value
        func hmac(algorithm: Algorithm, key: Data, data: Data) -> Data
    }
    
    /// Errors that can occur during TOTP/HOTP operations
    public enum Error: Swift.Error, LocalizedError, Equatable {
        case invalidBase32String
        case invalidDigits(String)
        case invalidTimeStep(String)
        case emptySecret
        
        public var errorDescription: String? {
            switch self {
            case .invalidBase32String:
                return "Invalid base32 encoded string"
            case .invalidDigits(let message):
                return "Invalid digits: \(message)"
            case .invalidTimeStep(let message):
                return "Invalid time step: \(message)"
            case .emptySecret:
                return "Secret key cannot be empty"
            }
        }
    }
}

// MARK: - Helper Functions

/// Performs constant-time string comparison to prevent timing attacks
private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
    guard a.count == b.count else { return false }
    
    var result = 0
    for (charA, charB) in zip(a, b) {
        result |= Int(charA.asciiValue ?? 0) ^ Int(charB.asciiValue ?? 0)
    }
    
    return result == 0
}

// MARK: - Data Extensions for Base32

extension Data {
    /// Base32 character set (RFC 4648)
    private static let base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    
    /// Creates data from a base32 encoded string
    /// - Parameter base32: The base32 encoded string
    public init?(base32Encoded base32: String) {
        // Remove whitespace and convert to uppercase
        let cleanedBase32 = base32
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "-", with: "")
            .uppercased()
        
        // Remove padding
        let noPadding = cleanedBase32.replacingOccurrences(of: "=", with: "")
        
        var bits = 0
        var value = 0
        var output = Data()
        
        for char in noPadding {
            guard let index = Data.base32Alphabet.firstIndex(of: char) else {
                return nil
            }
            
            value = (value << 5) | Data.base32Alphabet.distance(from: Data.base32Alphabet.startIndex, to: index)
            bits += 5
            
            if bits >= 8 {
                output.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        
        self = output
    }
    
    /// Returns a base32 encoded string
    /// - Returns: The base32 encoded string
    public func base32EncodedString() -> String {
        var result = ""
        var bits = 0
        var value = 0
        
        for byte in self {
            value = (value << 8) | Int(byte)
            bits += 8
            
            while bits >= 5 {
                let index = (value >> (bits - 5)) & 0x1F
                let charIndex = Data.base32Alphabet.index(Data.base32Alphabet.startIndex, offsetBy: index)
                result.append(Data.base32Alphabet[charIndex])
                bits -= 5
            }
        }
        
        if bits > 0 {
            let index = (value << (5 - bits)) & 0x1F
            let charIndex = Data.base32Alphabet.index(Data.base32Alphabet.startIndex, offsetBy: index)
            result.append(Data.base32Alphabet[charIndex])
        }
        
        // Add padding
        while result.count % 8 != 0 {
            result.append("=")
        }
        
        return result
    }
}
