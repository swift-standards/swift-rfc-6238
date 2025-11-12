# Swift RFC 6238

[![CI](https://github.com/swift-standards/swift-rfc-6238/workflows/CI/badge.svg)](https://github.com/swift-standards/swift-rfc-6238/actions/workflows/ci.yml)
![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Swift implementation of RFC 6238: TOTP - Time-Based One-Time Password Algorithm and RFC 4226: HOTP - HMAC-Based One-Time Password Algorithm.

## Overview

RFC 6238 defines the Time-Based One-Time Password (TOTP) algorithm, which generates one-time passwords based on the current time. This package provides a pure Swift implementation of both TOTP and the underlying HOTP (RFC 4226) algorithms. The implementation is crypto-library agnostic, using a protocol-based approach that allows you to plug in any HMAC provider, making it flexible and universally compatible across all Swift platforms.

## Features

- **RFC Compliant**: Full implementation of RFC 6238 (TOTP) and RFC 4226 (HOTP) specifications
- **Zero Crypto Dependencies**: Protocol-based design lets you choose your own crypto library
- **Cross-Platform**: Works on all Swift platforms (Linux, Windows, macOS, iOS, etc.)
- **Multiple Hash Algorithms**: Support for SHA1, SHA256, and SHA512
- **Base32 Support**: Built-in Base32 encoding/decoding for secret keys
- **Provisioning URIs**: Generate QR code URIs for authenticator apps
- **Security Features**: Constant-time comparison to prevent timing attacks
- **Type-Safe**: Proper error handling with throwing initializers

## Installation

Add swift-rfc-6238 to your package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-standards/swift-rfc-6238.git", from: "0.1.0")
]
```

Then add it to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC_6238", package: "swift-rfc-6238")
    ]
)
```

## Quick Start

### Implementing an HMAC Provider

First, create an HMAC provider using your preferred crypto library:

```swift
import RFC_6238
import CryptoKit

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
```

### Generating TOTP Codes

```swift
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
print("Current OTP: \(otp)")  // e.g., "123456"

// Check remaining time
let remaining = totp.timeRemaining()
print("Expires in: \(Int(remaining)) seconds")
```

### Validating TOTP Codes

```swift
// Validate OTP with time window (allows ±1 time step)
let isValid = totp.validate("123456", window: 1, using: hmacProvider)
print("Valid: \(isValid)")

// Validate at specific time
let testDate = Date(timeIntervalSince1970: 1111111109)
let isValidAtTime = totp.validate("123456", at: testDate, window: 0, using: hmacProvider)
```

### Generating Provisioning URIs

```swift
// Generate URI for authenticator apps (Google Authenticator, Authy, etc.)
let uri = totp.provisioningURI(
    label: "user@example.com",
    issuer: "Example Corp"
)
// Output: otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=Example%20Corp

// Use this URI to generate a QR code for easy setup
```

### Using HOTP (Counter-Based)

```swift
// Create HOTP instance
let hotp = try RFC_6238.HOTP(
    secret: Data("12345678901234567890".utf8),
    digits: 6,
    algorithm: .sha1
)

// Generate OTP for specific counter value
let counterOTP = hotp.generate(counter: 42, using: hmacProvider)
print("OTP for counter 42: \(counterOTP)")
```

## Usage

### TOTP Configuration

```swift
public struct TOTP {
    init(
        secret: Data,
        timeStep: TimeInterval = 30,
        digits: Int = 6,
        algorithm: Algorithm = .sha1,
        t0: TimeInterval = 0
    ) throws

    init(
        base32Secret: String,
        timeStep: TimeInterval = 30,
        digits: Int = 6,
        algorithm: Algorithm = .sha1,
        t0: TimeInterval = 0
    ) throws
}
```

### HOTP Configuration

```swift
public struct HOTP {
    init(
        secret: Data,
        digits: Int = 6,
        algorithm: Algorithm = .sha1
    ) throws
}
```

### Supported Algorithms

```swift
public enum Algorithm: String {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}
```

### Error Handling

```swift
public enum Error: Swift.Error {
    case invalidBase32String
    case invalidDigits(String)      // Digits must be 6-8
    case invalidTimeStep(String)    // Time step must be positive
    case emptySecret
}
```

## Related Packages

### Dependencies
- None - This is a pure Swift implementation that requires you to provide your own HMAC implementation

### Recommended Crypto Libraries
- [CryptoKit](https://developer.apple.com/documentation/cryptokit) - Apple's cryptography framework (Apple platforms)
- [Swift Crypto](https://github.com/apple/swift-crypto) - Cross-platform Swift cryptography

## Requirements

- Swift 6.0+
- macOS 13.0+ / iOS 16.0+ / tvOS 16.0+ / watchOS 9.0+

## License

This library is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
