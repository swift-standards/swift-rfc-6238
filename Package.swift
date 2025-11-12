// swift-tools-version:6.0

import Foundation
import PackageDescription

extension String {
    static let rfc6238: Self = "RFC_6238"
}

extension Target.Dependency {
    static var rfc6238: Self { .target(name: .rfc6238) }
}

let package = Package(
    name: "swift-rfc-6238",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: .rfc6238, targets: [.rfc6238]),
    ],
    dependencies: [
        // Add RFC dependencies here as needed
        // .package(url: "https://github.com/swift-standards/swift-rfc-1123.git", branch: "main"),
    ],
    targets: [
        .target(
            name: .rfc6238,
            dependencies: [
                // Add target dependencies here
            ]
        ),
        .testTarget(
            name: .rfc6238.tests,
            dependencies: [
                .rfc6238
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }