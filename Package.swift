// swift-tools-version:6.2

import PackageDescription

extension String {
    static let rfc6238: Self = "RFC 6238"
}

extension Target.Dependency {
    static var rfc6238: Self { .target(name: .rfc6238) }
}

let package = Package(
    name: "swift-rfc-6238",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11)
    ],
    products: [
        .library(name: .rfc6238, targets: [.rfc6238]),
    ],
    dependencies: [
        // Add RFC dependencies here as needed
        // .package(url: "https://github.com/swift-standards/swift-rfc-1123.git", from: "0.1.0"),
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

extension String {
    var tests: Self { self + " Tests" }
    var foundation: Self { self + " Foundation" }
}

for target in package.targets where ![.system, .binary, .plugin].contains(target.type) {
    let existing = target.swiftSettings ?? []
    target.swiftSettings = existing + [
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility")
    ]
}
