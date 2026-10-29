// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FindIPShield",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "FindIPShield", targets: ["FindIPShield"]),
    ],
    targets: [
        .target(
            name: "FindIPShield",
            resources: [.copy("Resources/PrivacyInfo.xcprivacy")],
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]
        ),
        .testTarget(
            name: "FindIPShieldTests",
            dependencies: ["FindIPShield"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
