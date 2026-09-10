// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "OariWalletModules",
    platforms: [
        .iOS("17.4"),
        .macOS(.v14),
    ],
    products: [
        .library(name: "WalletDomain", targets: ["WalletDomain"]),
        .library(name: "WalletVault", targets: ["WalletVault"]),
        .library(name: "ProfileDomain", targets: ["ProfileDomain"]),
        .library(name: "TrustDomain", targets: ["TrustDomain"]),
        .library(name: "PresentationDomain", targets: ["PresentationDomain"]),
        .library(name: "ProtocolEngine", targets: ["ProtocolEngine"]),
        .library(name: "OariDesignSystem", targets: ["OariDesignSystem"]),
        .library(name: "IdentityDomain", targets: ["IdentityDomain"]),
        .library(name: "EudiWalletKitAdapter", targets: ["EudiWalletKitAdapter"]),
        .library(name: "EbsiW3CBackend", targets: ["EbsiW3CBackend"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit.git",
            exact: "0.51.0"
        ),
        .package(
            url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security.git",
            exact: "0.25.0"
        ),
        .package(
            url: "https://github.com/apple/swift-certificates.git",
            exact: "1.19.4"
        ),
        .package(
            url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift.git",
            exact: "0.53.2"
        ),
        .package(
            url: "https://github.com/airsidemobile/JOSESwift.git",
            exact: "3.0.0"
        ),
    ],
    targets: [
        .target(
            name: "WalletDomain",
            path: "Packages/Sources/WalletDomain"
        ),
        .target(
            name: "WalletVault",
            dependencies: ["WalletDomain", "ProtocolEngine", "EbsiW3CBackend"],
            path: "Packages/Sources/WalletVault"
        ),
        .target(
            name: "ProfileDomain",
            dependencies: ["WalletDomain"],
            path: "Packages/Sources/ProfileDomain"
        ),
        .target(
            name: "TrustDomain",
            dependencies: ["ProfileDomain"],
            path: "Packages/Sources/TrustDomain"
        ),
        .target(
            name: "PresentationDomain",
            dependencies: ["ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Sources/PresentationDomain"
        ),
        .target(
            name: "ProtocolEngine",
            dependencies: ["PresentationDomain", "ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Sources/ProtocolEngine"
        ),
        .target(
            name: "OariDesignSystem",
            path: "Packages/Sources/OariDesignSystem"
        ),
        .target(
            name: "IdentityDomain",
            dependencies: ["TrustDomain"],
            path: "Packages/Sources/IdentityDomain"
        ),
        .target(
            name: "EudiWalletKitAdapter",
            dependencies: [
                "WalletDomain",
                "ProfileDomain",
                "TrustDomain",
                .product(
                    name: "EudiWalletKit",
                    package: "eudi-lib-ios-wallet-kit"
                ),
                .product(
                    name: "MdocSecurity18013",
                    package: "eudi-lib-ios-iso18013-security"
                ),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "OpenID4VCI", package: "eudi-lib-ios-openid4vci-swift"),
                .product(name: "JOSESwift", package: "joseswift"),
            ],
            path: "Packages/Sources/EudiWalletKitAdapter"
        ),
        .target(
            name: "EbsiW3CBackend",
            dependencies: [
                "IdentityDomain",
                "TrustDomain",
                "WalletDomain",
                .product(name: "JOSESwift", package: "joseswift"),
            ],
            path: "Packages/Sources/EbsiW3CBackend"
        ),
        .testTarget(
            name: "WalletDomainTests",
            dependencies: ["WalletDomain"],
            path: "Packages/Tests/WalletDomainTests"
        ),
        .testTarget(
            name: "WalletVaultTests",
            dependencies: ["WalletDomain", "WalletVault"],
            path: "Packages/Tests/WalletVaultTests"
        ),
        .testTarget(
            name: "ProfileDomainTests",
            dependencies: ["ProfileDomain"],
            path: "Packages/Tests/ProfileDomainTests"
        ),
        .testTarget(
            name: "TrustDomainTests",
            dependencies: ["ProfileDomain", "TrustDomain"],
            path: "Packages/Tests/TrustDomainTests"
        ),
        .testTarget(
            name: "IdentityDomainTests",
            dependencies: ["IdentityDomain"],
            path: "Packages/Tests/IdentityDomainTests"
        ),
        .testTarget(
            name: "PresentationDomainTests",
            dependencies: ["PresentationDomain", "ProfileDomain", "TrustDomain"],
            path: "Packages/Tests/PresentationDomainTests"
        ),
        .testTarget(
            name: "ProtocolEngineTests",
            dependencies: ["ProtocolEngine", "PresentationDomain", "ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Tests/ProtocolEngineTests",
            resources: [.process("Fixtures")]
        ),
        .testTarget(
            name: "EudiWalletKitAdapterTests",
            dependencies: ["EudiWalletKitAdapter"],
            path: "Packages/Tests/EudiWalletKitAdapterTests"
        ),
        .testTarget(
            name: "EbsiW3CBackendTests",
            dependencies: [
                "EbsiW3CBackend",
                .product(name: "JOSESwift", package: "joseswift"),
            ],
            path: "Packages/Tests/EbsiW3CBackendTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
