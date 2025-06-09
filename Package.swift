// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SupacryptCTK",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "SupacryptCTK",
            targets: ["SupacryptCTK"]
        ),
        .executable(
            name: "SupacryptCTKExtension",
            targets: ["SupacryptCTKExtension"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/grpc/grpc-swift.git", from: "1.19.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0")
    ],
    targets: [
        .target(
            name: "SupacryptCTK",
            dependencies: [
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Logging", package: "swift-log")
            ],
            path: "SupacryptCTK"
        ),
        .executableTarget(
            name: "SupacryptCTKExtension",
            dependencies: ["SupacryptCTK"],
            path: "SupacryptCTKExtension"
        ),
        .testTarget(
            name: "SupacryptCTKTests",
            dependencies: ["SupacryptCTK"],
            path: "SupacryptCTKTests"
        )
    ]
)