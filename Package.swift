// swift-tools-version:6.0

import PackageDescription

let package = Package(
    name: "secp256k1",
    products: [
        .library(name: "LibSECP256k1", targets: ["LibSECP256k1"]),
    ],
    targets: [
        .target(
            name: "LibSECP256k1PreComputed",
            path: "src",
            sources: ["precomputed_ecmult.c", "precomputed_ecmult_gen.c"],
            publicHeadersPath: "include-precomputed",
            cSettings: [
                .define("SECP256K1_BUILD", to: ""),
            ]
        ),
        .target(
            name: "LibSECP256k1",
            dependencies: ["LibSECP256k1PreComputed"],
            path: "src",
            sources: ["secp256k1.c"],
            publicHeadersPath: "include",
            cSettings: [
                .define("SECP256K1_BUILD", to: ""),
                .define("ENABLE_MODULE_ECDH"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_EXTRAKEYS"),
                .define("ENABLE_MODULE_SCHNORRSIG"),
                .define("ENABLE_MODULE_ELLSWIFT"),
                .define("ENABLE_MODULE_MUSIG")
            ]
        ),
        .executableTarget(
            name: "LibSECP256k1Tests",
            dependencies: ["LibSECP256k1PreComputed"],
            path: "src",
            sources: ["tests.c"],
            cSettings: [
                .define("SECP256K1_BUILD", to: ""),
                .define("ENABLE_MODULE_ECDH"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_EXTRAKEYS"),
                .define("ENABLE_MODULE_SCHNORRSIG"),
                .define("ENABLE_MODULE_ELLSWIFT"),
                .define("ENABLE_MODULE_MUSIG")
            ]
        )
    ],
    cLanguageStandard: .c90
)
