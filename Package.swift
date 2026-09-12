// swift-tools-version: 6.4

import PackageDescription

// libsecp256k1 is only three translation units. Everything else under src/ is
// either pulled in via #include from these, or belongs to upstream's own
// test/bench binaries (which #include secp256k1.c directly and therefore must
// never be linked against this target).
let librarySources = [
    "src/secp256k1.c",
    "src/precomputed_ecmult.c",
    "src/precomputed_ecmult_gen.c",
]

// Optional modules are gated behind these in src/secp256k1.c. All of them are
// enabled so the eventual Swift-facing surface is the full upstream API.
//
// Note: these are private to this target's compilation and do not reach
// importers of the module. That is fine -- the per-module public headers in
// include/ are self-contained and unconditional.
let moduleFlags: [CSetting] = [
    "ECDH", "RECOVERY", "EXTRAKEYS", "SCHNORRSIG",
    "MUSIG", "ELLSWIFT", "SILENTPAYMENTS",
].map { .define("ENABLE_MODULE_\($0)") }

// Upstream's C test binaries. Each is a one-line shim TU under swift-src/ that
// #includes the real upstream source, because:
//
//  - `tests` and `noverify_tests` are the SAME file (src/tests.c) built twice
//    with different defines, and SwiftPM will not let one file belong to two
//    targets. This is the wall you hit trying to have both at once.
//  - `sources:` paths cannot escape the target directory with "..", so a target
//    rooted in swift-src/ cannot name src/tests.c directly.
//
// None of these may link CSECP256K1: each upstream source #includes
// secp256k1.c wholesale, so linking the library too is a duplicate-symbol
// error. That is also why they are executableTargets with no dependencies.
//
// Directory names are deliberately not the upstream binary names: upstream's
// .gitignore lists the bare words `tests`, `noverify_tests`, `exhaustive_tests`
// and `ctime_tests`, and with core.ignorecase=true on macOS a directory so
// named would be silently untracked.
func cTestTarget(
    name: String,
    path: String,
    defines: [String]
) -> Target {
    .executableTarget(
        name: name,
        path: path,
        cSettings: [.headerSearchPath("../../src")]
            + moduleFlags
            + defines.map { .define($0) }
    )
}

// Mirrors CMake's TEST_DEFINITIONS: set when sys/types.h, sys/wait.h and
// unistd.h are all present, which is the case on Darwin and Linux. Consumed by
// src/unit_test.c (reached via src/tests.c:30) to enable the fork-based
// concurrency tests.
let supportsConcurrency = "SUPPORTS_CONCURRENCY=1"

// Span, MutableSpan and the safe overloads the API notes generate are all
// macOS 26+. Without this the importer silently falls back to
// UnsafeBufferPointer overloads, which are useless under strict memory safety.
let swiftInteropSettings: [SwiftSetting] = [
    // Turns BoundsSafety+NoEscape in swift-include/CSECP256K1.apinotes into
    // Span/MutableSpan overloads via the compiler's Swiftify macro.
    .enableExperimentalFeature("SafeInteropWrappers"),
    //.enableExperimentalFeature("Lifetimes"),
    // Every remaining use of an unsafe construct must be spelled `unsafe`.
    .strictMemorySafety(),
]

let package = Package(
    name: "secp256k1",
    platforms: [.macOS(.v27)],
    products: [
        .library(name: "CSECP256K1", targets: ["CSECP256K1"]),
        .library(name: "SECP256K1", targets: ["SECP256K1"]),
        .executable(name: "tests", targets: ["tests"]),
        .executable(name: "noverify_tests", targets: ["noverify_tests"]),
        .executable(name: "exhaustive_tests", targets: ["exhaustive_tests"]),
    ],
    targets: [
        // Compiles the vendored C library exactly as upstream ships it: no edits
        // to src/ or include/, no generated config header, no symlinked header
        // directory.
        //
        // path "." (rather than "src") is what makes that possible:
        // publicHeadersPath resolves relative to the target path, so targeting
        // src/ would require a src/include/ that does not exist upstream. From
        // the package root, upstream's real include/ is used directly and
        // SwiftPM synthesises an umbrella-directory module map over it,
        // exposing all nine public headers as module CSECP256K1.
        //
        // SECP256K1_BUILD is deliberately NOT defined here: src/secp256k1.c:18
        // defines it itself, and defining it for importers would strip the
        // SECP256K1_ARG_NONNULL attributes that Swift's importer turns into
        // non-optional pointers. The wide-multiplication backend and
        // ECMULT_WINDOW_SIZE are left to upstream's own autodetection.
        .target(
            name: "CSECP256K1",
            path: ".",
            sources: librarySources,
            publicHeadersPath: "swift-include",
            cSettings: [.headerSearchPath("src"), .headerSearchPath("include")] + moduleFlags
        ),

        // The Swift-facing wrapper. Consumes the annotated module and
        // contains the remaining unsafety (the OpaquePointer context and the
        // by-pointer struct parameters) behind a safe API.
        .target(
            name: "SECP256K1",
            dependencies: ["CSECP256K1"],
            path: "swift-src/SECP256K1",
            swiftSettings: swiftInteropSettings
        ),

        .testTarget(
            name: "SECP256K1Tests",
            dependencies: ["SECP256K1", "CSECP256K1"],
            path: "swift-test/SECP256K1Test",
            // Read at runtime from the source tree via #filePath, not bundled:
            // the vector tests also read upstream's files in src/ the same way,
            // and copying them would duplicate data this project is careful not
            // to touch. Excluded so SwiftPM does not warn about an unhandled
            // file.
            exclude: ["bip352-vectors.json"],
            swiftSettings: swiftInteropSettings
        ),

        // CMake: add_executable_and_tests(tests VERIFY)
        cTestTarget(
            name: "tests",
            path: "swift-src/ctest-verify",
            defines: ["VERIFY", supportsConcurrency]
        ),

        // CMake: add_executable_and_tests(noverify_tests "")
        cTestTarget(
            name: "noverify_tests",
            path: "swift-src/ctest-noverify",
            defines: [supportsConcurrency]
        ),

        // CMake: add_executable(exhaustive_tests tests_exhaustive.c), linked
        // WITHOUT secp256k1_precomputed -- it generates its tables at runtime.
        cTestTarget(
            name: "exhaustive_tests",
            path: "swift-src/ctest-exhaustive",
            defines: ["VERIFY"]
        ),

        // Swift ports of the generators in swift-tools/. A *command* plugin,
        // not a build-tool plugin: the API notes file is an input to
        // CSECP256K1's committed module map, which a build tool plugin's
        // work-directory outputs cannot satisfy.
        //
        //     swift package --allow-writing-to-package-directory codegen
        //     swift package codegen --check
        //
        // The Python scripts remain the reference implementation; both must
        // produce byte-identical output.
        .plugin(
            name: "Codegen",
            capability: .command(
                intent: .custom(verb: "codegen",
                                description: "Regenerate API notes and test vectors"),
                permissions: [
                    .writeToPackageDirectory(
                        reason: "regenerate the committed generated files")
                ]
            ),
            dependencies: ["bip352-dump"],
            path: "swift-plugins/Codegen"
        ),

        // The BIP352 vector dumper. Declared as a target so the plugin can run
        // it via context.tool(named:) and SwiftPM builds it -- no hand-rolled
        // clang invocation and no compiler flags to keep in sync.
        .executableTarget(
            name: "bip352-dump",
            path: "swift-tools",
            sources: ["bip352-dump.c"]
        ),

        // Not defined: ctime_tests. src/ctime_tests.c:15 is a hard #error
        // unless SECP256K1_CHECKMEM_ENABLED, which requires either
        // MemorySanitizer (Linux-only in practice) or valgrind's headers with
        // -DVALGRIND. Upstream gates it the same way: SECP256K1_BUILD_CTIME_TESTS
        // defaults to ${SECP256K1_VALGRIND}, i.e. off. It is also the only test
        // binary that links the real library rather than #including secp256k1.c,
        // so adding it later means depending on CSECP256K1.
    ],
    // Upstream builds as C90 (CMAKE_C_STANDARD 90, -std=c89 under autotools).
    cLanguageStandard: .c90
)
