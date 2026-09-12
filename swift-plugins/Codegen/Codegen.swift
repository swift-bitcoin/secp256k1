import PackagePlugin
import Foundation

/// Regenerates this package's generated files, in Swift.
///
/// Mirrors the scripts in `swift-tools/`, which are kept as a reference
/// implementation. Both must produce byte-identical output; `--check` is what
/// makes that verifiable rather than hopeful.
///
///     swift package --allow-writing-to-package-directory codegen            # all
///     swift package --allow-writing-to-package-directory codegen bip340
///     swift package codegen --check                                          # no writes
///
/// A *command* plugin rather than a build-tool plugin, deliberately. The API
/// notes file is an input to CSECP256K1's committed module map, and a build tool
/// plugin's outputs land in a work directory that a static module map cannot
/// reference. These outputs also only change when upstream is re-vendored, so
/// regenerating per build would cost a clang AST dump for nothing.
@main
struct Codegen: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let root = context.package.directoryURL
        let check = arguments.contains("--check")
        let selected = arguments.filter { !$0.hasPrefix("--") }
        let wanted = selected.isEmpty ? Generator.allNames : selected

        var failures = 0
        for name in wanted {
            guard let generator = Generator(name: name) else {
                Diagnostics.error("unknown generator '\(name)'; known: \(Generator.allNames.joined(separator: ", "))")
                failures += 1
                continue
            }
            let produced: String
            do {
                produced = try generator.generate(root: root, context: context)
            } catch {
                Diagnostics.error("\(name): \(error)")
                failures += 1
                continue
            }
            let destination = root.appending(path: generator.outputPath)
            let current = (try? String(contentsOf: destination, encoding: .utf8)) ?? ""

            if check {
                if current == produced {
                    print("\(generator.outputPath): up to date")
                } else {
                    Diagnostics.error("\(generator.outputPath) is out of date; regenerate it.")
                    failures += 1
                }
            } else if current == produced {
                print("\(generator.outputPath): unchanged")
            } else {
                try produced.write(to: destination, atomically: true, encoding: .utf8)
                print("\(generator.outputPath): written")
            }
        }
        if failures > 0 { throw CodegenError.failed(count: failures) }
    }
}

enum CodegenError: Error, CustomStringConvertible {
    case failed(count: Int)
    case toolFailed(String, Int32, String)
    case missingSection(String)

    var description: String {
        switch self {
        case .failed(let count): "\(count) generator(s) failed"
        case .toolFailed(let name, let status, let output):
            "\(name) exited with \(status): \(output.prefix(400))"
        case .missingSection(let what): "could not locate \(what) in the upstream source"
        }
    }
}

enum Generator {
    case bip340
    case bip352
    case apinotes

    static let allNames = ["bip340", "bip352", "apinotes"]

    init?(name: String) {
        switch name {
        case "bip340": self = .bip340
        case "bip352": self = .bip352
        case "apinotes": self = .apinotes
        default: return nil
        }
    }

    var outputPath: String {
        switch self {
        case .bip340: "swift-test/SECP256K1Test/BIP340Vectors.swift"
        case .bip352: "swift-test/SECP256K1Test/bip352-vectors.json"
        case .apinotes: "swift-include/CSECP256K1.apinotes"
        }
    }

    func generate(root: URL, context: PluginContext) throws -> String {
        switch self {
        case .bip340: try generateBIP340Vectors(root: root)
        case .bip352: try generateBIP352Vectors(root: root, context: context)
        case .apinotes: try generateAPINotes(root: root)
        }
    }
}

// MARK: - Shared helpers

/// Runs a tool and returns its standard output, or throws with its stderr.
func run(_ executable: URL, _ arguments: [String], name: String) throws -> String {
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    let out = Pipe()
    let err = Pipe()
    process.standardOutput = out
    process.standardError = err
    try process.run()
    // Read before waiting: a large AST dump will fill the pipe buffer and
    // deadlock if the child is left blocked on write.
    let outData = out.fileHandleForReading.readDataToEndOfFile()
    let errData = err.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw CodegenError.toolFailed(name, process.terminationStatus,
                                      String(decoding: errData, as: UTF8.self))
    }
    return String(decoding: outData, as: UTF8.self)
}

/// `clang` from the active toolchain, via `env` so PATH resolution applies.
func clangURL() -> URL { URL(filePath: "/usr/bin/env") }
