import PackagePlugin
import Foundation

/// Swift port of `swift-tools/generate-bip352-vectors.py`.
///
/// `src/modules/silentpayments/vectors.h` is a nested C aggregate initialiser
/// with positional fields, where a regex would misparse silently. So a C
/// program includes it and prints JSON, and the compiler does the parsing --
/// the same reasoning behind using clang's AST for the API notes.
///
/// The dumper is a declared SwiftPM target (`bip352-dump`), so SwiftPM builds it
/// and this plugin runs it via `context.tool(named:)`. No hand-rolled clang
/// invocation, and no compiler flags to keep in sync.
///
/// Its stdout is written through verbatim. Re-serialising here would be worse
/// than pointless: Python's `json.dumps(indent=1)` and Swift's
/// `JSONSerialization.prettyPrinted` disagree on indentation, so a round trip
/// would make byte-identical output between the two drivers impossible. The C
/// program owns the format instead, and both drivers just pass bytes along.
func generateBIP352Vectors(root: URL, context: PluginContext) throws -> String {
    let tool = try context.tool(named: "bip352-dump")
    let output = try run(tool.url, [], name: "bip352-dump")

    // Cheap sanity check: the dumper must have produced parseable JSON with the
    // expected shape, or a silent truncation would be committed.
    guard let parsed = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [Any],
          !parsed.isEmpty
    else { throw CodegenError.missingSection("BIP352 vectors in the dumper output") }

    return output
}
