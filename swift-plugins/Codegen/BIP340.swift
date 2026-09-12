import Foundation

/// Swift port of `swift-tools/generate-bip340-vectors.py`.
///
/// Upstream ships the BIP340 vectors only as C array literals inside
/// `src/modules/schnorrsig/tests_impl.h`; there is no JSON to read at runtime,
/// unlike Wycheproof and BIP352. Output must match the Python script byte for
/// byte -- `codegen --check` is what proves it.
func generateBIP340Vectors(root: URL) throws -> String {
    let source = root.appending(path: "src/modules/schnorrsig/tests_impl.h")
    let text = try String(contentsOf: source, encoding: .utf8)

    guard let start = text.range(of: "static void test_schnorrsig_bip_vectors(void)"),
          let end = text.range(of: "\n}\n", range: start.upperBound..<text.endIndex)
    else { throw CodegenError.missingSection("test_schnorrsig_bip_vectors") }

    let body = String(text[start.lowerBound..<end.lowerBound])
    // The blocks are the brace-delimited vector scopes inside that function.
    let blocks = body.components(separatedBy: "\n    {\n").dropFirst()

    var entries: [Entry] = []
    for (offset, block) in blocks.enumerated() {
        let found = byteArrays(in: block)
        let name = vectorLabel(in: block) ?? "block \(offset + 1)"

        let signs = block.contains("check_signing(")
        let verifyExpectations = verifyResults(in: block)
        let parseOnly = !signs && verifyExpectations.isEmpty
            && block.contains("xonly_pubkey_parse")

        guard let publicKey = found["pk"] else { continue }

        if parseOnly {
            entries.append(Entry(name: name, publicKey: publicKey, parses: false,
                                 secretKey: nil, auxRandom: nil, message: [],
                                 signature: nil, verifies: false))
            continue
        }
        entries.append(Entry(
            name: name,
            publicKey: publicKey,
            parses: true,
            secretKey: found["sk"],
            auxRandom: found["aux_rand"],
            message: message(in: block, arrays: found),
            signature: found["sig"],
            verifies: (verifyExpectations.first ?? "1") == "1"))
    }

    return render(entries)
}

private struct Entry {
    let name: String
    let publicKey: [UInt8]
    let parses: Bool
    let secretKey: [UInt8]?
    let auxRandom: [UInt8]?
    let message: [UInt8]
    let signature: [UInt8]?
    let verifies: Bool
}

/// Every `const unsigned char name[...] = { 0x.., ... };` in a block.
private func byteArrays(in block: String) -> [String: [UInt8]] {
    let pattern = /(?:const )?unsigned char (\w+)\[\d*\]\s*=\s*\{([^}]*)\};/
        .dotMatchesNewlines()
    var result: [String: [UInt8]] = [:]
    for match in block.matches(of: pattern) {
        result[String(match.1)] = hexBytes(in: String(match.2))
    }
    return result
}

private func hexBytes(in text: String) -> [UInt8] {
    text.matches(of: /0x([0-9A-Fa-f]{2})/).compactMap { UInt8($0.1, radix: 16) }
}

private func vectorLabel(in block: String) -> String? {
    guard let match = block.firstMatch(of: /\/\* (Test vector \d+[^*]*?)\s*\*\//) else {
        return nil
    }
    return String(match.1)
}

private func verifyResults(in block: String) -> [String] {
    block.matches(of: /check_verify\(([^;]*?)\);/.dotMatchesNewlines()).map {
        String($0.1).split(separator: ",").last?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "1"
    }
}

/// The message, which appears in four different shapes across the vectors.
private func message(in block: String, arrays: [String: [UInt8]]) -> [UInt8] {
    // memset(msg, 0xNN, sizeof(msg)) over a fixed-size declaration.
    if let decl = block.firstMatch(of: /unsigned char msg\[(\d+)\];/),
       let fill = block.firstMatch(of: /memset\(msg,\s*(0x[0-9A-Fa-f]+|\d+),/),
       let count = Int(decl.1) {
        let literal = String(fill.1)
        let value = literal.hasPrefix("0x")
            ? UInt8(literal.dropFirst(2), radix: 16) : UInt8(literal)
        return [UInt8](repeating: value ?? 0, count: count)
    }
    // `NULL, 0` -- the empty message.
    if block.contains(/check_signing\([^;]*?,\s*NULL,\s*0,/.dotMatchesNewlines()) {
        return []
    }
    return arrays["msg"] ?? []
}

/// Byte-array literal formatting, matching the Python script exactly: rows of
/// 12, uppercase hex, 12-space continuation indent.
private func swiftBytes(_ data: [UInt8]) -> String {
    guard !data.isEmpty else { return "[]" }
    var rows: [String] = []
    var index = 0
    while index < data.count {
        let row = data[index..<min(index + 12, data.count)]
        rows.append(row.map { String(format: "0x%02X", $0) }.joined(separator: ", "))
        index += 12
    }
    return "[\n            " + rows.joined(separator: ",\n            ") + ",\n        ]"
}

private func render(_ entries: [Entry]) -> String {
    var lines = [
        "// GENERATED FILE -- do not edit by hand.",
        "//",
        "// Regenerate with either front-end (both produce identical output):",
        "//     swift package --allow-writing-to-package-directory codegen bip340",
        "//     python3 swift-tools/generate-bip340-vectors.py",
        "// Add --check to verify instead of writing.",
        "//",
        "// Extracted from src/modules/schnorrsig/tests_impl.h, which is upstream's own",
        "// copy of the BIP340 test vectors. Upstream ships these only as C array",
        "// literals, so unlike Wycheproof and BIP352 they cannot be read at runtime.",
        "",
        "/// One BIP340 vector.",
        "struct BIP340Vector: Sendable {",
        "    let name: String",
        "    /// 32-byte x-only public key.",
        "    let publicKey: [UInt8]",
        "    /// False for the vectors whose public key is not a valid x coordinate.",
        "    let publicKeyParses: Bool",
        "    /// Present only for the sign-and-verify vectors.",
        "    let secretKey: [UInt8]?",
        "    let auxRandom: [UInt8]?",
        "    /// Any length: the later vectors cover BIP340's arbitrary-size messages.",
        "    let message: [UInt8]",
        "    let signature: [UInt8]?",
        "    /// Whether verification must succeed.",
        "    let verifies: Bool",
        "}",
        "",
        "/// All \(entries.count) vectors, in upstream's order.",
        "let bip340Vectors: [BIP340Vector] = [",
    ]
    for entry in entries {
        lines.append("    BIP340Vector(")
        lines.append("        name: \"\(entry.name)\",")
        lines.append("        publicKey: \(swiftBytes(entry.publicKey)),")
        lines.append("        publicKeyParses: \(entry.parses ? "true" : "false"),")
        // The Python script renders an absent *or empty* array as `nil` for
        // these two fields (Python treats [] as falsy), so match that.
        for (field, value) in [("secretKey", entry.secretKey),
                               ("auxRandom", entry.auxRandom)] {
            let rendered = (value?.isEmpty == false) ? swiftBytes(value!) : "nil"
            lines.append("        \(field): \(rendered),")
        }
        lines.append("        message: \(swiftBytes(entry.message)),")
        lines.append("        signature: \((entry.signature?.isEmpty == false) ? swiftBytes(entry.signature!) : "nil"),")
        lines.append("        verifies: \(entry.verifies ? "true" : "false")),")
    }
    lines.append("]")
    return lines.joined(separator: "\n") + "\n"
}
