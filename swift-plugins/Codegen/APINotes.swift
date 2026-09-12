import Foundation

/// Swift port of `swift-tools/generate-apinotes.py`.
///
/// Parameter names, types and order come from clang's JSON AST, so the
/// positional indices API notes rely on are never transcribed by hand. Exactly
/// one thing is read from the header text: the `SECP256K1_ARG_NONNULL(k)` macro,
/// whose argument indices clang's JSON AST records as bare `NonNullAttr` nodes
/// *without* the indices. That macro is trivially regular, so a regex is right
/// there and nowhere else.
///
/// Note this port does not make the pipeline "pure Swift": it still shells out
/// to clang, and must. The alternative -- parsing C headers by hand -- is
/// exactly the fragility the design avoids.
func generateAPINotes(root: URL) throws -> String {
    let include = root.appending(path: "include")
    let ast = try dumpAST(include: include)
    let nonnull = try nonnullIndices(include: include)

    var functions: [(name: String, params: [(String, String)], ret: String)] = []
    for node in (ast["inner"] as? [[String: Any]] ?? []) {
        guard node["kind"] as? String == "FunctionDecl",
              let name = node["name"] as? String,
              name.hasPrefix("secp256k1_") else { continue }
        let params = (node["inner"] as? [[String: Any]] ?? [])
            .filter { $0["kind"] as? String == "ParmVarDecl" }
            .map { param -> (String, String) in
                let type = (param["type"] as? [String: Any])?["qualType"] as? String ?? ""
                return (param["name"] as? String ?? "", type)
            }
        let signature = (node["type"] as? [String: Any])?["qualType"] as? String ?? ""
        let ret = signature.components(separatedBy: "(").first?
            .trimmingCharacters(in: .whitespaces) ?? ""
        functions.append((name, params, ret))
    }
    functions.sort { $0.name < $1.name }

    var skipped: [String] = []
    var lines: [String] = [
        "---",
        "# GENERATED FILE -- do not edit by hand.",
        "#",
        "# Regenerate with either front-end (both produce identical output):",
        "#     swift package --allow-writing-to-package-directory codegen apinotes",
        "#     python3 swift-tools/generate-apinotes.py",
        "# Add --check to verify instead of writing.",
        "#",
        "# Parameter names, types and positions come from clang's JSON AST, so the",
        "# positional indices below are never transcribed by hand. Naming choices,",
        "# fixed-size conventions and deliberate omissions live in the generator.",
        "#",
        "# See README-Swift.md for what each key does and why it is needed.",
        "Name: \(apiNotesModule)",
        "",
        "Tags:",
        "# The opaque context imports as OpaquePointer without this -- no type safety",
        "# and an unsafe type under strict memory safety. Retain/release are both",
        "# `immortal` because a retain must return the pointer it was given and",
        "# secp256k1_context_clone allocates a new context instead, so ARC cannot",
        "# manage the lifetime. Destruction stays explicit; Secp256k1Context owns it.",
        "- Name: secp256k1_context_struct",
        "  SwiftImportAs: reference",
        "  SwiftRetainOp: immortal",
        "  SwiftReleaseOp: immortal",
        "",
        "Functions:",
    ]

    for function in functions {
        var entry: [String] = []
        let nn = nonnull[function.name] ?? []

        var swiftName = nameOverrides[function.name]
        if swiftName == nil, let first = function.params.first,
           contextTypes.contains(first.1) {
            let base = camel(String(function.name.dropFirst("secp256k1_".count)))
            let labels = "self:" + function.params.dropFirst()
                .map { "\(camel($0.0.isEmpty ? "_" : $0.0)):" }.joined()
            swiftName = "secp256k1_context.\(base)(\(labels))"
        }
        if let swiftName { entry.append("  SwiftName: \"\(swiftName)\"") }

        if isPointer(function.ret) { entry.append("  NullabilityOfRet: O") }

        var parameterLines: [String] = []
        for (index, param) in function.params.enumerated() {
            let (pname, ptype) = param
            var keys: [String] = []
            if ptype.contains("unsigned char *") && !ptype.contains("*const *") {
                if let reason = skipReasons["\(function.name)(\(pname))"] {
                    skipped.append("\(function.name)(\(pname)): \(reason)")
                } else if let bound = bound(for: pname, params: function.params) {
                    keys.append("    NoEscape: true")
                    keys.append("    BoundsSafety: { Kind: \(bound.kind), BoundedBy: \(bound.by) }")
                } else {
                    let sizePointer = function.params.first { $0.1 == "size_t *" }?.0
                    let why = sizePointer.map {
                        "length is *\($0), an in/out pointer that BoundedBy cannot reference"
                    } ?? "no length parameter and no size in the name"
                    skipped.append("\(function.name)(\(pname)): \(why)")
                }
            }

            // TODO: Figure out when to insert the following: `keys.append("    BoundsSafety: { Kind: counted_by, BoundedBy: 1 }")`
            // This is because `BoundsSafety: { Kind: single }` trips the synthesizer

            // Nullability is stated for EVERY pointer parameter, N or O -- see
            // the Python script's comment, and README-Swift.md, for why partial
            // annotation is actively harmful.
            if isPointer(ptype) || isFunctionPointer(ptype) {
                keys.append("    Nullability: \(nn.contains(index + 1) ? "N" : "O")")
            }
            if !keys.isEmpty {
                parameterLines.append("  - Position: \(index)          # \(pname)")
                parameterLines.append(contentsOf: keys)
            }
        }
        if !parameterLines.isEmpty {
            entry.append("  Parameters:")
            entry.append(contentsOf: parameterLines)
        }
        if !entry.isEmpty {
            lines.append("- Name: \(function.name)")
            lines.append(contentsOf: entry)
        }
    }
    lines.append("")

    // --- Globals ---
    var globals: Set<[String]> = []
    for header in apiNotesHeaders {
        let text = try String(contentsOf: include.appending(path: header), encoding: .utf8)
        for chunk in text.components(separatedBy: "SECP256K1_API").dropFirst() {
            let decl = chunk.components(separatedBy: ";").first ?? ""
            if decl.contains("(") { continue }
            let words = decl.matches(of: /\w+/).map { String($0.output) }
            if let last = words.last {
                globals.insert([last, decl.trimmingCharacters(in: .whitespacesAndNewlines)])
            }
        }
    }
    lines.append("Globals:")
    lines.append("# None of upstream's exported constants is ever NULL, so `N` drops the")
    lines.append("# implicitly-unwrapped optional each would otherwise import as.")
    lines.append("#")
    lines.append("# secp256k1_context.shared must NEVER be destroyed, which is why")
    lines.append("# Secp256k1Context does not wrap it -- that class's deinit owns destroy().")
    for pair in globals.sorted(by: { $0[0] != $1[0] ? $0[0] < $1[0] : $0[1] < $1[1] }) {
        let gname = pair[0]
        let swift = globalOverrides[gname]
            ?? camel(String(gname.dropFirst("secp256k1_".count)))
        lines.append("- Name: \(gname)")
        lines.append("  SwiftName: \"\(swift)\"")
        lines.append("  Nullability: N")
    }

    if !skipped.isEmpty {
        print("apinotes: \(skipped.count) byte buffer(s) left unannotated:")
        for entry in skipped.sorted() { print("    \(entry)") }
    }
    return lines.joined(separator: "\n") + "\n"
}

// MARK: - clang

private func dumpAST(include: URL) throws -> [String: Any] {
    let temp = URL(filePath: NSTemporaryDirectory())
        .appending(path: "apinotes-\(UUID().uuidString).c")
    let translationUnit = apiNotesHeaders.map { "#include \"\($0)\"\n" }.joined()
    try translationUnit.write(to: temp, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: temp) }

    let output = try run(clangURL(),
                         ["clang", "-Xclang", "-ast-dump=json", "-fsyntax-only",
                          "-I", include.path(), temp.path()],
                         name: "clang")
    guard let ast = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any]
    else { throw CodegenError.missingSection("clang AST root object") }
    return ast
}

/// `{function name -> 1-based indices marked SECP256K1_ARG_NONNULL}`.
private func nonnullIndices(include: URL) throws -> [String: Set<Int>] {
    var result: [String: Set<Int>] = [:]
    for header in apiNotesHeaders {
        let text = try String(contentsOf: include.appending(path: header), encoding: .utf8)
        for chunk in text.components(separatedBy: "SECP256K1_API").dropFirst() {
            let decl = chunk.components(separatedBy: ";").first ?? ""
            guard let nameMatch = decl.firstMatch(of: /(\w+)\s*\(/) else { continue }
            let indices = decl.matches(of: /SECP256K1_ARG_NONNULL\((\d+)\)/)
                .compactMap { Int($0.1) }
            result[String(nameMatch.1), default: []].formUnion(indices)
        }
    }
    return result
}

// MARK: - Naming and bounds rules
//
// These mirror the Python script exactly. Both are kept, and `codegen --check`
// proves they agree byte for byte.

let apiNotesModule = "CSECP256K1"

let apiNotesHeaders = [
    "secp256k1.h",
    "secp256k1_preallocated.h",
    "secp256k1_ecdh.h",
    "secp256k1_ellswift.h",
    "secp256k1_extrakeys.h",
    "secp256k1_musig.h",
    "secp256k1_recovery.h",
    "secp256k1_schnorrsig.h",
    "secp256k1_silentpayments.h",
]

private let contextTypes: Set<String> = ["const secp256k1_context *", "secp256k1_context *"]

/// Only `seckey`, verified as "a 32-byte secret key" across all 11 uses.
private let namedBounds: [String: Int] = ["seckey": 32]

private let skipReasons: [String: String] = [
    "secp256k1_ecdh(output)":
        "length depends on the caller's hashfp; only 32 for the default hash",
    "secp256k1_ellswift_xdh(output)":
        "length depends on the caller's hashfp",
    "secp256k1_silentpayments_sender_create_outputs(seckeys)":
        "array of pointers, not a byte buffer",
]

private let nameOverrides: [String: String] = [
    "secp256k1_context_create": "secp256k1_context.init(flags:)",
    "secp256k1_context_destroy": "secp256k1_context.destroy(self:)",
    "secp256k1_context_clone": "secp256k1_context.clone(self:)",
    "secp256k1_ec_seckey_verify": "secp256k1_context.verifySecretKey(self:_:)",
    "secp256k1_ec_pubkey_create": "secp256k1_context.createPublicKey(self:_:secretKey:)",
    "secp256k1_ec_pubkey_parse": "secp256k1_context.parsePublicKey(self:_:from:length:)",
    "secp256k1_ecdsa_signature_parse_compact":
        "secp256k1_context.parseSignature(self:_:compact:)",
    "secp256k1_ecdsa_signature_serialize_compact":
        "secp256k1_context.serializeSignature(self:into:_:)",
    "secp256k1_ecdsa_sign":
        "secp256k1_context.sign(self:_:messageHash:secretKey:nonceFunction:nonceData:)",
    "secp256k1_ecdsa_verify":
        "secp256k1_context.verify(self:_:messageHash:publicKey:)",
]

private let globalOverrides: [String: String] = [
    "secp256k1_context_static": "secp256k1_context.shared"
]

/// Tokens that should not be title-cased into "Rfc6979" / "Sha256".
private let acronyms: [String: String] = [
    "rfc6979": "RFC6979",
    "sha256": "SHA256",
    "bip324": "BIP324",
    "bip340": "BIP340",
    "bip352": "BIP352",
    "xdh": "XDH",
    "der": "DER",
    "ecdh": "ECDH",
    "ecdsa": "ECDSA",
    "musig": "MuSig",
    "xonly": "XOnly",
]

private func camel(_ snake: String) -> String {
    let parts = snake.components(separatedBy: "_")
    guard let head = parts.first else { return snake }
    var out = head
    for word in parts.dropFirst() where !word.isEmpty {
        out += acronyms[word] ?? (word.prefix(1).uppercased() + word.dropFirst())
    }
    return out
}

private func isPointer(_ qualType: String) -> Bool {
    qualType.trimmingCharacters(in: .whitespaces).hasSuffix("*")
}

private func isFunctionPointer(_ qualType: String) -> Bool {
    qualType.hasPrefix("secp256k1_") && qualType.contains("function")
}

private func bound(for pname: String, params: [(String, String)]) -> (kind: String, by: String)? {
    // Swift 6.4 still does not support `__single` but can be tricked with `counted_by` with constant 1.
    if let match = pname.firstMatch(of: /(\d+)$/) {
        return ("counted_by", String(match.1))
    }
    for (other, otherType) in params where otherType == "size_t" && other == "\(pname)len" {
        return ("counted_by", other)
    }
    if let literal = namedBounds[pname] {
        return ("counted_by", String(literal))
    }
    return nil
}
