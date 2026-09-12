import Testing
import Foundation
import CryptoKit
import SECP256K1

/// Known-answer tests driven by upstream's own vector files.
///
/// libsecp256k1 vendors Google's Wycheproof vectors in `src/wycheproof/`, in
/// both `.h` and `.json` form. The JSON is read here **in place**, unmodified,
/// rather than being copied into the package as a resource -- keeping the
/// project's rule that upstream files are never touched or duplicated. The path
/// is derived from `#filePath`, so this only works when running from the source
/// tree, which is where these tests run.
///
/// These are the tests that were missing: everything else in this suite is a
/// round-trip or a property, whereas these check behaviour against an external
/// authority that knows nothing about libsecp256k1.
enum Vectors {
    /// The repository root, three levels up from this file.
    static var repositoryRoot: URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()   // SECP256K1Test
            .deletingLastPathComponent()   // swift-tests
            .deletingLastPathComponent()   // <root>
    }

    static func json(_ relativePath: String) throws -> [String: Any] {
        let url = repositoryRoot.appending(path: relativePath)
        let data = try Data(contentsOf: url)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Secp256k1Error.invalidSignature
        }
        return object
    }

    static func bytes(fromHex hex: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return [] }
            out.append(byte)
            index = next
        }
        return out
    }
}

@Suite("Wycheproof ECDSA")
struct WycheproofECDSATests {
    struct Case {
        let id: Int
        let comment: String
        let publicKey: [UInt8]      // 65-byte uncompressed
        let messageHash: [UInt8]    // SHA-256 of the message
        let derSignature: [UInt8]
        let expectedValid: Bool
    }

    static func load() throws -> [Case] {
        let root = try Vectors.json("src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json")
        let groups = root["testGroups"] as? [[String: Any]] ?? []
        var cases: [Case] = []
        for group in groups {
            guard let key = group["publicKey"] as? [String: Any],
                  let uncompressed = key["uncompressed"] as? String,
                  let tests = group["tests"] as? [[String: Any]] else { continue }
            // Every group in this file is SHA-256; assert rather than assume.
            #expect(group["sha"] as? String == "SHA-256")
            let publicKey = Vectors.bytes(fromHex: uncompressed)
            for test in tests {
                guard let id = test["tcId"] as? Int,
                      let msgHex = test["msg"] as? String,
                      let sigHex = test["sig"] as? String,
                      let result = test["result"] as? String else { continue }
                // Wycheproof supplies the message; the digest is ours to compute.
                let digest = SHA256.hash(data: Data(Vectors.bytes(fromHex: msgHex)))
                cases.append(Case(
                    id: id,
                    comment: test["comment"] as? String ?? "",
                    publicKey: publicKey,
                    messageHash: Array(digest),
                    derSignature: Vectors.bytes(fromHex: sigHex),
                    expectedValid: result == "valid"))
            }
        }
        return cases
    }

    @Test("all 463 vectors agree with libsecp256k1")
    func allVectors() throws {
        let ctx = try Context()
        let cases = try Self.load()

        // Guard against silently testing nothing if the file moves or the
        // schema changes.
        #expect(cases.count == 463)
        let valid = cases.filter(\.expectedValid).count
        #expect(valid == 162)
        #expect(cases.count - valid == 301)

        var failures: [String] = []
        for c in cases {
            // A vector can fail at parse time (malformed DER) or at
            // verification. Both count as "invalid" for Wycheproof's purposes.
            var accepted = false
            if let key = try? ctx.publicKey(parsing: c.publicKey.span),
               let sig = try? ctx.signature(parsingDER: c.derSignature.span) {
                accepted = ctx.isValid(sig, messageHash: c.messageHash.span, publicKey: key)
            }
            if accepted != c.expectedValid {
                failures.append("tcId \(c.id) (\(c.comment)): expected "
                                + "\(c.expectedValid ? "valid" : "invalid"), got "
                                + "\(accepted ? "valid" : "invalid")")
            }
        }
        if !failures.isEmpty {
            let shown = Array(failures.prefix(10)).joined(separator: "\n")
            Issue.record("\(failures.count) mismatches:\n\(shown)")
        }
        #expect(failures.isEmpty)
    }

    @Test("signature malleability is rejected")
    func malleabilityRejected() throws {
        // The reason this is the *bitcoin* variant of the Wycheproof file:
        // high-S signatures are mathematically valid but must be rejected.
        // This asserts those vectors exist and that we reject every one.
        let ctx = try Context()
        let root = try Vectors.json("src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json")
        let groups = root["testGroups"] as? [[String: Any]] ?? []
        var checked = 0
        for group in groups {
            guard let key = group["publicKey"] as? [String: Any],
                  let uncompressed = key["uncompressed"] as? String,
                  let tests = group["tests"] as? [[String: Any]] else { continue }
            let pkBytes = Vectors.bytes(fromHex: uncompressed)
            for test in tests {
                let flags = test["flags"] as? [String] ?? []
                guard flags.contains("SignatureMalleabilityBitcoin"),
                      let msgHex = test["msg"] as? String,
                      let sigHex = test["sig"] as? String else { continue }
                checked += 1
                let digest = Array(SHA256.hash(data: Data(Vectors.bytes(fromHex: msgHex))))
                let sigBytes = Vectors.bytes(fromHex: sigHex)
                var accepted = false
                if let pk = try? ctx.publicKey(parsing: pkBytes.span),
                   let sig = try? ctx.signature(parsingDER: sigBytes.span) {
                    accepted = ctx.isValid(sig, messageHash: digest.span, publicKey: pk)
                    // It should also report as non-normalised.
                    let res = ctx.isNormalized(sig)
                    #expect(!res)
                }
                #expect(!accepted)
            }
        }
        // If this hits zero the schema changed and the test is vacuous.
        #expect(checked > 0)
    }
}

@Suite("Wycheproof ECDH")
struct WycheproofECDHTests {
    /// The canonical secp256k1 SubjectPublicKeyInfo header, 23 bytes, followed
    /// by the 65-byte uncompressed point.
    static let canonicalSPKIHeader = Vectors.bytes(
        fromHex: "3056301006072a8648ce3d020106052b8104000a034200")

    struct Case {
        let id: Int
        let publicKey: [UInt8]    // 65-byte uncompressed point
        let secretKey: [UInt8]    // 32 bytes
        let shared: [UInt8]       // 32-byte raw x coordinate
    }

    /// Normalises Wycheproof's private keys, which appear as 1, 29, 32 or 33
    /// bytes -- 33 with a leading zero sign byte, shorter ones with leading
    /// zeros omitted.
    static func padded(_ bytes: [UInt8]) -> [UInt8]? {
        var trimmed = bytes
        while trimmed.first == 0 { trimmed.removeFirst() }
        guard trimmed.count <= 32 else { return nil }
        return [UInt8](repeating: 0, count: 32 - trimmed.count) + trimmed
    }

    /// Only the vectors whose SPKI is exactly canonical are used.
    ///
    /// Most of this file tests X.509/ASN.1 parsing -- wrong OIDs, bad lengths,
    /// trailing garbage -- which libsecp256k1 does not do and this wrapper does
    /// not either. Feeding malformed DER through a "take the last 65 bytes"
    /// shortcut would test the shortcut, not the library, so those vectors are
    /// deliberately skipped. What remains is the ECDH arithmetic, and it is the
    /// interesting part: 360 of these are flagged `EdgeCaseDoubling`.
    static func load() throws -> [Case] {
        let root = try Vectors.json("src/wycheproof/ecdh_secp256k1_test.json")
        let groups = root["testGroups"] as? [[String: Any]] ?? []
        var cases: [Case] = []
        for group in groups {
            for test in group["tests"] as? [[String: Any]] ?? [] {
                guard let id = test["tcId"] as? Int,
                      let publicHex = test["public"] as? String,
                      let privateHex = test["private"] as? String,
                      let sharedHex = test["shared"] as? String,
                      test["result"] as? String == "valid" else { continue }
                let der = Vectors.bytes(fromHex: publicHex)
                guard der.count == 88,
                      Array(der.prefix(23)) == canonicalSPKIHeader,
                      let secretKey = padded(Vectors.bytes(fromHex: privateHex))
                else { continue }
                cases.append(Case(id: id,
                                  publicKey: Array(der.suffix(65)),
                                  secretKey: secretKey,
                                  shared: Vectors.bytes(fromHex: sharedHex)))
            }
        }
        return cases
    }

    @Test("the well-formed valid vectors all agree, raw x coordinate")
    func rawXVectors() throws {
        let ctx = try Context()
        let cases = try Self.load()
        #expect(cases.count == 473)

        var failures: [String] = []
        for c in cases {
            let key = try ctx.publicKey(parsing: c.publicKey.span)
            let secret = try ctx.sharedSecret(publicKey: key,
                                              secretKey: c.secretKey.span,
                                              hash: .rawXCoordinate)
            if secret != c.shared { failures.append("tcId \(c.id)") }
        }
        if !failures.isEmpty {
            let shown = Array(failures.prefix(10)).joined(separator: ", ")
            Issue.record("\(failures.count) mismatches: \(shown)")
        }
        #expect(failures.isEmpty)
    }

    @Test("the default hash differs from the raw coordinate")
    func defaultHashIsNotRaw() throws {
        // Guards against the hash selector being ignored, which would make the
        // test above pass for the wrong reason.
        let ctx = try Context()
        let cases = try Self.load()
        let c = try #require(cases.first)
        let key = try ctx.publicKey(parsing: c.publicKey.span)
        let hashed = try ctx.sharedSecret(publicKey: key, secretKey: c.secretKey.span)
        let rawX = try ctx.sharedSecret(publicKey: key, secretKey: c.secretKey.span,
                                        hash: .rawXCoordinate)
        #expect(rawX == c.shared)
        #expect(hashed != rawX)
        #expect(hashed.count == 32)
    }
}
