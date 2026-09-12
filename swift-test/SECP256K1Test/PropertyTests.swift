import Testing
import Foundation
import SECP256K1

/// A small seeded PRNG so failures are reproducible.
///
/// This is deliberately not `SystemRandomNumberGenerator`: upstream's C tests
/// print their seed so a failure can be replayed, and a fuzz test that cannot
/// be replayed is a poor trade. `xoshiro256**`, seeded by SplitMix64.
struct SeededGenerator: RandomNumberGenerator {
    private var state: (UInt64, UInt64, UInt64, UInt64)

    init(seed: UInt64) {
        var z = seed
        func next() -> UInt64 {
            z &+= 0x9E3779B97F4A7C15
            var x = z
            x = (x ^ (x >> 30)) &* 0xBF58476D1CE4E5B9
            x = (x ^ (x >> 27)) &* 0x94D049BB133111EB
            return x ^ (x >> 31)
        }
        state = (next(), next(), next(), next())
    }

    mutating func next() -> UInt64 {
        func rotl(_ x: UInt64, _ k: UInt64) -> UInt64 { (x << k) | (x >> (64 - k)) }
        let result = rotl(state.1 &* 5, 7) &* 9
        let t = state.1 << 17
        state.2 ^= state.0
        state.3 ^= state.1
        state.1 ^= state.2
        state.0 ^= state.3
        state.2 ^= t
        state.3 = rotl(state.3, 45)
        return result
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8(next() & 0xFF) }
    }
}

/// Randomised property tests.
///
/// Upstream runs each C test `--iterations` times (default 16) on random inputs;
/// every other Swift suite here uses fixed vectors, so these close that gap.
/// Override the count with `SECP256K1_SWIFT_ITERS`, mirroring upstream's
/// `SECP256K1_TEST_ITERS`.
@Suite("Randomised properties")
struct PropertyTests {
    static let iterations = Int(ProcessInfo.processInfo.environment["SECP256K1_SWIFT_ITERS"] ?? "")
        ?? 64
    /// Fixed by default so a failure is reproducible; override to explore.
    static let seed = UInt64(ProcessInfo.processInfo.environment["SECP256K1_SWIFT_SEED"] ?? "")
        ?? 0x5EC2_56C1_BEEF_CAFE

    /// Draws a random *valid* secret key. Random 32-byte strings are valid with
    /// overwhelming probability, but not certainty, so this filters.
    static func secretKey(_ ctx: borrowing Context, _ rng: inout SeededGenerator) -> [UInt8] {
        while true {
            let candidate = rng.bytes(32)
            if ctx.isValidSecretKey(candidate.span) { return candidate }
        }
    }

    @Test("ECDSA sign/verify round-trips for random keys and messages")
    func ecdsaRoundTrip() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let msg = rng.bytes(32)
            let pub = try ctx.publicKey(secretKey: sk.span)
            let sig = try ctx.sign(messageHash: msg.span, secretKey: sk.span)

            let ok = ctx.isValid(sig, messageHash: msg.span, publicKey: pub)
            #expect(ok)

            // A different message must not verify.
            var other = msg
            other[0] ^= 0x01
            let bad = ctx.isValid(sig, messageHash: other.span, publicKey: pub)
            #expect(!bad)
        }
    }

    @Test("public keys round-trip through both serialisation formats")
    func publicKeySerialisation() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 1)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let pub = try ctx.publicKey(secretKey: sk.span)
            for format in [PublicKeyFormat.compressed, .uncompressed] {
                let bytes = ctx.serializedBytes(of: pub, format: format)
                #expect(bytes.count == (format == .compressed ? 33 : 65))
                let back = try ctx.publicKey(parsing: bytes.span)
                #expect(ctx.compare(back, pub) == 0)
            }
        }
    }

    @Test("DER signatures round-trip")
    func derRoundTrip() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 2)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let msg = rng.bytes(32)
            let sig = try ctx.sign(messageHash: msg.span, secretKey: sk.span)
            let der = ctx.derBytes(of: sig)
            let back = try ctx.signature(parsingDER: der.span)
            #expect(ctx.compactBytes(of: back) == ctx.compactBytes(of: sig))
        }
    }

    @Test("tweaking a secret key and its public key stay in correspondence")
    func tweakCorrespondence() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 3)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let tweak = Self.secretKey(ctx, &rng)
            let pub = try ctx.publicKey(secretKey: sk.span)

            guard let tweakedSecret = try? ctx.tweakedSecretKey(sk.span,
                                                                addingScalar: tweak.span),
                  let tweakedPublic = try? ctx.tweakedPublicKey(pub,
                                                                addingScalar: tweak.span)
            else { continue }   // the sum can be zero; negligible but possible

            let fromSecret = try ctx.publicKey(secretKey: tweakedSecret.span)
            #expect(ctx.compare(fromSecret, tweakedPublic) == 0)
        }
    }

    @Test("negating a secret key twice is the identity")
    func negateInvolution() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 4)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let once = try ctx.negatedSecretKey(sk.span)
            let twice = try ctx.negatedSecretKey(once.span)
            #expect(twice == sk)
            #expect(once != sk)
        }
    }

    @Test("ECDH agrees in both directions")
    func ecdhSymmetry() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 5)
        for _ in 0..<Self.iterations {
            let a = Self.secretKey(ctx, &rng)
            let b = Self.secretKey(ctx, &rng)
            let pubA = try ctx.publicKey(secretKey: a.span)
            let pubB = try ctx.publicKey(secretKey: b.span)
            let fromA = try ctx.sharedSecret(publicKey: pubB, secretKey: a.span)
            let fromB = try ctx.sharedSecret(publicKey: pubA, secretKey: b.span)
            #expect(fromA == fromB)
        }
    }

    @Test("Schnorr sign/verify round-trips at assorted message lengths")
    func schnorrRoundTrip() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 6)
        for i in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let kp = try ctx.keyPair(secretKey: sk.span)
            let (key, _) = try ctx.xOnlyPublicKey(of: kp)
            let aux = rng.bytes(32)
            // Cycle through lengths, including 0 and 32.
            let length = [0, 1, 32, 33, 100][i % 5]
            let msg = rng.bytes(length)

            let sig = try ctx.signSchnorr(message: msg.span, keyPair: kp,
                                          auxiliaryRandom: aux.span)
            let ok = ctx.isValidSchnorr(sig.span, message: msg.span, publicKey: key)
            #expect(ok)
        }
    }

    @Test("sorting public keys is a permutation, and ordered")
    func sortIsPermutation() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 7)
        for _ in 0..<(Self.iterations / 4) {
            let count = 2 + Int(rng.next() % 6)
            let keys = try (0..<count).map { _ -> PublicKey in
                try ctx.publicKey(secretKey: Self.secretKey(ctx, &rng).span)
            }
            let sorted = try ctx.sorted(publicKeys: keys)
            #expect(sorted.count == keys.count)

            // Ordered...
            let wire = sorted.map { ctx.serializedBytes(of: $0) }
            for (a, b) in zip(wire, wire.dropFirst()) {
                #expect(a.lexicographicallyPrecedes(b))
            }
            // ...and the same multiset as the input.
            let before = Set(keys.map { ctx.serializedBytes(of: $0) })
            #expect(Set(wire) == before)
        }
    }

    @Test("recovery recovers the signer for random inputs")
    func recoveryRoundTrip() throws {
        let ctx = try Context()
        var rng = SeededGenerator(seed: Self.seed &+ 8)
        for _ in 0..<Self.iterations {
            let sk = Self.secretKey(ctx, &rng)
            let msg = rng.bytes(32)
            let pub = try ctx.publicKey(secretKey: sk.span)
            let rec = try ctx.signRecoverable(messageHash: msg.span, secretKey: sk.span)
            let recovered = try ctx.recoverPublicKey(from: rec, messageHash: msg.span)
            #expect(ctx.compare(recovered, pub) == 0)
        }
    }
}
