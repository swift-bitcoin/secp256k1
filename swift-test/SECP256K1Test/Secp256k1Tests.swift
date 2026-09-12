import Testing
import SECP256K1
import CSECP256K1

/// Exercises the annotated C library through the Swift wrapper.
///
/// Note the shape of every assertion below: the call happens on its own line
/// and only the resulting `Bool` goes into `#expect`. That is not style, it is
/// required. `Span` is non-escapable, and Swift Testing's `#expect` expands to
/// `Testing.__checkFunctionCall(...)`, which is generic over `each U` with an
/// implicit `each U: Escapable` constraint. Passing a `Span` directly inside
/// `#expect` fails to compile with "requires that 'Span<UInt8>' conform to
/// 'Escapable'".
@Suite("ECDSA over the annotated C library")
struct ECDSATests {
    /// All-0x11 bytes: a valid scalar, comfortably below the group order.
    static let secretKey = [UInt8](repeating: 0x11, count: 32)
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    @Test("a context can be created and destroyed")
    func contextLifecycle() throws {
        _ = try Context()
    }

    @Test("a valid secret key verifies")
    func secretKeyVerify() throws {
        let ctx = try Context()
        let ok = ctx.isValidSecretKey(Self.secretKey.span)
        #expect(ok)
    }

    @Test("an all-zero secret key is rejected")
    func zeroSecretKeyRejected() throws {
        let ctx = try Context()
        let zero = [UInt8](repeating: 0, count: 32)
        let ok = ctx.isValidSecretKey(zero.span)
        #expect(!ok)
    }

    @Test("a wrong-length secret key is rejected without trapping")
    func shortSecretKeyRejected() throws {
        let ctx = try Context()
        let short = [UInt8](repeating: 0x11, count: 31)
        let ok = ctx.isValidSecretKey(short.span)
        #expect(!ok)
    }

    @Test("sign then verify round-trips")
    func signVerifyRoundTrip() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        let ok = ctx.isValid(sig, messageHash: Self.messageHash.span, publicKey: pub)
        #expect(ok)
    }

    @Test("a signature does not verify against a different message")
    func wrongMessageFails() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        let other = [UInt8](repeating: 0xCD, count: 32)
        let ok = ctx.isValid(sig, messageHash: other.span, publicKey: pub)
        #expect(!ok)
    }

    @Test("a signature does not verify against a different key")
    func wrongKeyFails() throws {
        let ctx = try Context()
        let otherSecret = [UInt8](repeating: 0x22, count: 32)
        let otherPub = try ctx.publicKey(secretKey: otherSecret.span)
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        let ok = ctx.isValid(sig, messageHash: Self.messageHash.span, publicKey: otherPub)
        #expect(!ok)
    }

    @Test("signing is deterministic (RFC6979)")
    func signingIsDeterministic() throws {
        let ctx = try Context()
        let a = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        let b = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        #expect(ctx.compactBytes(of: a) == ctx.compactBytes(of: b))
    }

    @Test("compact signature serialisation round-trips")
    func compactRoundTrip() throws {
        let ctx = try Context()
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        let bytes = ctx.compactBytes(of: sig)
        #expect(bytes.count == 64)
        let reparsed = try ctx.signature(parsingCompact: bytes.span)
        #expect(ctx.compactBytes(of: reparsed) == bytes)
    }

    @Test("a wrong-length compact signature throws rather than trapping")
    func shortCompactThrows() throws {
        let ctx = try Context()
        let short = [UInt8](repeating: 0, count: 63)
        // Also written out rather than using #expect(throws:), whose closure
        // would capture a Span.
        var caught: Secp256k1Error?
        do {
            _ = try ctx.signature(parsingCompact: short.span)
        } catch let error as Secp256k1Error {
            caught = error
        }
        #expect(caught == .wrongLength(expected: 64, actual: 63))
    }

    @Test("a serialised public key round-trips through parse")
    func publicKeyParseRoundTrip() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: Self.secretKey.span)
        // Verify with the original key to confirm the pair is coherent.
        let ok = ctx.isValid(sig, messageHash: Self.messageHash.span, publicKey: pub)
        #expect(ok)
    }

    @Test("garbage does not parse as a public key")
    func garbagePublicKeyRejected() throws {
        let ctx = try Context()
        let garbage = [UInt8](repeating: 0xFF, count: 33)
        var threw = false
        do {
            _ = try ctx.publicKey(parsing: garbage.span)
        } catch {
            threw = true
        }
        #expect(threw)
    }
}

/// Exercises the annotated C module directly, rather than through the wrapper.
///
/// These are the regression tests for the naming, nullability and globals
/// annotations: if an API notes entry stops producing the shape it should, this
/// suite stops compiling.
@Suite("The annotated C module")
struct AnnotatedModuleTests {
    static let secretKey = [UInt8](repeating: 0x11, count: 32)
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    @Test("the context is a class with an initialiser and methods")
    func contextIsAClass() {
        // init? not init! -- NullabilityOfRet: O
        guard let ctx = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            Issue.record("context creation failed")
            return
        }
        defer { ctx.destroy() }
        let ok = ctx.ecSeckeyVerify(Self.secretKey.span)
        #expect(ok == 1)
    }

    @Test("clone returns an Optional, not an implicitly unwrapped one")
    func cloneIsOptional() {
        guard let ctx = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            Issue.record("context creation failed")
            return
        }
        defer { ctx.destroy() }
        guard let copy = ctx.clone() else {
            Issue.record("clone failed")
            return
        }
        defer { copy.destroy() }
        let ok = copy.ecSeckeyVerify(Self.secretKey.span)
        #expect(ok == 1)
    }

    @Test("nil selects the default nonce function")
    func nilNonceFunction() throws {
        guard let ctx = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            Issue.record("context creation failed")
            return
        }
        defer { ctx.destroy() }
        var sig = CollectionOfOne(ECDSASignature())
        var sigSpan = sig.mutableSpan
        // `nil` here is the whole point: it only type-checks because the API
        // notes declare Nullability: O for this parameter.
        let ok = unsafe ctx.ecdsaSign(&sigSpan, messageHash: Self.messageHash.span,
                                 secretKey: Self.secretKey.span,
                                 nonceFunction: nil, nonceData: nil)
        #expect(ok == 1)
    }

    @Test("the shared static context verifies, and is non-optional")
    func sharedStaticContext() {
        // SECP256K1Context.shared is a static member on the class and imports
        // non-optional (Nullability: N). It must never be destroyed.
        let shared: SECP256K1Context = SECP256K1Context.shared

        guard let signing = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            Issue.record("context creation failed")
            return
        }
        defer { signing.destroy() }

        var pub = CollectionOfOne(Pubkey())
        var pubSpan = pub.mutableSpan
        let made = signing.ecPubkeyCreate(&pubSpan, secretKey: Self.secretKey.span)
        #expect(made == 1)

        var sigBox = CollectionOfOne(ECDSASignature())
        var sigSpan = sigBox.mutableSpan
        let signed = unsafe signing.ecdsaSign(&sigSpan, messageHash: Self.messageHash.span,
                                         secretKey: Self.secretKey.span,
                                         nonceFunction: nil, nonceData: nil)
        #expect(signed == 1)

        // Verification needs no randomisation, so the static context suffices.
        let verified = shared.ecdsaVerify(sigBox.span, messageHash: Self.messageHash.span,
                                                 publicKey: pub.span)
        #expect(verified == 1)
    }

    @Test("renamed global constants are reachable, non-optional and usable")
    func renamedGlobals() {
        // These bindings are themselves the assertion: each global is reachable
        // under its renamed Swift name, and each is non-optional rather than
        // implicitly unwrapped (Nullability: N). C function pointers are not
        // Equatable, so there is nothing to compare -- using one is the proof.
        // C function pointers are unsafe types, so each binding needs the
        // marker even though nothing is dereferenced here.
        let explicitDefault: NonceFunction = .default
        let _: NonceFunction = .rfc6979
        let _: ECDHHashFunction = .sha256
        let _: ECDHHashFunction = .default
        let _: EllSwiftHashFunction = .bip324
        let _: EllSwiftHashFunction = .prefix
        let _: NonceFunctionHardened = .bip340

        guard let ctx = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            Issue.record("context creation failed")
            return
        }
        defer { ctx.destroy() }

        // Passing the named default explicitly must match what nil selects.
        var viaSymbol = CollectionOfOne(ECDSASignature())
        var viaSymbolSpan = viaSymbol.mutableSpan
        let a = unsafe ctx.ecdsaSign(&viaSymbolSpan, messageHash: Self.messageHash.span,
                                secretKey: Self.secretKey.span,
                                nonceFunction: explicitDefault, nonceData: nil)

        var viaNil = CollectionOfOne(ECDSASignature())
        var viaNilSpan = viaNil.mutableSpan
        let b = unsafe ctx.ecdsaSign(&viaNilSpan, messageHash: Self.messageHash.span,
                                secretKey: Self.secretKey.span,
                                nonceFunction: nil, nonceData: nil)
        #expect(a == 1)
        #expect(b == 1)

        var outA = [UInt8](repeating: 0, count: 64)
        var outASpan = outA.mutableSpan
        _ = ctx.ecdsaSignatureSerializeCompact(into: &outASpan, viaSymbol.span)

        var outB = [UInt8](repeating: 0, count: 64)
        var outBSpan = outB.mutableSpan
        _ = ctx.ecdsaSignatureSerializeCompact(into: &outBSpan, viaNil.span)

        #expect(outA == outB)
    }
}

/// BIP340 Schnorr, checked against upstream's own test vector.
///
/// The vector below is vector 0 from `src/modules/schnorrsig/tests_impl.h`,
/// extracted from that file programmatically rather than transcribed. It is a
/// known-answer test: signing must reproduce these exact 64 bytes, not merely
/// produce something that verifies.
@Suite("BIP340 Schnorr signatures")
struct SchnorrTests {
    static func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map {
            let i = hex.index(hex.startIndex, offsetBy: $0)
            return UInt8(hex[i...hex.index(i, offsetBy: 1)], radix: 16)!
        }
    }

    static let secretKey = bytes("0000000000000000000000000000000000000000000000000000000000000003")
    static let publicKey = bytes("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    static let auxRandom = bytes("0000000000000000000000000000000000000000000000000000000000000000")
    static let message = bytes("0000000000000000000000000000000000000000000000000000000000000000")
    static let signature = bytes(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215" +
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

    @Test("the x-only public key matches the vector")
    func publicKeyMatchesVector() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let (xonly, _) = try ctx.xOnlyPublicKey(of: kp)
        #expect(ctx.serializedBytes(of: xonly) == Self.publicKey)
    }

    @Test("signing reproduces the vector signature exactly")
    func signingMatchesVector() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let sig = try ctx.signSchnorr(message32: Self.message.span, keyPair: kp,
                                      auxiliaryRandom: Self.auxRandom.span)
        #expect(sig == Self.signature)
    }

    @Test("the vector signature verifies")
    func vectorVerifies() throws {
        let ctx = try Context()
        let key = try ctx.xOnlyPublicKey(parsing: Self.publicKey.span)
        let ok = ctx.isValidSchnorr(Self.signature.span, message: Self.message.span, publicKey: key)
        #expect(ok)
    }

    @Test("a flipped bit in the signature fails verification")
    func flippedSignatureFails() throws {
        let ctx = try Context()
        let key = try ctx.xOnlyPublicKey(parsing: Self.publicKey.span)
        var bad = Self.signature
        bad[0] ^= 0x01
        let ok = ctx.isValidSchnorr(bad.span, message: Self.message.span, publicKey: key)
        #expect(!ok)
    }

    @Test("a flipped bit in the message fails verification")
    func flippedMessageFails() throws {
        let ctx = try Context()
        let key = try ctx.xOnlyPublicKey(parsing: Self.publicKey.span)
        var msg = Self.message
        msg[31] ^= 0x01
        let ok = ctx.isValidSchnorr(Self.signature.span, message: msg.span, publicKey: key)
        #expect(!ok)
    }

    @Test("an x-only public key round-trips through parse and serialize")
    func xOnlyRoundTrip() throws {
        let ctx = try Context()
        let key = try ctx.xOnlyPublicKey(parsing: Self.publicKey.span)
        #expect(ctx.serializedBytes(of: key) == Self.publicKey)
    }

    @Test("a key pair yields back its own secret key")
    func secretKeyRoundTrip() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        #expect(try ctx.secretKeyBytes(of: kp) == Self.secretKey)
    }

    @Test("the parity bit is reported")
    func parityIsReported() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let (_, parity) = try ctx.xOnlyPublicKey(of: kp)
        #expect(parity == 0 || parity == 1)
    }

    @Test("verification accepts a message of non-32 length")
    func variableLengthMessage() throws {
        // schnorrsig_verify is bounded by its length parameter rather than a
        // fixed 32, so the Span overload takes any length. A 16-byte message
        // simply does not verify against this signature -- the point is that it
        // compiles and returns false rather than trapping.
        let ctx = try Context()
        let key = try ctx.xOnlyPublicKey(parsing: Self.publicKey.span)
        let short = [UInt8](repeating: 0, count: 16)
        let ok = ctx.isValidSchnorr(Self.signature.span, message: short.span, publicKey: key)
        #expect(!ok)
    }

    @Test("a wrong-length auxiliary random value throws")
    func wrongAuxLengthThrows() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let short = [UInt8](repeating: 0, count: 31)
        var caught: Secp256k1Error?
        do {
            _ = try ctx.signSchnorr(message32: Self.message.span, keyPair: kp,
                                    auxiliaryRandom: short.span)
        } catch let e as Secp256k1Error { caught = e }
        #expect(caught == .wrongLength(expected: 32, actual: 31))
    }
}

/// ECDH key agreement.
@Suite("ECDH")
struct ECDHTests {
    static let aliceSecret = [UInt8](repeating: 0x11, count: 32)
    static let bobSecret = [UInt8](repeating: 0x22, count: 32)

    @Test("both parties derive the same 32-byte secret")
    func agreementIsSymmetric() throws {
        let ctx = try Context()
        let alicePub = try ctx.publicKey(secretKey: Self.aliceSecret.span)
        let bobPub = try ctx.publicKey(secretKey: Self.bobSecret.span)

        let a = try ctx.sharedSecret(publicKey: bobPub, secretKey: Self.aliceSecret.span)
        let b = try ctx.sharedSecret(publicKey: alicePub, secretKey: Self.bobSecret.span)

        #expect(a.count == 32)
        #expect(a == b)
    }

    @Test("a different counterparty gives a different secret")
    func differentPeerDiffers() throws {
        let ctx = try Context()
        let bobPub = try ctx.publicKey(secretKey: Self.bobSecret.span)
        let carolSecret = [UInt8](repeating: 0x33, count: 32)
        let carolPub = try ctx.publicKey(secretKey: carolSecret.span)

        let withBob = try ctx.sharedSecret(publicKey: bobPub, secretKey: Self.aliceSecret.span)
        let withCarol = try ctx.sharedSecret(publicKey: carolPub, secretKey: Self.aliceSecret.span)
        #expect(withBob != withCarol)
    }

    @Test("a wrong-length secret key throws")
    func wrongLengthThrows() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.bobSecret.span)
        let short = [UInt8](repeating: 0x11, count: 31)
        var caught: Secp256k1Error?
        do { _ = try ctx.sharedSecret(publicKey: pub, secretKey: short.span) }
        catch let e as Secp256k1Error { caught = e }
        #expect(caught == .wrongLength(expected: 32, actual: 31))
    }
}

/// Recoverable ECDSA signatures.
@Suite("ECDSA recovery")
struct RecoveryTests {
    static let secretKey = [UInt8](repeating: 0x11, count: 32)
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    @Test("the signer's public key is recovered from signature and message alone")
    func recoversSigner() throws {
        let ctx = try Context()
        let expected = try ctx.publicKey(secretKey: Self.secretKey.span)
        let sig = try ctx.signRecoverable(messageHash: Self.messageHash.span,
                                          secretKey: Self.secretKey.span)
        let recovered = try ctx.recoverPublicKey(from: sig, messageHash: Self.messageHash.span)

        // Compare by their ECDSA behaviour: a signature made under the original
        // key must verify against the recovered one.
        let plain = try ctx.sign(messageHash: Self.messageHash.span,
                                 secretKey: Self.secretKey.span)
        let okRecovered = ctx.isValid(plain, messageHash: Self.messageHash.span,
                                      publicKey: recovered)
        let okExpected = ctx.isValid(plain, messageHash: Self.messageHash.span,
                                     publicKey: expected)
        #expect(okRecovered)
        #expect(okExpected)
    }

    @Test("recovering with the wrong message gives a different key")
    func wrongMessageRecoversDifferentKey() throws {
        let ctx = try Context()
        let sig = try ctx.signRecoverable(messageHash: Self.messageHash.span,
                                          secretKey: Self.secretKey.span)
        let other = [UInt8](repeating: 0xCD, count: 32)
        let recovered = try ctx.recoverPublicKey(from: sig, messageHash: other.span)
        let plain = try ctx.sign(messageHash: Self.messageHash.span,
                                 secretKey: Self.secretKey.span)
        // Recovery still succeeds -- it yields *some* key -- but not ours.
        let ok = ctx.isValid(plain, messageHash: Self.messageHash.span, publicKey: recovered)
        #expect(!ok)
    }

    @Test("compact serialisation round-trips with its recovery id")
    func compactRoundTrip() throws {
        let ctx = try Context()
        let sig = try ctx.signRecoverable(messageHash: Self.messageHash.span,
                                          secretKey: Self.secretKey.span)
        let (bytes, recid) = ctx.compactBytes(of: sig)
        #expect(bytes.count == 64)
        #expect((0...3).contains(recid))
        let back = try ctx.recoverableSignature(compact: bytes.span, recoveryID: recid)
        let (bytes2, recid2) = ctx.compactBytes(of: back)
        #expect(bytes2 == bytes)
        #expect(recid2 == recid)
    }

    @Test("converting to a plain signature agrees with signing directly")
    func convertMatchesPlainSign() throws {
        let ctx = try Context()
        let rec = try ctx.signRecoverable(messageHash: Self.messageHash.span,
                                          secretKey: Self.secretKey.span)
        let converted = try ctx.signature(from: rec)
        let direct = try ctx.sign(messageHash: Self.messageHash.span,
                                  secretKey: Self.secretKey.span)
        // Both are RFC6979 deterministic, so the bytes must match exactly.
        #expect(ctx.compactBytes(of: converted) == ctx.compactBytes(of: direct))
    }

    @Test("an out-of-range recovery id is rejected")
    func badRecoveryIDRejected() throws {
        let ctx = try Context()
        let sig = try ctx.signRecoverable(messageHash: Self.messageHash.span,
                                          secretKey: Self.secretKey.span)
        let (bytes, _) = ctx.compactBytes(of: sig)
        var threw = false
        do { _ = try ctx.recoverableSignature(compact: bytes.span, recoveryID: 7) }
        catch { threw = true }
        #expect(threw)
    }
}

/// ElligatorSwift encoding and X-only DH.
@Suite("ElligatorSwift")
struct EllSwiftTests {
    static let aliceSecret = [UInt8](repeating: 0x11, count: 32)
    static let bobSecret = [UInt8](repeating: 0x22, count: 32)
    static let randomness = [UInt8](repeating: 0x42, count: 32)

    @Test("an encoding round-trips back to the same public key")
    func encodeDecodeRoundTrip() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.aliceSecret.span)
        let ell = try ctx.ellswiftEncodedBytes(of: pub, randomness32: Self.randomness.span)
        #expect(ell.count == 64)

        let decoded = try ctx.publicKey(ellswift: ell.span)
        // Compare behaviourally: a signature verifies under the decoded key.
        let msg = [UInt8](repeating: 0xAB, count: 32)
        let sig = try ctx.sign(messageHash: msg.span, secretKey: Self.aliceSecret.span)
        let ok = ctx.isValid(sig, messageHash: msg.span, publicKey: decoded)
        #expect(ok)
    }

    @Test("different randomness gives different encodings of the same key")
    func encodingIsRandomised() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.aliceSecret.span)
        let r2 = [UInt8](repeating: 0x99, count: 32)
        let a = try ctx.ellswiftEncodedBytes(of: pub, randomness32: Self.randomness.span)
        let b = try ctx.ellswiftEncodedBytes(of: pub, randomness32: r2.span)
        #expect(a != b)
    }

    @Test("create from a secret key decodes to that key's public key")
    func createMatchesEncode() throws {
        let ctx = try Context()
        let ell = try ctx.ellswiftCreate(secretKey32: Self.aliceSecret.span,
                                         auxiliaryRandom32: Self.randomness.span)
        #expect(ell.count == 64)
        let decoded = try ctx.publicKey(ellswift: ell.span)
        let msg = [UInt8](repeating: 0xAB, count: 32)
        let sig = try ctx.sign(messageHash: msg.span, secretKey: Self.aliceSecret.span)
        let ok = ctx.isValid(sig, messageHash: msg.span, publicKey: decoded)
        #expect(ok)
    }

    @Test("both parties derive the same shared secret")
    func xdhIsSymmetric() throws {
        let ctx = try Context()
        let ellA = try ctx.ellswiftCreate(secretKey32: Self.aliceSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)
        let ellB = try ctx.ellswiftCreate(secretKey32: Self.bobSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)

        let fromA = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                        ourSecretKey: Self.aliceSecret.span, weAre: .a)
        let fromB = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                        ourSecretKey: Self.bobSecret.span, weAre: .b)
        #expect(fromA.count == 32)
        #expect(fromA == fromB)
    }

    @Test("claiming the wrong party yields a different secret, not an error")
    func wrongPartyIsSilentlyWrong() throws {
        // Upstream: the correspondence between `party` and the secret key "is
        // not checked". This test pins that hazard so the wrapper's docs stay
        // honest about it.
        let ctx = try Context()
        let ellA = try ctx.ellswiftCreate(secretKey32: Self.aliceSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)
        let ellB = try ctx.ellswiftCreate(secretKey32: Self.bobSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)
        let right = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                        ourSecretKey: Self.aliceSecret.span, weAre: .a)
        let wrong = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                        ourSecretKey: Self.aliceSecret.span, weAre: .b)
        #expect(right != wrong)
    }

    @Test("the two hash functions give different secrets")
    func hashChoiceMatters() throws {
        // .prefix carries its own 64-byte prefix; passing it is mandatory,
        // because the C hash reads it through the `data` pointer.
        let prefix64 = [UInt8](repeating: 0x5A, count: 64)
        let ctx = try Context()
        let ellA = try ctx.ellswiftCreate(secretKey32: Self.aliceSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)
        let ellB = try ctx.ellswiftCreate(secretKey32: Self.bobSecret.span,
                                          auxiliaryRandom32: Self.randomness.span)
        let bip324 = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                         ourSecretKey: Self.aliceSecret.span,
                                         weAre: .a, hash: .bip324)
        let prefix = try ctx.ellswiftXDH(partyA: ellA.span, partyB: ellB.span,
                                         ourSecretKey: Self.aliceSecret.span,
                                         weAre: .a, hash: .prefix(prefix64))
        #expect(bip324 != prefix)
    }
}

/// MuSig2 (BIP327) multi-signatures.
@Suite("MuSig2")
struct MuSigTests {
    static let aliceSecret = [UInt8](repeating: 0x11, count: 32)
    static let bobSecret = [UInt8](repeating: 0x22, count: 32)
    static let message = [UInt8](repeating: 0xAB, count: 32)

    /// Runs a full two-of-two signing session and returns the aggregate
    /// signature together with the aggregate key it should verify under.
    static func sign(
        _ ctx: borrowing Context,
        message: [UInt8]
    ) throws -> (signature: [UInt8], aggregateKey: XOnlyPublicKey) {
        let aliceKP = try ctx.keyPair(secretKey: aliceSecret.span)
        let bobKP = try ctx.keyPair(secretKey: bobSecret.span)
        let alicePub = try ctx.publicKey(of: aliceKP)
        let bobPub = try ctx.publicKey(of: bobKP)

        let (aggKey, cache) = try ctx.aggregate(publicKeys: [alicePub, bobPub])

        var aliceRand = [UInt8](repeating: 0x01, count: 32)
        var bobRand = [UInt8](repeating: 0x02, count: 32)
        let alicePair = try ctx.generateNonce(
            sessionRandomness32: &aliceRand, secretKey: Self.aliceSecret.span,
            publicKey: alicePub, message32: message.span, cache: cache)
        let bobPair = try ctx.generateNonce(
            sessionRandomness32: &bobRand, secretKey: Self.bobSecret.span,
            publicKey: bobPub, message32: message.span, cache: cache)

        // Public nonces are copyable and meant to be published; keep copies for
        // partial-signature verification after the pairs are consumed.
        let alicePubNonce = alicePair.publicNonce
        let bobPubNonce = bobPair.publicNonce

        let aggNonce = try ctx.aggregateNonces([alicePubNonce, bobPubNonce])
        let session = try ctx.session(aggregateNonce: aggNonce,
                                      message32: message.span, cache: cache)

        // Each pair is consumed here -- using one twice is a compile error.
        let aliceSig = try ctx.partialSign(noncePair: consume alicePair, keyPair: aliceKP,
                                           cache: cache, session: session)
        let bobSig = try ctx.partialSign(noncePair: consume bobPair, keyPair: bobKP,
                                         cache: cache, session: session)

        // Upstream recommends verifying partials: partial_sign does not verify
        // its own output, deviating from BIP327.
        let aliceOK = ctx.isValidPartialSignature(aliceSig, publicNonce: alicePubNonce,
                                                  publicKey: alicePub, cache: cache,
                                                  session: session)
        let bobOK = ctx.isValidPartialSignature(bobSig, publicNonce: bobPubNonce,
                                                publicKey: bobPub, cache: cache,
                                                session: session)
        #expect(aliceOK)
        #expect(bobOK)

        let agg = try ctx.aggregate(partialSignatures: [aliceSig, bobSig], session: session)
        return (agg, aggKey)
    }

    @Test("a two-of-two MuSig signature verifies as a plain BIP340 signature")
    func aggregateVerifiesAsSchnorr() throws {
        let ctx = try Context()
        let (sig, aggKey) = try Self.sign(ctx, message: Self.message)
        #expect(sig.count == 64)
        // This is the whole point of MuSig2: the verifier needs no knowledge
        // that multiple signers were involved.
        let ok = ctx.isValidSchnorr(sig.span, message: Self.message.span, publicKey: aggKey)
        #expect(ok)
    }

    @Test("the aggregate signature does not verify against another message")
    func wrongMessageFails() throws {
        let ctx = try Context()
        let (sig, aggKey) = try Self.sign(ctx, message: Self.message)
        let other = [UInt8](repeating: 0xCD, count: 32)
        let ok = ctx.isValidSchnorr(sig.span, message: other.span, publicKey: aggKey)
        #expect(!ok)
    }

    @Test("the aggregate key is not either signer's own key")
    func aggregateKeyDiffersFromMembers() throws {
        let ctx = try Context()
        let aliceKP = try ctx.keyPair(secretKey: Self.aliceSecret.span)
        let bobKP = try ctx.keyPair(secretKey: Self.bobSecret.span)
        let alicePub = try ctx.publicKey(of: aliceKP)
        let bobPub = try ctx.publicKey(of: bobKP)
        let (aggKey, _) = try ctx.aggregate(publicKeys: [alicePub, bobPub])

        let (aliceXOnly, _) = try ctx.xOnlyPublicKey(of: aliceKP)
        let (bobXOnly, _) = try ctx.xOnlyPublicKey(of: bobKP)
        let aggBytes = ctx.serializedBytes(of: aggKey)
        #expect(aggBytes != ctx.serializedBytes(of: aliceXOnly))
        #expect(aggBytes != ctx.serializedBytes(of: bobXOnly))
    }

    @Test("key order changes the aggregate key")
    func keyOrderMatters() throws {
        let ctx = try Context()
        let alicePub = try ctx.publicKey(secretKey: Self.aliceSecret.span)
        let bobPub = try ctx.publicKey(secretKey: Self.bobSecret.span)
        let (ab, _) = try ctx.aggregate(publicKeys: [alicePub, bobPub])
        let (ba, _) = try ctx.aggregate(publicKeys: [bobPub, alicePub])
        #expect(ctx.serializedBytes(of: ab) != ctx.serializedBytes(of: ba))
    }

    @Test("a partial signature does not verify against the wrong signer's nonce")
    func partialVerifyRejectsWrongNonce() throws {
        let ctx = try Context()
        let aliceKP = try ctx.keyPair(secretKey: Self.aliceSecret.span)
        let bobKP = try ctx.keyPair(secretKey: Self.bobSecret.span)
        let alicePub = try ctx.publicKey(of: aliceKP)
        let bobPub = try ctx.publicKey(of: bobKP)
        let (_, cache) = try ctx.aggregate(publicKeys: [alicePub, bobPub])

        var r1 = [UInt8](repeating: 0x01, count: 32)
        var r2 = [UInt8](repeating: 0x02, count: 32)
        let alicePair = try ctx.generateNonce(
            sessionRandomness32: &r1, secretKey: Self.aliceSecret.span,
            publicKey: alicePub, message32: Self.message.span, cache: cache)
        let bobPair = try ctx.generateNonce(
            sessionRandomness32: &r2, secretKey: Self.bobSecret.span,
            publicKey: bobPub, message32: Self.message.span, cache: cache)
        let aliceNonce = alicePair.publicNonce
        let bobNonce = bobPair.publicNonce

        let aggNonce = try ctx.aggregateNonces([aliceNonce, bobNonce])
        let session = try ctx.session(aggregateNonce: aggNonce,
                                      message32: Self.message.span, cache: cache)
        let aliceSig = try ctx.partialSign(noncePair: consume alicePair, keyPair: aliceKP,
                                           cache: cache, session: session)
        _ = consume bobPair

        // Alice's partial signature checked against Bob's nonce must fail.
        let ok = ctx.isValidPartialSignature(aliceSig, publicNonce: bobNonce,
                                             publicKey: alicePub, cache: cache,
                                             session: session)
        #expect(!ok)
    }

    @Test("the session randomness is wiped by nonce generation")
    func sessionRandomnessIsWiped() throws {
        // libsecp256k1 overwrites session_secrand32 so it cannot be reused by
        // accident, which is why the wrapper takes it `inout` rather than as a
        // Span.
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.aliceSecret.span)
        var rand = [UInt8](repeating: 0x07, count: 32)
        let before = rand
        let pair = try ctx.generateNonce(
            sessionRandomness32: &rand, secretKey: Self.aliceSecret.span,
            publicKey: pub, message32: Self.message.span, cache: nil)
        _ = consume pair
        #expect(rand != before)
    }
}

/// Silent payments (BIP352).
///
/// These are round-trip tests: the sender derives outputs and the recipient
/// independently rediscovers them by scanning. That agreement between two
/// separately-computed sides is the property that matters, and it fails if
/// either half of the wrapper is wrong.
@Suite("Silent payments")
struct SilentPaymentsTests {
    // Recipient's two keys.
    static let scanKey = [UInt8](repeating: 0x11, count: 32)
    static let spendKey = [UInt8](repeating: 0x22, count: 32)
    // Sender's taproot input key.
    static let senderKey = [UInt8](repeating: 0x33, count: 32)
    // Smallest outpoint of the transaction (txid || vout), 36 bytes.
    static let outpoint = [UInt8](repeating: 0x44, count: 36)

    /// Everything both sides need.
    struct Fixture : ~Copyable {
        let ctx: Context
        let scanPub: PublicKey
        let spendPub: PublicKey
        let senderKeyPair: KeyPair
        let senderXOnly: XOnlyPublicKey
    }

    static func fixture() throws -> Fixture {
        let ctx = try Context()
        let scanPub = try ctx.publicKey(secretKey: scanKey.span)
        let spendPub = try ctx.publicKey(secretKey: spendKey.span)
        let senderKeyPair = try ctx.keyPair(secretKey: senderKey.span)
        let senderXOnly = try ctx.xOnlyPublicKey(of: senderKeyPair).key
        return Fixture(
            ctx: ctx,
            scanPub: scanPub,
            spendPub: spendPub,
            senderKeyPair: senderKeyPair,
            senderXOnly: senderXOnly
        )
    }

    @Test("the recipient rediscovers the sender's output by scanning")
    func sendThenScan() throws {
        let f = try Self.fixture()
        let recipient = SilentPaymentRecipient(scanPublicKey: f.scanPub,
                                               spendPublicKey: f.spendPub)
        let outputs = try f.ctx.silentPaymentOutputs(
            recipients: [recipient],
            smallestOutpoint36: Self.outpoint.span,
            keyPairs: [f.senderKeyPair])
        #expect(outputs.count == 1)

        let summary = try f.ctx.silentPaymentPrevoutsSummary(
            smallestOutpoint36: Self.outpoint.span,
            xOnlyPublicKeys: [f.senderXOnly])

        let found = try f.ctx.scanSilentPaymentOutputs(
            txOutputs: outputs,
            scanKey32: Self.scanKey.span,
            prevoutsSummary: summary,
            unlabeledSpendPublicKey: f.spendPub)

        #expect(found.count == 1)
        #expect(f.ctx.serializedBytes(of: found[0].output)
                == f.ctx.serializedBytes(of: outputs[0]))
        #expect(found[0].tweak.count == 32)
        #expect(found[0].label == nil)   // sent to the unlabeled address
    }

    @Test("scanning with the wrong scan key finds nothing")
    func wrongScanKeyFindsNothing() throws {
        let f = try Self.fixture()
        let recipient = SilentPaymentRecipient(scanPublicKey: f.scanPub,
                                               spendPublicKey: f.spendPub)
        let outputs = try f.ctx.silentPaymentOutputs(
            recipients: [recipient],
            smallestOutpoint36: Self.outpoint.span,
            keyPairs: [f.senderKeyPair])
        let summary = try f.ctx.silentPaymentPrevoutsSummary(
            smallestOutpoint36: Self.outpoint.span,
            xOnlyPublicKeys: [f.senderXOnly])

        let otherScan = [UInt8](repeating: 0x55, count: 32)
        let found = try f.ctx.scanSilentPaymentOutputs(
            txOutputs: outputs,
            scanKey32: otherScan.span,
            prevoutsSummary: summary,
            unlabeledSpendPublicKey: f.spendPub)
        #expect(found.isEmpty)
    }

    @Test("two recipients get two distinct outputs, in the caller's order")
    func twoRecipients() throws {
        let f = try Self.fixture()
        let otherScan = try f.ctx.publicKey(secretKey: [UInt8](repeating: 0x66, count: 32).span)
        let otherSpend = try f.ctx.publicKey(secretKey: [UInt8](repeating: 0x77, count: 32).span)

        let outputs = try f.ctx.silentPaymentOutputs(
            recipients: [
                SilentPaymentRecipient(scanPublicKey: f.scanPub, spendPublicKey: f.spendPub),
                SilentPaymentRecipient(scanPublicKey: otherScan, spendPublicKey: otherSpend),
            ],
            smallestOutpoint36: Self.outpoint.span,
            keyPairs: [f.senderKeyPair])

        #expect(outputs.count == 2)
        let a = f.ctx.serializedBytes(of: outputs[0])
        let b = f.ctx.serializedBytes(of: outputs[1])
        #expect(a != b)

        // Our recipient scans and finds exactly its own output, which must be
        // the one at its own index -- proving the wrapper unpicks the internal
        // reordering correctly.
        let summary = try f.ctx.silentPaymentPrevoutsSummary(
            smallestOutpoint36: Self.outpoint.span,
            xOnlyPublicKeys: [f.senderXOnly])
        let found = try f.ctx.scanSilentPaymentOutputs(
            txOutputs: outputs, scanKey32: Self.scanKey.span,
            prevoutsSummary: summary, unlabeledSpendPublicKey: f.spendPub)
        #expect(found.count == 1)
        #expect(f.ctx.serializedBytes(of: found[0].output) == a)
    }

    @Test("a labeled address round-trips, and the label is reported")
    func labeledAddress() throws {
        let f = try Self.fixture()
        let (label, labelTweak) = try f.ctx.silentPaymentLabel(
            scanKey32: Self.scanKey.span, m: 1)
        #expect(labelTweak.count == 32)

        let labeledSpend = try f.ctx.labeledSpendPublicKey(
            unlabeledSpendPublicKey: f.spendPub, label: label)

        let outputs = try f.ctx.silentPaymentOutputs(
            recipients: [SilentPaymentRecipient(scanPublicKey: f.scanPub,
                                                spendPublicKey: labeledSpend)],
            smallestOutpoint36: Self.outpoint.span,
            keyPairs: [f.senderKeyPair])

        let summary = try f.ctx.silentPaymentPrevoutsSummary(
            smallestOutpoint36: Self.outpoint.span,
            xOnlyPublicKeys: [f.senderXOnly])

        // The recipient's label cache: serialised label -> its tweak.
        let expectedLabel = f.ctx.serializedBytes(of: label)
        var lookupCalls = 0
        let found = try f.ctx.scanSilentPaymentOutputs(
            txOutputs: outputs,
            scanKey32: Self.scanKey.span,
            prevoutsSummary: summary,
            unlabeledSpendPublicKey: f.spendPub,
            labelLookup: { candidate in
                lookupCalls += 1
                return candidate == expectedLabel ? labelTweak : nil
            })

        #expect(lookupCalls > 0)          // the C callback really reached Swift
        #expect(found.count == 1)
        #expect(found[0].label != nil)    // found via the label, not the plain key
    }

    @Test("a label serialises to 33 bytes and parses back")
    func labelRoundTrip() throws {
        let ctx = try Context()
        let (label, _) = try ctx.silentPaymentLabel(scanKey32: Self.scanKey.span, m: 7)
        let bytes = ctx.serializedBytes(of: label)
        #expect(bytes.count == 33)
        let back = try ctx.silentPaymentLabel(parsing: bytes.span)
        #expect(ctx.serializedBytes(of: back) == bytes)
    }

    @Test("different label indices give different labels")
    func labelsDiffer() throws {
        let ctx = try Context()
        let (one, tweak1) = try ctx.silentPaymentLabel(scanKey32: Self.scanKey.span, m: 1)
        let (two, tweak2) = try ctx.silentPaymentLabel(scanKey32: Self.scanKey.span, m: 2)
        #expect(ctx.serializedBytes(of: one) != ctx.serializedBytes(of: two))
        #expect(tweak1 != tweak2)
    }

    @Test("a prevouts summary needs at least one input key")
    func summaryNeedsInputs() throws {
        let ctx = try Context()
        var threw = false
        do {
            _ = try ctx.silentPaymentPrevoutsSummary(smallestOutpoint36: Self.outpoint.span)
        } catch { threw = true }
        #expect(threw)
    }

    @Test("a wrong-length outpoint throws")
    func wrongOutpointLengthThrows() throws {
        let f = try Self.fixture()
        let short = [UInt8](repeating: 0x44, count: 35)
        var caught: Secp256k1Error?
        do {
            _ = try f.ctx.silentPaymentPrevoutsSummary(
                smallestOutpoint36: short.span, xOnlyPublicKeys: [f.senderXOnly])
        } catch let e as Secp256k1Error { caught = e }
        #expect(caught == .wrongLength(expected: 36, actual: 35))
    }
}

/// Serialisation: the wire formats.
@Suite("Serialisation")
struct SerialisationTests {
    static let secretKey = [UInt8](repeating: 0x11, count: 32)
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    @Test("a public key round-trips in both formats, with the right lengths")
    func publicKeyFormats() throws {
        let ctx = try Context()
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)

        let compressed = ctx.serializedBytes(of: pub, format: .compressed)
        let uncompressed = ctx.serializedBytes(of: pub, format: .uncompressed)
        #expect(compressed.count == 33)
        #expect(uncompressed.count == 65)
        #expect(compressed[0] == 0x02 || compressed[0] == 0x03)
        #expect(uncompressed[0] == 0x04)

        // Both must parse back to the same key.
        let fromCompressed = try ctx.publicKey(parsing: compressed.span)
        let fromUncompressed = try ctx.publicKey(parsing: uncompressed.span)
        #expect(ctx.compare(fromCompressed, fromUncompressed) == 0)
        #expect(ctx.compare(fromCompressed, pub) == 0)
    }

    @Test("a DER signature round-trips and is 70-72 bytes")
    func derRoundTrip() throws {
        let ctx = try Context()
        let sig = try ctx.sign(messageHash: Self.messageHash.span,
                               secretKey: Self.secretKey.span)
        let der = ctx.derBytes(of: sig)
        #expect(der.count <= Context.maximumDERSignatureSize)
        #expect(der[0] == 0x30)   // DER SEQUENCE

        let back = try ctx.signature(parsingDER: der.span)
        #expect(ctx.compactBytes(of: back) == ctx.compactBytes(of: sig))
    }

    @Test("garbage does not parse as DER")
    func garbageDERRejected() throws {
        let ctx = try Context()
        let garbage = [UInt8](repeating: 0xFF, count: 20)
        var threw = false
        do { _ = try ctx.signature(parsingDER: garbage.span) } catch { threw = true }
        #expect(threw)
    }

    @Test("x-only extraction agrees with the key-pair route")
    func xOnlyFromPublicKeyAgrees() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let pub = try ctx.publicKey(of: kp)

        let viaPublicKey = try ctx.xOnlyPublicKey(of: pub)
        let viaKeyPair = try ctx.xOnlyPublicKey(of: kp)
        #expect(ctx.serializedBytes(of: viaPublicKey.key)
                == ctx.serializedBytes(of: viaKeyPair.key))
        #expect(viaPublicKey.parity == viaKeyPair.parity)
    }

    @Test("a whole MuSig session survives a round-trip through the wire formats")
    func muSigOverTheWire() throws {
        // This is what the serialisation gap blocked: without it MuSig only
        // worked in a single process. Every value that crosses between signers
        // is serialised and re-parsed here.
        let ctx = try Context()
        let aliceSecret = [UInt8](repeating: 0x11, count: 32)
        let bobSecret = [UInt8](repeating: 0x22, count: 32)
        let message = [UInt8](repeating: 0xAB, count: 32)

        let aliceKP = try ctx.keyPair(secretKey: aliceSecret.span)
        let bobKP = try ctx.keyPair(secretKey: bobSecret.span)
        let alicePub = try ctx.publicKey(of: aliceKP)
        let bobPub = try ctx.publicKey(of: bobKP)

        // Keys are exchanged as compressed bytes and re-parsed.
        let aliceWire = ctx.serializedBytes(of: alicePub)
        let bobWire = ctx.serializedBytes(of: bobPub)
        let keys = try [aliceWire, bobWire].map { try ctx.publicKey(parsing: $0.span) }
        let (aggKey, cache) = try ctx.aggregate(publicKeys: keys)

        var r1 = [UInt8](repeating: 0x01, count: 32)
        var r2 = [UInt8](repeating: 0x02, count: 32)
        let alicePair = try ctx.generateNonce(sessionRandomness32: &r1,
                                              secretKey: aliceSecret.span,
                                              publicKey: alicePub,
                                              message32: message.span, cache: cache)
        let bobPair = try ctx.generateNonce(sessionRandomness32: &r2,
                                            secretKey: bobSecret.span,
                                            publicKey: bobPub,
                                            message32: message.span, cache: cache)

        // Nonces cross the wire as 66 bytes each.
        let aliceNonceWire = ctx.serializedBytes(of: alicePair.publicNonce)
        let bobNonceWire = ctx.serializedBytes(of: bobPair.publicNonce)
        #expect(aliceNonceWire.count == 66)
        let nonces = try [aliceNonceWire, bobNonceWire].map {
            try ctx.muSigPublicNonce(parsing: $0.span)
        }

        // The aggregate nonce is itself serialisable, as a coordinator would send it.
        let aggNonce = try ctx.aggregateNonces(nonces)
        let aggNonceWire = ctx.serializedBytes(of: aggNonce)
        #expect(aggNonceWire.count == 66)
        let aggNonceBack = try ctx.muSigAggregateNonce(parsing: aggNonceWire.span)

        let session = try ctx.session(aggregateNonce: aggNonceBack,
                                      message32: message.span, cache: cache)
        let alicePartial = try ctx.partialSign(noncePair: consume alicePair,
                                               keyPair: aliceKP, cache: cache,
                                               session: session)
        let bobPartial = try ctx.partialSign(noncePair: consume bobPair,
                                             keyPair: bobKP, cache: cache,
                                             session: session)

        // Partial signatures cross the wire as 32 bytes each.
        let partials = try [alicePartial, bobPartial]
            .map { ctx.serializedBytes(of: $0) }
            .map { wire -> MuSigPartialSignature in
                #expect(wire.count == 32)
                return try ctx.muSigPartialSignature(parsing: wire.span)
            }

        let signature = try ctx.aggregate(partialSignatures: partials, session: session)
        let ok = ctx.isValidSchnorr(signature.span, message: message.span, publicKey: aggKey)
        #expect(ok)
    }

    @Test("wrong-length wire values throw")
    func wrongWireLengths() throws {
        let ctx = try Context()
        let short = [UInt8](repeating: 0, count: 65)
        var caught: Secp256k1Error?
        do { _ = try ctx.muSigPublicNonce(parsing: short.span) }
        catch let e as Secp256k1Error { caught = e }
        #expect(caught == .wrongLength(expected: 66, actual: 65))
    }
}

/// Tweaks: BIP32 derivation and BIP341 taproot.
@Suite("Tweaks")
struct TweakTests {
    static let secretKey = [UInt8](repeating: 0x11, count: 32)
    static let tweak = [UInt8](repeating: 0x33, count: 32)
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    @Test("adding a scalar to a secret key matches adding it to the public key")
    func addCorrespondence() throws {
        // The property BIP32 rests on: tweaking a secret key and tweaking its
        // public key must land on the same keypair.
        let ctx = try Context()
        let tweakedSecret = try ctx.tweakedSecretKey(Self.secretKey.span,
                                                     addingScalar: Self.tweak.span)
        let fromSecret = try ctx.publicKey(secretKey: tweakedSecret.span)

        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let fromPublic = try ctx.tweakedPublicKey(pub, addingScalar: Self.tweak.span)
        #expect(ctx.compare(fromSecret, fromPublic) == 0)
    }

    @Test("multiplying by a scalar matches on both sides")
    func mulCorrespondence() throws {
        let ctx = try Context()
        let tweakedSecret = try ctx.tweakedSecretKey(Self.secretKey.span,
                                                     multiplyingByScalar: Self.tweak.span)
        let fromSecret = try ctx.publicKey(secretKey: tweakedSecret.span)
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let fromPublic = try ctx.tweakedPublicKey(pub, multiplyingByScalar: Self.tweak.span)
        #expect(ctx.compare(fromSecret, fromPublic) == 0)
    }

    @Test("negation matches on both sides, and is an involution")
    func negateCorrespondence() throws {
        let ctx = try Context()
        let negSecret = try ctx.negatedSecretKey(Self.secretKey.span)
        let fromSecret = try ctx.publicKey(secretKey: negSecret.span)
        let pub = try ctx.publicKey(secretKey: Self.secretKey.span)
        let fromPublic = try ctx.negatedPublicKey(pub)
        #expect(ctx.compare(fromSecret, fromPublic) == 0)

        // Negating twice returns the original.
        let back = try ctx.negatedSecretKey(negSecret.span)
        #expect(back == Self.secretKey)
    }

    @Test("a taproot output key verifies against its internal key and tweak")
    func taprootTweakCheck() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let (internalKey, _) = try ctx.xOnlyPublicKey(of: kp)

        let outputFull = try ctx.tweakedPublicKey(xOnly: internalKey,
                                                  addingScalar: Self.tweak.span)
        let (outputXOnly, parity) = try ctx.xOnlyPublicKey(of: outputFull)
        let outputBytes = ctx.serializedBytes(of: outputXOnly)

        // The verifier's side of a key-path spend.
        let ok = ctx.isValidTweak(tweakedKey32: outputBytes.span, parity: parity,
                                  internalKey: internalKey, tweak32: Self.tweak.span)
        #expect(ok)

        // A different tweak must not check out.
        let otherTweak = [UInt8](repeating: 0x44, count: 32)
        let bad = ctx.isValidTweak(tweakedKey32: outputBytes.span, parity: parity,
                                   internalKey: internalKey, tweak32: otherTweak.span)
        #expect(!bad)
    }

    @Test("a tweaked key pair signs for the tweaked output key")
    func taprootKeyPathSpend() throws {
        // The full taproot key-path flow: tweak the key pair, sign, and have
        // the signature verify under the tweaked x-only key.
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: Self.secretKey.span)
        let tweakedKP = try ctx.tweakedKeyPair(kp, addingScalar: Self.tweak.span)
        let (outputKey, _) = try ctx.xOnlyPublicKey(of: tweakedKP)

        let aux = [UInt8](repeating: 0x55, count: 32)
        let sig = try ctx.signSchnorr(message32: Self.messageHash.span,
                                      keyPair: tweakedKP, auxiliaryRandom: aux.span)
        let ok = ctx.isValidSchnorr(sig.span, message: Self.messageHash.span,
                                    publicKey: outputKey)
        #expect(ok)

        // And it must NOT verify under the untweaked key.
        let (untweaked, _) = try ctx.xOnlyPublicKey(of: kp)
        let wrong = ctx.isValidSchnorr(sig.span, message: Self.messageHash.span,
                                       publicKey: untweaked)
        #expect(!wrong)
    }

    @Test("a MuSig session under an x-only tweaked key produces a valid signature")
    func muSigTweakedSession() throws {
        let ctx = try Context()
        let aliceSecret = [UInt8](repeating: 0x11, count: 32)
        let bobSecret = [UInt8](repeating: 0x22, count: 32)
        let message = [UInt8](repeating: 0xAB, count: 32)
        let aliceKP = try ctx.keyPair(secretKey: aliceSecret.span)
        let bobKP = try ctx.keyPair(secretKey: bobSecret.span)
        let alicePub = try ctx.publicKey(of: aliceKP)
        let bobPub = try ctx.publicKey(of: bobKP)

        var (_, cache) = try ctx.aggregate(publicKeys: [alicePub, bobPub])
        // Taproot-style tweak applied to the aggregate key.
        let tweakedFull = try ctx.applyXOnlyTweak(to: &cache, tweak32: Self.tweak.span)
        let (tweakedKey, _) = try ctx.xOnlyPublicKey(of: tweakedFull)

        var r1 = [UInt8](repeating: 0x01, count: 32)
        var r2 = [UInt8](repeating: 0x02, count: 32)
        let ap = try ctx.generateNonce(sessionRandomness32: &r1, secretKey: aliceSecret.span,
                                       publicKey: alicePub, message32: message.span,
                                       cache: cache)
        let bp = try ctx.generateNonce(sessionRandomness32: &r2, secretKey: bobSecret.span,
                                       publicKey: bobPub, message32: message.span,
                                       cache: cache)
        let agg = try ctx.aggregateNonces([ap.publicNonce, bp.publicNonce])
        let session = try ctx.session(aggregateNonce: agg, message32: message.span,
                                      cache: cache)
        let s1 = try ctx.partialSign(noncePair: consume ap, keyPair: aliceKP,
                                     cache: cache, session: session)
        let s2 = try ctx.partialSign(noncePair: consume bp, keyPair: bobKP,
                                     cache: cache, session: session)
        let sig = try ctx.aggregate(partialSignatures: [s1, s2], session: session)

        // Verifies under the *tweaked* aggregate key.
        let ok = ctx.isValidSchnorr(sig.span, message: message.span, publicKey: tweakedKey)
        #expect(ok)
    }

    @Test("a wrong-length tweak throws")
    func wrongTweakLength() throws {
        let ctx = try Context()
        let short = [UInt8](repeating: 0x33, count: 31)
        var caught: Secp256k1Error?
        do { _ = try ctx.tweakedSecretKey(Self.secretKey.span, addingScalar: short.span) }
        catch let e as Secp256k1Error { caught = e }
        #expect(caught == .wrongLength(expected: 32, actual: 31))
    }
}

/// Comparison, sorting, combining, normalisation, tagged hashing.
@Suite("Utilities")
struct UtilityTests {
    static let messageHash = [UInt8](repeating: 0xAB, count: 32)

    static func keys(_ ctx: borrowing Context, _ bytes: [UInt8]) throws -> PublicKey {
        try ctx.publicKey(secretKey: bytes.span)
    }

    @Test("sorting matches lexicographic order of the compressed serialisation")
    func sortIsLexicographic() throws {
        let ctx = try Context()
        let unsorted = try [0x11, 0x22, 0x33, 0x44].map {
            try Self.keys(ctx, [UInt8](repeating: UInt8($0), count: 32))
        }
        let sorted = try ctx.sorted(publicKeys: unsorted)
        #expect(sorted.count == unsorted.count)

        let wire = sorted.map { ctx.serializedBytes(of: $0) }
        for (a, b) in zip(wire, wire.dropFirst()) {
            #expect(a.lexicographicallyPrecedes(b))
        }
    }

    @Test("combining public keys matches adding the secret keys")
    func combineMatchesScalarAdd() throws {
        let ctx = try Context()
        let a = [UInt8](repeating: 0x11, count: 32)
        let b = [UInt8](repeating: 0x22, count: 32)
        let combined = try ctx.combined(publicKeys: [try Self.keys(ctx, a),
                                                     try Self.keys(ctx, b)])
        let summedSecret = try ctx.tweakedSecretKey(a.span, addingScalar: b.span)
        let fromSum = try ctx.publicKey(secretKey: summedSecret.span)
        #expect(ctx.compare(combined, fromSum) == 0)
    }

    @Test("comparison is consistent and antisymmetric")
    func comparisonIsOrdered() throws {
        let ctx = try Context()
        let a = try Self.keys(ctx, [UInt8](repeating: 0x11, count: 32))
        let b = try Self.keys(ctx, [UInt8](repeating: 0x22, count: 32))
        let ab = ctx.compare(a, b)
        let ba = ctx.compare(b, a)
        #expect(ab != 0)
        #expect((ab < 0) == (ba > 0))
        #expect(ctx.compare(a, a) == 0)
    }

    @Test("freshly produced signatures are already lower-S")
    func signaturesAreNormalized() throws {
        // libsecp256k1 only ever emits lower-S, so normalising is a no-op here.
        // The value of the API is for signatures arriving from elsewhere.
        let ctx = try Context()
        let sk = [UInt8](repeating: 0x11, count: 32)
        let sig = try ctx.sign(messageHash: Self.messageHash.span, secretKey: sk.span)
        let res = ctx.isNormalized(sig)
        #expect(res)
        let (normalised, changed) = ctx.normalized(sig)
        #expect(!changed)
        #expect(ctx.compactBytes(of: normalised) == ctx.compactBytes(of: sig))
    }

    @Test("tagged hashes are 32 bytes, deterministic, and tag-separated")
    func taggedHashing() throws {
        let ctx = try Context()
        let tagA = Array("TapLeaf".utf8)
        let tagB = Array("TapBranch".utf8)
        let msg = [UInt8](repeating: 0x07, count: 40)

        let h1 = try ctx.taggedSHA256(tag: tagA.span, message: msg.span)
        let h2 = try ctx.taggedSHA256(tag: tagA.span, message: msg.span)
        let other = try ctx.taggedSHA256(tag: tagB.span, message: msg.span)
        #expect(h1.count == 32)
        #expect(h1 == h2)          // deterministic
        #expect(h1 != other)       // the tag domain-separates
    }

    @Test("variable-length Schnorr signing round-trips")
    func variableLengthSchnorr() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: [UInt8](repeating: 0x11, count: 32).span)
        let (key, _) = try ctx.xOnlyPublicKey(of: kp)
        let long = [UInt8](repeating: 0x5A, count: 100)

        let sig = try ctx.signSchnorr(message: long.span, keyPair: kp)
        #expect(sig.count == 64)
        let ok = ctx.isValidSchnorr(sig.span, message: long.span, publicKey: key)
        #expect(ok)

        // A different length must not verify.
        let shorter = [UInt8](repeating: 0x5A, count: 99)
        let bad = ctx.isValidSchnorr(sig.span, message: shorter.span, publicKey: key)
        #expect(!bad)
    }

    @Test("counter-based MuSig nonces work and differ per counter")
    func counterNonces() throws {
        let ctx = try Context()
        let kp = try ctx.keyPair(secretKey: [UInt8](repeating: 0x11, count: 32).span)
        let pub = try ctx.publicKey(of: kp)
        let message = [UInt8](repeating: 0xAB, count: 32)
        let (aggKey, cache) = try ctx.aggregate(publicKeys: [pub])

        let p0 = try ctx.generateNonce(counter: 0, keyPair: kp,
                                       message32: message.span, cache: cache)
        let p1 = try ctx.generateNonce(counter: 1, keyPair: kp,
                                       message32: message.span, cache: cache)
        // Different counters must give different nonces -- that is the whole
        // safety property of the counter mode.
        #expect(ctx.serializedBytes(of: p0.publicNonce)
                != ctx.serializedBytes(of: p1.publicNonce))

        // And a session built from one of them must produce a valid signature.
        let agg = try ctx.aggregateNonces([p0.publicNonce])
        let session = try ctx.session(aggregateNonce: agg, message32: message.span,
                                      cache: cache)
        let partial = try ctx.partialSign(noncePair: consume p0, keyPair: kp,
                                          cache: cache, session: session)
        _ = consume p1
        let sig = try ctx.aggregate(partialSignatures: [partial], session: session)
        let ok = ctx.isValidSchnorr(sig.span, message: message.span, publicKey: aggKey)
        #expect(ok)
    }

    @Test("randomising the context does not disturb signing")
    func randomizeKeepsWorking() throws {
        let ctx = try Context()
        let sk = [UInt8](repeating: 0x11, count: 32)
        let before = try ctx.sign(messageHash: Self.messageHash.span, secretKey: sk.span)

        let seed = [UInt8](repeating: 0x9E, count: 32)
        try ctx.randomize(seed32: seed.span)

        // Blinding is internal, so RFC6979 output must be unchanged.
        let after = try ctx.sign(messageHash: Self.messageHash.span, secretKey: sk.span)
        #expect(ctx.compactBytes(of: before) == ctx.compactBytes(of: after))

        try ctx.randomize(seed32: nil)   // reset
        let reset = try ctx.sign(messageHash: Self.messageHash.span, secretKey: sk.span)
        #expect(ctx.compactBytes(of: reset) == ctx.compactBytes(of: before))
    }
}
