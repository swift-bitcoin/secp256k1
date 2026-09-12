import CSECP256K1

// MARK: - Comparison and ordering

extension Context {
    /// Compares two public keys by their compressed serialisation.
    ///
    /// Returns a negative number, zero, or a positive number, like `memcmp`.
    /// Comparison needs a context, so `PublicKey` cannot simply be `Comparable`.
    public func compare(_ a: PublicKey, _ b: PublicKey) -> Int {
        let x = CollectionOfOne(a.raw)
        let y = CollectionOfOne(b.raw)
        return Int(raw.ecPubkeyCmp(pubkey1: x.span, pubkey2: y.span))
    }

    /// Compares two x-only public keys.
    public func compare(_ a: XOnlyPublicKey, _ b: XOnlyPublicKey) -> Int {
        var x = a.raw
        var y = b.raw
        return Int(unsafe raw.xonlyPubkeyCmp(pk1: &x, pk2: &y))
    }

    /// Sorts public keys into lexicographic order of their compressed
    /// serialisation.
    ///
    /// This is not a convenience: BIP327 MuSig key aggregation depends on key
    /// order, so all signers must agree on one. Sorting is the standard way to
    /// reach that agreement without extra coordination.
    public func sorted(publicKeys: [PublicKey]) throws -> [PublicKey] {
        guard !publicKeys.isEmpty else { return [] }
        var structs = publicKeys.map(\.raw)
        // secp256k1_ec_pubkey_sort permutes the array of *pointers*, leaving the
        // structs where they are, so the sorted order is read back through them.
        return try structs.withUnsafeMutableBufferPointer { buf -> [PublicKey] in
            var ptrs: [UnsafePointer<Pubkey>?] =
                unsafe (0..<buf.count).map { unsafe UnsafePointer(buf.baseAddress! + $0) }
            let ok = ptrs.withUnsafeMutableBufferPointer { pp in
                unsafe raw.ecPubkeySort(pubkeys: pp.baseAddress!, nPubkeys: buf.count)
            }
            guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
            return unsafe ptrs.map { PublicKey(raw: unsafe $0!.pointee) }
        }
    }

    /// Adds public keys together as curve points.
    public func combined(publicKeys: [PublicKey]) throws -> PublicKey {
        guard !publicKeys.isEmpty else { throw Secp256k1Error.invalidPublicKey }
        var structs = publicKeys.map(\.raw)
        var out = CollectionOfOne(Pubkey())
        var outSpan = out.mutableSpan
        let ok = structs.withUnsafeMutableBufferPointer { buf -> Int32 in
            let ptrs: [UnsafePointer<Pubkey>?] = unsafe (0..<buf.count).map { unsafe UnsafePointer(buf.baseAddress! + $0) }
            return unsafe raw.ecPubkeyCombine(out: &outSpan, ins: ptrs.span)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: out[0])
    }
}

// MARK: - Signature normalisation

extension Context {
    /// Converts a signature to lower-S form.
    ///
    /// ECDSA admits a second valid signature for the same message and key, with
    /// S replaced by `n - S`; anyone can compute it from the first. Bitcoin
    /// therefore requires lower-S, and `isValid(_:messageHash:publicKey:)`
    /// rejects the other form. Use this when accepting signatures from
    /// elsewhere.
    ///
    /// `wasNormalized` is `true` if the input needed changing -- useful for
    /// rejecting non-canonical signatures rather than silently fixing them.
    public func normalized(_ signature: Signature) -> (signature: Signature, wasNormalized: Bool) {
        let input = CollectionOfOne(signature.raw)
        var out = CollectionOfOne(ECDSASignature())
        var outSpan: MutableSpan<ECDSASignature>? = out.mutableSpan
        let changed = raw.ecdsaSignatureNormalize(sigout: &outSpan, sigin: input.span)
        return (Signature(raw: out[0]), changed == 1)
    }

    /// Whether a signature is already in lower-S form, without producing the
    /// normalised value.
    public func isNormalized(_ signature: Signature) -> Bool {
        var input = signature.raw
        return unsafe raw.ecdsaSignatureNormalize(sigout: nil, sigin: &input) == 0
    }
}

// MARK: - Tagged hashing

extension Context {
    /// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || message)`.
    ///
    /// Exposed by libsecp256k1 because getting the double-tag construction
    /// right by hand is error-prone, and taproot uses it throughout.
    public func taggedSHA256(tag: Span<UInt8>, message: Span<UInt8>) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var outSpan = out.mutableSpan
        let ok = raw.taggedSHA256(hash32: &outSpan, tag: tag, msg: message)
        guard ok == 1 else { throw Secp256k1Error.signingFailed }
        return out
    }
}

// MARK: - Variable-length Schnorr signing

extension Context {
    /// Signs a message of any length with BIP340 Schnorr.
    ///
    /// `signSchnorr(message32:keyPair:auxiliaryRandom:)` is fixed at 32 bytes
    /// because that is what BIP340 specifies for Bitcoin. This variant uses
    /// `schnorrsig_sign_custom`, which accepts any length -- needed for
    /// BIP340's "message of arbitrary size" mode.
    ///
    /// Passing `nil` extraparams selects the default nonce function, so this
    /// is deterministic with no auxiliary randomness. Prefer the 32-byte
    /// version with fresh `auxiliaryRandom` where BIP340 applies.
    public func signSchnorr(
        message: Span<UInt8>,
        keyPair: KeyPair,
        auxiliaryRandom: Span<UInt8>? = nil
    ) throws -> [UInt8] {
        if let auxiliaryRandom, auxiliaryRandom.count != 32 {
            throw Secp256k1Error.wrongLength(expected: 32, actual: auxiliaryRandom.count)
        }
        var kp = keyPair.raw
        var sig = [UInt8](repeating: 0, count: 64)

        let ok = sig.withUnsafeMutableBufferPointer { s -> Int32 in
            message.withUnsafeBufferPointer { m -> Int32 in
                guard let auxiliaryRandom else {
                    return unsafe raw.schnorrsigSignCustom(
                        sig64: s.baseAddress!, msg: m.baseAddress, msglen: m.count,
                        keypair: &kp, extraparams: nil)
                }
                return auxiliaryRandom.withUnsafeBufferPointer { aux -> Int32 in
                    // The auxiliary randomness reaches BIP340's nonce function
                    // through extraparams.ndata.
                    //
                    // `magic` must be set or libsecp256k1 calls the illegal
                    // callback and aborts. Its value comes from
                    // SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC
                    // (include/secp256k1_schnorrsig.h:88), a brace-init macro
                    // that cannot import into Swift as a value, so the bytes
                    // are repeated here. A wrong value is not a silent
                    // failure -- it aborts -- and the BIP340 vector tests
                    // exercise this path, so the constant is self-checking.
                    var extra = unsafe secp256k1_schnorrsig_extraparams(
                        magic: (0xDA, 0x6F, 0xB3, 0x8C),
                        noncefp: nil,
                        ndata: UnsafeMutableRawPointer(mutating: aux.baseAddress!))
                    return unsafe raw.schnorrsigSignCustom(
                        sig64: s.baseAddress!, msg: m.baseAddress, msglen: m.count,
                        keypair: &kp, extraparams: &extra)
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.signingFailed }
        return sig
    }
}

// MARK: - Counter-based MuSig nonces

extension Context {
    /// Generates a MuSig nonce from a monotonic counter instead of fresh
    /// randomness.
    ///
    /// For signers with no RNG -- hardware wallets in particular. The safety
    /// requirement moves from "randomness must be fresh" to "`counter` must
    /// never repeat for this key pair", which is why upstream names it
    /// `nonrepeating_cnt`. Persisting that counter across power loss is the
    /// caller's problem, and getting it wrong leaks the secret key exactly as
    /// nonce reuse does.
    public func generateNonce(
        counter: UInt64,
        keyPair: KeyPair,
        message32: Span<UInt8>?,
        cache: MuSigKeyAggCache?,
        extraInput32: Span<UInt8>? = nil
    ) throws -> MuSigNoncePair {
        var kp = keyPair.raw
        var c = cache?.raw
        var secnonce = secp256k1_musig_secnonce()
        var pubnonce = secp256k1_musig_pubnonce()

        func withOptional<R>(
            _ span: Span<UInt8>?, _ body: (UnsafePointer<UInt8>?) -> R
        ) -> R {
            guard let span else { return body(nil) }
            return span.withUnsafeBufferPointer { unsafe body($0.baseAddress) }
        }

        let ok = unsafe withOptional(message32) { msg in
            unsafe withOptional(extraInput32) { extra in
                if c != nil {
                    return unsafe raw.musigNonceGenCounter(
                        secnonce: &secnonce, pubnonce: &pubnonce,
                        nonrepeatingCnt: counter, keypair: &kp, msg32: msg,
                        keyaggCache: &c!, extraInput32: extra)
                }
                return unsafe raw.musigNonceGenCounter(
                    secnonce: &secnonce, pubnonce: &pubnonce,
                    nonrepeatingCnt: counter, keypair: &kp, msg32: msg,
                    keyaggCache: nil, extraInput32: extra)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.nonceGenerationFailed }
        return MuSigNoncePair(secret: MuSigSecretNonce(raw: secnonce),
                              publicNonce: MuSigPublicNonce(raw: pubnonce))
    }
}

// MARK: - Side-channel hardening

extension Context {
    /// Re-randomises the context's blinding values.
    ///
    /// libsecp256k1 is written to be constant-time, but a compiler or CPU may
    /// still leak through power draw or emissions. Randomising blinds secret
    /// values against that. Call it periodically between signing operations if
    /// you care about physical side channels.
    ///
    /// Pass `nil` to reset to the initial state. Not valid on
    /// `SECP256K1Context.shared`, which is why `Secp256k1Context` never wraps
    /// that one.
    public func randomize(seed32: Span<UInt8>?) throws {
        if let seed32, seed32.count != 32 {
            throw Secp256k1Error.wrongLength(expected: 32, actual: seed32.count)
        }
        let ok: Int32
        if let seed32 {
            ok = seed32.withUnsafeBufferPointer { s in
                unsafe raw.randomize(seed32: s.baseAddress!)
            }
        } else {
            ok = unsafe raw.randomize(seed32: nil)
        }
        guard ok == 1 else { throw Secp256k1Error.contextCreationFailed }
    }
}
