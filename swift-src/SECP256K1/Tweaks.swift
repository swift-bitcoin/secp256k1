import CSECP256K1

/// Copies a `Span` into an `Array`. `Array.init` has no `Span` overload, and
/// the copy is needed anyway: every tweak below is in-place on 32 bytes the
/// caller must not see mutated.
@inline(__always)
private func copied(_ span: Span<UInt8>) -> [UInt8] {
    span.withUnsafeBufferPointer { unsafe Array($0) }
}

// Tweaking is what BIP32 hierarchical derivation and BIP341 taproot are built
// from: adding a scalar to a key, or to its public counterpart, such that the
// two stay in correspondence.

// MARK: - Secret key tweaks

extension Context {
    /// Returns `secretKey + tweak32` (mod n).
    ///
    /// Throws if the result would be zero or the arguments are invalid, which
    /// happens with negligible probability for random tweaks but must still be
    /// handled -- an attacker who chooses the tweak can force it.
    public func tweakedSecretKey(
        _ secretKey: Span<UInt8>,
        addingScalar tweak32: Span<UInt8>
    ) throws -> [UInt8] {
        try unsafe tweakSecretKey(secretKey, tweak32) { ctx, key, tweak in
            unsafe ctx.ecSeckeyTweakAdd(seckey: key, tweak32: tweak)
        }
    }

    /// Returns `secretKey * tweak32` (mod n).
    public func tweakedSecretKey(
        _ secretKey: Span<UInt8>,
        multiplyingByScalar tweak32: Span<UInt8>
    ) throws -> [UInt8] {
        try unsafe tweakSecretKey(secretKey, tweak32) { ctx, key, tweak in
            unsafe ctx.ecSeckeyTweakMul(seckey: key, tweak32: tweak)
        }
    }

    /// Returns `-secretKey` (mod n).
    public func negatedSecretKey(_ secretKey: Span<UInt8>) throws -> [UInt8] {
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        var out = copied(secretKey)
        let ok = out.withUnsafeMutableBufferPointer { buf in
            unsafe raw.ecSeckeyNegate(seckey: buf.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        return out
    }

    /// Shared plumbing: both secret-key tweaks are in-place on a 32-byte copy.
    private func tweakSecretKey(
        _ secretKey: Span<UInt8>,
        _ tweak32: Span<UInt8>,
        _ body: (SECP256K1Context, UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>) -> Int32
    ) throws -> [UInt8] {
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        guard tweak32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: tweak32.count)
        }
        var out = copied(secretKey)
        let ok = out.withUnsafeMutableBufferPointer { buf in
            tweak32.withUnsafeBufferPointer { tw in
                unsafe body(raw, buf.baseAddress!, tw.baseAddress!)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        return out
    }
}

// MARK: - Public key tweaks

extension Context {
    /// Returns `publicKey + tweak32 * G`, matching `tweakedSecretKey(_:addingScalar:)`.
    public func tweakedPublicKey(
        _ publicKey: PublicKey,
        addingScalar tweak32: Span<UInt8>
    ) throws -> PublicKey {
        var key = CollectionOfOne(publicKey.raw)
        var keySpan = key.mutableSpan
        let ok = raw.ecPubkeyTweakAdd(pubkey: &keySpan, tweak32: tweak32)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: key[0])
    }

    /// Returns `publicKey * tweak32`, matching `tweakedSecretKey(_:multiplyingByScalar:)`.
    public func tweakedPublicKey(
        _ publicKey: PublicKey,
        multiplyingByScalar tweak32: Span<UInt8>
    ) throws -> PublicKey {
        try unsafe tweakPublicKey(publicKey, tweak32) { ctx, key, tweak in
            unsafe ctx.ecPubkeyTweakMul(pubkey: key, tweak32: tweak)
        }
    }

    /// Returns the point negation of a public key.
    public func negatedPublicKey(_ publicKey: PublicKey) throws -> PublicKey {
        var key = CollectionOfOne(publicKey.raw)
        var keySpan = key.mutableSpan
        let ok = raw.ecPubkeyNegate(pubkey: &keySpan)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: key[0])
    }

    private func tweakPublicKey(
        _ publicKey: PublicKey,
        _ tweak32: Span<UInt8>,
        _ body: (SECP256K1Context, UnsafeMutablePointer<Pubkey>, UnsafePointer<UInt8>) -> Int32
    ) throws -> PublicKey {
        guard tweak32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: tweak32.count)
        }
        var key = publicKey.raw
        let ok = tweak32.withUnsafeBufferPointer { tw in
            unsafe body(raw, &key, tw.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: key)
    }
}

// MARK: - Taproot (BIP341) tweaks

extension Context {
    /// Tweaks an x-only key, giving the full output key. This is the taproot
    /// output-key computation: `Q = P + t*G`.
    ///
    /// The result is a full key, not x-only, because the parity is needed to
    /// verify the tweak later.
    public func tweakedPublicKey(
        xOnly internalKey: XOnlyPublicKey,
        addingScalar tweak32: Span<UInt8>
    ) throws -> PublicKey {
        guard tweak32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: tweak32.count)
        }
        let internalKey = CollectionOfOne(internalKey.raw)
        var out = CollectionOfOne(Pubkey())
        var outSpan = out.mutableSpan
        let ok = raw.xonlyPubkeyTweakAdd(outputPubkey: &outSpan, internalPubkey: internalKey.span,
                                           tweak32: tweak32)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: out[0])
    }

    /// Checks that `tweakedKey32`/`parity` really is `internalKey` tweaked by
    /// `tweak32`, without recomputing the full key.
    ///
    /// This is the verifier's side of a taproot spend.
    public func isValidTweak(
        tweakedKey32: Span<UInt8>,
        parity: Int32,
        internalKey: XOnlyPublicKey,
        tweak32: Span<UInt8>
    ) -> Bool {
        guard tweakedKey32.count == 32, tweak32.count == 32 else { return false }
        let internalKey = CollectionOfOne(internalKey.raw)
        return raw.xonlyPubkeyTweakAddCheck(
                    tweakedPubkey32: tweakedKey32, tweakedPkParity: parity,
                    internalPubkey: internalKey.span, tweak32: tweak32) == 1
    }

    /// Tweaks a key pair in place, so it can sign for the tweaked x-only key.
    ///
    /// This is the taproot key-path spending side: the signer applies the same
    /// tweak the verifier checks.
    public func tweakedKeyPair(
        _ keyPair: KeyPair,
        addingScalar tweak32: Span<UInt8>
    ) throws -> KeyPair {
        guard tweak32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: tweak32.count)
        }
        var kp = CollectionOfOne(keyPair.raw)
        var kpSpan = kp.mutableSpan
        let ok = raw.keypairXOnlyTweakAdd(keypair: &kpSpan, tweak32: tweak32)
        guard ok == 1 else { throw Secp256k1Error.invalidKeyPair }
        return KeyPair(raw: kp[0])
    }
}

// MARK: - MuSig tweaks

extension Context {
    /// Applies an x-only (taproot-style) tweak to an aggregate key.
    ///
    /// The cache is modified in place, so the returned cache -- not the
    /// original -- must be used for the rest of the session. That is why this
    /// takes the cache `inout` rather than returning a fresh one: sharing a
    /// pre-tweak cache with a post-tweak session produces invalid signatures.
    public func applyXOnlyTweak(
        to cache: inout MuSigKeyAggCache,
        tweak32: Span<UInt8>
    ) throws -> PublicKey {
        try unsafe applyMuSigTweak(&cache, tweak32) { ctx, out, c, tw in
            unsafe ctx.musigPubkeyXOnlyTweakAdd(outputPubkey: out, keyaggCache: c, tweak32: tw)
        }
    }

    /// Applies a plain EC tweak to an aggregate key.
    public func applyECTweak(
        to cache: inout MuSigKeyAggCache,
        tweak32: Span<UInt8>
    ) throws -> PublicKey {
        try unsafe applyMuSigTweak(&cache, tweak32) { ctx, out, c, tw in
            unsafe ctx.musigPubkeyEcTweakAdd(outputPubkey: out, keyaggCache: c, tweak32: tw)
        }
    }

    private func applyMuSigTweak(
        _ cache: inout MuSigKeyAggCache,
        _ tweak32: Span<UInt8>,
        _ body: (SECP256K1Context,
                 UnsafeMutablePointer<Pubkey>?,
                 UnsafeMutablePointer<secp256k1_musig_keyagg_cache>,
                 UnsafePointer<UInt8>) -> Int32
    ) throws -> PublicKey {
        guard tweak32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: tweak32.count)
        }
        var c = cache.raw
        var out = Pubkey()
        let ok = tweak32.withUnsafeBufferPointer { tw in
            unsafe body(raw, &out, &c, tw.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        cache = MuSigKeyAggCache(raw: c)
        return PublicKey(raw: out)
    }
}
