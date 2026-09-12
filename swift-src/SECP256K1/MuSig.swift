import CSECP256K1

// MARK: - Types

/// Cached state from aggregating a set of public keys. Also carries any tweaks
/// applied afterwards, so it must be the same cache throughout a session.
public struct MuSigKeyAggCache: Sendable {
    @usableFromInline var raw: secp256k1_musig_keyagg_cache
    @usableFromInline init(raw: secp256k1_musig_keyagg_cache) { self.raw = raw }
}

/// A signer's public nonce, safe to publish. Serialises to 66 bytes.
public struct MuSigPublicNonce: Sendable {
    @usableFromInline var raw: secp256k1_musig_pubnonce
    @usableFromInline init(raw: secp256k1_musig_pubnonce) { self.raw = raw }
}

/// All signers' public nonces combined. Serialises to 66 bytes.
public struct MuSigAggregateNonce: Sendable {
    @usableFromInline var raw: secp256k1_musig_aggnonce
    @usableFromInline init(raw: secp256k1_musig_aggnonce) { self.raw = raw }
}

/// Per-signing-session state derived from the aggregate nonce and message.
public struct MuSigSession: Sendable {
    @usableFromInline var raw: secp256k1_musig_session
    @usableFromInline init(raw: secp256k1_musig_session) { self.raw = raw }
}

/// One signer's partial signature. Serialises to 32 bytes.
public struct MuSigPartialSignature: Sendable {
    @usableFromInline var raw: secp256k1_musig_partial_sig
    @usableFromInline init(raw: secp256k1_musig_partial_sig) { self.raw = raw }
}

/// A signer's **secret** nonce.
///
/// This type is `~Copyable` and is *consumed* by `partialSign`, which makes
/// libsecp256k1's most dangerous precondition a compile-time one.
///
/// Upstream's contract: the secnonce "has been never used in a partial_sign
/// call before", and reusing one "will leak the secret key". Upstream also
/// advises avoiding copies or serialisation of the value, since every extra
/// copy is another chance to sign twice with it.
///
/// Making it non-copyable enforces all of that structurally: it cannot be
/// duplicated, and because `partialSign` takes it as `consuming`, using it a
/// second time is a compile error rather than a key disclosure. libsecp256k1
/// also invalidates the nonce internally and returns 0 on reuse, so this is
/// belt and braces -- but a compile error is strictly better than a runtime 0.
///
/// There is deliberately no serialisation on this type.
public struct MuSigSecretNonce: ~Copyable {
    @usableFromInline var raw: secp256k1_musig_secnonce
    @usableFromInline init(raw: secp256k1_musig_secnonce) { self.raw = raw }

    // No scrubbing deinit: a noncopyable struct's `deinit` cannot mutate
    // `self` ("cannot assign to property: 'self' is immutable"), so the bytes
    // cannot be zeroed on destruction. The guarantee this type provides is
    // single use, not erasure.
}

/// The nonce pair produced by `generateNonce`.
///
/// Non-copyable because it holds the secret nonce. Read `publicNonce` freely --
/// it is a copyable value meant to be published -- then hand the whole pair to
/// `partialSign`, which consumes it. A tuple cannot be used here: Swift does
/// not support tuples with noncopyable elements.
public struct MuSigNoncePair: ~Copyable {
    /// Safe to broadcast, and to keep a copy of for `isValidPartialSignature`.
    public let publicNonce: MuSigPublicNonce

    @usableFromInline var secret: MuSigSecretNonce

    @usableFromInline init(secret: consuming MuSigSecretNonce, publicNonce: MuSigPublicNonce) {
        self.secret = secret
        self.publicNonce = publicNonce
    }
}

// MARK: - Key aggregation

extension Context {
    /// Aggregates signers' public keys into a single x-only key plus the cache
    /// needed for the rest of the session.
    ///
    /// Key order matters: a different order gives a different aggregate key.
    public func aggregate(
        publicKeys: [PublicKey]
    ) throws -> (aggregateKey: XOnlyPublicKey, cache: MuSigKeyAggCache) {
        guard !publicKeys.isEmpty else { throw Secp256k1Error.invalidPublicKey }
        var structs = publicKeys.map(\.raw)
        var aggPk = secp256k1_xonly_pubkey()
        var cache = secp256k1_musig_keyagg_cache()
        let ok = structs.withUnsafeMutableBufferPointer { buf -> Int32 in
            let ptrs: [UnsafePointer<Pubkey>?] =
                unsafe (0..<buf.count).map { unsafe UnsafePointer(buf.baseAddress! + $0) }
            return ptrs.withUnsafeBufferPointer { pp in
                unsafe raw.musigPubkeyAgg(aggPk: &aggPk, keyaggCache: &cache,
                                          pubkeys: pp.baseAddress!, nPubkeys: buf.count)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return (XOnlyPublicKey(raw: aggPk), MuSigKeyAggCache(raw: cache))
    }

    /// The full (parity-carrying) aggregate public key held in a cache.
    public func aggregatePublicKey(from cache: MuSigKeyAggCache) throws -> PublicKey {
        var c = cache.raw
        var pub = Pubkey()
        let ok = unsafe raw.musigPubkeyGet(aggPk: &pub, keyaggCache: &c)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: pub)
    }
}

// MARK: - Nonces

extension Context {
    /// Generates this signer's nonce pair.
    ///
    /// `sessionRandomness32` must be 32 bytes of fresh randomness and is
    /// **overwritten** by libsecp256k1 so it cannot be reused by accident,
    /// which is why it is `inout` here rather than a `Span`.
    ///
    /// Supplying `secretKey` and `message32` is strongly recommended: they are
    /// mixed into the nonce so that a repeated `sessionRandomness32` is less
    /// catastrophic.
    public func generateNonce(
        sessionRandomness32: inout [UInt8],
        secretKey: Span<UInt8>?,
        publicKey: PublicKey,
        message32: Span<UInt8>?,
        cache: MuSigKeyAggCache?,
        extraInput32: Span<UInt8>? = nil
    ) throws -> MuSigNoncePair {
        guard sessionRandomness32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: sessionRandomness32.count)
        }
        var secnonce = secp256k1_musig_secnonce()
        var pubnonce = secp256k1_musig_pubnonce()
        var pub = publicKey.raw
        var c = cache?.raw

        // Optional Spans have to be bridged to pointers one level at a time;
        // there is no way to pass "a Span or nil" to a nullable pointer.
        func withOptional<R>(
            _ span: Span<UInt8>?, _ body: (UnsafePointer<UInt8>?) -> R
        ) -> R {
            guard let span else { return body(nil) }
            return span.withUnsafeBufferPointer { unsafe body($0.baseAddress) }
        }

        let ok = sessionRandomness32.withUnsafeMutableBufferPointer { rand -> Int32 in
            unsafe withOptional(secretKey) { sk in
                unsafe withOptional(message32) { msg in
                    unsafe withOptional(extraInput32) { extra in
                        if c != nil {
                            return unsafe raw.musigNonceGen(
                                secnonce: &secnonce, pubnonce: &pubnonce,
                                sessionSecrand32: rand.baseAddress!,
                                seckey: sk, pubkey: &pub, msg32: msg,
                                keyaggCache: &c!, extraInput32: extra)
                        }
                        return unsafe raw.musigNonceGen(
                            secnonce: &secnonce, pubnonce: &pubnonce,
                            sessionSecrand32: rand.baseAddress!,
                            seckey: sk, pubkey: &pub, msg32: msg,
                            keyaggCache: nil, extraInput32: extra)
                    }
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.nonceGenerationFailed }
        return MuSigNoncePair(secret: MuSigSecretNonce(raw: secnonce),
                              publicNonce: MuSigPublicNonce(raw: pubnonce))
    }

    /// Combines every signer's public nonce.
    public func aggregateNonces(_ nonces: [MuSigPublicNonce]) throws -> MuSigAggregateNonce {
        guard !nonces.isEmpty else { throw Secp256k1Error.invalidNonce }
        var structs = nonces.map(\.raw)
        var agg = secp256k1_musig_aggnonce()
        let ok = structs.withUnsafeMutableBufferPointer { buf -> Int32 in
            let ptrs: [UnsafePointer<secp256k1_musig_pubnonce>?] =
                unsafe (0..<buf.count).map { unsafe UnsafePointer(buf.baseAddress! + $0) }
            return ptrs.withUnsafeBufferPointer { pp in
                unsafe raw.musigNonceAgg(aggnonce: &agg, pubnonces: pp.baseAddress!,
                                         nPubnonces: buf.count)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidNonce }
        return MuSigAggregateNonce(raw: agg)
    }

    /// Derives the session state every signer needs before partial signing.
    public func session(
        aggregateNonce: MuSigAggregateNonce,
        message32: Span<UInt8>,
        cache: MuSigKeyAggCache
    ) throws -> MuSigSession {
        guard message32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: message32.count)
        }
        var agg = aggregateNonce.raw
        var c = cache.raw
        var sess = secp256k1_musig_session()
        let ok = unsafe raw.musigNonceProcess(session: &sess, aggnonce: &agg,
                                              msg32: message32, keyaggCache: &c)
        guard ok == 1 else { throw Secp256k1Error.invalidNonce }
        return MuSigSession(raw: sess)
    }
}

// MARK: - Partial signing

extension Context {
    /// Produces this signer's partial signature, **consuming** the secret nonce.
    ///
    /// The nonce cannot be used again: it is non-copyable and consumed here, so
    /// a second call is a compile error. That is the whole reason
    /// `MuSigSecretNonce` exists as a distinct type.
    public func partialSign(
        noncePair: consuming MuSigNoncePair,
        keyPair: KeyPair,
        cache: MuSigKeyAggCache,
        session: MuSigSession
    ) throws -> MuSigPartialSignature {
        var pair = consume noncePair
        var kp = keyPair.raw
        var c = cache.raw
        var s = session.raw
        var sig = secp256k1_musig_partial_sig()
        let ok = withUnsafeMutablePointer(to: &pair.secret.raw) { np in
            unsafe raw.musigPartialSign(partialSig: &sig, secnonce: np, keypair: &kp,
                                        keyaggCache: &c, session: &s)
        }
        guard ok == 1 else { throw Secp256k1Error.signingFailed }
        return MuSigPartialSignature(raw: sig)
    }

    /// Verifies one partial signature.
    ///
    /// Upstream recommends always doing this: `partial_sign` deliberately does
    /// not verify its own output, deviating from BIP327, so this is the defence
    /// against random or adversarially provoked computation errors.
    public func isValidPartialSignature(
        _ signature: MuSigPartialSignature,
        publicNonce: MuSigPublicNonce,
        publicKey: PublicKey,
        cache: MuSigKeyAggCache,
        session: MuSigSession
    ) -> Bool {
        var sig = signature.raw
        var pn = publicNonce.raw
        var pk = publicKey.raw
        var c = cache.raw
        var s = session.raw
        return unsafe raw.musigPartialSigVerify(partialSig: &sig, pubnonce: &pn,
                                                pubkey: &pk, keyaggCache: &c,
                                                session: &s) == 1
    }

    /// Combines partial signatures into a single 64-byte BIP340 signature,
    /// verifiable against the aggregate x-only key by any Schnorr verifier.
    public func aggregate(
        partialSignatures: [MuSigPartialSignature],
        session: MuSigSession
    ) throws -> [UInt8] {
        guard !partialSignatures.isEmpty else { throw Secp256k1Error.invalidSignature }
        var structs = partialSignatures.map(\.raw)
        var s = session.raw
        var out = [UInt8](repeating: 0, count: 64)
        let ok = structs.withUnsafeMutableBufferPointer { buf -> Int32 in
            let ptrs: [UnsafePointer<secp256k1_musig_partial_sig>?] =
                unsafe (0..<buf.count).map { unsafe UnsafePointer(buf.baseAddress! + $0) }
            return ptrs.withUnsafeBufferPointer { pp in
                out.withUnsafeMutableBufferPointer { o in
                    unsafe raw.musigPartialSigAgg(sig64: o.baseAddress!, session: &s,
                                                  partialSigs: pp.baseAddress!,
                                                  nSigs: buf.count)
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return out
    }
}
