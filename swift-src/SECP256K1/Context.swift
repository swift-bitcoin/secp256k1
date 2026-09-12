import CSECP256K1

/// Errors surfaced by the wrapper. libsecp256k1 signals failure with a 0/1
/// return code and never allocates or throws, so these map return codes onto
/// something Swift callers can `try`.
public enum Secp256k1Error: Error, Equatable {
    case contextCreationFailed
    case invalidSecretKey
    case invalidPublicKey
    case invalidSignature
    case signingFailed
    case invalidKeyPair
    case invalidNonce
    case nonceGenerationFailed
    /// ECDH agreement failed, which means the public key or secret key was
    /// invalid rather than that the hash function misbehaved.
    case keyAgreementFailed
    /// A fixed-width buffer was the wrong length. The C API takes bare
    /// pointers with the size baked into the parameter name (`msghash32`,
    /// `input64`), so length is checked here rather than by the type system.
    case wrongLength(expected: Int, actual: Int)
}

/// Owns a `SECP256K1Context`.
///
/// API notes import the context as a Swift *class* (`SwiftImportAs: reference`
/// on the `secp256k1_context_struct` tag) rather than the `OpaquePointer` it
/// would otherwise be. A class reference is not an unsafe type, so no `@unsafe`
/// storage or compensating `@safe` on this class is needed.
///
/// What the reference type does NOT give us is lifetime management. Retain and
/// release are both declared `immortal`, because a retain operation has to
/// return the pointer it was given and `secp256k1_context_clone` allocates a
/// new context instead -- there is no function in this API that can serve as
/// one. So the reference is unmanaged and destruction stays explicit, which is
/// what this class exists for.
public struct Context: ~Copyable {
    let raw: SECP256K1Context

    /// Creates a context usable for both signing and verification.
    public init() throws {
        guard let ctx = SECP256K1Context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            throw Secp256k1Error.contextCreationFailed
        }
        self.raw = ctx
    }

    deinit { raw.destroy() }
}

// MARK: - Secret keys

extension Context {
    /// Whether `secretKey` is a valid 32-byte scalar.
    ///
    /// Takes a `Span` -- the safe overload synthesised from this package's
    /// API notes, not the raw pointer version.
    public func isValidSecretKey(_ secretKey: Span<UInt8>) -> Bool {
        guard secretKey.count == 32 else { return false }
        return raw.ecSeckeyVerify(secretKey) == 1
    }
}

// MARK: - Public keys

/// A parsed public key. Wraps the opaque 64-byte C struct, which is *not* a
/// serialised key and must not be treated as bytes.
public struct PublicKey: Sendable {
    @usableFromInline var raw: Pubkey

    @usableFromInline init(raw: Pubkey) { self.raw = raw }
}

extension Context {
    /// Derives the public key for a 32-byte secret key.
    public func publicKey(secretKey: Span<UInt8>) throws -> PublicKey {
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        let pubkeys = try [Pubkey](capacity: 1) { outputSpan in
            outputSpan.append(Pubkey())
            var mutableSpan = outputSpan.mutableSpan
            let ok = raw.ecPubkeyCreate(&mutableSpan, secretKey: secretKey)
            guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        }
        return PublicKey(raw: pubkeys[0])
    }

    /// Parses a 33-byte compressed or 65-byte uncompressed public key.
    public func publicKey(parsing input: Span<UInt8>) throws -> PublicKey {
        var pubkey = CollectionOfOne(Pubkey())
        var pubkeySpan = pubkey.mutableSpan
        let ok = raw.ecPubkeyParse(&pubkeySpan, from: input)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: pubkey[0])
    }
}

// MARK: - ECDSA

/// A parsed ECDSA signature in libsecp256k1's internal form.
public struct Signature: Sendable {
    @usableFromInline var raw: ECDSASignature

    @usableFromInline init(raw: ECDSASignature) { self.raw = raw }
}

extension Context {
    /// Signs a 32-byte message hash with RFC6979 deterministic nonces.
    ///
    /// `nil` selects libsecp256k1's default nonce function, per
    /// include/secp256k1.h:431. It type-checks because the API notes state
    /// `Nullability: O` for this parameter: importing the context as a
    /// reference type and renaming into method form together drop
    /// `_Null_unspecified` from function-pointer parameters, and the explicit
    /// annotation restores it -- as a true Optional rather than the implicitly
    /// unwrapped one it started as.
    public func sign(messageHash: Span<UInt8>, secretKey: Span<UInt8>) throws -> Signature {
        guard messageHash.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: messageHash.count)
        }
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        var sig = CollectionOfOne(ECDSASignature())
        var sigSpan = sig.mutableSpan
        let ok = unsafe raw.ecdsaSign(&sigSpan, messageHash: messageHash, secretKey: secretKey,
                                 nonceFunction: nil, nonceData: nil)
        guard ok == 1 else { throw Secp256k1Error.signingFailed }
        return Signature(raw: sig[0])
    }

    /// Verifies a signature against a 32-byte message hash.
    ///
    /// Note this enforces libsecp256k1's low-S rule: signatures with a high S
    /// value are rejected even if mathematically valid.
    public func isValid(_ signature: Signature, messageHash: Span<UInt8>, publicKey: PublicKey) -> Bool {
        guard messageHash.count == 32 else { return false }
        let sig = signature.raw
        let pub = publicKey.raw
        return raw.ecdsaVerify(CollectionOfOne(sig).span, messageHash: messageHash, publicKey: CollectionOfOne(pub).span) == 1
    }

    /// Parses a 64-byte compact signature.
    public func signature(parsingCompact input: Span<UInt8>) throws -> Signature {
        guard input.count == 64 else {
            throw Secp256k1Error.wrongLength(expected: 64, actual: input.count)
        }
        var sig = CollectionOfOne(ECDSASignature())
        var sigSpan = sig.mutableSpan
        let ok = raw.ecdsaSignatureParseCompact(&sigSpan, compact: input)
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return Signature(raw: sig[0])
    }

    /// Serialises a signature to 64 compact bytes.
    public func compactBytes(of signature: Signature) -> [UInt8] {
        let sig = signature.raw

        var out = Array(repeating: UInt8(), count: 64)
        var mutableSpan = out.mutableSpan
        _ = raw.ecdsaSignatureSerializeCompact(into: &mutableSpan, CollectionOfOne(sig).span)

//        let out = [UInt8](capacity: 64) { outputSpan in
//            outputSpan.append(repeating: 0, count: outputSpan.freeCapacity)
//            var mutableSpan = outputSpan.mutableSpan
//            _ = raw.ecdsaSignatureSerializeCompact(into: &mutableSpan, CollectionOfOne(sig).span)
//        }
        return out // Argument type 'UniqueArray<UInt8>' expected to be an instance of a class or class-constrained type
    }
}
