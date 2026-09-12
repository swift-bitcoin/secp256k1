import CSECP256K1

/// How to serialise a public key.
public enum PublicKeyFormat: Sendable {
    /// 33 bytes: a parity byte followed by the x coordinate. What Bitcoin uses.
    case compressed
    /// 65 bytes: `0x04` followed by both coordinates.
    case uncompressed

    @usableFromInline var flags: UInt32 {
        switch self {
        case .compressed: UInt32(SECP256K1_EC_COMPRESSED)
        case .uncompressed: UInt32(SECP256K1_EC_UNCOMPRESSED)
        }
    }

    @usableFromInline var byteCount: Int {
        switch self {
        case .compressed: 33
        case .uncompressed: 65
        }
    }
}

// MARK: - Public keys

extension Context {
    /// Serialises a public key.
    ///
    /// `secp256k1_ec_pubkey_serialize` takes its length as an in/out pointer:
    /// the caller sets it to the buffer size and the callee overwrites it with
    /// the bytes written. That is one of the four buffers the API notes
    /// generator deliberately leaves unbounded -- `BoundedBy` cannot reference
    /// `*outputlen` -- so this is a pointer call, and the wrapper owns the
    /// size contract.
    public func serializedBytes(
        of publicKey: PublicKey,
        format: PublicKeyFormat = .compressed
    ) -> [UInt8] {
        let key = CollectionOfOne(publicKey.raw)
        let initialLength = PublicKeyFormat.uncompressed.byteCount // Maximum size
        var out = [UInt8](repeating: 0, count: initialLength)
        var outSpan = out.mutableSpan
        var length = CollectionOfOne(initialLength)
        var lengthSpan = length.mutableSpan
        let ok = raw.ecPubkeySerialize(output: &outSpan, outputlen: &lengthSpan,
                              pubkey: key.span, flags: format.flags)
        precondition(ok == 1)
        // The C function always writes exactly the format's length for a valid
        // key, but trust its report rather than the assumption.
        return Array(out.prefix(length[0]))
    }

    /// Drops the parity bit, giving the x-only key and the parity needed to
    /// reconstruct the original.
    public func xOnlyPublicKey(of publicKey: PublicKey) throws -> (key: XOnlyPublicKey, parity: Int32) {
        var key = publicKey.raw
        var xonly = secp256k1_xonly_pubkey()
        var parity: Int32 = 0
        let ok = unsafe raw.xonlyPubkeyFromPubkey(xonlyPubkey: &xonly, pkParity: &parity,
                                                  pubkey: &key)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return (XOnlyPublicKey(raw: xonly), parity)
    }
}

// MARK: - ECDSA signatures, DER

extension Context {
    /// The maximum size of a DER-encoded secp256k1 ECDSA signature.
    public static let maximumDERSignatureSize = 72

    /// Serialises a signature as DER.
    ///
    /// DER is variable-length, so unlike the 64-byte compact form the result's
    /// count is meaningful. Returns `nil` only if the buffer was too small,
    /// which cannot happen at `maximumDERSignatureSize`.
    public func derBytes(of signature: Signature) -> [UInt8] {
        let sig = CollectionOfOne(signature.raw)
        let initialLength = Self.maximumDERSignatureSize
        var out = [UInt8](repeating: 0, count: initialLength)
        var outSpan = out.mutableSpan
        var length = CollectionOfOne(initialLength)
        var lengthSpan = length.mutableSpan
        let ok = raw.ecdsaSignatureSerializeDER(output: &outSpan, outputlen: &lengthSpan, sig: sig.span)
        precondition(ok == 1, "72 bytes is the documented maximum; serialisation cannot overflow it")
        return Array(out.prefix(length[0]))
    }

    /// Parses a DER-encoded signature.
    ///
    /// Strict: libsecp256k1 rejects the various non-canonical encodings that
    /// historically appeared on the Bitcoin network. `contrib/lax_der_parsing.c`
    /// exists upstream for those, and is not wrapped here.
    public func signature(parsingDER input: Span<UInt8>) throws -> Signature {
        var sig = CollectionOfOne(ECDSASignature())
        var sigSpan = sig.mutableSpan
        let ok = raw.ecdsaSignatureParseDER(sig: &sigSpan, input: input)
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return Signature(raw: sig[0])
    }
}

// MARK: - MuSig wire formats
//
// These are what make MuSig usable across a network rather than only in a
// single process: nonces and partial signatures have to be exchanged between
// signers.

extension Context {
    /// Serialises a public nonce to 66 bytes.
    public func serializedBytes(of nonce: MuSigPublicNonce) -> [UInt8] {
        var n = nonce.raw
        var out = [UInt8](repeating: 0, count: 66)
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.musigPubnonceSerialize(out66: buf.baseAddress!, nonce: &n)
        }
        return out
    }

    /// Parses a 66-byte public nonce received from another signer.
    public func muSigPublicNonce(parsing in66: Span<UInt8>) throws -> MuSigPublicNonce {
        guard in66.count == 66 else {
            throw Secp256k1Error.wrongLength(expected: 66, actual: in66.count)
        }
        var n = secp256k1_musig_pubnonce()
        let ok = in66.withUnsafeBufferPointer { buf in
            unsafe raw.musigPubnonceParse(nonce: &n, in66: buf.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidNonce }
        return MuSigPublicNonce(raw: n)
    }

    /// Serialises an aggregate nonce to 66 bytes.
    public func serializedBytes(of nonce: MuSigAggregateNonce) -> [UInt8] {
        var n = nonce.raw
        var out = [UInt8](repeating: 0, count: 66)
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.musigAggnonceSerialize(out66: buf.baseAddress!, nonce: &n)
        }
        return out
    }

    /// Parses a 66-byte aggregate nonce.
    public func muSigAggregateNonce(parsing in66: Span<UInt8>) throws -> MuSigAggregateNonce {
        guard in66.count == 66 else {
            throw Secp256k1Error.wrongLength(expected: 66, actual: in66.count)
        }
        var n = secp256k1_musig_aggnonce()
        let ok = in66.withUnsafeBufferPointer { buf in
            unsafe raw.musigAggnonceParse(nonce: &n, in66: buf.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidNonce }
        return MuSigAggregateNonce(raw: n)
    }

    /// Serialises a partial signature to 32 bytes.
    public func serializedBytes(of signature: MuSigPartialSignature) -> [UInt8] {
        var s = signature.raw
        var out = [UInt8](repeating: 0, count: 32)
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.musigPartialSigSerialize(out32: buf.baseAddress!, sig: &s)
        }
        return out
    }

    /// Parses a 32-byte partial signature received from another signer.
    public func muSigPartialSignature(parsing in32: Span<UInt8>) throws -> MuSigPartialSignature {
        guard in32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: in32.count)
        }
        var s = secp256k1_musig_partial_sig()
        let ok = in32.withUnsafeBufferPointer { buf in
            unsafe raw.musigPartialSigParse(sig: &s, in32: buf.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return MuSigPartialSignature(raw: s)
    }
}
