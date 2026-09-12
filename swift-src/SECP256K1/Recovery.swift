import CSECP256K1

/// An ECDSA signature carrying the recovery id needed to recompute the signer's
/// public key from the signature and message alone.
///
/// Bitcoin uses this for message signing, where transmitting the public key
/// would be redundant.
public struct RecoverableSignature: Sendable {
    @usableFromInline var raw: secp256k1_ecdsa_recoverable_signature

    @usableFromInline init(raw: secp256k1_ecdsa_recoverable_signature) { self.raw = raw }
}

extension Context {
    /// Signs a 32-byte message hash, producing a recoverable signature.
    public func signRecoverable(
        messageHash: Span<UInt8>,
        secretKey: Span<UInt8>
    ) throws -> RecoverableSignature {
        guard messageHash.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: messageHash.count)
        }
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        var sig = secp256k1_ecdsa_recoverable_signature()
        let ok = unsafe raw.ecdsaSignRecoverable(sig: &sig, msghash32: messageHash,
                                                 seckey: secretKey,
                                                 noncefp: nil, ndata: nil)
        guard ok == 1 else { throw Secp256k1Error.signingFailed }
        return RecoverableSignature(raw: sig)
    }

    /// Recovers the signer's public key from a recoverable signature.
    ///
    /// This is the point of the type: verification normally needs the public
    /// key as an input, whereas here it is an output.
    public func recoverPublicKey(
        from signature: RecoverableSignature,
        messageHash: Span<UInt8>
    ) throws -> PublicKey {
        guard messageHash.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: messageHash.count)
        }
        var sig = signature.raw
        var pub = Pubkey()
        let ok = unsafe raw.ecdsaRecover(pubkey: &pub, sig: &sig, msghash32: messageHash)
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return PublicKey(raw: pub)
    }

    /// Serialises to 64 compact bytes plus the recovery id (0...3).
    public func compactBytes(
        of signature: RecoverableSignature
    ) -> (signature: [UInt8], recoveryID: Int32) {
        var sig = signature.raw
        var out = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.ecdsaRecoverableSignatureSerializeCompact(
                output64: buf.baseAddress!, recid: &recid, sig: &sig)
        }
        return (out, recid)
    }

    /// Parses 64 compact bytes plus a recovery id.
    public func recoverableSignature(
        compact input64: Span<UInt8>,
        recoveryID: Int32
    ) throws -> RecoverableSignature {
        guard input64.count == 64 else {
            throw Secp256k1Error.wrongLength(expected: 64, actual: input64.count)
        }
        guard (0...3).contains(recoveryID) else { throw Secp256k1Error.invalidSignature }
        var sig = secp256k1_ecdsa_recoverable_signature()
        let ok = unsafe raw.ecdsaRecoverableSignatureParseCompact(
            sig: &sig, input64: input64, recid: recoveryID)
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return RecoverableSignature(raw: sig)
    }

    /// Discards the recovery id, giving a plain ECDSA signature.
    public func signature(from signature: RecoverableSignature) throws -> Signature {
        var sigin = signature.raw
        var out = ECDSASignature()
        let ok = unsafe raw.ecdsaRecoverableSignatureConvert(sig: &out, sigin: &sigin)
        guard ok == 1 else { throw Secp256k1Error.invalidSignature }
        return Signature(raw: out)
    }
}
