import CSECP256K1

// MARK: - Key pairs

/// A BIP340 key pair: a secret key together with its cached public key.
///
/// Wraps the opaque 96-byte C struct. Not serialisable as bytes -- use
/// `Secp256k1Context.secretKeyBytes(of:)` to extract the secret scalar.
public struct KeyPair: Sendable {
    @usableFromInline var raw: Keypair

    @usableFromInline init(raw: Keypair) { self.raw = raw }
}

/// An x-only public key: the 32-byte x coordinate, with the y parity dropped.
///
/// This is the public key form BIP340 signs under. Two different full public
/// keys share an x-only key, which is why `xOnlyPublicKey(of:)` also reports
/// the parity needed to reconstruct the original.
public struct XOnlyPublicKey: Sendable {
    @usableFromInline var raw: secp256k1_xonly_pubkey

    @usableFromInline init(raw: secp256k1_xonly_pubkey) { self.raw = raw }
}

extension Context {
    /// Derives a BIP340 key pair from a 32-byte secret key.
    public func keyPair(secretKey: Span<UInt8>) throws -> KeyPair {
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        var kp = CollectionOfOne(Keypair())
        var kpSpan = kp.mutableSpan
        let ok = raw.keypairCreate(keypair: &kpSpan, seckey: secretKey)
        guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        return KeyPair(raw: kp[0])
    }

    /// The full (parity-carrying) public key of a key pair.
    public func publicKey(of keyPair: KeyPair) throws -> PublicKey {
        let kp = CollectionOfOne(keyPair.raw)
        var pub = CollectionOfOne(Pubkey())
        var pubSpan = pub.mutableSpan
        let ok = raw.keypairPub(pubkey: &pubSpan, keypair: kp.span)
        guard ok == 1 else { throw Secp256k1Error.invalidKeyPair }
        return PublicKey(raw: pub[0])
    }

    /// The 32-byte secret scalar held by a key pair.
    public func secretKeyBytes(of keyPair: KeyPair) throws -> [UInt8] {
        let kp = CollectionOfOne(keyPair.raw)
        var out = [UInt8](repeating: 0, count: 32)
        var outSpan = out.mutableSpan
        let ok = raw.keypairSec(seckey: &outSpan, keypair: kp.span)
        guard ok == 1 else { throw Secp256k1Error.invalidKeyPair }
        return out
    }

    /// The x-only public key of a key pair, with the parity bit needed to
    /// recover the full key.
    ///
    /// `parity` is 0 or 1. libsecp256k1 takes it as a nullable out-parameter;
    /// here it is always requested, since discarding it loses information.
    public func xOnlyPublicKey(of keyPair: KeyPair) throws -> (key: XOnlyPublicKey, parity: Int32) {
        let kp = CollectionOfOne(keyPair.raw)
        var xonly = CollectionOfOne(secp256k1_xonly_pubkey())
        var xonlySpan = xonly.mutableSpan
        var parity = CollectionOfOne(Int32(0))
        var paritySpan: MutableSpan<Int32>? = parity.mutableSpan
        let ok = raw.keypairXOnlyPub(pubkey: &xonlySpan, pkParity: &paritySpan, keypair: kp.span)
        guard ok == 1 else { throw Secp256k1Error.invalidKeyPair }
        return (XOnlyPublicKey(raw: xonly[0]), parity[0])
    }
}

// MARK: - X-only public keys

extension Context {
    /// Parses a 32-byte x-only public key.
    public func xOnlyPublicKey(parsing input32: Span<UInt8>) throws -> XOnlyPublicKey {
        guard input32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: input32.count)
        }
        var xonly = secp256k1_xonly_pubkey()
        let ok = unsafe raw.xonlyPubkeyParse(pubkey: &xonly, input32: input32)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return XOnlyPublicKey(raw: xonly)
    }

    /// Serialises an x-only public key to its 32-byte x coordinate.
    public func serializedBytes(of key: XOnlyPublicKey) -> [UInt8] {
        var k = key.raw
        var out = [UInt8](repeating: 0, count: 32)
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.xonlyPubkeySerialize(output32: buf.baseAddress!, pubkey: &k)
        }
        return out
    }
}

// MARK: - BIP340 Schnorr signatures

extension Context {
    /// Signs a 32-byte message with BIP340 Schnorr, returning 64 bytes.
    ///
    /// `auxiliaryRandom` must be 32 bytes. BIP340 makes it optional but
    /// recommends supplying fresh randomness per signature as a defence against
    /// fault and side-channel attacks, so it is required here rather than
    /// silently defaulted -- pass a fixed value only when determinism is what
    /// you actually want, as the tests do.
    public func signSchnorr(
        message32: Span<UInt8>,
        keyPair: KeyPair,
        auxiliaryRandom: Span<UInt8>
    ) throws -> [UInt8] {
        guard message32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: message32.count)
        }
        guard auxiliaryRandom.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: auxiliaryRandom.count)
        }
        var kp = keyPair.raw
        let sig = try [UInt8](capacity: 64) { outputSpan in
            outputSpan.append(repeating: 0, count: outputSpan.freeCapacity)
            var mutableSpan = outputSpan.mutableSpan

            // @_lifetime(sig64: copy sig64)
            // public final func schnorrsigSign32(sig64: inout MutableSpan<UInt8>, msg32: Span<UInt8>, keypair: UnsafePointer<secp256k1_keypair>, auxRand32 aux_rand32: Span<UInt8>) -> Int32

            let ok = unsafe raw.schnorrsigSign32(
                sig64: &mutableSpan,
                msg32: message32,
                keypair: &kp,
                auxRand32: auxiliaryRandom
            )
            guard ok == 1 else { throw Secp256k1Error.signingFailed }
        }
        return sig
    }

    /// Verifies a 64-byte BIP340 signature.
    ///
    /// Unlike signing, verification accepts a message of any length -- the
    /// annotated overload takes a `Span` bounded by the length parameter rather
    /// than a fixed 32.
    public func isValidSchnorr(
        _ signature64: Span<UInt8>,
        message: Span<UInt8>,
        publicKey: XOnlyPublicKey
    ) -> Bool {
        guard signature64.count == 64 else { return false }
        var key = publicKey.raw
        return unsafe raw.schnorrsigVerify(sig64: signature64, msg: message, pubkey: &key) == 1
    }
}
