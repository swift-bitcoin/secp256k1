import CSECP256K1

/// Which side of an ElligatorSwift key exchange we are.
///
/// `ellswift_xdh` takes both parties' encoded keys in fixed A/B positions plus a
/// flag saying which one we hold the secret for; upstream notes the
/// correspondence "is not checked", so getting this wrong yields a silently
/// wrong shared secret rather than an error.
public enum EllSwiftParty: Sendable {
    case a, b

    @usableFromInline var rawValue: Int32 { self == .a ? 0 : 1 }
}

/// Hash function for `ellswift_xdh`. Not optional: upstream requires one.
///
/// The associated value on `.prefix` is not decoration. That hash computes
/// `SHA256(prefix64 || ell_a64 || ell_b64 || x32)` where `prefix64` is read
/// **through the C `data` pointer**, so selecting it without supplying 64 bytes
/// dereferences NULL and crashes. Carrying the bytes in the case makes that
/// impossible to get wrong -- an earlier version of this enum had a bare
/// `.prefix` case and segfaulted in the test suite.
public enum EllSwiftXDHHash: Sendable {
    /// BIP324's hash: `H_tag(ell_a64 || ell_b64 || x32)` with tag
    /// "bip324_ellswift_xonly_ecdh". Ignores `data`.
    case bip324
    /// `SHA256(prefix64 || ell_a64 || ell_b64 || x32)`. The prefix must be
    /// exactly 64 bytes.
    case prefix([UInt8])
}

extension Context {
    /// Encodes a public key as 64 uniformly-random-looking bytes.
    ///
    /// `randomness32` decides which of the many valid encodings is produced,
    /// so the same key encodes differently each time.
    public func ellswiftEncodedBytes(
        of publicKey: PublicKey,
        randomness32: Span<UInt8>
    ) throws -> [UInt8] {
        guard randomness32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: randomness32.count)
        }
        var pub = publicKey.raw
        var out = [UInt8](repeating: 0, count: 64)
        let ok = out.withUnsafeMutableBufferPointer { buf in
            randomness32.withUnsafeBufferPointer { rnd in
                unsafe raw.ellswiftEncode(ell64: buf.baseAddress!, pubkey: &pub,
                                          rnd32: rnd.baseAddress!)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return out
    }

    /// Decodes a 64-byte ElligatorSwift encoding back to a public key.
    ///
    /// Every 64-byte string decodes to some valid public key, so this does not
    /// fail on arbitrary input.
    public func publicKey(ellswift ell64: Span<UInt8>) throws -> PublicKey {
        guard ell64.count == 64 else {
            throw Secp256k1Error.wrongLength(expected: 64, actual: ell64.count)
        }
        var pub = Pubkey()
        let ok = unsafe raw.ellswiftDecode(pubkey: &pub, ell64: ell64)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: pub)
    }

    /// Creates an ElligatorSwift encoding directly from a secret key, without
    /// materialising the public key first.
    public func ellswiftCreate(
        secretKey32: Span<UInt8>,
        auxiliaryRandom32: Span<UInt8>
    ) throws -> [UInt8] {
        guard secretKey32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey32.count)
        }
        guard auxiliaryRandom32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: auxiliaryRandom32.count)
        }
        var out = [UInt8](repeating: 0, count: 64)
        let ok = out.withUnsafeMutableBufferPointer { buf in
            secretKey32.withUnsafeBufferPointer { sk in
                auxiliaryRandom32.withUnsafeBufferPointer { aux in
                    unsafe raw.ellswiftCreate(ell64: buf.baseAddress!,
                                              seckey32: sk.baseAddress!,
                                              auxrnd32: aux.baseAddress!)
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        return out
    }

    /// ElligatorSwift Diffie-Hellman: derives a 32-byte shared secret from both
    /// parties' encodings and our secret key.
    ///
    /// `partyA` and `partyB` must be in that order regardless of which side we
    /// are; `weAre` says which secret key we hold.
    public func ellswiftXDH(
        partyA ellA64: Span<UInt8>,
        partyB ellB64: Span<UInt8>,
        ourSecretKey secretKey32: Span<UInt8>,
        weAre party: EllSwiftParty,
        hash: EllSwiftXDHHash = .bip324
    ) throws -> [UInt8] {
        guard ellA64.count == 64 else {
            throw Secp256k1Error.wrongLength(expected: 64, actual: ellA64.count)
        }
        guard ellB64.count == 64 else {
            throw Secp256k1Error.wrongLength(expected: 64, actual: ellB64.count)
        }
        guard secretKey32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey32.count)
        }
        // Both hashes produce 32 bytes (each is a single SHA256), which is why
        // this buffer is fixed at 32. That length is a property of the hash, not
        // of the C function -- `secp256k1_ellswift_xdh`'s output length is
        // whatever `hashfp` writes, which is exactly why the API notes
        // generator refuses to put a bound on that parameter.
        var out = [UInt8](repeating: 0, count: 32)
        let ok: Int32
        switch hash {
        case .bip324:
            ok = out.withUnsafeMutableBufferPointer { buf in
                unsafe raw.ellswiftXDH(output: buf.baseAddress!,
                                       ellA64: ellA64, ellB64: ellB64,
                                       seckey32: secretKey32,
                                       party: party.rawValue,
                                       hashfp: EllSwiftHashFunction.bip324,
                                       data: nil)
            }
        case .prefix(let prefix64):
            guard prefix64.count == 64 else {
                throw Secp256k1Error.wrongLength(expected: 64, actual: prefix64.count)
            }
            var prefix = prefix64
            ok = out.withUnsafeMutableBufferPointer { buf in
                prefix.withUnsafeMutableBufferPointer { pfx in
                    unsafe raw.ellswiftXDH(output: buf.baseAddress!,
                                           ellA64: ellA64, ellB64: ellB64,
                                           seckey32: secretKey32,
                                           party: party.rawValue,
                                           hashfp: EllSwiftHashFunction.prefix,
                                           data: UnsafeMutableRawPointer(pfx.baseAddress!))
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.keyAgreementFailed }
        return out
    }
}
