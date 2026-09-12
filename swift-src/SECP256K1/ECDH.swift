import CSECP256K1

/// Which hash `ecdh` applies to the shared point.
public enum ECDHHash: Sendable {
    /// libsecp256k1's default: SHA256 of the compressed shared point. 32 bytes.
    case defaultSHA256
    /// The raw x coordinate of the shared point, unhashed. 32 bytes.
    ///
    /// This is what the SEC1/X9.63 "ECDH primitive" specifies, and what test
    /// vector suites such as Wycheproof report as the shared secret. Most
    /// protocols should hash it -- prefer `defaultSHA256` unless a
    /// specification says otherwise.
    case rawXCoordinate
}

/// The `.rawXCoordinate` implementation: copy `x32` through and report success.
///
/// A plain C function pointer with no captured state, so no trampoline box is
/// needed -- unlike silent payments' label lookup.
private let rawXCoordinateHash: ECDHHashFunction = unsafe .init({ output, x32, _, _ in
    guard let output = unsafe output, let x32 = unsafe x32 else { return 0 }
    unsafe output.update(from: x32, count: 32)
    return 1
})

extension Context {
    /// Computes an ECDH shared secret, hashed with libsecp256k1's default
    /// (SHA256 of the compressed point), giving 32 bytes.
    ///
    /// The output buffer is one of the four the API notes generator
    /// deliberately leaves unannotated: `secp256k1_ecdh`'s output length is
    /// whatever the caller's `hashfp` produces, and is 32 only for the default
    /// hash. Claiming `BoundedBy: 32` would be a lie for any custom hash, so
    /// this wrapper pins the default hash (`hashfp: nil`) and owns the 32-byte
    /// contract itself.
    public func sharedSecret(
        publicKey: PublicKey,
        secretKey: Span<UInt8>,
        hash: ECDHHash = .defaultSHA256
    ) throws -> [UInt8] {
        guard secretKey.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: secretKey.count)
        }
        var pub = publicKey.raw
        var out = [UInt8](repeating: 0, count: 32)
        let ok = out.withUnsafeMutableBufferPointer { buf in
            unsafe raw.ecdh(output: buf.baseAddress!, pubkey: &pub, seckey: secretKey,
                            hashfp: hash == .rawXCoordinate ? rawXCoordinateHash : nil,
                            data: nil)
        }
        guard ok == 1 else { throw Secp256k1Error.keyAgreementFailed }
        return out
    }
}
