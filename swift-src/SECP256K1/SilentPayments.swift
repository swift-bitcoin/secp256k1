import CSECP256K1

// MARK: - Types

/// A silent-payments recipient address: the scan and spend public keys, plus
/// the index this recipient occupied in the caller's original list.
///
/// `index` matters because `senderCreateOutputs` sorts recipients internally
/// (BIP352 groups outputs per scan key), so it needs to know where each
/// generated output belongs in the caller's ordering. This wrapper fills it in
/// automatically, so callers never set it by hand.
public struct SilentPaymentRecipient: Sendable {
    public var scanPublicKey: PublicKey
    public var spendPublicKey: PublicKey

    public init(scanPublicKey: PublicKey, spendPublicKey: PublicKey) {
        self.scanPublicKey = scanPublicKey
        self.spendPublicKey = spendPublicKey
    }

    @usableFromInline func raw(index: Int) -> secp256k1_silentpayments_recipient {
        var r = secp256k1_silentpayments_recipient()
        r.scan_pubkey = scanPublicKey.raw
        r.spend_pubkey = spendPublicKey.raw
        r.index = index
        return r
    }
}

/// A recipient label, letting one silent-payments address be subdivided.
///
/// Serialises to 33 bytes.
public struct SilentPaymentLabel: Sendable {
    @usableFromInline var raw: secp256k1_silentpayments_label
    @usableFromInline init(raw: secp256k1_silentpayments_label) { self.raw = raw }
}

/// Summary of a transaction's prevouts: the smallest outpoint plus the sum of
/// the input public keys. Both sender and recipient derive the same value.
public struct SilentPaymentPrevoutsSummary: Sendable {
    @usableFromInline var raw: secp256k1_silentpayments_prevouts_summary
    @usableFromInline init(raw: secp256k1_silentpayments_prevouts_summary) { self.raw = raw }
}

/// An output found by scanning, with the tweak needed to spend it.
public struct SilentPaymentFoundOutput: Sendable {
    /// The x-only output key that belongs to us.
    public let output: XOnlyPublicKey
    /// 32-byte tweak: add this to the spend secret key to get the output's key.
    public let tweak: [UInt8]
    /// The label this output was found under, or `nil` if it matched the
    /// unlabeled spend key.
    public let label: SilentPaymentLabel?
}

// MARK: - Labels

extension Context {
    /// Creates label `m` for a scan key.
    ///
    /// Returns both the label (for deriving the labeled spend key) and its
    /// 32-byte tweak, which the recipient must keep in order to spend outputs
    /// found under this label. `m == 0` is reserved for change.
    public func silentPaymentLabel(
        scanKey32: Span<UInt8>,
        m: UInt32
    ) throws -> (label: SilentPaymentLabel, tweak32: [UInt8]) {
        guard scanKey32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: scanKey32.count)
        }
        var label = secp256k1_silentpayments_label()
        var tweak = [UInt8](repeating: 0, count: 32)
        let ok = tweak.withUnsafeMutableBufferPointer { tw in
            scanKey32.withUnsafeBufferPointer { sk in
                unsafe raw.silentpaymentsRecipientLabelCreate(
                    label: &label, labelTweak32: tw.baseAddress!,
                    scanKey32: sk.baseAddress!, m: m)
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidSecretKey }
        return (SilentPaymentLabel(raw: label), tweak)
    }

    /// Serialises a label to 33 bytes.
    public func serializedBytes(of label: SilentPaymentLabel) -> [UInt8] {
        var l = label.raw
        var out = [UInt8](repeating: 0, count: 33)
        out.withUnsafeMutableBufferPointer { buf in
            _ = unsafe raw.silentpaymentsRecipientLabelSerialize(
                out33: buf.baseAddress!, label: &l)
        }
        return out
    }

    /// Parses a 33-byte serialised label.
    public func silentPaymentLabel(parsing in33: Span<UInt8>) throws -> SilentPaymentLabel {
        guard in33.count == 33 else {
            throw Secp256k1Error.wrongLength(expected: 33, actual: in33.count)
        }
        var label = secp256k1_silentpayments_label()
        let ok = in33.withUnsafeBufferPointer { buf in
            unsafe raw.silentpaymentsRecipientLabelParse(label: &label, in33: buf.baseAddress!)
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return SilentPaymentLabel(raw: label)
    }

    /// The spend public key to publish for a given label.
    public func labeledSpendPublicKey(
        unlabeledSpendPublicKey: PublicKey,
        label: SilentPaymentLabel
    ) throws -> PublicKey {
        var unlabeled = unlabeledSpendPublicKey.raw
        var l = label.raw
        var out = Pubkey()
        let ok = unsafe raw.silentpaymentsRecipientCreateLabeledSpendPubkey(
            labeledSpendPubkey: &out, unlabeledSpendPubkey: &unlabeled, label: &l)
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return PublicKey(raw: out)
    }
}

// MARK: - Prevouts summary

extension Context {
    /// Summarises a transaction's inputs.
    ///
    /// Pass the x-only keys of taproot inputs and the full keys of everything
    /// else; at least one of the two must be non-empty.
    public func silentPaymentPrevoutsSummary(
        smallestOutpoint36: Span<UInt8>,
        xOnlyPublicKeys: [XOnlyPublicKey] = [],
        publicKeys: [PublicKey] = []
    ) throws -> SilentPaymentPrevoutsSummary {
        guard smallestOutpoint36.count == 36 else {
            throw Secp256k1Error.wrongLength(expected: 36, actual: smallestOutpoint36.count)
        }
        guard !xOnlyPublicKeys.isEmpty || !publicKeys.isEmpty else {
            throw Secp256k1Error.invalidPublicKey
        }
        var xonlyStructs = xOnlyPublicKeys.map(\.raw)
        var plainStructs = publicKeys.map(\.raw)
        var summary = secp256k1_silentpayments_prevouts_summary()

        let ok = xonlyStructs.withUnsafeMutableBufferPointer { xb -> Int32 in
            plainStructs.withUnsafeMutableBufferPointer { pb -> Int32 in
                let xptrs: [UnsafePointer<secp256k1_xonly_pubkey>?] =
                    unsafe (0..<xb.count).map { unsafe UnsafePointer(xb.baseAddress! + $0) }
                let pptrs: [UnsafePointer<Pubkey>?] =
                    unsafe (0..<pb.count).map { unsafe UnsafePointer(pb.baseAddress! + $0) }
                return xptrs.withUnsafeBufferPointer { xp in
                    pptrs.withUnsafeBufferPointer { pp in
                        smallestOutpoint36.withUnsafeBufferPointer { op in
                            unsafe raw.silentpaymentsRecipientPrevoutsSummaryCreate(
                                prevoutsSummary: &summary,
                                outpointSmallest36: op.baseAddress!,
                                xonlyPubkeys: xb.isEmpty ? nil : xp.baseAddress,
                                nXOnlyPubkeys: xb.count,
                                pubkeys: pb.isEmpty ? nil : pp.baseAddress,
                                nPubkeys: pb.count)
                        }
                    }
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return SilentPaymentPrevoutsSummary(raw: summary)
    }
}

// MARK: - Sender

extension Context {
    /// Generates one x-only output key per recipient.
    ///
    /// Results come back in the caller's recipient order. libsecp256k1 sorts
    /// recipients internally to group outputs per scan key, which is why each
    /// recipient carries an index; this wrapper assigns those and unpicks the
    /// ordering afterwards so callers never see it.
    ///
    /// Supply the input keys being spent: `keyPairs` for taproot inputs and
    /// `secretKeys` for plain ones. At least one must be non-empty.
    public func silentPaymentOutputs(
        recipients: [SilentPaymentRecipient],
        smallestOutpoint36: Span<UInt8>,
        keyPairs: [KeyPair] = [],
        secretKeys: [[UInt8]] = []
    ) throws -> [XOnlyPublicKey] {
        guard !recipients.isEmpty else { throw Secp256k1Error.invalidPublicKey }
        guard smallestOutpoint36.count == 36 else {
            throw Secp256k1Error.wrongLength(expected: 36, actual: smallestOutpoint36.count)
        }
        guard !keyPairs.isEmpty || !secretKeys.isEmpty else {
            throw Secp256k1Error.invalidSecretKey
        }
        for key in secretKeys where key.count != 32 {
            throw Secp256k1Error.wrongLength(expected: 32, actual: key.count)
        }

        var recipientStructs = recipients.enumerated().map { $0.element.raw(index: $0.offset) }
        var keypairStructs = keyPairs.map(\.raw)
        // Flatten the secret keys into one buffer so the pointers stay valid.
        var flatSeckeys = secretKeys.flatMap { $0 }
        var outputs = [secp256k1_xonly_pubkey](repeating: secp256k1_xonly_pubkey(),
                                               count: recipients.count)

        let ok = outputs.withUnsafeMutableBufferPointer { ob -> Int32 in
            recipientStructs.withUnsafeMutableBufferPointer { rb -> Int32 in
                keypairStructs.withUnsafeMutableBufferPointer { kb -> Int32 in
                    flatSeckeys.withUnsafeMutableBufferPointer { sb -> Int32 in
                        var outPtrs: [UnsafeMutablePointer<secp256k1_xonly_pubkey>?] =
                            unsafe (0..<ob.count).map { unsafe ob.baseAddress! + $0 }
                        var recPtrs: [UnsafePointer<secp256k1_silentpayments_recipient>?] =
                            unsafe (0..<rb.count).map { unsafe UnsafePointer(rb.baseAddress! + $0) }
                        let kpPtrs: [UnsafePointer<Keypair>?] =
                            unsafe (0..<kb.count).map { unsafe UnsafePointer(kb.baseAddress! + $0) }
                        let skPtrs: [UnsafePointer<UInt8>?] =
                            unsafe (0..<secretKeys.count).map {
                                unsafe UnsafePointer(sb.baseAddress! + $0 * 32)
                            }
                        return outPtrs.withUnsafeMutableBufferPointer { op in
                            recPtrs.withUnsafeMutableBufferPointer { rp in
                                kpPtrs.withUnsafeBufferPointer { kp in
                                    skPtrs.withUnsafeBufferPointer { sp in
                                        smallestOutpoint36.withUnsafeBufferPointer { outpoint in
                                            unsafe raw.silentpaymentsSenderCreateOutputs(
                                                generatedOutputs: op.baseAddress!,
                                                recipients: rp.baseAddress!,
                                                nRecipients: rb.count,
                                                outpointSmallest36: outpoint.baseAddress!,
                                                keypairs: kb.isEmpty ? nil : kp.baseAddress,
                                                nKeypairs: kb.count,
                                                seckeys: secretKeys.isEmpty ? nil : sp.baseAddress,
                                                nSeckeys: secretKeys.count)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }
        return outputs.map { XOnlyPublicKey(raw: $0) }
    }
}

// MARK: - Recipient scanning

/// Holds the caller's label-lookup closure across the C call, plus a stable
/// 32-byte buffer for its result.
///
/// The C callback must return a pointer that stays valid after it returns, so
/// the tweak is copied into `scratch` rather than handed out from a temporary.
@safe private final class LabelLookupBox {
    let lookup: ([UInt8]) -> [UInt8]?
    @unsafe let scratch: UnsafeMutablePointer<UInt8>

    init(lookup: @escaping ([UInt8]) -> [UInt8]?) {
        self.lookup = lookup
        unsafe self.scratch = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
    }

    deinit { unsafe scratch.deallocate() }
}

extension Context {
    /// Scans a transaction's outputs for payments to us.
    ///
    /// `labelLookup` is called with a serialised 33-byte label and should
    /// return that label's 32-byte tweak if it is one of ours, or `nil`. Pass
    /// `{ _ in nil }` if you use no labels.
    public func scanSilentPaymentOutputs(
        txOutputs: [XOnlyPublicKey],
        scanKey32: Span<UInt8>,
        prevoutsSummary: SilentPaymentPrevoutsSummary,
        unlabeledSpendPublicKey: PublicKey,
        labelLookup: @escaping ([UInt8]) -> [UInt8]? = { _ in nil }
    ) throws -> [SilentPaymentFoundOutput] {
        guard !txOutputs.isEmpty else { return [] }
        guard scanKey32.count == 32 else {
            throw Secp256k1Error.wrongLength(expected: 32, actual: scanKey32.count)
        }

        var outputStructs = txOutputs.map(\.raw)
        var summary = prevoutsSummary.raw
        var spend = unlabeledSpendPublicKey.raw
        var found = [secp256k1_silentpayments_found_output](
            repeating: secp256k1_silentpayments_found_output(), count: txOutputs.count)
        var nFound: UInt32 = 0

        let box = LabelLookupBox(lookup: labelLookup)
        let trampoline: secp256k1_silentpayments_label_lookup = { label33, context in
            guard let context = unsafe context, let label33 = unsafe label33 else {
                return nil
            }
            let box = unsafe Unmanaged<LabelLookupBox>.fromOpaque(context)
                .takeUnretainedValue()
            let buffer = unsafe UnsafeBufferPointer(start: label33, count: 33)
            let bytes = unsafe Array(buffer)
            guard let tweak = box.lookup(bytes), tweak.count == 32 else { return nil }
            unsafe box.scratch.update(from: tweak, count: 32)
            return unsafe UnsafePointer(box.scratch)
        }

        let ok = found.withUnsafeMutableBufferPointer { fb -> Int32 in
            outputStructs.withUnsafeMutableBufferPointer { ob -> Int32 in
                var foundPtrs: [UnsafeMutablePointer<secp256k1_silentpayments_found_output>?] =
                    unsafe (0..<fb.count).map { unsafe fb.baseAddress! + $0 }
                let outPtrs: [UnsafePointer<secp256k1_xonly_pubkey>?] =
                    unsafe (0..<ob.count).map { unsafe UnsafePointer(ob.baseAddress! + $0) }
                return foundPtrs.withUnsafeMutableBufferPointer { fp in
                    outPtrs.withUnsafeBufferPointer { op in
                        scanKey32.withUnsafeBufferPointer { sk in
                            unsafe raw.silentpaymentsRecipientScanOutputs(
                                foundOutputs: fp.baseAddress!,
                                nFoundOutputs: &nFound,
                                txOutputs: op.baseAddress!,
                                nTxOutputs: ob.count,
                                scanKey32: sk.baseAddress!,
                                prevoutsSummary: &summary,
                                unlabeledSpendPubkey: &spend,
                                labelLookup: trampoline,
                                labelContext: unsafe Unmanaged.passUnretained(box).toOpaque())
                        }
                    }
                }
            }
        }
        guard ok == 1 else { throw Secp256k1Error.invalidPublicKey }

        return found.prefix(Int(nFound)).map { entry in
            SilentPaymentFoundOutput(
                output: XOnlyPublicKey(raw: entry.output),
                tweak: withUnsafeBytes(of: entry.tweak) { unsafe Array($0) },
                label: entry.found_with_label != 0 ? SilentPaymentLabel(raw: entry.label) : nil)
        }
    }
}
