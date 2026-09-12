# libsecp256k1 under SwiftPM — notes for Swift developers

A vendored checkout of [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1)
that builds with `swift build`, imports into Swift as *safe* API taking `Span`, and runs
both upstream's C test suites and a Swift Testing suite.

**Not one upstream file is modified.** Everything is achieved from `Package.swift`, a
hand-written module map, an API notes file, and three shim translation units — all in new
directories. See [What we changed upstream](#what-we-changed-upstream) for the audit.

This document covers the Swift packaging and annotation work. Upstream's own `README.md`
describes the C library.

**Status.** Complete. `swift build` compiles the vendored C library as-is; all three
runnable upstream C suites pass; the C module is annotated across all seven optional
modules from generated API notes; and the Swift wrapper reaches **73 of the 80 public C
functions (91%)**, covering every module — ECDSA, BIP340 Schnorr, ECDH, recovery,
ElligatorSwift, MuSig2 and silent payments, plus serialisation, tweaks and utilities.

**96 Swift Testing cases in 16 suites pass**, including **1,463 known-answer vectors** from
upstream's own files (Wycheproof ECDSA and ECDH, BIP340, BIP352) and seeded randomised
property tests. The library and test targets both compile with **zero warnings** under
`.strictMemorySafety()`. Not one upstream file is modified.

---

## Requirements

| | |
|---|---|
| Swift | **6.4 or newer** |
| Pinned toolchain | `6.4.x-snapshot-2026-09-04` (see `.swift-version`) |
| Deployment target | **macOS 27+** (`platforms: [.macOS(.v27)]`) |
| Verified on | macOS (Darwin 25.4), arm64 |

`Package.swift` declares `// swift-tools-version: 6.4`, so **older toolchains cannot even
parse the manifest**.

Both version floors are load-bearing:

- **Swift 6.4** for the interop annotations. The `SafeInteropWrappers` feature and the
  API notes `BoundsSafety` key are what turn C pointer/length pairs into `Span`. The
  Swift blog post that this work follows asks for 6.2.3 as a floor; the 6.4
  `usr/include/swift/bridging` header also carries annotations older releases lack
  (`SWIFT_SAFE`, `SWIFT_UNSAFE`, `SWIFT_NO_SAFE_WRAPPER`, `SWIFT_COMPUTED_PROPERTY`,
  `SWIFT_REFCOUNTED_PTR`).
- **macOS 27** because `Span` and `MutableSpan` are macOS 26+. This one is a trap: with a
  lower deployment target the importer **silently** emits `UnsafeBufferPointer` overloads
  instead of `Span` ones, with no diagnostic at all. If your safe overloads have the wrong
  type, check `platforms:` first.
---

## Quick start

No setup, bootstrap or code generation is needed — a fresh checkout builds directly:

```sh
swift build                      # library, Swift wrapper, and the C test binaries
swift build -c release           # do this before running any C test suite (see below)
swift test                       # the Swift Testing suite

./.build/release/tests --iterations=2 --jobs=4
./.build/release/noverify_tests --iterations=2 --jobs=4
./.build/release/exhaustive_tests
```

That emits 139 `-Wshorten-64-to-32` warnings from upstream's C sources. They are expected
and harmless — see [Expected compiler warnings](#expected-compiler-warnings). To build
quietly, add `-Xcc -Wno-shorten-64-to-32`:

```sh
swift build -c release -Xcc -Wno-shorten-64-to-32
swift test -Xcc -Wno-shorten-64-to-32
```

`-Xcc` passes the flag straight through to Clang for every C target. It is a property of
the *invocation*, not of the package, so nothing in `Package.swift` changes and the package
stays usable as a dependency.

### Using the safe Swift API

```swift
import SECP256K1

let ctx = try Secp256k1Context()

let secretKey = [UInt8](repeating: 0x11, count: 32)
let messageHash = [UInt8](repeating: 0xAB, count: 32)

let publicKey = try ctx.publicKey(secretKey: secretKey.span)
let signature = try ctx.sign(messageHash: messageHash.span, secretKey: secretKey.span)

if ctx.isValid(signature, messageHash: messageHash.span, publicKey: publicKey) {
    print("verified")
}

let compact = ctx.compactBytes(of: signature)   // 64 bytes
```

BIP340 Schnorr and ECDH are wrapped too:

```swift
// Schnorr
let keyPair = try ctx.keyPair(secretKey: secretKey.span)
let (xonly, parity) = try ctx.xOnlyPublicKey(of: keyPair)
let schnorrSig = try ctx.signSchnorr(message32: messageHash.span,
                                     keyPair: keyPair,
                                     auxiliaryRandom: auxRandom.span)
ctx.isValidSchnorr(schnorrSig.span, message: messageHash.span, publicKey: xonly)

// ECDH -- 32 bytes, libsecp256k1's default SHA256-of-compressed-point hash
let shared = try ctx.sharedSecret(publicKey: theirKey, secretKey: secretKey.span)
```

`auxiliaryRandom` is required rather than defaulted. BIP340 permits omitting it but
recommends fresh randomness per signature against fault and side-channel attacks, so the
wrapper makes the caller decide; pass a fixed value only when determinism is the goal, as
the tests do.

MuSig2, recovery, ElligatorSwift and silent payments are wrapped as well. MuSig is worth
showing, because its most dangerous precondition is enforced by the type system:

```swift
let (aggregateKey, cache) = try ctx.aggregate(publicKeys: [alicePub, bobPub])

var randomness = freshRandom32()                       // wiped by the call below
let pair = try ctx.generateNonce(sessionRandomness32: &randomness,
                                 secretKey: aliceSecret.span, publicKey: alicePub,
                                 message32: message.span, cache: cache)
let myNonce = pair.publicNonce                         // copyable, publish this

let session = try ctx.session(aggregateNonce: try ctx.aggregateNonces([myNonce, theirNonce]),
                              message32: message.span, cache: cache)

// `pair` is consumed here. Using it twice will not compile.
let partial = try ctx.partialSign(noncePair: consume pair, keyPair: aliceKP,
                                  cache: cache, session: session)

let signature = try ctx.aggregate(partialSignatures: [partial, theirPartial],
                                  session: session)
// Verifiable by any BIP340 verifier, with no knowledge that two signers were involved:
ctx.isValidSchnorr(signature.span, message: message.span, publicKey: aggregateKey)
```

### Enforcing single-use nonces in the type system

libsecp256k1's sharpest footgun is the MuSig secret nonce. Upstream's contract is that it
"has been never used in a `partial_sign` call before", that reuse "will leak the secret
key", and that you should avoid copying or serialising the value at all.

`MuSigSecretNonce` expresses all three structurally rather than in prose. It is
`~Copyable`, it has no serialisation API, and `partialSign` takes the pair as `consuming`.
A second use is a compile error:

```
error: 'pair' consumed more than once
  note: consumed here
  note: consumed again here
```

libsecp256k1 also invalidates the nonce internally and returns 0 on reuse, so this is belt
and braces — but a compile error beats a runtime zero that a caller might ignore.

Two limits worth stating rather than glossing:

- A tuple cannot carry it. Swift has no tuples with noncopyable elements
  (`tuple with noncopyable element type 'MuSigSecretNonce' is not supported`), hence
  `MuSigNoncePair`. That turned out to read better anyway: the public nonce is copyable
  and publishable, and the pair as a whole is single-use.
- There is **no scrubbing `deinit`**. A noncopyable struct's `deinit` cannot mutate `self`
  (`cannot assign to property: 'self' is immutable`), so the bytes are not zeroed on
  destruction. The guarantee is single use, not erasure.

### A bug the generator predicted

`EllSwiftXDHHash` first had a bare `.prefix` case that passed `data: nil`. That segfaulted
in the test suite: `secp256k1_ellswift_xdh_hash_function_prefix` computes
`SHA256(prefix64 || …)` where `prefix64` is read *through* the `data` pointer. The case now
carries its 64 bytes (`case prefix([UInt8])`), so choosing it without them is impossible.

This is the same hazard that made the generator refuse to bound
`secp256k1_ellswift_xdh`'s output buffer — for that function, both the output length and
the required inputs depend on the caller's `hashfp`. The refusal to guess a bound and the
crash have the same root cause, which is a reasonable argument that the generator's
conservatism is earning its keep.

No pointers, no `withUnsafe…` closure, no manual `secp256k1_context_destroy`. Every byte
buffer crosses the boundary as a `Span`.

### Using the annotated C module directly

`CSECP256K1` is importable on its own if you want the C API rather than the wrapper. It is
not the raw slug-style API: the annotations turn the context into a class and the
context-taking functions into methods on it, with the `Span` overloads carried along.

```swift
import CSECP256K1

guard let ctx = secp256k1_context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else { … }
defer { ctx.destroy() }

var pubkey = secp256k1_pubkey()
let seckey = [UInt8](repeating: 0x11, count: 32)
_ = ctx.createPublicKey(&pubkey, secretKey: seckey.span)   // Span overload
```

`secp256k1_context_create` no longer exists as a free function — it is
`secp256k1_context.init(flags:)`. Two wrinkles remain at this level, both of which the
wrapper hides:

- The initialiser is `init?` (annotated `NullabilityOfRet: O`), so it needs a `guard let`
  — but honestly so, rather than pretending to be non-optional.
- The flag macros import as `Int32` while the parameter is `UInt32`, hence `UInt32(...)`.

---

## What the package produces

| Product | Kind | Target | Notes |
|---|---|---|---|
| `CSECP256K1` | library | `CSECP256K1` | `libCSECP256K1.a` + the annotated module |
| `Secp256k1` | library | `Secp256k1` | Safe Swift wrapper, strict-memory-safe |
| `tests` | executable | `tests` | upstream `tests`, with `VERIFY` |
| `noverify_tests` | executable | `noverify_tests` | upstream `noverify_tests` |
| `exhaustive_tests` | executable | `exhaustive_tests` | upstream `exhaustive_tests` |
| — | test target | `SECP256K1Test` | 12 Swift Testing cases |

---

## How the manifest is structured

### The C target is rooted at the package root, not at `src/`

```swift
.target(
    name: "CSECP256K1",
    path: ".",
    sources: ["src/secp256k1.c", "src/precomputed_ecmult.c", "src/precomputed_ecmult_gen.c"],
    publicHeadersPath: "swift-include",
    cSettings: [.headerSearchPath("src"), .headerSearchPath("include")] + moduleFlags
)
```

> **This package requires no symlinks and no setup step.** Clone it and run
> `swift build` — that is all. There are no symlinks anywhere in the tree, `src/include/`
> does not exist and is not needed, and nothing has to be generated or bootstrapped first.
> Verified by building a copy of the tree stripped of `.build` and `.git`.
>
> The symlink described below is the trap this layout **avoids**. It is a cost of the
> common `path: "src"` approach, not a prerequisite of this one.

`path: "."` is the single most important choice in the manifest, and it is what sidesteps
the symlink hack that most SwiftPM wrappers of this library resort to.

The reason is that `publicHeadersPath` resolves **relative to the target path**. So *had*
the target been rooted at `src/`, SwiftPM would insist its public headers live at
`src/include/` — a directory upstream does not ship. Wrappers that take that route have to
manufacture it, either by committing a real `src/include/` containing copies of the nine
headers or by symlinking `../include` into place. Both mean the header list has to be kept
in sync with upstream by hand, and a symlinked directory is fragile across platforms and
archive formats.

### `publicHeadersPath` points at `swift-include/`, not upstream's `include/`

This is the part that makes annotation possible while keeping upstream pristine.

Clang locates API notes by looking for `<ModuleName>.apinotes` **next to the module map**.
Left to itself, SwiftPM generates an umbrella-directory module map into `.build/`, where
there is nowhere to put the notes. So the package ships its own directory:

```
swift-include/
├── module.modulemap        # names the nine upstream headers by relative path
└── CSECP256K1.apinotes     # the annotations
```

```
module CSECP256K1 {
    header "../include/secp256k1.h"
    header "../include/secp256k1_preallocated.h"
    header "../include/secp256k1_ecdh.h"
    …
    export *
}
```

Module maps resolve header paths relative to the map's own directory, so `../include/…`
reaches upstream's real headers without copying, symlinking or editing them. The notes sit
beside the map where clang will find them. `include/` gains no files.

### Only three translation units, and no config header

The library is `src/secp256k1.c`, `src/precomputed_ecmult.c` and
`src/precomputed_ecmult_gen.c`. Everything else in `src/` is `#include`d from those
(upstream uses a unity-ish build with `*_impl.h` files) or belongs to upstream's
test/bench binaries.

Autotools and CMake normally hand this library a generated config header. It is not
needed: `src/util.h:331`+ autodetects the wide-multiplication backend (native `__int128`
on arm64), `src/ecmult.h:15` defaults `ECMULT_WINDOW_SIZE` to 15, and `src/ecmult_gen.h`
defaults `COMB_BLOCKS`/`COMB_TEETH` to 11/6. So `-I include -I src` plus the module
defines is the whole configuration.

---

## Flags used, and why

| Flag | Where | Why |
|---|---|---|
| `ENABLE_MODULE_ECDH`, `_RECOVERY`, `_EXTRAKEYS`, `_SCHNORRSIG`, `_MUSIG`, `_ELLSWIFT`, `_SILENTPAYMENTS` | all C targets | Gates the optional modules in `src/secp256k1.c:825`+. All seven on, so the Swift-facing surface is the complete upstream API. CMake applies these directory-wide, so the test binaries get them too. |
| `.headerSearchPath("src")`, `.headerSearchPath("include")` | library | Internal and upstream public headers. `include/` must be named explicitly now that `publicHeadersPath` points elsewhere. |
| `.headerSearchPath("../../src")` | C test targets | Same, relative to each shim directory. |
| `VERIFY` | `tests`, `exhaustive_tests` | Upstream's internal consistency assertions. `noverify_tests` is the same code *without* it — that contrast is the point of having both. |
| `SUPPORTS_CONCURRENCY=1` | `tests`, `noverify_tests` | Fork-based parallel workers behind `--jobs`. Mirrors CMake, which sets it after probing for `sys/types.h`, `sys/wait.h`, `unistd.h`. Consumed by `src/unit_test.c`, reached via `src/tests.c:30`. |
| `.enableExperimentalFeature("SafeInteropWrappers")` | Swift targets | Turns the API notes bounds annotations into `Span` overloads via the compiler's Swiftify macro. |
| `.strictMemorySafety()` | Swift targets | Every remaining use of an unsafe construct must be spelled `unsafe`. |
| `cLanguageStandard: .c90` | package-wide | Matches upstream (`CMAKE_C_STANDARD 90`, `-std=c89` under autotools). Verified c90, gnu90 and gnu17 all compile the tree without errors or warnings. |

### `SECP256K1_BUILD` is deliberately *not* defined

Older manifests pass `.define("SECP256K1_BUILD", to: "")`. Do not copy that:

1. It is redundant — `src/secp256k1.c:18` defines it for its own translation unit.
2. It is actively harmful to interop. `include/secp256k1.h:177` **drops**
   `SECP256K1_ARG_NONNULL` when `SECP256K1_BUILD` is set (upstream does this so the
   compiler cannot optimise away its internal null checks). Those `nonnull` attributes are
   exactly what Swift's importer lowers into non-optional pointer parameters. Define it
   package-wide and you silently throw away nullability information on the Swift side.

---

## Annotating the C library

The guiding document for this work is the Swift blog post
**[Improving the usability of C libraries in Swift](https://www.swift.org/blog/improving-usability-of-c-libraries-in-swift/)**.
Its central claim is the one this package leans on entirely: C headers need no edits,
because Swift-facing information can be layered on through a separate
`<ModuleName>.apinotes` YAML file. Everything below is an application of that idea, plus
the bounds-safety machinery that arrived after the post was written.

### The mechanism

`swift-include/CSECP256K1.apinotes` annotates pointer parameters like this:

```yaml
- Name: secp256k1_ecdsa_sign
  Parameters:
  - Position: 2          # const unsigned char *msghash32
    NoEscape: true
    BoundsSafety: { Kind: counted_by, BoundedBy: 32 }
  - Position: 3          # const unsigned char *seckey
    NoEscape: true
    BoundsSafety: { Kind: counted_by, BoundedBy: 32 }
```

The importer then synthesises a **second, safe overload** alongside the original:

```swift
// original, still available
func secp256k1_ecdsa_sign(_ ctx: OpaquePointer,
                          _ sig: UnsafeMutablePointer<secp256k1_ecdsa_signature>,
                          _ msghash32: UnsafePointer<UInt8>,
                          _ seckey: UnsafePointer<UInt8>, …) -> Int32

// generated from the annotations
func secp256k1_ecdsa_sign(_ ctx: OpaquePointer,
                          _ sig: UnsafeMutablePointer<secp256k1_ecdsa_signature>,
                          _ msghash32: Span<UInt8>,
                          _ seckey: Span<UInt8>, …) -> Int32
```

### Three things worth knowing

**`NoEscape: true` is mandatory, not decorative.** With `BoundsSafety` alone you get an
`UnsafeBufferPointer` overload, which is no improvement under strict memory safety. `Span`
is non-escapable, so the importer will only produce it once it has been told the callee
does not retain the pointer. This single key is the difference between the annotation being
useful and being pointless.

**`BoundedBy` accepts an integer literal as well as a parameter name.** This is what makes
the approach applicable to this library at all. A minority of secp256k1's buffers are
pointer/length pairs (`input` + `inputlen`); most are fixed-size with the length baked into
the parameter *name* (`msghash32`, `seckey`, `input64`) and no length argument to reference.
`BoundedBy: 32` covers those.

**This could not be done in the headers even if editing them were acceptable.** On a
function parameter, `counted_by` requires `-fbounds-safety`; in plain C the attribute
applies only to struct flexible-array members, and clang rejects it outright:

```
error: counted_by attribute only applies to non-static data members
```

Written inline it also refers to a parameter declared later in the same list, which plain C
mode rejects as `use of undeclared identifier 'len'`. API notes sidestep both: they are
consumed only when clang builds the module for Swift, so the C90 library compilation never
sees them. Here the unmodified-upstream constraint is not merely preserved — it is
*required*.

### Renaming: the context as a class, functions as methods

Bounds safety is orthogonal to naming. API notes change only what you name, so annotating
buffers left every symbol with its original C spelling. Two more keys fix that.

`SwiftImportAs: reference` on the **tag** imports the opaque context as a Swift class
instead of an `OpaquePointer`:

```yaml
Tags:
- Name: secp256k1_context_struct
  SwiftImportAs: reference
  SwiftRetainOp: immortal
  SwiftReleaseOp: immortal
```

`SwiftName` with a leading `self:` then turns the context-taking functions into methods on
it:

```yaml
- Name: secp256k1_context_create
  SwiftName: "secp256k1_context.init(flags:)"
- Name: secp256k1_ecdsa_sign
  SwiftName: "secp256k1_context.sign(self:_:messageHash:secretKey:nonceFunction:nonceData:)"
```

which yields, with the `Span` overloads intact:

```swift
public class secp256k1_context_struct { }
extension secp256k1_context_struct {
    public init!(flags: UInt32)
    public func destroy()
    public func clone() -> secp256k1_context!
    public func verifySecretKey(_ seckey: UnsafePointer<UInt8>) -> Int32
    public final func verifySecretKey(_ seckey: Span<UInt8>) -> Int32
    public func sign(_ sig: UnsafeMutablePointer<secp256k1_ecdsa_signature>,
                     messageHash: Span<UInt8>, secretKey: Span<UInt8>, …) -> Int32
    …
}
```

Two rules to keep in mind:

- **`SwiftName` must match the original C arity**, `self:` included. Where a bounds
  annotation collapses a pointer/length pair, the *generated* safe overload derives its own
  shorter name — write the collapsed form here and the attribute is rejected with
  `too few parameters in the signature specified by the 'swift_name' attribute`.
- **`immortal` retain/release is a deliberate choice, not a shortcut.** A retain operation
  must return the pointer it was handed, and `secp256k1_context_clone` allocates a *new*
  context instead. No function in this API can serve as a retain, so ARC cannot manage the
  lifetime. `immortal` buys type safety without memory management; destruction stays
  explicit, which is what `Secp256k1Context` is for.

### Nullability: getting rid of `!`

Left alone, every pointer return imports implicitly unwrapped, which is the worst of both
worlds — it looks non-optional but decays to `Optional` the moment it is bound.
`NullabilityOfRet` (or `ResultType`) fixes returns, and `Parameters`/`Nullability` fixes
arguments. Values are `O` (nullable), `N` (non-null), `U` (unspecified):

```yaml
- Name: secp256k1_context_create
  SwiftName: "secp256k1_context.init(flags:)"
  NullabilityOfRet: O
```

| | before | after |
|---|---|---|
| `secp256k1_context_create` | `init!(flags:)` | `init?(flags:)` |
| `secp256k1_context_clone` | `-> secp256k1_context!` | `-> secp256k1_context?` |
| `secp256k1_ecdsa_sign`'s `noncefp` | non-optional (see [rough edges](#three-rough-edges)) | `secp256k1_nonce_function?` |
| `secp256k1_context_static` | `secp256k1_context!` | `secp256k1_context` |

Note that upstream's `SECP256K1_ARG_NONNULL` already covers most pointer *parameters*, so
they import non-optional without help. Nullability annotations are needed for returns,
globals, and the genuinely-nullable arguments upstream leaves unmarked.

### Globals

Upstream exports eight constants. `SwiftName` under `Globals` renames them, and can attach
one to a type as a static member:

```yaml
Globals:
- Name: secp256k1_context_static
  SwiftName: "secp256k1_context.shared"
  Nullability: N
- Name: secp256k1_nonce_function_default
  SwiftName: "nonceFunctionDefault"
  Nullability: N
```

giving `secp256k1_context.shared` (a `class let` on the context class) and
`nonceFunctionDefault`, `nonceFunctionRFC6979`, `nonceFunctionBIP340`,
`ecdhHashFunctionSHA256`, `ecdhHashFunctionDefault`, `ellswiftXDHHashFunctionPrefix`,
`ellswiftXDHHashFunctionBIP324`.

> `secp256k1_context.shared` must **never** be destroyed, which is why
> `Secp256k1Context` does not wrap it — that class's `deinit` owns `destroy()`. It is
> usable directly for verification, which needs no randomisation.

### The API notes are generated, not hand-written

`swift-include/CSECP256K1.apinotes` is **generated** — 1,010 lines produced by
`swift-tools/generate-apinotes.py`. Do not edit it by hand.

There are two interchangeable front-ends, a Swift command plugin and the original Python
script, which produce byte-identical output — see
[Regenerating](#regenerating-python-scripts-or-a-swift-plugin):

```sh
swift package --allow-writing-to-package-directory codegen apinotes
swift package --allow-writing-to-package-directory codegen apinotes --check

python3 swift-tools/generate-apinotes.py            # regenerate
python3 swift-tools/generate-apinotes.py --check     # non-zero if out of date
python3 swift-tools/generate-apinotes.py --report    # what was left out, and why
```

`--report` lists the deliberately-unannotated buffers; the plugin prints the same list
whenever it runs the API notes generator.

This follows the article's own advice: it recommends generating API notes for any
non-trivial header set, and prefers a real AST over regex. Hand-writing got the ECDSA
surface to 11 of 82 functions and stopped being sensible — API notes address parameters by
*position*, and hand-transcribed indices rot silently when a header changes.

**Coverage now:**

| | |
|---|---|
| functions annotated | **80 of 82** (the other two take no pointers) |
| with a Swift name | 79 |
| with bounds safety | 73 parameters |
| nullability stated | 247 `N` + 35 `O` + 4 returns |
| globals | 8 |
| functions taking `Span` | **52** |
| `MutableSpan` overloads | 19 |
| byte buffers deliberately skipped | 4 |

#### How it works

Parameter names, types and order come from **clang's JSON AST**
(`clang -Xclang -ast-dump=json`), so the positional indices are never transcribed by hand.
Exactly one thing is read from the header text: the `SECP256K1_ARG_NONNULL(k)` macro, whose
argument indices clang's JSON AST records as bare `NonNullAttr` nodes *without* the
indices. That macro is trivially regular, so a regex is right there and nowhere else.

Bound inference, in order:

1. **Size in the parameter name** — `msghash32`, `input64`, `tweak32` → `BoundedBy: 32`/`64`.
   This covers most of the API; upstream names buffers after their length.
2. **A `size_t <name>len` sibling** — `input`/`inputlen` → `BoundedBy: inputlen`.
3. **A small table of documented conventions** — only `seckey` → 32, verified against all
   11 occurrences in the public headers, every one documented as "a 32-byte secret key".
4. **Otherwise: skip and report.** The generator never guesses a bound.

#### What is deliberately not annotated

`--report` lists four byte buffers, each for a reason rather than an oversight:

| buffer | why |
|---|---|
| `secp256k1_ec_pubkey_serialize(output)` | length is `*outputlen`, an in/out pointer `BoundedBy` cannot reference |
| `secp256k1_ecdsa_signature_serialize_der(output)` | same |
| `secp256k1_ecdh(output)` | length depends on the caller's `hashfp`; 32 only for the default hash |
| `secp256k1_ellswift_xdh(output)` | same |

The `hashfp` cases matter: 32 would be right for the default hash and wrong for a custom
one, so annotating them would introduce a bug rather than a safety improvement.

#### Nullability is audited per function, not per parameter

The generator states nullability for **every** pointer parameter of any function it
touches, `N` as well as `O`. That is not belt-and-braces — partial annotation is actively
harmful:

> Giving one parameter explicit nullability drops the *others* back to implicitly
> unwrapped, even where upstream's `SECP256K1_ARG_NONNULL` had already made them
> non-optional.

Observed on `secp256k1_keypair_xonly_pub`: annotating the genuinely-optional `pk_parity`
regressed the non-null `keypair` from `UnsafePointer<secp256k1_keypair>` to
`UnsafePointer<secp256k1_keypair>!`. Auditing the whole function fixes it, and mirrors the
`ASSUME_NONNULL_BEGIN` advice in the article's own postscript.

The effect across the module: **implicitly-unwrapped optionals fell from 31 to 8**. The
eight that remain are the `noncefp` and `ndata` *fields* of
`secp256k1_schnorrsig_extraparams` (and their memberwise-initialiser copies) — struct
members are not reachable from function-level API notes.

### Other API notes keys available

The toolchain's YAML reader accepts, among others: `SwiftName` (rename, including
`getter:`/`setter:` and `Type.method(self:)` forms), `SwiftImportAs: reference` with
`SwiftRetainOp`/`SwiftReleaseOp` (foreign reference types — turns an opaque C struct into a
Swift `class`), `SwiftReturnOwnership`, `Nullability`, `EnumExtensibility`, `SwiftWrapper`,
`SwiftConformsTo` (e.g. `Swift.OptionSet`), `SwiftCopyable`, `SwiftEscapable`,
`Lifetimebound`, `SwiftPrivate` and `Availability`.

`SwiftImportAs: reference` and `SwiftName` are both applied — see
[Renaming](#renaming-the-context-as-a-class-functions-as-methods).

One is earmarked but not applicable yet: `SwiftWrapper: struct` +
`SwiftConformsTo: Swift.OptionSet` for the context and compression flags. Those are plain
`#define`s over `unsigned int` rather than a typedef'd enum, so there is no declaration to
attach the keys to without a header change.

### Inspecting the result

`swift-synthesize-interface` is the feedback loop — it prints the module exactly as Swift
sees it, so you can confirm an annotation landed:

```sh
TC=~/Library/Developer/Toolchains/swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-09-04-a.xctoolchain
$TC/usr/bin/swift-synthesize-interface -module-name CSECP256K1 \
  -target arm64-apple-macos27.0 -I swift-include | grep Span
```

Or with Xcode:

```bash
xcrun swift-synthesize-interface \
  -I include \
  -Xcc -fmodule-map-file=swift-include/module.modulemap \
  -module-name CSECP256K1 \
  -target arm64-apple-macos27 \
  -sdk $(xcrun --sdk macosx --show-sdk-path)
```

Note the tool does **not** accept `-enable-experimental-feature`; it shows the
`Span` overloads regardless. It needs no `-sdk`.

To compile a scratch Swift file against the module outside SwiftPM, pass the module map,
the include path, **and an SDK**. `-typecheck` works without `-sdk`, but linking without it
fails on a misleading `ld: library 'System' not found`:

```sh
$TC/usr/bin/swiftc -O snippet.swift -o snippet \
  -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
  -Xcc -fmodule-map-file=swift-include/module.modulemap \
  -I swift-include -L .build/release -lCSECP256K1
```

Setting `SDKROOT` works instead of the flag.

---

## How strict memory safety was achieved

Both Swift targets enable `.strictMemorySafety()`, and both compile with **zero** safety
warnings. That was not free; it took three things.

**1. The annotations do the heavy lifting.** Under strict memory safety, any expression
touching an unsafe type must be spelled `unsafe`. Passing a `[UInt8]` to a C
`const uint8_t *` is exactly that, and it is also the single most common operation in this
API. The `Span` overloads remove the unsafety rather than papering over it.

This is verifiable rather than a matter of opinion. Calling the pointer overload under
strict memory safety:

```
warning: expression uses unsafe constructs but is not marked with 'unsafe'
  note: argument 'data' in call to global function '…' has unsafe type 'UnsafePointer<UInt8>?'
```

Calling the `Span` overload with the same deployment target and flags: no diagnostic at
all.

**2. Importing the context as a class removed the rest.** The context used to be the
wrapper's main unsafe surface — `@unsafe let raw: OpaquePointer`, needing a compensating
`@safe` on the class to silence `class 'Secp256k1Context' has storage involving unsafe
types`. Annotating the tag as a reference type made that vanish: a class reference is not
an unsafe type, so no attributes are needed at all.

```swift
public final class Secp256k1Context {
    let raw: secp256k1_context           // a class reference, not a pointer

    public init() throws {
        guard let ctx = secp256k1_context(flags: UInt32(SECP256K1_CONTEXT_NONE)) else {
            throw Secp256k1Error.contextCreationFailed
        }
        self.raw = ctx
    }

    deinit { raw.destroy() }
}
```

Measured effect on the wrapper:

| | before | after |
|---|---|---|
| `unsafe` expression markers | 11 | **6** |
| `@unsafe` / `@safe` attributes | 3 | **0** |

What is left is exactly one category: passing a struct out-parameter by pointer
(`&pubkey`, `&sig`, `&pub`) and the one raw output buffer. Those six call sites keep their
`unsafe` marker. They are not annotatable away today — bounds safety addresses byte
buffers, not by-pointer struct arguments.

**3. Fixed lengths are still checked by hand.** `BoundedBy: 32` tells the *importer* the
buffer is 32 bytes; it does not give Swift a 32-element `Span` type. A caller can still
pass a 31-byte span. The wrapper therefore checks `count` and throws
`Secp256k1Error.wrongLength` rather than letting the C code read out of bounds. Two tests
cover exactly this.

So: memory safety within Swift is enforced by the compiler; the fixed-size contract is
enforced by the wrapper.

> **Strict memory safety also flags *over*-marking.** Writing `unsafe` on an expression
> that needs no such marker earns `warning: no unsafe operations occur within 'unsafe'
> expression`. It is worth keeping the build clean of these: they are the signal that your
> mental model of which operations are actually unsafe has drifted. In this wrapper only
> the C call inside `compactBytes(of:)` needs the marker —
> `withUnsafeMutableBufferPointer` and `buf.baseAddress!` do not.

---

## Three rough edges

All are documented in the source at the point they bite.

**The generated `inout MutableSpan<UInt8>` overload is unusable.** Annotating a *mutable*
output parameter does produce

```swift
func secp256k1_ecdsa_signature_serialize_compact(_ ctx: OpaquePointer,
                                                 _ output64: inout MutableSpan<UInt8>,
                                                 _ sig: UnsafePointer<…>) -> Int32
```

but calling it with `&span` makes overload resolution prefer the *pointer* overload via
inout-to-pointer conversion, forming an `UnsafeMutablePointer<UInt8>` to the span variable
itself:

```
warning: forming 'UnsafeMutablePointer<UInt8>' to a variable of type 'MutableSpan<UInt8>';
         this is likely incorrect because 'MutableSpan<UInt8>' may contain an object reference
error: lifetime-dependent variable 'span' escapes its scope
```

`compactBytes(of:)` therefore takes the pointer path explicitly, inside `unsafe`. Input
parameters of *read-only* functions are unaffected: every `Span` argument to a function
that returns only an `Int32` resolves to the safe overload cleanly.

The knock-on effect is worse than it first appears, because **the two overloads are
all-or-nothing**. Passing a `Span` for any input selects the safe overload, whose output
parameter is the unusable `inout MutableSpan`:

```
error: cannot convert value of type 'UnsafeMutablePointer<UInt8>'
       to expected argument type 'MutableSpan<UInt8>'
```

So a function with a mutable output buffer must be called through its *fully* unsafe
overload, bridging every `Span` input back to a pointer with
`Span.withUnsafeBufferPointer`. `signSchnorr` does exactly that and says so in a comment.
The Span-typed *public* API is still worth having — callers get bounds safety at that
boundary — but the C call underneath cannot. This affects every output-producing function
in the library, not just one, which is why it is worth reporting.

**Method-form renaming drops function-pointer nullability — fixable.** Isolated by
bisecting the API notes keys: `Tags`/`SwiftImportAs: reference` alone keeps it, a
method-form `SwiftName` alone keeps it, but **both together** turn

```swift
_ noncefp: secp256k1_nonce_function!     // implicitly unwrapped, nil is fine
```

into a non-optional parameter, so `nil` stops compiling:

```
error: 'nil' is not compatible with expected argument type 'secp256k1_nonce_function'
```

That matters because upstream documents `noncefp == NULL` as "use the default nonce
function" (`include/secp256k1.h:431`) and marks only args 1–4 `SECP256K1_ARG_NONNULL`, so
the nullability is genuinely lost rather than correctly inferred.

Stating it explicitly repairs it completely, and lands somewhere better than the starting
point — a true `Optional` rather than an implicitly unwrapped one:

```yaml
  Parameters:
  - Position: 4
    Nullability: O
```

Still worth reporting, since needing the annotation at all is a defect: neither key
triggers the loss alone.

**Swift Testing's `#expect` cannot take a `Span`.** `#expect` expands to
`Testing.__checkFunctionCall(...)`, which is generic over `each U` with an implicit
`each U: Escapable`. `Span` is non-escapable, so this fails to compile:

```swift
#expect(ctx.isValidSecretKey(key.span))
// error: global function '__checkFunctionCall(…)' requires that 'Span<UInt8>' conform to 'Escapable'
```

Compute the value on its own line and assert on the result:

```swift
let ok = ctx.isValidSecretKey(key.span)
#expect(ok)
```

The same applies to `#expect(throws:)`, whose closure would capture a span — the length
test uses `do`/`catch` and asserts on the caught error instead.

---

## What we changed upstream

**Nothing.** Audited against the pristine import commit `96cc327`:

```sh
git diff --diff-filter=M 96cc327 HEAD   # modified: (none)
git diff --diff-filter=D 96cc327 HEAD   # deleted:  (none)
```

Every file this package adds lives in a new path:

```
.swift-version                      Package.swift
swift-include/module.modulemap      swift-include/CSECP256K1.apinotes
Sources/Secp256k1/                  swift-test/SECP256K1Test/
Sources/ctest-verify/               Sources/ctest-noverify/
Sources/ctest-exhaustive/           README-Swift.md, CLAUDE.md
swift-tools/                        swift-plugins/Codegen/
```

`swift-tools/` holds the Python generators and `bip352-dump.c`;
`swift-plugins/Codegen/` is the Swift command plugin that does the same work.

### Why the Swift test target is not in `Tests/`

This is the one place where staying at zero modifications took deliberate effort, and it
is worth explaining because the failure mode is silent.

Upstream's `.gitignore:5` is a bare `tests` pattern — it ignores the autotools build
product of that name. Git matches a bare pattern against *any* path component, and macOS
git sets `core.ignorecase=true`, so it also matches a directory named `Tests/`. Put a
Swift test target in the conventional `Tests/SECP256K1Test/` and **git silently ignores
the entire suite**. Nothing warns you; `swift test` works fine and the files are simply
never committed.

Three ways out, all tested with `git check-ignore --no-index -v`:

| approach | result | why |
|---|---|---|
| `!/Tests/` + `!/Tests/**` in the root `.gitignore` | works | but modifies an upstream file |
| a nested `.gitignore` inside `Tests/` | **fails** | git never descends into an excluded directory, so the nested file is never read |
| `.git/info/exclude` | **fails** | `.gitignore` in the working tree outranks `info/exclude` in git's precedence order — and it is not committed, so it would not help anyone else anyway |
| **rename the directory** | **works** | no collision to negate |

Hence `swift-test/SECP256K1Test/`, declared with an explicit `path:`. A `testTarget` is
not required to live under `Tests/`.

The same reasoning names the C shim directories `ctest-*`: `tests`, `noverify_tests`,
`exhaustive_tests` and `ctime_tests` are all bare patterns in upstream's `.gitignore`.
Target and product names are unaffected, since they create no directories — so the
binaries still carry upstream's names.

---

## The Swift test suite

```sh
swift test -Xcc -Wno-shorten-64-to-32
```

30 cases in `swift-test/SECP256K1Test`, in four suites:

| suite | what it covers |
|---|---|
| ECDSA over the annotated C library | context lifecycle, secret-key validation, sign/verify round-trip, wrong-message and wrong-key rejection, RFC6979 determinism, compact round-trip, garbage handling |
| The annotated C module | the C API directly: context-as-class, `init?`/`clone()` optionality, `nil` nonce function, `secp256k1_context.shared`, renamed globals |
| BIP340 Schnorr signatures | **known-answer test against upstream's own vector**, plus bit-flip rejection, x-only round-trip, secret-key recovery, parity, variable-length verification |
| ECDH | agreement symmetry, distinct peers give distinct secrets, length checks |
| ECDSA recovery | recovering the signer from signature and message alone, recovery-id round-trip, conversion agreeing byte-for-byte with direct signing |
| ElligatorSwift | encode/decode round-trip, randomised encodings, XDH symmetry, the silently-wrong-party hazard, hash choice |
| MuSig2 | **two-of-two aggregate verifying under the plain BIP340 verifier**, partial-signature verification, key-order sensitivity, session-randomness wiping |
| Silent payments | sender/recipient round-trip, wrong-scan-key finding nothing, two recipients in caller order, labeled addresses through the C callback, label round-trip |
| Serialisation | both public-key formats, DER round-trip, x-only extraction agreeing across routes, **a whole MuSig session over the wire formats** |
| Tweaks | secret/public tweak correspondence for add, multiply and negate; taproot output-key check; a full key-path spend; a MuSig session under a tweaked aggregate key |
| Utilities | sort order matching lexicographic serialisation, combine matching scalar addition, lower-S normalisation, tag domain separation, variable-length Schnorr, counter-based nonces, context randomisation |
| Wycheproof ECDSA | **463 vectors** (162 valid, 301 invalid), plus the malleability subset checked explicitly |
| Wycheproof ECDH | **473 vectors**, raw x coordinate; 360 flagged `EdgeCaseDoubling` |
| BIP340 vectors | **all 19**, signing byte-for-byte and verification, message lengths 0/1/17/32/100 |
| BIP352 vectors | **28 vectors, 29 receive subtests**, sending and scanning, including the three deliberate-failure cases |
| Randomised properties | 9 properties over seeded random inputs: sign/verify, serialisation, tweak correspondence, negation involution, ECDH symmetry, sort permutation, recovery |

The Schnorr suite is a genuine known-answer test, not a round-trip: it reproduces the
exact 64 signature bytes of vector 0 from `src/modules/schnorrsig/tests_impl.h`. Those
bytes were extracted from upstream's file programmatically rather than transcribed —
worth doing, since the real signature ends `...2DCA8215`, a single character away from a
plausible-looking mistake.

These exercise the annotated library through the wrapper, so they are also the regression
test for the annotations themselves: if an API notes entry stops producing a `Span`
overload, this target stops compiling.

---

## Why the C tests are `executableTarget`s, not `testTarget`s

A `testTarget` means XCTest or Swift Testing: a Swift bundle the `swift test` harness
loads. Upstream's suites are none of that — they are self-contained C programs with their
own `main()`, RNG seeding and CLI. There is nothing for `swift test` to discover, so they
are plain executables. CMake treats them the same way: `add_executable` plus `add_test`.

Two hard constraints shape the wiring:

**1. They must never link `CSECP256K1`.** Both `src/tests.c:21` and
`src/tests_exhaustive.c:23` `#include "secp256k1.c"` — the entire library, textually. Link
the library as well and you get duplicate symbols for every function in it. These targets
have **no dependencies at all**.

**2. `tests` and `noverify_tests` are the same source file.** Upstream compiles
`src/tests.c` twice, once with `VERIFY` and once without. SwiftPM refuses to let one file
belong to two targets, so a manifest naming `src/tests.c` directly can only ever have *one*
of the two. And `sources:` cannot escape a target's directory with `..`, so a target rooted
under `Sources/` cannot name `src/tests.c` either.

The way out is one shim translation unit per binary:

```
Sources/ctest-verify/main.c        #include "../../src/tests.c" (+ precomputed tables)
Sources/ctest-noverify/main.c      same, different defines from Package.swift
Sources/ctest-exhaustive/main.c    #include "../../src/tests_exhaustive.c"
```

Each shim is a comment block and one or three `#include`s. Quoted `#include` resolves
relative to the *including* file, so the nested includes inside `tests.c` still resolve
against `src/`.

### The precomputed table requirement

Asymmetric, and easy to get wrong in both directions:

| binary | source | precomputed tables |
|---|---|---|
| `tests` | `tests.c` | **required** |
| `noverify_tests` | `tests.c` | **required** |
| `exhaustive_tests` | `tests_exhaustive.c` | **must be absent** |

`src/tests.c` includes `secp256k1.c` but *not* the two precomputed table units, so a shim
that only includes `tests.c` fails to link:

```
Undefined symbols for architecture arm64:
  "_secp256k1_pre_g", referenced from: …
  "_secp256k1_ecmult_gen_prec_table", referenced from: …
```

`tests_exhaustive.c` is the opposite: it pulls in `ecmult_compute_table_impl.h` and
generates its tables **at runtime** over a small test group order. Adding the precomputed
units there is a duplicate-symbol error. Upstream's `src/CMakeLists.txt` has an explicit
comment about exactly this.

---

## Running the C test suites

`tests` and `noverify_tests` share the framework in `src/unit_test.c`:

```
--help, -h                      Show help
--list_tests, -l                List all tests and modules (17 modules)
--jobs=<n>, -j=<n>              Parallel worker processes (default 0 = sequential)
--iterations=<n>, -i=<n>        Iterations per test (default 16)
--seed=<hex>                    Fixed RNG seed (default random)
--target=<test|module>, -t=     Run one test or one module; repeatable
--log=<0|1>                     Execution logging (default 0)
```

`SECP256K1_TEST_ITERS` works as an environment equivalent, and leading positional arguments
are still accepted as `[iterations] [seed]`.

`exhaustive_tests` predates that framework and takes positional arguments only:

```
exhaustive_tests [count] [seed] [numcores] [thiscore]
```

Some tests self-skip at low iteration counts (`Skipping test_ecmult_constants_sha 2048
(iteration count too low)`). That is expected, not a failure — raise `--iterations`.

> **Invoke the binaries directly, not through `swift run`.** `swift run tests --help` is
> ambiguous: the flags get consumed by SwiftPM rather than forwarded. Use
> `./.build/release/tests --help`.

### Debug vs release: build release

Debug builds are unoptimised, and this is a library doing big-integer field arithmetic in a
loop. The difference is not marginal:

| suite | debug | release | speedup |
|---|---|---|---|
| `exhaustive_tests` (default count) | 59.8 s | **5.6 s** | ~11x |
| `tests --iterations=2 --jobs=4` | 54.7 s | **4.7 s** | ~12x |
| `noverify_tests --iterations=2 --jobs=4` | 33.5 s | — | |

Those debug numbers are at `--iterations=2`, far below the default of 16. A
default-iteration debug run is unpleasant. `--jobs` scales well (~200% CPU at `--jobs=4`).

---

## `ctime_tests` is not packaged

Upstream has a fourth suite, `ctime_tests`, checking that secret-dependent branches do not
exist. It is **not** a target here and cannot be built on macOS: `src/ctime_tests.c:15` is
a hard `#error` unless `SECP256K1_CHECKMEM_ENABLED`, which needs either MemorySanitizer
(Linux in practice) or valgrind's headers with `-DVALGRIND`.

This is not a packaging shortcoming — upstream gates it identically, defaulting
`SECP256K1_BUILD_CTIME_TESTS` to `${SECP256K1_VALGRIND}`, i.e. off. It is also the only
suite that links the real library instead of `#include`ing `secp256k1.c`, so if it is ever
added it should depend on `CSECP256K1` — unlike the other three.

---

## Expected compiler warnings

**A clean `swift build` emits 139 warnings and 0 errors. All 139 are
`-Wshorten-64-to-32`**, and all come from upstream's C sources. The Swift targets emit
none, including under `.strictMemorySafety()`.

One unrelated message shows up in **release** builds only: `warning: input verification
failed`, three times, from Swift Build's compilation cache while linking the three C test
executables. It does not come from this package's code and the build completes
successfully; it is noted here so it is not mistaken for something the package did.

| target | warnings |
|---|---|
| `CSECP256K1` | 15 |
| `tests` | 53 |
| `noverify_tests` | 53 |
| `exhaustive_tests` | 18 |

The C test targets carry more because they compile the library *and* the test harness
(`testrand_impl.h`, `testutil.h`) into one TU. Concentrated in `src/modinv64_impl.h` (24),
`src/scalar_4x64_impl.h` (12), `src/testrand_impl.h` (9) and `src/hash_impl.h` (8).

### Why these are safe to silence

1. **Upstream does not consider them warnings.** This tree compiles clean under CMake and
   autotools. Upstream builds with `-Wall -Wextra` plus a few `-Wno-*`, and
   `-Wshorten-64-to-32` is implied by neither — it is off by default and upstream never
   turns it on. SwiftPM does. Every one of these 139 lines is a diagnostic upstream has
   never opted into, on code it audits under its own flag set.
2. **They are deliberate.** This is constant-time big-integer arithmetic; truncation to a
   narrower type is the intended operation in field, scalar and modular-inverse code.
3. **89% are in code that never ships.** Only 15 of 139 are in the library itself
   (`modinv64_impl.h` 6, `scalar_4x64_impl.h` 4, `silentpayments/main_impl.h` 2,
   `hash_impl.h` 2, `ecmult_impl.h` 1). The other 124 come from upstream's test harness.
   A representative example, `src/modules/musig/tests_impl.h:684`:

   ```c
   int xonly = testrand_bits(1);
   ```

   `testrand_bits` returns `uint64_t`; asking for one bit and storing it in an `int` cannot
   lose information. The warning is structurally correct and semantically vacuous.
4. **Silencing costs nothing in signal.** A warning class that fires 139 times on first
   build, all of it expected, is not signal — it is a wall of text hiding the diagnostics
   you *would* want to see.

The one thing not to do is "fix" them by editing upstream sources. That would mean 139
casts across `src/`, and it forfeits this package's central property.

### How to silence them

| approach | effect | cost |
|---|---|---|
| `swift build -Xcc -Wno-shorten-64-to-32` | 139 → **0** | none; per-invocation, package untouched |
| `.unsafeFlags(["-Wno-shorten-64-to-32"])` in a target's `cSettings` | 139 → **15** when applied to the three C test targets only | `unsafeFlags` makes the package **ineligible as a dependency** of any other package |

Both are verified. **`-Xcc` is the recommended one** and is what this README uses in its
examples. Nothing is applied in `Package.swift` deliberately — the default build stays
honest about what upstream emits, and silence is opt-in per invocation.

> **SwiftPM's supported warning API cannot do this.** `CSetting.treatWarning(_:as:)` and
> `CSetting.treatAllWarnings(as:)` do exist for C targets in 6.4, but `WarningLevel` offers
> only `.warning` and `.error` — there is no `.ignored`. The supported API can *escalate* a
> warning, never suppress it. Suppression is `-Xcc` or `unsafeFlags`, and nothing else.

---

## API coverage

The wrapper reaches **73 of the 80 public C functions**. Seven are deliberately not
wrapped, each for a reason rather than by omission:

| not wrapped | why |
|---|---|
| `secp256k1_context_preallocated_create` / `_clone` / `_clone_size` / `_destroy` | For environments without `malloc`. The Swift layer allocates anyway — `Array`, a `class` context — so wrapping these would expose manual memory management while delivering none of the benefit. |
| `secp256k1_context_set_illegal_callback` / `set_error_callback` | Cannot be wrapped soundly as recoverable errors. Upstream is explicit: "Should this callback return instead of crashing, the return value and output arguments of the API function call are undefined. Moreover, the same API call may trigger the callback again." A Swift closure that must not return normally is not a useful error-handling API, and the wrapper's job is to make those illegal arguments unrepresentable instead. |
| `secp256k1_context_set_sha256_compression` | Plugs in a hand-optimised SHA256 implementation. Niche, and orthogonal to binding ergonomics. |

### Relationship to upstream's own tests

Worth being precise about what is and is not covered, because the two are easy to conflate.

**The C library's correctness is covered by upstream's own suites, which this package runs
unchanged** — `tests`, `noverify_tests` and `exhaustive_tests`, 115 tests across 17
modules, all passing. Roughly 40 of those (`integer`, `scalar`, `field`, `group`, `ecmult`,
`utils`, most of `hash`) exercise symbols that are not in `include/` at all — verified:
`secp256k1_fe_mul`, `secp256k1_scalar_mul`, `secp256k1_ge_set_gej`, `secp256k1_ecmult`,
`secp256k1_modinv64` and `secp256k1_hsort` are all internal-only. No Swift binding can
reach them, which is exactly why upstream's test binaries `#include "secp256k1.c"`.

**The Swift suite covers the binding**, not the cryptography. It is an integration layer:
does each annotated function reach the right C symbol, with the right lengths, and do the
Swift-side invariants hold. It has earned its keep — it caught the ElligatorSwift
`.prefix` segfault and a double-sort defect — but it is not a re-implementation of
upstream's proof.

Two of the three gaps that used to sit here are now closed — see
[Known-answer tests](#known-answer-tests-from-upstreams-own-vectors). What remains:

- **No API-misuse tests.** Upstream's `*_api_tests` pass NULL and invalid arguments and
  assert the illegal callback fires. Largely unrepresentable through this wrapper, which is
  the point — but it does mean those error paths are untested from Swift.
- **No BIP327 MuSig vectors.** Upstream's `src/modules/musig/vectors.h` uses
  index-into-array indirection across several nested struct types, so extracting it needs
  more than the flat dumper BIP352 got. The MuSig suite is still round-trip only.
- **No ellswift vectors.** Upstream keeps them inline in `tests_impl.h` rather than in a
  separate file.

## Known-answer tests from upstream's own vectors

Round-trips and properties only prove self-consistency. These check against external
authorities, and they are what closed the biggest hole in the Swift suite.

| source | vectors | how it is read |
|---|---|---|
| `src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json` | 463 | read in place at runtime |
| `src/wycheproof/ecdh_secp256k1_test.json` | 473 of 752 | read in place at runtime |
| `src/modules/schnorrsig/tests_impl.h` | 19 | extracted to Swift by a generator |
| `src/modules/silentpayments/vectors.h` | 28 (+29 subtests) | dumped to JSON by a C program |

Three different mechanisms, because upstream ships them three different ways. In every
case the upstream file is read or parsed, never edited or transcribed.

### Wycheproof, read in place

The JSON files are read straight out of `src/wycheproof/` via a path derived from
`#filePath`, rather than copied in as SwiftPM resources. Copying would duplicate data this
project is careful not to touch, and the files are large. The trade is that these tests
only run from a source checkout, which is where they run.

Wycheproof gives the *message*, not its digest, so the tests hash it with CryptoKit —
libsecp256k1 exposes only `tagged_sha256`, which is a different construction.

**ECDH needed a capability the wrapper lacked.** Wycheproof reports the shared secret as
the raw x coordinate, while `sharedSecret` hashes it (libsecp256k1's default). So
`ECDHHash.rawXCoordinate` was added — a plain `@convention(c)` hash that copies `x32`
through. It is what SEC1/X9.63 specify, so it is useful in its own right, and a second
test asserts the hashed and raw forms differ so the selector cannot be silently ignored.

**Only 473 of the 752 ECDH vectors are used, deliberately.** Most of that file tests
X.509/ASN.1 parsing — wrong OIDs, bad lengths, trailing garbage — which libsecp256k1 does
not do and this wrapper does not either. The tests take only vectors whose
SubjectPublicKeyInfo header is byte-for-byte canonical, where the trailing 65 bytes are
unambiguously the point; there are 56 distinct headers among the 88-byte entries alone.
Running malformed DER through a "take the last 65 bytes" shortcut would test the shortcut,
not the library.

### BIP340, extracted to Swift

Upstream ships these only as C array literals, so a generator extracts all 19 into
`swift-test/SECP256K1Test/BIP340Vectors.swift` — either
`swift package ... codegen bip340` or `swift-tools/generate-bip340-vectors.py`. The four arbitrary-length vectors
(messages of 0, 1, 17 and 100 bytes) required adding auxiliary-randomness support to the
variable-length signer — `schnorrsig_sign_custom` with `extraparams` — which also
validates the `EXTRAPARAMS_MAGIC` constant that has to be repeated in Swift, since a wrong
value aborts rather than failing quietly.

### BIP352, dumped by a C program

`src/modules/silentpayments/vectors.h` is a nested C aggregate initialiser with positional
fields, where a regex would misparse silently. So `swift-tools/bip352-dump.c` `#include`s
it and prints JSON, and the generator compiles and runs it — the C compiler does the
parsing, the same reasoning behind using clang's AST for the API notes. The dumper is a
declared `executableTarget`, so the Swift plugin runs it through
`context.tool(named:)` rather than invoking clang itself.

Upstream's raw `bip352_send_and_receive_test_vectors.json` cannot be used directly: its
`vin` entries are transaction inputs, so recovering the input public keys needs Bitcoin
script parsing (P2TR, P2WPKH, P2PKH, P2SH-P2WPKH). `vectors.h` is upstream's own resolved
form, which is why upstream's C runner uses it too.

Two details in that file are load-bearing, and getting either wrong produces a test that
passes for the wrong reason:

- **Row widths differ** — 32, 33 and 64 bytes. The dumper takes an explicit stride rather
  than an array-typed parameter, which would fix the stride at one width and read every
  row after the first from the wrong offset. That bug happened, and produced public keys
  that would not parse.
- **`full_check`** is upstream's flag, documented in `vectors.h` as *"1..detailed check
  against tweaks and signatures, 0..only check found outputs count"*. Vector 28 uses 0 and
  leaves its expected pubkeys zero-filled, so comparing contents there compares against
  padding.

Three vectors expect *failure*: 25 has no valid inputs, 26's input keys sum to the point at
infinity, and 28 exceeds BIP352's per-group recipient limit. Upstream encodes that as an
empty expected output set, so the tests assert the wrapper throws rather than treating it
as a bug.

### Randomised properties

`PropertyTests.swift` runs nine properties over random inputs — the other gap upstream's
suites have and ours did not. It uses a seeded `xoshiro256**` rather than the system RNG,
because upstream prints its seed so a failure can be replayed, and a fuzz test that cannot
be replayed is a poor trade.

```sh
swift test --filter PropertyTests                      # 64 iterations, fixed seed
SECP256K1_SWIFT_ITERS=512 swift test --filter PropertyTests
SECP256K1_SWIFT_SEED=99 swift test --filter PropertyTests
```

Mirrors upstream's `SECP256K1_TEST_ITERS`. Verified at 512 iterations and under a second
seed.

### Run the Swift tests in release too

The same debug penalty applies as to the C suites, and BIP352 vector 28 scans 2,324
outputs:

| | debug | release |
|---|---|---|
| full Swift suite | 30.8 s | **2.2 s** |

```sh
swift test -c release -Xcc -Wno-shorten-64-to-32
```

## Regenerating: Python scripts or a Swift plugin

Every generated file has two interchangeable generators — the original Python in
`swift-tools/` and a Swift command plugin in `swift-plugins/Codegen`. Both produce
**byte-identical output**, which `--check` makes verifiable rather than hopeful.

```sh
# Swift plugin
swift package --allow-writing-to-package-directory codegen            # all three
swift package --allow-writing-to-package-directory codegen bip340     # just one
swift package --allow-writing-to-package-directory codegen --check    # exit 1 on drift

# Python, unchanged
python3 swift-tools/generate-apinotes.py --check
python3 swift-tools/generate-bip340-vectors.py --check
python3 swift-tools/generate-bip352-vectors.py --check
```

Verified in both directions: the plugin writes all three files, then all three Python
`--check` runs report up to date. Drift is detected — tampering with a generated file
makes `codegen --check` exit 1.

### Why a command plugin and not a build-tool plugin

Not a sandbox limitation — an architectural one. The API notes file is an **input** to
`CSECP256K1`'s committed module map (`publicHeadersPath: "swift-include"`). A build-tool
plugin's outputs land in a work directory that a static module map cannot reference, and
build-tool plugins also cannot write into the package directory at all.

Automatic regeneration would not be desirable anyway. These outputs change only when
upstream is re-vendored, so regenerating per build would cost a ~4 MB clang AST dump for
nothing and make the build less hermetic.

### What the sandbox does and does not allow

Probed before committing to the design. A **command** plugin can:

| capability | result |
|---|---|
| run `clang` via `Process` | works |
| write into the package directory | works, with `--allow-writing-to-package-directory` |
| read upstream files in `src/` and `include/` | works |
| run an executable *target* of this package | works — but only after declaring it in the plugin's `dependencies` |

That last one is easy to miss: without the dependency, `context.tool(named:)` fails with
*"Plugin does not have access to a tool named …"*.

One wart: because the plugin declares `writeToPackageDirectory`, even `--check` requires
`--allow-writing-to-package-directory`. SwiftPM gates on the declared permission, not on
what the invocation actually does.

### What the port did and did not achieve

- **BIP340** ported cleanly — pure text and regex, Swift `Regex` covers it.
- **BIP352** got *better*. The C dumper is now a declared `executableTarget`
  (`bip352-dump`), so SwiftPM builds it and the plugin runs it via `context.tool(named:)`
  — no hand-rolled clang invocation and no compiler flags to keep in sync.
  This also exposed a design flaw worth fixing: the Python driver used to re-serialise the
  dumper's JSON through `json.dumps(indent=1)`, which no Swift API reproduces, making
  byte-identical output impossible. The C program now owns the format and both drivers pass
  its bytes through unchanged.
- **API notes** ported, but it is *not* "pure Swift" and cannot be: it still shells out to
  clang for the JSON AST, and must. Parsing C headers by hand is precisely the fragility
  the design exists to avoid. What became Swift is the driver, not the pipeline.

## What's next

1. Consider known-answer tests for silent payments. Upstream ships
   `src/modules/silentpayments/bip352_send_and_receive_test_vectors.json`; the current
   tests are sender/recipient round-trips, which prove the two sides agree but not that
   they agree with BIP352. Using the vectors needs the JSON bundled as a test resource.
2. Revisit the `MutableSpan` output-parameter ambiguity; if it is a toolchain bug rather
   than expected overload-resolution behaviour, it is worth reducing and reporting.
3. Reduce and report the function-pointer nullability loss under method-form renaming.
4. Consider whether the by-pointer struct out-parameters (`&pubkey`, `&sig`) can be
   improved — they are the last six `unsafe` markers in the wrapper.
