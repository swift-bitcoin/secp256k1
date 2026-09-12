#!/usr/bin/env python3
"""Generate swift-include/CSECP256K1.apinotes from upstream's headers.

The Swift blog post this project follows
(https://www.swift.org/blog/improving-usability-of-c-libraries-in-swift/)
recommends generating API notes rather than hand-writing them, and prefers a
real AST over regex. That is what this does: parameter names, types and order
come from clang's JSON AST, so the positional indices API notes rely on are
never transcribed by hand.

Only one thing is read from the header text: the SECP256K1_ARG_NONNULL(k)
macro, whose argument indices clang's JSON AST does not preserve. That macro is
trivially regular, so a regex is appropriate there and nowhere else.

Usage:
    python3 swift-tools/generate-apinotes.py            # write the file
    python3 swift-tools/generate-apinotes.py --check    # fail if out of date
    python3 swift-tools/generate-apinotes.py --report    # list skipped buffers
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
INCLUDE = ROOT / "include"
OUTPUT = ROOT / "swift-include" / "CSECP256K1.apinotes"
MODULE = "CSECP256K1"

HEADERS = [
    "secp256k1.h",
    "secp256k1_preallocated.h",
    "secp256k1_ecdh.h",
    "secp256k1_ellswift.h",
    "secp256k1_extrakeys.h",
    "secp256k1_musig.h",
    "secp256k1_recovery.h",
    "secp256k1_schnorrsig.h",
    "secp256k1_silentpayments.h",
]

CONTEXT_TYPES = ("const secp256k1_context *", "secp256k1_context *")

# Byte buffers whose length is fixed by upstream convention but absent from the
# parameter name. Every occurrence of `seckey` in the public headers is
# documented as "a 32-byte secret key" -- verified across all 11 uses. Anything
# not covered by a rule or this table is SKIPPED, never guessed; run --report to
# see what was left out and why.
NAMED_BOUNDS = {"seckey": 32}

# Buffers deliberately left unannotated, with the reason. These are not
# oversights: annotating them would be wrong.
SKIP_REASONS = {
    ("secp256k1_ecdh", "output"):
        "length depends on the caller's hashfp; only 32 for the default hash",
    ("secp256k1_ellswift_xdh", "output"):
        "length depends on the caller's hashfp",
    ("secp256k1_silentpayments_sender_create_outputs", "seckeys"):
        "array of pointers, not a byte buffer",
}

# Hand-chosen Swift names, kept because they read better than the mechanical
# transformation and because the test suite pins them. Everything else gets a
# predictable mechanical name.
NAME_OVERRIDES = {
    "secp256k1_context_create": "secp256k1_context.init(flags:)",
    "secp256k1_context_destroy": "secp256k1_context.destroy(self:)",
    "secp256k1_context_clone": "secp256k1_context.clone(self:)",
    "secp256k1_ec_seckey_verify": "secp256k1_context.verifySecretKey(self:_:)",
    "secp256k1_ec_pubkey_create": "secp256k1_context.createPublicKey(self:_:secretKey:)",
    "secp256k1_ec_pubkey_parse": "secp256k1_context.parsePublicKey(self:_:from:length:)",
    "secp256k1_ecdsa_signature_parse_compact":
        "secp256k1_context.parseSignature(self:_:compact:)",
    "secp256k1_ecdsa_signature_serialize_compact":
        "secp256k1_context.serializeSignature(self:into:_:)",
    "secp256k1_ecdsa_sign":
        "secp256k1_context.sign(self:_:messageHash:secretKey:nonceFunction:nonceData:)",
    "secp256k1_ecdsa_verify":
        "secp256k1_context.verify(self:_:messageHash:publicKey:)",
}

GLOBAL_OVERRIDES = {"secp256k1_context_static": "secp256k1_context.shared"}

# Tokens that should not be title-cased into "Rfc6979" / "Sha256". Applied to
# every word except the first, which stays lowercase to keep lowerCamelCase.
ACRONYMS = {
    "rfc6979": "RFC6979",
    "sha256": "SHA256",
    "bip324": "BIP324",
    "bip340": "BIP340",
    "bip352": "BIP352",
    "xdh": "XDH",
    "der": "DER",
    "ecdh": "ECDH",
    "ecdsa": "ECDSA",
    "musig": "MuSig",
    "xonly": "XOnly",
}


def clang() -> str:
    """The pinned toolchain's clang, not whatever is first on PATH."""
    for candidate in (
        pathlib.Path.home() / ".swiftly/bin/swiftly",
    ):
        if candidate.exists():
            out = subprocess.run(
                ["swiftly", "run", "clang", "--version"],
                capture_output=True, text=True,
            )
            if out.returncode == 0:
                return "swiftly-run"
    return "clang"


def dump_ast() -> dict:
    """clang's JSON AST for a TU including every public header."""
    with tempfile.TemporaryDirectory() as tmp:
        tu = pathlib.Path(tmp) / "all_headers.c"
        tu.write_text("".join(f'#include "{h}"\n' for h in HEADERS))
        cmd = ["clang", "-Xclang", "-ast-dump=json", "-fsyntax-only",
               "-I", str(INCLUDE), str(tu)]
        if clang() == "swiftly-run":
            cmd = ["swiftly", "run"] + cmd
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.exit(f"clang failed:\n{proc.stderr[:2000]}")
        return json.loads(proc.stdout)


def nonnull_indices() -> dict[str, set[int]]:
    """{function name -> 1-based indices marked SECP256K1_ARG_NONNULL}.

    Read from the header text because clang's JSON AST records a NonNullAttr
    node but drops its argument indices.
    """
    out: dict[str, set[int]] = {}
    for header in HEADERS:
        src = (INCLUDE / header).read_text()
        for chunk in re.split(r"\bSECP256K1_API\b", src)[1:]:
            decl = chunk.split(";", 1)[0]
            m = re.search(r"(\w+)\s*\(", decl)
            if not m:
                continue            # a global, not a function
            name = m.group(1)
            idx = {int(i) for i in re.findall(r"SECP256K1_ARG_NONNULL\((\d+)\)", decl)}
            out.setdefault(name, set()).update(idx)
    return out


def camel(snake: str) -> str:
    head, *rest = snake.split("_")
    out = [head]
    for w in rest:
        if not w:
            continue
        out.append(ACRONYMS.get(w) or (w[:1].upper() + w[1:]))
    return "".join(out)


def is_pointer(qual_type: str) -> bool:
    return qual_type.rstrip().endswith("*")


def is_function_pointer(qual_type: str) -> bool:
    # The public typedefs are all function pointers: secp256k1_nonce_function etc.
    return qual_type.startswith("secp256k1_") and "function" in qual_type


def bound_for(pname: str, params: list[tuple[str, str]]) -> tuple[str, object] | None:
    """Return ("counted_by", bound) or None if no rule applies."""
    m = re.search(r"(\d+)$", pname or "")
    if m:
        return ("counted_by", int(m.group(1)))
    for other, otype in params:
        if otype == "size_t" and other == f"{pname}len":
            return ("counted_by", other)
    if pname in NAMED_BOUNDS:
        return ("counted_by", NAMED_BOUNDS[pname])
    return None


def build() -> tuple[str, list[str]]:
    ast = dump_ast()
    nonnull = nonnull_indices()
    skipped: list[str] = []

    funcs = []
    for node in ast.get("inner", []):
        if node.get("kind") != "FunctionDecl":
            continue
        name = node.get("name", "")
        if not name.startswith("secp256k1_"):
            continue
        params = [
            (p.get("name") or "", p["type"]["qualType"])
            for p in node.get("inner", [])
            if p.get("kind") == "ParmVarDecl"
        ]
        ret = node["type"]["qualType"].split("(", 1)[0].strip()
        funcs.append((name, params, ret, node))

    lines: list[str] = []
    lines.append("---")
    lines.append("# GENERATED FILE -- do not edit by hand.")
    lines.append("#")
    lines.append("# Regenerate with either front-end (both produce identical output):")
    lines.append("#     swift package --allow-writing-to-package-directory codegen apinotes")
    lines.append("#     python3 swift-tools/generate-apinotes.py")
    lines.append("# Add --check to verify instead of writing.")
    lines.append("#")
    lines.append("# Parameter names, types and positions come from clang's JSON AST, so the")
    lines.append("# positional indices below are never transcribed by hand. Naming choices,")
    lines.append("# fixed-size conventions and deliberate omissions live in the generator.")
    lines.append("#")
    lines.append("# See README-Swift.md for what each key does and why it is needed.")
    lines.append(f"Name: {MODULE}")
    lines.append("")

    # --- Tags ---------------------------------------------------------------
    lines.append("Tags:")
    lines.append("# The opaque context imports as OpaquePointer without this -- no type safety")
    lines.append("# and an unsafe type under strict memory safety. Retain/release are both")
    lines.append("# `immortal` because a retain must return the pointer it was given and")
    lines.append("# secp256k1_context_clone allocates a new context instead, so ARC cannot")
    lines.append("# manage the lifetime. Destruction stays explicit; Secp256k1Context owns it.")
    lines.append("- Name: secp256k1_context_struct")
    lines.append("  SwiftImportAs: reference")
    lines.append("  SwiftRetainOp: immortal")
    lines.append("  SwiftReleaseOp: immortal")
    lines.append("")

    # --- Functions ----------------------------------------------------------
    lines.append("Functions:")
    for name, params, ret, _node in sorted(funcs):
        entry: list[str] = []
        nn = nonnull.get(name, set())

        # Swift name: override, or mechanical method form when the first
        # parameter is the context.
        swift_name = NAME_OVERRIDES.get(name)
        if swift_name is None and params and params[0][1] in CONTEXT_TYPES:
            base = camel(name[len("secp256k1_"):])
            labels = "self:" + "".join(f"{camel(p or '_')}:" for p, _ in params[1:])
            swift_name = f"secp256k1_context.{base}({labels})"
        if swift_name:
            entry.append(f'  SwiftName: "{swift_name}"')

        # Nullable pointer return.
        if is_pointer(ret):
            entry.append("  NullabilityOfRet: O")

        # Parameters: bounds for byte buffers, nullability for anything
        # upstream left unmarked.
        param_lines: list[str] = []
        for i, (pname, ptype) in enumerate(params):
            keys: list[str] = []
            if "unsigned char *" in ptype and "*const *" not in ptype:
                if (name, pname) in SKIP_REASONS:
                    skipped.append(f"{name}({pname}): {SKIP_REASONS[(name, pname)]}")
                else:
                    bound = bound_for(pname, params)
                    if bound is None:
                        sizeptr = [o for o, t in params if t == "size_t *"]
                        why = (f"length is *{sizeptr[0]}, an in/out pointer "
                               "that BoundedBy cannot reference"
                               if sizeptr else "no length parameter and no size in the name")
                        skipped.append(f"{name}({pname}): {why}")
                    else:
                        kind, b = bound
                        keys.append("    NoEscape: true")
                        keys.append(f"    BoundsSafety: {{ Kind: {kind}, BoundedBy: {b} }}")
            # Nullability is stated for EVERY pointer parameter, N or O, not
            # just the nullable ones. Two reasons:
            #
            #  * An unannotated pointer imports implicitly unwrapped, which is
            #    the worst of both worlds -- and after a method-form rename it
            #    can come through wrongly non-optional instead.
            #  * Annotating only some parameters is actively harmful: giving one
            #    parameter explicit nullability drops the others back to
            #    implicitly unwrapped, even where upstream's
            #    SECP256K1_ARG_NONNULL had already made them non-optional.
            #    Observed on secp256k1_keypair_xonly_pub, where annotating the
            #    optional pk_parity regressed the non-null keypair to `!`.
            #
            # So each function this generator touches gets a complete
            # nullability audit, mirroring the ASSUME_NONNULL_BEGIN advice in
            # the blog post's postscript.
            if is_pointer(ptype) or is_function_pointer(ptype):
                keys.append(f"    Nullability: {'N' if (i + 1) in nn else 'O'}")
            if keys:
                param_lines.append(f"  - Position: {i}          # {pname}")
                param_lines.extend(keys)

        if param_lines:
            entry.append("  Parameters:")
            entry.extend(param_lines)

        if entry:
            lines.append(f"- Name: {name}")
            lines.extend(entry)
    lines.append("")

    # --- Globals ------------------------------------------------------------
    globals_: list[tuple[str, str]] = []
    for header in HEADERS:
        src = (INCLUDE / header).read_text()
        for chunk in re.split(r"\bSECP256K1_API\b", src)[1:]:
            decl = chunk.split(";", 1)[0]
            if "(" in decl:
                continue
            m = re.findall(r"(\w+)", decl)
            if m:
                globals_.append((m[-1], decl.strip()))

    lines.append("Globals:")
    lines.append("# None of upstream's exported constants is ever NULL, so `N` drops the")
    lines.append("# implicitly-unwrapped optional each would otherwise import as.")
    lines.append("#")
    lines.append("# secp256k1_context.shared must NEVER be destroyed, which is why")
    lines.append("# Secp256k1Context does not wrap it -- that class's deinit owns destroy().")
    for gname, _decl in sorted(set(globals_)):
        swift = GLOBAL_OVERRIDES.get(gname) or camel(gname[len("secp256k1_"):])
        lines.append(f"- Name: {gname}")
        lines.append(f'  SwiftName: "{swift}"')
        lines.append("  Nullability: N")

    return "\n".join(lines) + "\n", sorted(set(skipped))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed file is out of date")
    ap.add_argument("--report", action="store_true",
                    help="list byte buffers left unannotated, with reasons")
    args = ap.parse_args()

    text, skipped = build()

    if args.report:
        print(f"{len(skipped)} byte buffer(s) left unannotated:\n")
        for s in skipped:
            print(f"  {s}")
        return 0

    if args.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != text:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date; regenerate it.",
                  file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is up to date.")
        return 0

    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    if skipped:
        print(f"{len(skipped)} byte buffer(s) left unannotated "
              f"(run --report for details)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
