#!/usr/bin/env python3
"""Extract BIP340 test vectors from upstream's C tests into Swift.

Upstream ships the BIP340 vectors only as C array literals inside
src/modules/schnorrsig/tests_impl.h -- unlike Wycheproof and BIP352, there is no
JSON to read at runtime. Rather than transcribe 19 vectors by hand (the kind of
task that produced a one-character error the first time round), this extracts
them and emits Swift.

Usage:
    python3 swift-tools/generate-bip340-vectors.py            # write
    python3 swift-tools/generate-bip340-vectors.py --check     # verify current
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src/modules/schnorrsig/tests_impl.h"
OUTPUT = ROOT / "swift-test/SECP256K1Test/BIP340Vectors.swift"


def arrays(block: str) -> dict[str, list[int]]:
    """Every `const unsigned char name[...] = { 0x.., ... };` in the block."""
    out: dict[str, list[int]] = {}
    for m in re.finditer(r'(?:const )?unsigned char (\w+)\[\d*\]\s*=\s*\{(.*?)\};',
                         block, re.S):
        out[m.group(1)] = [int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', m.group(2))]
    return out


def message(block: str, found: dict[str, list[int]]) -> list[int]:
    """The message, which appears in four different shapes."""
    # memset(msg, 0xNN, sizeof(msg)) over a fixed-size declaration
    decl = re.search(r'unsigned char msg\[(\d+)\];', block)
    fill = re.search(r'memset\(msg,\s*(0x[0-9A-Fa-f]+|\d+),', block)
    if decl and fill:
        return [int(fill.group(1), 16 if fill.group(1).startswith("0x") else 10)] * int(decl.group(1))
    # NULL, 0 -- the empty message
    if re.search(r'check_signing\([^;]*?,\s*NULL,\s*0,', block, re.S):
        return []
    return found.get("msg", [])


def swift_bytes(data: list[int]) -> str:
    if not data:
        return "[]"
    rows = []
    for i in range(0, len(data), 12):
        rows.append(", ".join(f"0x{b:02X}" for b in data[i:i + 12]))
    joined = ",\n            ".join(rows)
    return "[\n            " + joined + ",\n        ]"


def build() -> str:
    src = SOURCE.read_text()
    start = src.index("static void test_schnorrsig_bip_vectors(void)")
    body = src[start:src.index("\n}\n", start)]
    blocks = body.split("\n    {\n")[1:]

    entries = []
    for n, block in enumerate(blocks, start=1):
        found = arrays(block)
        label = re.search(r'/\* (Test vector \d+[^*]*?)\s*\*/', block)
        name = label.group(1) if label else f"block {n}"

        signing = "check_signing(" in block
        verifies = re.findall(r'check_verify\((.*?)\);', block, re.S)
        parse_only = not signing and not verifies and "xonly_pubkey_parse" in block

        if parse_only:
            entries.append(dict(
                name=name, publicKey=found["pk"], parses=False,
                secretKey=None, auxRandom=None, msg=[], signature=None, verifies=False))
            continue

        expected = verifies[0].strip().split(",")[-1].strip() if verifies else "1"
        entries.append(dict(
            name=name,
            publicKey=found["pk"],
            parses=True,
            secretKey=found.get("sk"),
            auxRandom=found.get("aux_rand"),
            msg=message(block, found),
            signature=found.get("sig"),
            verifies=(expected == "1")))

    lines = [
        "// GENERATED FILE -- do not edit by hand.",
        "//",
        "// Regenerate with either front-end (both produce identical output):",
        "//     swift package --allow-writing-to-package-directory codegen bip340",
        "//     python3 swift-tools/generate-bip340-vectors.py",
        "// Add --check to verify instead of writing.",
        "//",
        "// Extracted from src/modules/schnorrsig/tests_impl.h, which is upstream's own",
        "// copy of the BIP340 test vectors. Upstream ships these only as C array",
        "// literals, so unlike Wycheproof and BIP352 they cannot be read at runtime.",
        "",
        "/// One BIP340 vector.",
        "struct BIP340Vector: Sendable {",
        "    let name: String",
        "    /// 32-byte x-only public key.",
        "    let publicKey: [UInt8]",
        "    /// False for the vectors whose public key is not a valid x coordinate.",
        "    let publicKeyParses: Bool",
        "    /// Present only for the sign-and-verify vectors.",
        "    let secretKey: [UInt8]?",
        "    let auxRandom: [UInt8]?",
        "    /// Any length: the later vectors cover BIP340's arbitrary-size messages.",
        "    let message: [UInt8]",
        "    let signature: [UInt8]?",
        "    /// Whether verification must succeed.",
        "    let verifies: Bool",
        "}",
        "",
        f"/// All {len(entries)} vectors, in upstream's order.",
        "let bip340Vectors: [BIP340Vector] = [",
    ]
    for e in entries:
        lines.append("    BIP340Vector(")
        lines.append(f'        name: "{e["name"]}",')
        lines.append(f'        publicKey: {swift_bytes(e["publicKey"])},')
        lines.append(f'        publicKeyParses: {"true" if e["parses"] else "false"},')
        for key, field in (("secretKey", "secretKey"), ("auxRandom", "auxRandom")):
            v = e[key]
            lines.append(f'        {field}: {swift_bytes(v) if v else "nil"},')
        lines.append(f'        message: {swift_bytes(e["msg"])},')
        sig = e["signature"]
        lines.append(f'        signature: {swift_bytes(sig) if sig else "nil"},')
        lines.append(f'        verifies: {"true" if e["verifies"] else "false"}),')
    lines.append("]")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = build()
    if args.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != text:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date; regenerate it.", file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is up to date.")
        return 0
    OUTPUT.write_text(text)
    n = text.count("BIP340Vector(")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({n} vectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
