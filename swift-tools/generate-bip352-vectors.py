#!/usr/bin/env python3
"""Generate swift-test/SECP256K1Test/bip352-vectors.json from upstream.

Compiles swift-tools/bip352-dump.c -- which #includes upstream's
src/modules/silentpayments/vectors.h -- and captures its JSON output. The C
compiler does the parsing, so the positional fields of that nested aggregate
initialiser cannot be silently misread.

Usage:
    python3 swift-tools/generate-bip352-vectors.py            # write
    python3 swift-tools/generate-bip352-vectors.py --check     # verify current
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DUMPER = ROOT / "swift-tools/bip352-dump.c"
OUTPUT = ROOT / "swift-test/SECP256K1Test/bip352-vectors.json"


def build() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        binary = pathlib.Path(tmp) / "bip352-dump"
        compile_cmd = ["clang", "-O1", "-std=c90", "-o", str(binary), str(DUMPER)]
        proc = subprocess.run(compile_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.exit(f"compiling the dumper failed:\n{proc.stderr[:2000]}")
        proc = subprocess.run([str(binary)], capture_output=True, text=True)
        if proc.returncode != 0:
            sys.exit(f"running the dumper failed:\n{proc.stderr[:2000]}")
    # The dumper's output is written through verbatim. Re-serialising it here
    # would make byte-identical output from the Swift port impossible: Python's
    # json.dumps(indent=1) and Swift's JSONSerialization.prettyPrinted disagree
    # on indentation. The C program owns the format; both drivers pass bytes
    # along. json.loads is still called, as a check that it is parseable.
    json.loads(proc.stdout)
    return proc.stdout


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
    data = json.loads(text)
    subtests = sum(len(v["receive_subtests"]) for v in data)
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(data)} vectors, {subtests} receive subtests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
