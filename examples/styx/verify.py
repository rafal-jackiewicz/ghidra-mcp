#!/usr/bin/env python3
# Copyright 2026 Rafał Jackiewicz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Differential test: the original C binaries against the Rust reconstruction.

Three experiments, all on the same inputs:
  1. board   - both programs read the same manifest; exit code, stdout, stderr and the
               ledger file must be identical byte for byte.
  2. audit   - both programs read the same (intact and damaged) ledgers.
  3. transplant - the ORIGINAL executable runs with the RECONSTRUCTED library in place of
               its own, and must not notice.

Usage: verify.py [--seed N] [--cases N] [--show N]
"""
import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
C_DIR = os.path.join(HERE, "..", "build", "styx", "linux")
RUST_DIR = os.path.join(HERE, "reconstructed", "target", "release")


def coin(serial):
    return (serial << 8) | ((serial * 31 + 7) % 251)


def ordinary_line(rng):
    name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(1, 23))).capitalize()
    cls = rng.choice("MHPKTmhpkt" * 3 + "XQ")
    sins = rng.choice([0, 1, 99, 100, 249, 250, 251, 4999, 5000, 5249, 5250, 8999, 9000, 9001,
                       65535, 65536, 70000, rng.randint(0, 9500), rng.randint(0, 9500)])
    serial = rng.choice([0, 1, rng.randint(1, 0xFFFFFF), rng.randint(1, 0xFFFFFF)])
    value = coin(serial) if rng.random() < 0.8 else rng.randint(0, 0xFFFFFFFF)
    flags = rng.choice([0, 0, 0, 1, 2, 4, 6, 7, 8, 255, 256, 258])
    return f"{name};{cls};{sins};{value:x};{flags}"


AWKWARD = [
    "   Leading Spaces;M;10;a11c37a;0",          # spaces before the name
    "Two Words;H;10;a11c37a;0",                   # space inside the name
    "Trailing ;M;10;a11c37a;0",                   # space before the separator
    "ExactlyTwentyThreeChars;M;10;a11c37a;0",    # the longest name that fits
    "ExactlyTwentyFourCharsXX;M;10;a11c37a;0",   # one too many
    "AVeryLongNameThatGoesOnAndOnAndOnForever;K;10;a11c37a;0",
    ";M;10;a11c37a;0",                            # no name
    "NoFlags;M;10;a11c37a",                       # a field is missing
    "Extra;M;10;a11c37a;0;surprise",              # a field too many
    "Plus;M;+12;a11c37a;0",                       # explicit sign
    "Minus;M;-1;a11c37a;0",                       # negative sins: saints?
    "HexPrefix;M;10;0xa11c37a;0",                 # 0x in front of the coin
    "UpperHex;M;10;A11C37A;0",
    "SpacedNumbers;M; 10; a11c37a; 0",            # spaces before numbers
    "SpaceAfter;M;10 ;a11c37a;0",                 # space after a number
    "Junk;M;10abc;a11c37a;0",                     # digits followed by letters
    "FlagJunk;M;10;a11c37a;2 and then some",      # text after the last field
    "TwoLetters;MM;10;a11c37a;0",                 # class field too long
    "SpaceClass; ;10;a11c37a;0",                  # a space as the class
    "Tabbed;M;\t10;a11c37a;0",
    "#Commented;M;10;a11c37a;0",
    " #NotAComment;M;10;a11c37a;0",               # the '#' is not in the first column
    "",
    "NotHex;M;10;zzz;0",
    "BigFlags;M;10;a11c37a;4294967295",
    "Semicolons;;;;",
    "LongLine;M;10;a11c37a;0" + " " * 150 + "tail;M;1;a11c37a;0",  # longer than the read buffer
    "Sub\x1astitute;M;10;a11c37a;0",              # Ctrl-Z: an ordinary byte on Linux, end of file on Windows
]


def make_manifest(rng, index):
    lines = ["# generated manifest %d" % index]
    for _ in range(rng.randint(0, 90)):
        lines.append(rng.choice(AWKWARD) if rng.random() < 0.25 else ordinary_line(rng))
    ending = rng.choice(["\n", "\n", "\r\n"])
    text = ending.join(lines)
    if rng.random() < 0.8:
        text += ending
    return text.encode()


def run(exe, *args):
    p = subprocess.run([exe, *args], capture_output=True)
    return p.returncode, p.stdout, p.stderr


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def describe(a, b):
    """First point where two results differ, for a readable report."""
    for label, x, y in zip(("exit code", "stdout", "stderr", "ledger"), a, b):
        if x == y:
            continue
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            return f"{label}: original {x!r}, reconstruction {y!r}"
        if label != "ledger" and x.replace(b"\r\n", b"\n") == y.replace(b"\r\n", b"\n"):
            ends = lambda data: "CR LF" if b"\r\n" in data else "LF"
            return f"{label}: same text, different line ends (original {ends(x)}, reconstruction {ends(y)})"
        xs, ys = x.splitlines(), y.splitlines()
        for i in range(max(len(xs), len(ys))):
            lx = xs[i] if i < len(xs) else b"<nothing>"
            ly = ys[i] if i < len(ys) else b"<nothing>"
            if lx != ly:
                if label == "ledger":
                    return f"ledger differs ({len(x)} vs {len(y)} bytes)"
                return (f"{label}, line {i + 1}:\n      original:       {lx.decode(errors='replace')}"
                        f"\n      reconstruction: {ly.decode(errors='replace')}")
    return "identical"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--show", type=int, default=4, help="how many differences to print per experiment")
    opt = ap.parse_args()

    c_exe = os.path.join(C_DIR, "ferryman")
    rust_exe = os.path.join(RUST_DIR, "ferryman")
    rust_lib = os.path.join(RUST_DIR, "libobol.so")
    for path in (c_exe, os.path.join(C_DIR, "libobol.so"), rust_exe, rust_lib):
        if not os.path.exists(path):
            sys.exit(f"missing {path}\nrun ./build.sh and (cd reconstructed && cargo build --release) first")

    rng = random.Random(opt.seed)
    work = tempfile.mkdtemp(prefix="styx-verify-")
    failures = 0
    try:
        # The transplant: the original executable beside the reconstructed library.
        clinic = os.path.join(work, "transplant")
        os.mkdir(clinic)
        shutil.copy(c_exe, clinic)
        shutil.copy(rust_lib, clinic)
        hybrid_exe = os.path.join(clinic, "ferryman")

        manifests = []
        fixed = os.path.join(HERE, "manifests")
        for name in sorted(os.listdir(fixed)):
            manifests.append((name, read(os.path.join(fixed, name))))
        awkward = "\n".join(AWKWARD).encode() + b"\n"
        manifests.append(("awkward lines", awkward))
        for i in range(opt.cases):
            manifests.append((f"generated #{i}", make_manifest(rng, i)))

        results = {"board": [0, 0, []], "audit": [0, 0, []], "transplant": [0, 0, []]}

        def check(experiment, case, original, other):
            results[experiment][0] += 1
            if original != other:
                results[experiment][1] += 1
                results[experiment][2].append((case, describe(original, other)))

        ledgers = []
        for index, (case, data) in enumerate(manifests):
            m = os.path.join(work, "manifest.txt")
            with open(m, "wb") as f:
                f.write(data)
            outs = {}
            for who, exe in (("c", c_exe), ("rust", rust_exe), ("hybrid", hybrid_exe)):
                ledger = os.path.join(work, f"{who}.ledger")
                if os.path.exists(ledger):
                    os.remove(ledger)
                outs[who] = run(exe, "board", m, ledger) + (read(ledger),)
            check("board", case, outs["c"], outs["rust"])
            check("transplant", case, outs["c"], outs["hybrid"])
            if outs["c"][3] is not None and index < 60:
                ledgers.append((case, outs["c"][3]))

        # Audit: intact ledgers, then ledgers damaged in every way the format can be damaged.
        damaged = []
        for case, good in ledgers:
            damaged.append((case, good))
            if len(good) > 16:
                flipped = bytearray(good)
                flipped[rng.randrange(16, len(good))] ^= 1 << rng.randrange(8)
                damaged.append((case + ", one payload bit flipped", bytes(flipped)))
                damaged.append((case + ", truncated", good[:rng.randrange(16, len(good))]))
                skim = bytearray(good)
                skim[8] ^= 1
                damaged.append((case + ", total altered", bytes(skim)))
            damaged.append((case + ", wrong magic", b"STYZ" + good[4:]))
            damaged.append((case + ", version 2", good[:4] + b"\x02\x00" + good[6:]))
            damaged.append((case + ", count 65", good[:6] + b"\x41\x00" + good[8:]))
            damaged.append((case + ", header cut short", good[:rng.randrange(0, 16)]))
        for case, data in damaged:
            path = os.path.join(work, "audit.ledger")
            with open(path, "wb") as f:
                f.write(data)
            check("audit", case, run(c_exe, "audit", path), run(rust_exe, "audit", path))
        missing = os.path.join(work, "no-such-file")
        check("audit", "missing ledger", run(c_exe, "audit", missing), run(rust_exe, "audit", missing))
        check("board", "missing manifest", run(c_exe, "board", missing, os.devnull),
              run(rust_exe, "board", missing, os.devnull))
        check("board", "no arguments", run(c_exe), run(rust_exe))

        print(f"{'experiment':<12} {'cases':>6} {'identical':>10} {'different':>10}")
        for name, (total, bad, details) in results.items():
            print(f"{name:<12} {total:>6} {total - bad:>10} {bad:>10}")
            failures += bad
        for name, (total, bad, details) in results.items():
            for case, text in details[:opt.show]:
                print(f"\n[{name}] {case}\n    {text}")
            if len(details) > opt.show:
                print(f"\n[{name}] ... and {len(details) - opt.show} more")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\nVERDICT:", "indistinguishable" if failures == 0 else f"{failures} differences found")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
