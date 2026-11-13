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

"""Differential test of the Windows builds, run on a real Windows machine.

The test cases are produced on the Linux host, executed on Windows, and judged on the host:

  verify_windows.py prepare BUNDLE.zip     write the test bundle (binaries, cases, run.cmd)
      ... copy BUNDLE.zip to Windows, unpack it, run "run.cmd", pack the "out" folder ...
  verify_windows.py compare OUT.zip        compare what the three configurations produced

The bundle contains three configurations of the same program:
  orig        ferryman.exe + obol.dll as built from the original C sources (MinGW)
  rust        ferryman.exe built from the Rust reconstruction
  transplant  the ORIGINAL ferryman.exe beside the RECONSTRUCTED obol.dll

How the bundle travels is up to you: a shared folder, scp, or the QEMU guest agent when the
guest has no network at all.
"""
import argparse
import io
import os
import random
import subprocess
import sys
import tempfile
import zipfile

import verify  # the generator and the report format of the Linux test

HERE = os.path.dirname(os.path.abspath(__file__))
WIN_C = os.path.join(HERE, "..", "build", "styx", "windows")
WIN_RUST = os.path.join(HERE, "reconstructed", "target", "x86_64-pc-windows-gnu", "release")
LINUX_C = os.path.join(HERE, "..", "build", "styx", "linux", "ferryman")
CONFIGS = ("orig", "rust", "transplant")


def cases(seed, count):
    rng = random.Random(seed)
    manifests = []
    fixed = os.path.join(HERE, "manifests")
    for name in sorted(os.listdir(fixed)):
        manifests.append((name, verify.read(os.path.join(fixed, name))))
    manifests.append(("awkward lines", "\n".join(verify.AWKWARD).encode() + b"\n"))
    for i in range(count):
        manifests.append((f"generated #{i}", verify.make_manifest(rng, i)))
    return manifests, rng


def damaged_ledgers(manifests, rng, limit=60):
    """Ledgers written by the Linux original, intact and damaged. Windows must judge them alike."""
    out = []
    with tempfile.TemporaryDirectory() as work:
        for case, data in manifests[:limit]:
            m, l = os.path.join(work, "m.txt"), os.path.join(work, "l.bin")
            with open(m, "wb") as f:
                f.write(data)
            subprocess.run([LINUX_C, "board", m, l], capture_output=True)
            good = verify.read(l)
            if good is None:
                continue
            out.append((case, good))
            if len(good) > 16:
                flipped = bytearray(good)
                flipped[rng.randrange(16, len(good))] ^= 1 << rng.randrange(8)
                out.append((case + ", one payload bit flipped", bytes(flipped)))
                out.append((case + ", truncated", good[:rng.randrange(16, len(good))]))
                skim = bytearray(good)
                skim[8] ^= 1
                out.append((case + ", total altered", bytes(skim)))
            out.append((case + ", wrong magic", b"STYZ" + good[4:]))
            out.append((case + ", version 2", good[:4] + b"\x02\x00" + good[6:]))
            out.append((case + ", count 65", good[:6] + b"\x41\x00" + good[8:]))
            out.append((case + ", header cut short", good[:rng.randrange(0, 16)]))
    return out


def prepare(opt):
    manifests, rng = cases(opt.seed, opt.cases)
    ledgers = damaged_ledgers(manifests, rng)
    script = ["@echo off", "cd /d %~dp0", "if exist out rmdir /s /q out"]
    for config in CONFIGS:
        script.append(f"mkdir out\\{config}")
    index = []
    with zipfile.ZipFile(opt.bundle, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(WIN_C, "ferryman.exe"), "orig/ferryman.exe")
        z.write(os.path.join(WIN_C, "obol.dll"), "orig/obol.dll")
        z.write(os.path.join(WIN_RUST, "ferryman.exe"), "rust/ferryman.exe")
        z.write(os.path.join(WIN_C, "ferryman.exe"), "transplant/ferryman.exe")
        z.write(os.path.join(WIN_RUST, "obol.dll"), "transplant/obol.dll")
        for i, (case, data) in enumerate(manifests):
            z.writestr(f"cases/m{i:04d}.txt", data)
            index.append(f"m{i:04d}\t{case}")
            for config in CONFIGS:
                base = f"out\\{config}\\m{i:04d}"
                script.append(f"{config}\\ferryman.exe board cases\\m{i:04d}.txt {base}.ledger > {base}.out 2> {base}.err")
                script.append(f"echo %ERRORLEVEL% > {base}.rc")
        for i, (case, data) in enumerate(ledgers):
            z.writestr(f"ledgers/a{i:04d}.bin", data)
            index.append(f"a{i:04d}\t{case}")
            for config in ("orig", "rust"):
                base = f"out\\{config}\\a{i:04d}"
                script.append(f"{config}\\ferryman.exe audit ledgers\\a{i:04d}.bin > {base}.out 2> {base}.err")
                script.append(f"echo %ERRORLEVEL% > {base}.rc")
        script.append("echo done > out\\finished.txt")
        z.writestr("run.cmd", "\r\n".join(script) + "\r\n")
        z.writestr("index.txt", "\n".join(index) + "\n")
    print(f"{opt.bundle}: {len(manifests)} manifests, {len(ledgers)} ledgers, {len(script)} commands")
    print("On Windows: unpack, run run.cmd, then pack the folder 'out' and bring it back.")


def compare(opt):
    with zipfile.ZipFile(opt.results) as z:
        files = {name.replace("\\", "/"): z.read(name) for name in z.namelist()}
    prefix = "out/" if any(n.startswith("out/") for n in files) else ""
    names = {}
    if opt.bundle and os.path.exists(opt.bundle):
        with zipfile.ZipFile(opt.bundle) as z:
            for line in z.read("index.txt").decode().splitlines():
                key, case = line.split("\t", 1)
                names[key] = case

    def result(config, key):
        base = f"{prefix}{config}/{key}"
        rc = files.get(base + ".rc")
        if rc is None:
            return None
        return (int(rc.split()[0]), files.get(base + ".out", b""), files.get(base + ".err", b""),
                files.get(base + ".ledger"))

    keys = sorted({n.split("/")[-1].split(".")[0] for n in files if n.endswith(".rc")})
    table = {"board": [0, 0, []], "audit": [0, 0, []], "transplant": [0, 0, []]}

    def check(experiment, key, a, b):
        if a is None or b is None:
            return
        table[experiment][0] += 1
        if a != b:
            table[experiment][1] += 1
            table[experiment][2].append((names.get(key, key), verify.describe(a, b)))

    for key in keys:
        orig = result("orig", key)
        if key.startswith("m"):
            check("board", key, orig, result("rust", key))
            check("transplant", key, orig, result("transplant", key))
        else:
            check("audit", key, orig, result("rust", key))

    print(f"{'experiment':<12} {'cases':>6} {'identical':>10} {'different':>10}")
    failures = 0
    for name, (total, bad, details) in table.items():
        print(f"{name:<12} {total:>6} {total - bad:>10} {bad:>10}")
        failures += bad
    for name, (total, bad, details) in table.items():
        for case, text in details[:opt.show]:
            print(f"\n[{name}] {case}\n    {text}")
        if len(details) > opt.show:
            print(f"\n[{name}] ... and {len(details) - opt.show} more")
    print("\nVERDICT (Windows):", "indistinguishable" if failures == 0 else f"{failures} differences found")

    if opt.linux:
        # How does the Windows original compare with the Linux original on the same manifests?
        same = crlf_only = other = 0
        examples = []
        with zipfile.ZipFile(opt.bundle) as z, tempfile.TemporaryDirectory() as work:
            for key in keys:
                if not key.startswith("m"):
                    continue
                m, l = os.path.join(work, "m.txt"), os.path.join(work, "l.bin")
                with open(m, "wb") as f:
                    f.write(z.read(f"cases/{key}.txt"))
                if os.path.exists(l):
                    os.remove(l)
                p = subprocess.run([LINUX_C, "board", m, l], capture_output=True)
                lin = (p.returncode, p.stdout, p.stderr, verify.read(l))
                win = result("orig", key)
                if win == lin:
                    same += 1
                elif (win[0], win[1].replace(b"\r\n", b"\n"), win[2].replace(b"\r\n", b"\n"), win[3]) == lin:
                    crlf_only += 1
                else:
                    other += 1
                    if len(examples) < opt.show:
                        examples.append((names.get(key, key), verify.describe(
                            lin, (win[0], win[1].replace(b"\r\n", b"\n"), win[2].replace(b"\r\n", b"\n"), win[3]))))
        print("\nWindows original against Linux original, same manifests:")
        print(f"  byte-identical                         {same}")
        print(f"  identical apart from CR LF line ends   {crlf_only}")
        print(f"  different in substance                 {other}")
        for case, text in examples:
            print(f"\n[platform] {case}\n    {text}".replace("original:", "linux:  ").replace("reconstruction:", "windows:"))
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("bundle")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--cases", type=int, default=300)
    c = sub.add_parser("compare")
    c.add_argument("results")
    c.add_argument("--bundle", default="bundle.zip", help="the bundle the results came from (for case names)")
    c.add_argument("--show", type=int, default=4)
    c.add_argument("--linux", action="store_true", help="also compare the Windows original with the Linux original")
    opt = ap.parse_args()
    return prepare(opt) if opt.command == "prepare" else compare(opt)


if __name__ == "__main__":
    sys.exit(main())
