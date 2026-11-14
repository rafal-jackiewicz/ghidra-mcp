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

"""Black-box study of the original ferryman: no disassembler, no decompiler.

Everything this script learns, it learns by running the program with chosen manifests and
reading what the program prints and writes. It then states each finding as a rule and
counts how many observations agree with it.

Usage: blackbox.py [--exe PATH] [--seal]

  --seal   also identify the generator behind the ledger's seal by trying textbook
           generators with every possible seed (needs numpy, takes a few minutes)
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
COIN = 0xA11C37A  # taken from the client's own sample manifest, where it is accepted

# What the seal search finds (see --seal). Used by the later steps when the search is skipped.
SEAL = dict(name="Numerical Recipes", a=1664525, c=1013904223, shift=24, key=0x58595453)

runs = 0


class Bench:
    def __init__(self, exe):
        self.exe = exe
        self.work = tempfile.mkdtemp(prefix="styx-blackbox-")

    def board(self, lines):
        """One run. lines are bytes. Returns (rows, summary, ledger bytes, raw stdout)."""
        global runs
        runs += 1
        m, l = os.path.join(self.work, "m.txt"), os.path.join(self.work, "l.bin")
        with open(m, "wb") as f:
            f.write(b"".join(line + b"\n" for line in lines))
        if os.path.exists(l):
            os.remove(l)
        p = subprocess.run([self.exe, "board", m, l], capture_output=True)
        out = p.stdout.split(b"\n")[:-1]
        rows = []
        for row in out[:-1]:
            rest = row[25:].decode()
            rows.append(("REFUSED", rest[9:]) if rest.startswith("REFUSED") else (rest[:8].rstrip(), int(rest[8:])))
        ledger = open(l, "rb").read() if os.path.exists(l) else None
        return rows, out[-1].decode() if out else "", ledger, p.stdout

    def each(self, lines):
        """Many lines, 64 to a boat (a 65th passenger is refused because the boat is full)."""
        rows = []
        for i in range(0, len(lines), 64):
            rows += self.board(lines[i:i + 64])[0]
        return rows


def line(name, cls, sins, coin, flags):
    return f"{name};{cls};{sins};{coin:x};{flags}".encode()


def fnv1a(data):
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def keystream(seed, n, a, c, shift, **_):
    out, state = bytearray(), seed
    for _ in range(n):
        state = (state * a + c) & 0xFFFFFFFF
        out.append((state >> shift) & 255)
    return bytes(out)


def record(name, cls, sins, coin, flags, fare):
    return name.encode().ljust(24, b"\0") + struct.pack("<HBBII", sins, cls, flags & 255, coin, fare)


def say(step, text=""):
    print(f"{step:<11}{text}")


def fares(bench):
    base, table = {}, {}
    for cls in "MHPKT":
        rows = bench.each([line("p", cls, s, COIN, 0) for s in range(0, 9003)])
        table[cls] = [r[1] for r in rows]
        base[cls] = table[cls][250] - 1
    m = table["M"]
    steps = [s for s in range(1, 9001) if m[s] != m[s - 1]]
    say("1 fares", f"{5 * 9003} passengers observed: five classes, 0 to 9002 sins each")
    say("", "fare at 250 sins, less one: " + ", ".join(f"{c} {base[c]}" for c in "MHPKT"))
    say("", f"the fare rises by 1 at {steps[0]}, {steps[1]}, {steps[2]} ... {steps[-1]} sins, {len(steps)} times in all")
    say("", f"first refusal at {m.index('too many sins for one boat')} sins: \"too many sins for one boat\"")

    def rule(cls, s):
        if s > 9000:
            return "too many sins for one boat"
        return 0 if cls == "P" and s < 100 else base[cls] + min(s // 250, 20)

    agree = sum(table[c][s] == rule(c, s) for c in "MHPKT" for s in range(0, 9003))
    say("", f"RULE  fare = base + min(sins div 250, 20); refused above 9000: {agree} of {5 * 9003} agree")
    return base


def flags(bench):
    cases = [(c, s) for c in "MHPKT" for s in (0, 99, 100, 600, 6000, 9000)]
    seen = {fl: [r[1] for r in bench.each([line("q", c, s, COIN, fl) for c, s in cases])] for fl in range(0, 260)}
    plain = seen[0]
    say("2 flags", f"{260 * len(cases)} passengers observed: flags 0 to 259")
    mortal = [i for i, (c, s) in enumerate(cases) if c == "M" and s in (0, 600, 6000)]
    for fl in (2, 4, 6):
        say("", f"flags {fl}: a mortal's fares {[plain[i] for i in mortal]} become {[seen[fl][i] for i in mortal]}")
    p99, p100 = cases.index(("P", 99)), cases.index(("P", 100))
    say("", f"a poet with flags 2 pays {seen[2][p99]} at 99 sins and {seen[2][p100]} at 100: under 100 sins poets are exempt")

    def rule(fl, f):
        fl &= 255
        if fl & 1:
            return "unburied: come back in a hundred years"
        if fl & 2:
            f = f * 2 + 1
        if fl & 4:
            f *= 3
        return f

    def expect(fl, i):
        cls, sins = cases[i]
        if cls == "P" and sins < 100:        # free passage stays free
            return "unburied: come back in a hundred years" if fl & 1 else 0
        return rule(fl, plain[i])

    agree = sum(seen[fl][i] == expect(fl, i) for fl in seen for i in range(len(cases)))
    say("", f"RULE  bit 0 refuses; bit 1: 2f+1; then bit 2: 3f; the rest ignored: {agree} of {260 * len(cases)} agree")


def classes(bench):
    letters = [b for b in range(1, 256) if b not in (10, 13)]
    rows = bench.each([b"c;" + bytes([b]) + f";0;{COIN:x};0".encode() for b in letters])
    ok = {}
    for b, r in zip(letters, rows):
        if r[0] != "REFUSED":
            ok.setdefault(r[0], []).append(chr(b))
    say("3 classes", f"{len(letters)} byte values tried as the class; accepted: " +
        ", ".join(f"{''.join(v)} {k}" for k, v in ok.items()))


def coins(bench):
    accepted = {}
    for serial in range(0, 301):
        rows = bench.each([line("c", "M", 0, (serial << 8) | c, 0) for c in range(256)])
        accepted[serial] = [c for c, r in enumerate(rows) if r[0] != "REFUSED"]
    say("4 coins", f"{301 * 256} coins observed: serials 0 to 300, every value of the last byte")
    say("", f"serial 0: {len(accepted[0])} accepted.  Serials 1 to 300: exactly one each: "
            f"{all(len(accepted[s]) == 1 for s in range(1, 301))}")
    say("", "the accepted byte for serials 1 to 10: " + " ".join(str(accepted[s][0]) for s in range(1, 11)))
    say("", f"largest accepted byte: {max(accepted[s][0] for s in range(1, 301))}; "
            f"step from one serial to the next, modulo 251: "
            f"{sorted({(accepted[s + 1][0] - accepted[s][0]) % 251 for s in range(1, 300)})}")
    rng = random.Random(7)
    serials = [rng.randrange(1, 1 << 24) for _ in range(6400)]
    good = bench.each([line("c", "M", 0, (s << 8) | ((s * 31 + 7) % 251), 0) for s in serials])
    near = bench.each([line("c", "M", 0, (s << 8) | ((s * 31 + 8) % 251), 0) for s in serials])
    say("", "RULE  last byte = (31 x serial + 7) mod 251, and the serial is not 0")
    say("", f"      6400 random serials: {sum(r[0] != 'REFUSED' for r in good)} accepted; "
            f"the same coins with the byte one higher: {sum(r[0] != 'REFUSED' for r in near)} accepted")


def order(bench):
    rows = bench.each([line("x", "X", 9999, 1, 1), line("x", "M", 9999, 1, 1), line("x", "M", 9999, 1, 0),
                       line("x", "M", 9999, COIN, 0)])
    say("5 refusals", "a passenger wrong in four ways, corrected one fault at a time:")
    for r in rows:
        say("", "  " + r[1])


def ledger(bench):
    _, _, e, _ = bench.board([])
    _, _, one, _ = bench.board([line("Aaaa", "M", 0, COIN, 0)])
    _, _, two, _ = bench.board([line("Aaaa", "M", 0, COIN, 0), line("Bbbb", "M", 0, COIN, 0)])
    say("6 ledger", f"0, 1, 2 passengers: {len(e)}, {len(one)}, {len(two)} bytes: a 16-byte header, 36 bytes each")
    say("", f"header for 2 passengers, total 4:  {two[:16].hex(' ')}")
    _, _, other, _ = bench.board([line("Baaa", "M", 0, COIN, 0)])
    diff = [(i - 16, one[i] ^ other[i]) for i in range(16, 52) if one[i] != other[i]]
    say("", f"name Aaaa -> Baaa: {len(diff)} byte of the record changes, by {diff[0][1]} ('A' xor 'B' = {ord('A') ^ ord('B')})")
    _, _, more, _ = bench.board([line("Aaaa", "M", 250, COIN, 0)])
    say("", f"sins 0 -> 250, so total 2 -> 3: {sum(one[i] != more[i] for i in range(16, 52))} of 36 bytes change")
    streams = {}
    for sins in (0, 250, 500, 750):
        _, _, led, _ = bench.board([line("Aaaa", "M", sins, COIN, 0)])
        total = struct.unpack_from("<I", led, 8)[0]
        streams[total] = bytes(x ^ y for x, y in zip(led[16:], record("Aaaa", 0, sins, COIN, 0, total)))
    _, _, led, _ = bench.board([line("Zeno", "H", 250, COIN, 0)])
    again = bytes(x ^ y for x, y in zip(led[16:], record("Zeno", 1, 250, COIN, 0, 2)))
    say("", f"record xor what was put in, total 2:  {streams[2][:10].hex(' ')} ...")
    say("", f"a different passenger with the same total gives the same bytes: {again == streams[2]}")
    return streams


def seal(streams):
    import numpy as np
    cands = [("ANSI C example", 1103515245, 12345), ("Numerical Recipes", 1664525, 1013904223),
             ("Microsoft C", 214013, 2531011), ("Borland C", 22695477, 1)]
    target = streams[2]
    say("7 seal", "four textbook generators x three choices of output byte x every 32-bit seed")
    found = None
    for name, a, c in cands:
        for label, shift in (("top byte", 24), ("third byte", 16), ("low byte", 0)):
            hits = []
            for hi in range(256):
                seed = np.arange(1 << 24, dtype=np.uint32) | np.uint32(hi << 24)
                state = seed
                for k in range(6):
                    state = state * np.uint32(a) + np.uint32(c)
                    keep = ((state >> np.uint32(shift)) & np.uint32(255)) == target[k]
                    state, seed = state[keep], seed[keep]
                    if not len(seed):
                        break
                hits += [int(s) for s in seed]
            hits = [s for s in hits if keystream(s, 36, a, c, shift) == target]
            say("", f"  {name:<18} {label:<10} seeds that reproduce the record: {len(hits)}")
            if hits and not found:
                found = dict(name=name, a=a, c=c, shift=shift, key=hits[0] ^ 2)
    if not found:
        sys.exit("no textbook generator fits; the seal needs another idea")
    say("", f"seed xor total = {found['key']:#x}, the bytes {struct.pack('<I', found['key'])!r}")
    return found


def seal_check(streams, g):
    ok = all(keystream(t ^ g["key"], 36, **g) == s for t, s in streams.items())
    say("", f"RULE  {g['name']} generator, top byte of the state, seed = total xor {g['key']:#x}")
    say("", f"      predicts the stream for totals {sorted(streams)}: {ok}")


def checksum(bench):
    import verify
    _, _, e, _ = bench.board([])
    field = struct.unpack_from("<I", e, 12)[0]
    say("8 checksum", f"empty ledger: field {field:08x}; CRC-32 {zlib.crc32(b''):08x}, Adler-32 {zlib.adler32(b''):08x}, "
                      f"FNV-1a {fnv1a(b''):08x}")
    rng = random.Random(3)
    n = ok = 0
    shown = 0
    for i in range(500):
        _, _, led, _ = bench.board(verify.make_manifest(rng, i).split(b"\n"))
        if led is None:
            continue
        f, h = struct.unpack_from("<I", led, 12)[0], fnv1a(led[16:])
        if shown < 2 and len(led) > 16:
            say("", f"field {f:08x}  FNV-1a of the stored records {h:08x}  xor {f ^ h:08x}  FNV-1a >> 15 {h >> 15:08x}")
            shown += 1
        n += 1
        ok += (h ^ (h >> 15)) == f
    say("", f"RULE  FNV-1a over the records as stored, then h xor (h >> 15): {ok} of {n} ledgers agree")


def model(bench, base, g):
    """A complete model of the program, built from the rules above, against the original."""
    import verify
    kinds = {"M": (0, "mortal"), "H": (1, "hero"), "P": (2, "poet"), "K": (3, "king"), "T": (4, "publican")}

    def predict(lines, draft):
        out, recs, refused, total = [], [], 0, 0
        for text in lines:
            name, cls, sins, coin, fl = text.split(";")
            sins, coin, fl = int(sins), int(coin, 16), int(fl) & 255
            if not draft:
                cls = cls.upper()
            reason = None
            if cls not in kinds:
                reason = "unknown kind of soul"
            elif fl & 1:
                reason = "unburied: come back in a hundred years"
            elif coin >> 8 == 0 or ((coin >> 8) * 31 + 7) % 251 != coin & 255:
                reason = "coin is counterfeit"
            elif sins > 9000:
                reason = "too many sins for one boat"
            elif len(recs) == 64:
                reason = "the boat is full"
            if reason:
                out.append(f"{name:<24} REFUSED  {reason}")
                refused += 1
                continue
            fare = 0
            if not (cls == "P" and sins < 100):
                fare = base[cls] + min(sins // 250, 20)
                if fl & 2:
                    fare = fare * 2 + 1
                if fl & 4:
                    fare *= 3
            out.append(f"{name:<24} {kinds[cls][1]:<8} {fare:5d}")
            recs.append(record(name, kinds[cls][0], sins, coin, fl, fare))
            total += fare
        out.append(f"{len(recs)} boarded, {refused} refused, {total} oboli collected")
        payload = b"".join(recs)
        payload = bytes(x ^ y for x, y in zip(payload, keystream(total ^ g["key"], len(payload), **g)))
        h = fnv1a(payload)
        return ("\n".join(out) + "\n").encode(), b"STYX" + struct.pack("<HHII", 3, len(recs), total, h ^ (h >> 15)) + payload

    say("9 model", "the rules above as a program, against the original on 1000 well-formed manifests")
    for draft in (True, False):
        rng = random.Random(11)
        same, first = 0, None
        for _ in range(1000):
            lines = [verify.ordinary_line(rng) for _ in range(rng.randint(0, 90))]
            _, _, led, stdout = bench.board([text.encode() for text in lines])
            if (stdout, led) == predict(lines, draft):
                same += 1
            elif first is None:
                mine = predict(lines, draft)[0].split(b"\n")
                first = next((a.decode(), b.decode()) for a, b in zip(stdout.split(b"\n"), mine) if a != b)
        say("", f"{'without finding 3' if draft else 'with every finding'}: {same} of 1000 identical, screen text and ledger byte for byte")
        if first:
            say("", f"  original: {' '.join(first[0].split())}")
            say("", f"  model:    {' '.join(first[1].split())}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", default=os.path.join(HERE, "..", "build", "styx", "linux", "ferryman"))
    ap.add_argument("--seal", action="store_true", help="search for the generator behind the seal (minutes)")
    opt = ap.parse_args()
    if not os.path.exists(opt.exe):
        sys.exit(f"missing {opt.exe}\nrun ./build.sh first")
    sys.path.insert(0, HERE)
    bench = Bench(opt.exe)
    print("ferryman as a black box: inputs in, outputs out, nothing opened.\n")
    base = fares(bench)
    flags(bench)
    classes(bench)
    coins(bench)
    order(bench)
    streams = ledger(bench)
    g = seal(streams) if opt.seal else SEAL
    if not opt.seal:
        say("7 seal", "search skipped (run with --seal); using its recorded result")
    seal_check(streams, g)
    checksum(bench)
    model(bench, base, g)
    print(f"\n{runs} runs of the original. Instructions read: none.")


if __name__ == "__main__":
    main()
