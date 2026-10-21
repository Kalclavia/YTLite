#!/usr/bin/env python3
"""patch_gate.py — bake-time static crack of the YTLite 6.0.b2 licensing gate.

Round-6 RE result (see Unlocker/docs/RE-notes-6.0.b2-gate.md):

  The gate is one fat state-machine function (vma 0xb98a4 in this build).
  Symbolic execution of its dispatcher established three exit paths:

    f = bool cached from bl #0xdfabc       (license/validation check)
    g = byte at global 0x228e0200          (anti-tamper/env flag)

    f=0              -> returns 0 for every preference key (all features off)
    f=1, g=1         -> returns 0 (tamper detected)
    f=1, g=0         -> [[standardUserDefaults] integerForKey:<key>]
                        -> returns the REAL preference value

  The crack forces the value path unconditionally with two 4-byte patches
  inside __TEXT (applied at bake time, then re-signed; zero runtime hooks,
  zero writes to process memory -> LiveContainer-safe):

    0xb9be8: bl #0xdfabc            (0x940097b5) -> mov w0, #1   (0x52800020)
    0xb9ecc: csel w8, w26, w11, ne  (0x1a8b1348) -> mov w8, w11  (0x2a0b03e8)

  Patch 1 forces the validation bool to TRUE (skips the unknown check).
  Patch 2 forces the "environment clean" branch regardless of the
  anti-tamper byte. After both patches the dispatcher has exactly one
  reachable terminal state: return integerForKey: with the caller's key.

Usage:
    patch_gate.py <YTLite.dylib>            # patch in place (asserts first)
    patch_gate.py --verify <YTLite.dylib>   # assert patched words, no write

Exit codes: 0 = patched/verified, 1 = signature mismatch / not this build.
"""

import hashlib
import os
import struct
import sys

# --- crack data (this build == YTLite 6.0.b2, sha256 666ef733... pre-signature) ---

GATE_ENTRY = 0xB98A4
SITE_BOOL = (0xB9BE8, 0x940097B5, 0x52800020)   # bl #0xdfabc -> mov w0, #1
SITE_ENV = (0xB9ECC, 0x1A8B1348, 0x2A0B03E8)    # csel w8,w26,w11,ne -> mov w8, w11

# cheap identity anchors for the exact build (entry-stub DAT + a magic constant)
IDENTITY_ANCHORS = [
    (0x21C9EA8, 0x2E14F9EC, "entry stub DAT"),
]

MH_MAGIC_64 = 0xFEEDFACF
MH_CPUTYPE_ARM64 = 0x0100000C


def parse_segments(data):
    """Return [(vmaddr, fileoff, vmsize, filesize, name)] for every segment."""
    magic, cputype = struct.unpack_from("<II", data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit("error: not a 64-bit Mach-O (magic 0x%08x)" % magic)
    if cputype != MH_CPUTYPE_ARM64:
        raise SystemExit("error: not an arm64 Mach-O (cputype 0x%08x)" % cputype)
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8: off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((vmaddr, fileoff, vmsize, filesize, name))
        off += size
    return segs


def vma2file(data, segs, vma):
    for vmaddr, fileoff, vmsize, filesize, _ in segs:
        if vmaddr <= vma < vmaddr + vmsize:
            return fileoff + (vma - vmaddr)
    raise SystemExit("error: vma 0x%x unmapped" % vma)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_word(data, fo):
    return struct.unpack_from("<I", data, fo)[0]


def main():
    args = [a for a in sys.argv[1:] if a != "--verify"]
    verify_only = "--verify" in sys.argv
    if len(args) != 1:
        print(__doc__)
        return 2
    path = args[0]
    with open(path, "rb") as f:
        data = bytearray(f.read())

    segs = parse_segments(data)

    # identity anchors: refuse to touch anything but the analyzed build
    for vma, expect, label in IDENTITY_ANCHORS:
        fo = vma2file(data, segs, vma)
        got = read_word(data, fo)
        if got != expect:
            print("error: identity anchor %s @0x%x: got 0x%08x, want 0x%08x"
                  % (label, vma, got, expect))
            return 1

    ops = []
    for vma, expect, patch in (SITE_BOOL, SITE_ENV):
        fo = vma2file(data, segs, vma)
        got = read_word(data, fo)
        if got == patch:
            ops.append((vma, fo, None, patch))          # already patched
        elif got == expect:
            ops.append((vma, fo, patch, expect))        # needs patching
        else:
            print("error: gate signature mismatch @0x%x: got 0x%08x, want 0x%08x"
                  "(not the analyzed 6.0.b2 rootful build; refusing)"
                  % (vma, got, expect))
            return 1

    if not verify_only:
        wrote = 0
        for vma, fo, patch, _ in ops:
            if patch is not None:
                struct.pack_into("<I", data, fo, patch)
                wrote += 1
        if wrote:
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
            # restore executable bit the theos/dpkg layout expects
            os.chmod(path, 0o755)
        print("patch_gate: %s (%d site(s) written) entry=0x%x"
              % ("already-patched" if wrote == 0 else "patched",
                 wrote, GATE_ENTRY))
        print("patch_gate: sha256 %s" % sha256(path))
        return 0

    # strict verify: every site must already carry the patched word
    n_patched = sum(1 for _, _, p, _ in ops if p is None)
    if n_patched != len(ops):
        for vma, fo, patch, _ in ops:
            if patch is not None:
                print("error: site 0x%x is NOT patched (0x%08x != patched word 0x%08x)"
                      % (vma, read_word(data, fo), patch))
        print("patch_gate: verify FAILED (%d/%d sites patched)" % (n_patched, len(ops)))
        return 1
    print("patch_gate: verify OK (%d/%d sites patched)" % (n_patched, len(ops)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
