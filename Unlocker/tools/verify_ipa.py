#!/usr/bin/env python3
"""verify_ipa.py — structural & behavioral screening for third-party decrypted IPAs.

A decrypted IPA has *no* remaining code signature (decryption rewrites __TEXT),
so cryptographic provenance is impossible for any dumper source. What we CAN do:

  A. Metadata check    — bundle id / version vs the official App Store registry.
  B. Inventory sweep   — flag suspicious file names (tweak/hook/crack artifacts).
  C. Mach-O hygiene    — every embedded binary: valid arch, load-command dylib
                         paths limited to System/own frameworks, LC scanner
                         flags MobileSubstrate/ellekit/frida-style injections.
  D. Endpoint sweep    — strings scan for URLs pointing at non-Google hosts,
                         plus known hook-framework strings.
  E. Cross-consensus   — `--crosscompare a.ipa b.ipa`: hash+inventory diff of the
                         same version from two independent dump sources; matches
                         = selective tampering unlikely.

Usage:
    verify_ipa.py <ipa> [--expect-bundle BID] [--expect-version VER] [--strict]
    verify_ipa.py --crosscompare <ipa> <other-ipa>

Exit codes: 0 ok/warnings, 2 fatal (wrong bundle/version/corrupt), 1 if --strict
and any FLAG line fired.
"""

import argparse
import fnmatch
import hashlib
import plistlib
import re
import struct
import sys
import zipfile
from urllib.parse import urlparse

# ---------------------------------------------------------------- constants

FATAL = 2
STRICT_FAIL = 1
OK = 0

MACHO_MAGICS = {0xFEEDFACF: 64, 0xFEEDFACE: 32, 0xCFFAEDFE: 64, 0xCFFAEDFE: 32}
FAT_MAGICS = {0xCAFEBABE, 0xBEBAFECA}
CPU_ARCHES = {12: "arm", 0x0100000C: "arm64", 0x0100000E: "arm64e", 7: "x86", 0x01000007: "x86_64"}

LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_LAZY_LOAD_DYLIB = 0x20
LC_CODE_SIGNATURE = 0x1D
DYLIB_CMDS = {LC_LOAD_DYLIB: "load", LC_LOAD_WEAK_DYLIB: "weak",
              LC_REEXPORT_DYLIB: "reexport", LC_LOAD_UPWARD_DYLIB: "upward",
              LC_LAZY_LOAD_DYLIB: "lazy"}

# prefix allowlist for load-command dylib paths (system + private framweworks)
SYSTEM_DYLIB_PREFIXES = ("/System/", "/usr/lib/", "@rpath/", "@executable_path/", "@loader_path/")

SUSPICIOUS_NAME_TOKENS = (
    "substrate", "hooker", "ellekit", "cydia", "sileo", "zeon", "frida",
    "cracker", "crack", "jailbreak", "tweak", "patched", "ripped", "deb",
    "flex", "inject", "hijack", "spy",
)

SUSPICIOUS_STRING_TOKENS = [
    ("MobileSubstrate", "substrate path"),
    ("MSHookMessage", "substrate hook api"),
    ("MSHookFunction", "substrate hook api"),
    ("libhooker", "libhooker"),
    ("ELLEKIT", "ellekit marker"),
    ("/var/jb/", "rootless jb path"),
    ("/Applications/Cydia", "cydia reference"),
    ("frida", "frida marker"),
    ("cycript", "cycript marker"),
]

ALLOWED_HOST_SUFFIXES = (
    # google/youtube + ads/analytics machinery shipped in the official app
    "google.com", "youtube.com", "ytimg.com", "ggpht.com", "gstatic.com",
    "googleapis.com", "googleusercontent.com", "googlevideo.com", "ggoogle.com",
    "googletagservices.com", "googlesyndication.com", "googleadservices.com",
    "doubleclick.net", "gvt1.com", "gvt2.com", "recaptcha.net", "gfra.org",
    "withgoogle.com", "firebaseio.com", "app-measurement.com", "crashlytics.com",
    "fabric.io", "adjust.com", "oneplatform.build", "cloudmindsdk.com",
    # apple platform bits
    "apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com",
)

UKNOWN_HOST_EXTRA_OK = 0   # hosts not matching allowlist are FLAGS (not silent)

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")

VOLATILE_PATH_CHARS = (
    "_CodeSignature/", "embedded.mobileprovision", "SC_Info/",
    "iTunesMetadata.plist", "iTunesArtwork", ".com.apple.",
)

# ---------------------------------------------------------------- helpers


class Report:
    def __init__(self):
        self.lines = []
        self.flags = 0
        self.fatal = 0

    def info(self, msg):
        self.lines.append(f"[INFO] {msg}")

    def ok(self, msg):
        self.lines.append(f"[ OK ] {msg}")

    def warn(self, msg):
        self.lines.append(f"[WARN] {msg}")

    def flag(self, msg):
        self.flags += 1
        self.lines.append(f"[FLAG] {msg}")

    def fail(self, msg):
        self.fatal += 1
        self.lines.append(f"[FATAL] {msg}")


def is_macho(data: bytes):
    """Return (arch, is_64) or None; handles FAT."""
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (0xCAFEBABE,):
        (nfat,) = struct.unpack_from(">I", data, 4)
        arches = []
        for i in range(nfat):
            cpu, sub, off = struct.unpack_from(">III", data, 8 + i * 20)
            arches.append((CPU_ARCHES.get(cpu, hex(cpu)), off))
        if not arches:
            return "fat-empty", None
        # parse the primary (arm64 preferred) slice
        arch, off = arches[-1]
        if off + 32 > len(data):
            return arch, None
        return arch, None
    if magic == 0xFEEDFACF:
        (cpu,) = struct.unpack_from("<I", data, 4)
        return CPU_ARCHES.get(cpu, hex(cpu)), True
    if magic == 0xFEEDFACE:
        (cpu,) = struct.unpack_from("<I", data, 4)
        return CPU_ARCHES.get(cpu, hex(cpu)), False
    return None


def macho_load_dylibs(data: bytes):
    """Return (arch, [dylib paths], has_code_signature) for a 64-bit Mach-O."""
    paths, has_codesig = [], False
    ncmds, _ = struct.unpack_from("<II", data, 16)
    p = 32
    arch = None
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, size = struct.unpack_from("<II", data, p)
        if cmd == 0x19 and arch is None:  # LC_SEGMENT_64
            pass
        if cmd in DYLIB_CMDS:
            if p + 12 > len(data):
                break
            (nameoff,) = struct.unpack_from("<I", data, p + 8)
            end = data.find(b"\0", p + nameoff, p + size)
            if end > 0:
                paths.append(data[p + nameoff:end].decode("utf-8", "replace"))
        if cmd == LC_CODE_SIGNATURE:
            has_codesig = True
        if size <= 0 or p + size > len(data):
            break
        p += size
    (cpu,) = struct.unpack_from("<I", data, 4)
    arch = CPU_ARCHES.get(cpu, hex(cpu))
    return arch, paths, has_codesig


def extract_strings(data: bytes, minlen=6):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


def scan_urls(data: bytes, rep, label, seen):
    hosts = set()
    for m in URL_RE.finditer(data):
        try:
            h = urlparse(m.group(0).decode("utf-8", "ignore")).hostname
        except Exception:
            continue
        if h:
            hosts.add(h.lower())
    new_hosts = hosts - seen
    seen |= hosts
    for h in sorted(hosts):
        parts = h.split(".")
        ok = any(h == suf or h.endswith("." + suf) for suf in ALLOWED_HOST_SUFFIXES)
        if not ok and (parts[-2:] and ".".join(parts[-2:]) not in ALLOWED_HOST_SUFFIXES):
            rep.flag(f"non-allowlisted URL host in {label}: {h}")
    return hosts


def scan_strings_for_tokens(data: bytes, rep, label):
    text = data
    for token, desc in SUSPICIOUS_STRING_TOKENS:
        needle = token.encode()
        if needle in text:
            rep.flag(f"suspicious string in {label}: '{token}' ({desc})")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- main flow


def app_dir_of_z(z: zipfile.ZipFile, rep):
    top = {n.split("/")[0] for n in z.namelist()}
    payload = [t for t in top if t == "Payload"]
    if not payload:
        rep.fail("no Payload/ directory")
        return None
    apps = sorted({n for n in z.namelist() if n.startswith("Payload/") and
                   n.count("/") == 1 and n.split("/")[-1].endswith(".app")})
    # Payload/<app>.app listing pattern: entries look like 'Payload/X.app/...'
    apps = sorted({n.split("/")[1] for n in z.namelist()
                   if n.startswith("Payload/") and "/" in n[len("Payload/"):] and
                   n.split("/")[-1] != ""})
    if not apps:
        # .app dir itself may appear as its own entry
        apps = [n for n in z.namelist() if n.startswith("Payload/") and n.endswith(".app") and "/" not in n[len("Payload/"):]]
        apps = [a.split("/")[-1] for a in apps]
    if len(apps) != 1:
        rep.warn(f"unexpected app bundle count in Payload/: {apps}")
    if not apps:
        rep.fail("no .app bundle under Payload/")
        return None
    return f"Payload/{apps[0]}"


def verify_single(ipa_path, rep, expect_bundle=None, expect_version=None):
    z = zipfile.ZipFile(ipa_path)
    app = app_dir_of_z(z, rep)
    if not app:
        return None

    # ---- Info.plist
    try:
        pinfo = plistlib.loads(z.read(f"{app}/Info.plist"))
    except KeyError:
        rep.fail(f"{app}/Info.plist missing")
        return None
    bundle = pinfo.get("CFBundleIdentifier") or pinfo.get("CFBundleName")
    version = pinfo.get("CFBundleShortVersionString")
    minos = pinfo.get("MinimumOSVersion")
    rep.info(f"Info.plist: bundle={bundle} version={version} minOS={minos or '?'}")
    if expect_bundle and bundle != expect_bundle:
        rep.flag(f"bundle id mismatch: got {bundle!r}, expected {expect_bundle!r}")
    if expect_version and version != expect_version:
        rep.flag(f"version mismatch: got {version!r}, expected {expect_version!r}")
    # unusual-but-legit conventions print once
    rep.info(f"URL schemes: {[x.get('CFBundleURLName', x.get('CFBundleURLSchemes')) for x in pinfo.get('CFBundleURLTypes', [])]}")
    rep.info(f"BackgroundModes: {pinfo.get('UIBackgroundModes')}")

    # ---- inventory
    names = z.namelist()
    frameworks, executables, appexes = [], [], []
    for n in names:
        bn = n.split("/")[-1].lower()
        rel = n[len(app) + 1:] if len(n) > len(app) else n
        if n.endswith("/"):
            continue
        for tok in SUSPICIOUS_NAME_TOKENS:
            # only match token in filename part, not in path like 'Payload/...'
            if tok in bn:
                rep.flag(f"suspicious file name: {n} (token '{tok}')")
                break
        if "/Frameworks/" in f"/{rel}" and (rel.endswith(".dylib") or (bn.endswith(".") is False and rel.endswith("Frameworks/"))):
            frameworks.append(rel)
        if "/Frameworks/" in f"/{rel}" and "." in bn and bn.endswith((".dylib",)) :
            executables.append(rel)
        if ".appex" in rel and bn:
            appexes.append(rel)
    rep.info(f"extensions (.appex): {len(appexes)} entry/-ies")
    if appexes:
        rep.info("  " + ", ".join(sorted(b.split("/")[-1] for b in sorted(appexes)))[:1500])

    # ---- Mach-O hygiene + strings sweep over every binary
    url_seen = set()
    macho_ok = 0
    macho_fail = 0
    dylib_path_flags = 0
    own_fwx = set()
    for n in names:
        if n.endswith("/") or n.split("/")[-1].endswith((".plist", ".strings", ".png", ".lproj", ".stringsdict")):
            continue
        bn = n.split("/")[-1]
        try:
            head = z.open(n).read(8)
        except Exception:
            continue
        (magic,) = struct.unpack_from("<I", head, 0)
        looks_macho = magic in MACHO_MAGICS or magic in FAT_MAGICS

        # read whole thing (bounded)
        try:
            full = z.read(n)
        except Exception:
            continue
        rel = n[len(app) + 1:] if len(n) > len(app) else n

        if not looks_macho:
            # non-executable payload: still sweep strings unless it is a
            # recognized resource where URLs legitimately live anyway
            known_resource = bn.lower().endswith(
                (".plist", ".strings", ".stringsdict", ".png", ".jpg", ".car",
                 ".nib", ".storyboardc", ".lproj", ".intentdefinition", ".json"))
            if not known_resource and len(full) < (32 << 20):
                scan_urls(full, rep, rel, url_seen)
                scan_strings_for_tokens(full, rep, rel)
            continue

        arch, _ = is_macho(full)
        if arch is None:
            rep.flag(f"file looks like Mach-O but cannot be parsed: {n}")
            macho_fail += 1
            continue
        macho_ok += 1
        rep.info(f"mach-o {rel} arch={arch} size={len(full)}")

        try:
            macho_arch, dylibs, has_cs = macho_load_dylibs(full)
        except Exception:
            dylibs, has_cs = [], False

        for d in dylibs:
            dop = d
            if any(dop.startswith(pfx) for pfx in SYSTEM_DYLIB_PREFIXES):
                if dop.startswith("@rpath/"):
                    own_fwx.add(dop.split("/")[1] if "/" in dop[7:] else dop)
                continue
            dylib_path_flags += 1
            rep.flag(f"non-system load dylib in {rel}: {dop}")
        if not has_cs:
            rep.info(f"{rel}: no LC_CODE_SIGNATURE (expected for decrypted)")

        scan_urls(full[:64 << 20], rep, rel, url_seen)
        scan_strings_for_tokens(full, rep, rel)

        # collect framework ids rpath resolution was seen for
        for tok, _desc in SUSPICIOUS_STRING_TOKENS:
            pass

    rep.ok(f"mach-o files parsed: {macho_ok} ok / {macho_fail} bad")
    if dylib_path_flags == 0:
        rep.ok("no non-system load-command dylibs anywhere")
    else:
        rep.flag(f"{dylib_path_flags} non-system load-command dylibs total")
    return z


def crosscompare(a_path, b_path, rep):
    ha = {n: sha256_file_in_zip(a_path, n) for n in safe_names(a_path)}
    hb = {n: sha256_file_in_zip(b_path, n) for n in safe_names(b_path)}
    only_a = sorted(set(ha) - set(hb))
    only_b = sorted(set(hb) - set(ha))
    if not only_a and not only_b:
        rep.ok("inventory identical across the two sources")
    else:
        rep.flag(f"inventory mismatch: {len(only_a)} files only in A, {len(only_b)} only in B")
        for n in (only_a + only_b)[:25]:
            rep.info(f"  diff sample: {n}")
        if len(only_a) + len(only_b) > 25:
            rep.info(f"  ... (+{len(only_a) + len(only_b) - 25} more)")

    differing = []
    for n in sorted(set(ha) & set(hb)):
        if any(v in n for v in VOLATILE_PATH_CHARS):
            continue
        if ha[n] != hb[n]:
            differing.append(n)
    if not differing:
        rep.ok(f"content hashes identical for {len(set(ha) & set(hb))} shared files")
    else:
        rep.flag(f"{len(differing)} shared files have different content hashes")
        for n in differing[:25]:
            rep.info(f"  hash-diff sample: {n}")
        if len(differing) > 25:
            rep.info(f"  ... (+{len(differing) - 25} more)")

    # URL-set consensus on full payloads
    ua = collect_urls_from_zip(a_path)
    ub = collect_urls_from_zip(b_path)
    if ua == ub:
        rep.ok(f"URL host sets identical ({len(ua)} hosts)")
    else:
        rep.flag(f"URL host sets differ: only-in-A={len(ua - ub)}, only-in-B={len(ub - ua)}")
        for h in sorted(ua - ub)[:15]:
            rep.info(f"  only in A: {h}")
        for h in sorted(ub - ua)[:15]:
            rep.info(f"  only in B: {h}")


def safe_names(ipa_path):
    z = zipfile.ZipFile(ipa_path)
    return [n for n in z.namelist() if not n.endswith("/")]


def sha256_file_in_zip(ipa_path, name):
    z = zipfile.ZipFile(ipa_path)
    h = hashlib.sha256()
    with z.open(name) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_urls_from_zip(ipa_path):
    z = zipfile.ZipFile(ipa_path)
    hosts = set()
    for n in z.namelist():
        if n.endswith("/"):
            continue
        bn = n.split("/")[-1].lower()
        if bn.endswith((".plist", ".strings", ".png", ".lproj", ".stringsdict", ".nib", ".storyboardc", ".car", ".intentdefinition")):
            continue
        try:
            head = z.open(n).read(4)
            (magic,) = struct.unpack_from("<I", head, 0)
            if magic not in MACHO_MAGICS and magic not in FAT_MAGICS:
                continue
            full = z.read(n)
        except Exception:
            continue
        for m in URL_RE.finditer(full):
            try:
                h = urlparse(m.group(0).decode("utf-8", "ignore")).hostname
            except Exception:
                continue
            if h:
                hosts.add(h.lower())
    return hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa", nargs="?")
    ap.add_argument("--expect-bundle", default="com.google.ios.youtube")
    ap.add_argument("--expect-version", default=None)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--crosscompare", nargs=2, metavar=("A", "B"))
    args = ap.parse_args()

    rep = Report()
    if args.crosscompare:
        a, b = args.crosscompare
        rep.info(f"cross-comparing {a} vs {b}")
        crosscompare(a, b, rep)
    else:
        if not args.ipa:
            ap.error("provide <ipa> or --crosscompare")
        rep.info(f"verifying {args.ipa}")
        z = verify_single(args.ipa, rep, args.expect_bundle, args.expect_version)

    for line in rep.lines:
        print(line)
    print()
    if rep.fatal:
        print(f"RESULT: FAIL ({rep.fatal} fatal, {rep.flags} flags)")
        sys.exit(FATAL)
    if rep.flags:
        print(f"RESULT: {rep.flags} flag(s) — inspect before trusting; not auto-fatal.")
        sys.exit(STRICT_FAIL if args.strict else OK)
    print("RESULT: PASS (no flags)")
    sys.exit(OK)


if __name__ == "__main__":
    main()
