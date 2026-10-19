#!/usr/bin/env python3
"""Offline Objective-C class dumper for YTLite.dylib (Mach-O arm64 / FAT).

Parses __objc_classlist / __objc_methname / __objc_classname / __objc_methtype
and per-class method lists, handling both classic dyld info (relokative raw
pointers) and modern dyld chained fixups (encoded binds).

Usage: python3 classdump.py <path-to-.dylib> [class-name-filter ...]
Prints: class name, super, and every method `+/-` `selector:...` with type.
"""

import struct
import sys
import tarfile
import lzma
import io

# ---- Mach-O constants -----------------------------------------------------
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022 | 0x22  # placeholder, replaced below
LC_DYLD_CHAINED_FIXUPS = 0x80000022 | 0  # unused, computed below as raw id

LC_DYLD_INFO_ID = 0x22
LC_DYLD_CHAINED_FIXUPS_ID = 0x32

RW_FLAG = 0x8000000000000000
PTR_MASK = 0x0000FFFFFFFFFFF8


class MachO:
    def __init__(self, data: bytes, off: int = 0):
        self.d = data
        self.o = off
        (self.magic,) = struct.unpack_from("<I", data, off)
        if self.magic not in (MH_MAGIC_64,):
            raise ValueError(f"not a 64-bit Mach-O slice (magic {self.magic:#x})")
        self.cmds = []          # list of dicts
        ncmds, sizeofcmds = struct.unpack_from("<II", data, off + 16)
        p = off + 32  # 64-bit Mach-O header is 32 bytes (incl. `reserved`)
        end = off + 4 * 7 + sizeofcmds
        for _ in range(ncmds):
            cid, sz = struct.unpack_from("<II", data, p)
            self.cmds.append({"id": cid, "sz": sz, "off": p})
            p += sz
        self.has_chained = any(
            c["id"] == LC_DYLD_CHAINED_FIXUPS_ID for c in self.cmds
        )
        self.has_dyldinfo = any(c["id"] == LC_DYLD_INFO_ID for c in self.cmds)
        # ^ chained-fixups and dyld_info may both exist; chained wins if present
        self.chained_mode = self.has_chained and not self.has_dyldinfo

        # segments
        self.segs = []
        for c in self.cmds:
            if c["id"] != LC_SEGMENT_64:
                continue
            o = c["off"]
            name = data[o + 8:o + 24].split(b"\0")[0].decode()
            vm, msz, fo, fsz = struct.unpack_from("<QQQQ", data, o + 24)
            (nsects,) = struct.unpack_from("<I", data, o + 68)
            sects = []
            so = o + 72
            for _ in range(nsects):
                sn = data[so:so + 16].split(b"\0")[0].decode()
                sg = data[so + 16:so + 32].split(b"\0")[0].decode()
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                (foff,) = struct.unpack_from("<I", data, so + 48)
                sects.append((sn, addr, size, foff))
                so += 80
            self.segs.append(
                {"name": name, "vm": vm, "size": msz, "fo": fo, "fs": fsz,
                 "sects": sects}
            )

    def sect(self, segname, sectname):
        for s in self.segs:
            if s["name"] != segname:
                continue
            for (sn, addr, size, foff) in s["sects"]:
                if sn == sectname:
                    return (addr, size, foff)
        return None

    # -- pointer decoding ---------------------------------------------------
    def vaddr_to_foff(self, vmaddr):
        for s in self.segs:
            if s["vm"] <= vmaddr < s["vm"] + s["fs"]:
                return vmaddr - s["vm"] + s["fo"]
        return None

    def cstr(self, vmaddr, maxlen=200):
        f = self.vaddr_to_foff(vmaddr)
        if f is None:
            return None
        end = self.d.find(b"\0", f, f + maxlen)
        if end < 0:
            return None
        s = self.d[f:end]
        try:
            t = s.decode("utf-8", "replace")
        except Exception:
            return None
        if not t or any(ord(ch) < 0x20 for ch in t):
            return None
        return t

    def decode_ptr(self, raw, ctx_addr=None):
        """Decode an (unrelocated) pointer field raw value to vmaddr, or None."""
        if raw == 0:
            return None
        if not self.chained_mode:
            return raw  # plain vmaddr
        # chained fixups: pointer 64-bit encoding.
        # decode via libdispatch-style masks (arm64 formats 1-3)
        # try "target = low 48-ish" and validate downstream.
        tgt = raw & 0x0000FFFFFFFFFFF
        if tgt:
            return tgt
        return None

    # -- parsing -------------------------------------------------------------
    def iptr(self, fo):
        if fo is None:
            return 0
        return struct.unpack_from("<Q", self.d, fo)[0]

    def i32(self, fo):
        if fo is None:
            return 0
        return struct.unpack_from("<i", self.d, fo)[0]

    def methods(self, list_vmaddr):
        """Return [(isclass, name, types)] for a method list."""
        out = []
        f = self.vaddr_to_foff(list_vmaddr)
        if f is None:
            return out
        entsize, count = struct.unpack_from("<II", self.d, f)
        flags = entsize >> 24
        entsz = entsize & 0xFFFF
        relative = bool(flags & 0x2) or (entsz == 12)  # relative method lists
        for i in range(count):
            ef = f + 8 + i * entsz
            if relative:
                sel_rel = self.i32(ef)
                ty_rel = self.i32(ef + 4)
                entry_vm = list_vmaddr + 8 + i * entsz
                # sel field points at a __objc_selrefs slot (raw or chained ptr)
                selref_vm = entry_vm + sel_rel
                sel_vm = self.decode_ptr(self.iptr(self.vaddr_to_foff(selref_vm)))
                ty_vm = entry_vm + ty_rel
            else:
                sel_vm = self.decode_ptr(self.iptr(ef))
                ty_vm = self.decode_ptr(self.iptr(ef + 8))
            name = self.cstr(sel_vm) if sel_vm else "?"
            types = self.cstr(ty_vm) if ty_vm else "?"
            out.append((name, types))
        return out

    def ivars_of(self, ro_f):
        return None  # not needed for our goal

    def dump(self, filter=()):
        clist = self.sect("__DATA_CONST", "__objc_classlist")
        if clist is None:
            clist = self.sect("__DATA", "__objc_classlist")
        if clist is None:
            raise ValueError("no __objc_classlist section")
        vm, size, fo = clist
        n = size // 8
        shown = 0
        for i in range(n):
            raw = self.iptr(fo + i * 8)
            c = self.decode_ptr(raw)
            if c is None:
                continue
            cf = self.vaddr_to_foff(c)
            if cf is None:
                continue
            sup_raw = self.iptr(cf + 8)
            sup = self.decode_ptr(sup_raw)
            sup = self.cstr(self.iptr(self.vaddr_to_foff(sup))) if sup else None
            # ro or rw pointer at +0x20
            bits = self.iptr(cf + 0x20)
            ptr = bits & PTR_MASK
            dptr = self.decode_ptr(ptr | (bits & 7)) if ptr else None
            df = self.vaddr_to_foff(dptr) if dptr is not None else None
            if df is None:
                # try without reor'ing
                df = self.vaddr_to_foff(bits & PTR_MASK)
            if df is None:
                continue
            is_rw = bool(bits & RW_FLAG) or (
                self.chained_mode
                and (bits & 0x6000000000000000)  # heuristic: chained encodes RW in high bits
            )
            ro = df
            if is_rw:
                # class_rw_t: ro pointer at +0x08 (flags+witness at 0x00)
                ro_raw = self.iptr(df + 8)
                ro = self.vaddr_to_foff(self.decode_ptr(ro_raw))
                if ro is None:
                    continue
            name_vm = self.decode_ptr(self.iptr(ro + 0x18))
            cname = self.cstr(name_vm)
            if not cname:
                continue
            if filter and not any(f.lower() in cname.lower() for f in filter):
                continue
            shown += 1
            methods_vm = self.decode_ptr(self.iptr(ro + 0x20))
            sup_name = sup or "nil"
            print(f"\n=== @{cname} : {sup_name} ===")
            if methods_vm:
                for (msel, mty) in self.methods(methods_vm):
                    kind = "+" if mty and mty.startswith("+") else "-"
                    ty = mty[1:] if mty and mty.startswith("+") else mty
                    print(f"  {kind} {msel}   {ty}")
        return shown


def fat_to_arm64(data: bytes) -> bytes:
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic != FAT_MAGIC:
        return data
    (narcs,) = struct.unpack_from(">I", data, 4)
    for i in range(narcs):
        cpu, sub, of, sz, al = struct.unpack_from(">IIIII", data, 8 + i * 20)
        if cpu == CPU_TYPE_ARM64:
            return data[of:of + sz]
    return data


def ar_extract(data: bytes, suffix=None):
    """Very small ar reader: returns archive members matching suffix."""
    assert data[:8] == b"!<arch>\n", "not an ar archive"
    i = 8
    out = []
    while i < len(data):
        hdr = data[i:i + 60]
        name = hdr[:16].split(b"/")[0].decode("utf-8", "replace").strip()
        sz = int(hdr[48:58].decode().strip())
        body = data[i + 60:i + 60 + sz]
        if suffix and name.startswith(suffix):
            out.append(body)
        i += 60 + (sz if sz % 2 == 0 else sz + 1)
    return out


def load_dylib_from_deb(path):
    if not path.endswith(".deb"):
        return open(path, "rb").read()
    data = open(path, "rb").read()
    members = ar_extract(data, "data.tar")
    if not members:
        raise ValueError("no data.tar in deb")
    payload = members[0]
    if payload[:5] != b"\xfd7zX" and payload[:4] != b"\xfd\xb2\x01\x7b":  # xz magic
        # ours use lodash/XZ; detect via first bytes
        pass
    # try xz then zstd then plain tar
    for opener in (
        lambda b: tarfile.open(fileobj=io.BytesIO(b), mode="r:"),
        lambda b: tarfile.open(fileobj=io.BytesIO(b), mode="r:xz"),
        lambda b: tarfile.open(fileobj=io.BytesIO(b), mode="r:gz"),
        lambda b: tarfile.open(fileobj=io.BytesIO(b), mode="r:bz2"),
    ):
        try:
            with opener(payload) as tf:
                mem = [m for m in tf.getmembers() if m.name.endswith("YTLite.dylib")]
                if mem:
                    return tf.extractfile(mem[0]).read()
        except Exception:
            continue
    raise ValueError("could not read YTLite.dylib from deb")


def main():
    path = sys.argv[1]
    filt = sys.argv[2:]
    blob = load_dylib_from_deb(path)
    blob = fat_to_arm64(blob)
    mo = MachO(blob, 0)
    print(f"# chained_fixups mode: {mo.chained_mode} "
          f"(has_chained={mo.has_chained}, has_dyldinfo={mo.has_dyldinfo})")
    n = mo.dump(filt)
    print(f"\n# {n} classes shown")


if __name__ == "__main__":
    main()
