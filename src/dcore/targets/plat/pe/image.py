"""Windows PE parsing (DOS/COFF/optional headers, sections, debug directory, Rich header).

Both PE32 (32-bit) and PE32+ (64-bit) parse; the two differ in the optional header's shape —
u32 vs u64 image base, where the data directories start — and the Rich header is magic-based,
so it works for either. Read-only and cheap: identifying a file installs nothing.
"""

from __future__ import annotations

import struct

from ...image import NativeImage, Section, _u16, _u32, _u64

PE_MACHINES = {0x8664: "x86_64", 0xAA64: "aarch64", 0x014C: "x86"}

# Rich header build number -> Visual Studio release. A guess by nature (the header only
# names the `cl` build); the PDB's S_COMPILE3 record, read during analysis, is exact.
MSVC_BUILDS = {
    8168: "MSVC 12.00 (VS6)", 9466: "MSVC 13.00 (VS2002)", 3077: "MSVC 13.10 (VS2003)",
    50727: "MSVC 14.00 (VS2005 / 17.00 VS2012)", 21022: "MSVC 15.00 (VS2008)",
    30319: "MSVC 16.00 (VS2010)", 51106: "MSVC 17.00 (VS2012)", 21005: "MSVC 18.00 (VS2013)",
    23026: "MSVC 19.00 (VS2015)", 24210: "MSVC 19.00 (VS2015 U3)", 24215: "MSVC 19.00 (VS2015 U3)",
    25019: "MSVC 19.10 (VS2017)", 27023: "MSVC 19.16 (VS2017 15.9)",
    27508: "MSVC 19.20 (VS2019)", 30133: "MSVC 19.29 (VS2019 16.11)",
    30704: "MSVC 19.30 (VS2022)", 33130: "MSVC 19.38 (VS2022)", 34433: "MSVC 19.44 (VS2022)",
}
MSVC_RANGES = [(26000, 27500, "MSVC 19.1x (VS2017)"), (27500, 30133, "MSVC 19.2x (VS2019)"),
               (30133, 36000, "MSVC 19.3x+ (VS2022)")]


def sniff(head: bytes) -> str | None:
    """The arch this PE header names, from the first bytes alone."""
    if head[:2] != b"MZ" or len(head) < 0x40:
        return None
    pe_off = _u32(head, 0x3C)
    if not (0 < pe_off < len(head) - 6) or head[pe_off:pe_off + 2] != b"PE":
        return None
    return PE_MACHINES.get(_u16(head, pe_off + 4))


def rich_build(data: bytes, pe_off: int) -> int | None:
    """The Visual Studio build most of the binary's objects were compiled with, from the Rich header.

    Each entry decodes to `comp.id` = high 16 bits product id + low 16 bits build (richprint's
    layout; a real header carries what looks exactly like `0x00DD520D` = prodid 0xDD, build 21005).
    A binary mixes toolsets — its own compiler with counts in the thousands, plus static libraries
    built with older ones — so the dominant entry by count is the answer, not the highest build."""
    end = data.find(b"Rich", 0x40, pe_off)
    if end < 0:
        return None
    key = _u32(data, end + 4)
    best: tuple[int, int] | None = None  # (count, build)
    off = end - 8
    while off >= 0x40:
        comp = _u32(data, off) ^ key
        if comp == 0x536E6144:  # "DanS": the header's start
            break
        build, count = comp & 0xFFFF, _u32(data, off + 4) ^ key
        if 6000 <= build < 100000 and (best is None or (count, build) > best):
            best = (count, build)
        off -= 8
    return best[1] if best else None


def msvc_label(build: int | None) -> str:
    if build is None:
        return ""
    if build in MSVC_BUILDS:
        return MSVC_BUILDS[build]
    for lo, hi, label in MSVC_RANGES:
        if lo <= build < hi:
            return f"{label} (cl {build})"
    return f"MSVC (cl {build})"


def _rva_to_offset(secs: list[tuple[int, int, int, int]], rva: int) -> int | None:
    """File offset of an RVA, via the section table: (rva, vsize, raw_ptr, raw_size)."""
    for sv, vsize, raw, rawsize in secs:
        if sv <= rva < sv + max(vsize, 1) and raw:
            return raw + (rva - sv)
    return None


def parse(data: bytes) -> NativeImage | None:
    return parse_python(data)


def parse_python(data: bytes) -> NativeImage | None:
    """The pure-Python PE parser."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = _u32(data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    machine, nsec = _u16(data, pe_off + 4), _u16(data, pe_off + 6)
    size_opt = _u16(data, pe_off + 20)
    characteristics = _u16(data, pe_off + 22)
    opt = pe_off + 24
    if machine not in PE_MACHINES or opt + size_opt > len(data):
        return None
    magic = _u16(data, opt)
    entry_rva = _u32(data, opt + 16)
    if magic == 0x20B:  # PE32+ (64-bit): u64 image base, 16 data directories
        bits, image_base, dd = 64, _u64(data, opt + 24), opt + 112
    elif magic == 0x10B:  # PE32 (32-bit): u32 image base, 16 data directories, shorter header
        bits, image_base, dd = 32, _u32(data, opt + 28), opt + 96
    else:
        return None
    secs: list[tuple[int, int, int, int]] = []
    sections: list[Section] = []
    for i in range(nsec):
        o = opt + size_opt + 40 * i
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        schar = _u32(data, o + 36)
        if not (vsize or rawsize):
            continue
        sk = ("code" if schar & 0x20000000 else "bss" if schar & 0x80 else
              "data" if schar & 0x80000000 else "rodata")
        secs.append((vaddr, vsize, rawptr, rawsize))
        sections.append(Section(name, image_base + vaddr, max(vsize, rawsize), rawptr, sk))
    pdb = None
    if dd + 8 * 16 <= len(data):
        rva, size = struct.unpack_from("<II", data, dd + 8 * 6)  # directory 6: debug
        off = _rva_to_offset(secs, rva) if rva else None
        if off:
            for i in range(size // 28):
                e = off + 28 * i
                if e + 28 > len(data):
                    break
                if _u32(data, e + 12) == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    blob_at = _rva_to_offset(secs, _u32(data, e + 20)) or _u32(data, e + 20)
                    blob_size = _u32(data, e + 16)
                    blob = data[blob_at:blob_at + blob_size]
                    if blob[:4] == b"RSDS" and len(blob) >= 24:
                        pdb = {"guid": blob[4:20].hex(), "age": _u32(blob, 20),
                               "path": blob[24:].split(b"\0", 1)[0].decode("utf-8", "replace")}
                    break
    kind = "dll" if characteristics & 0x2000 else "exe"
    build = rich_build(data, pe_off)
    notes = [f"PE timestamp {_u32(data, pe_off + 8)}"] if _u32(data, pe_off + 8) else []
    if pdb is None:
        notes.append("no CodeView debug directory: analysis will be name-less beyond exports")
    return NativeImage("pe", PE_MACHINES[machine], bits, kind, image_base, image_base + entry_rva,
                       sections, pdb is not None, "pdb" if pdb else "", pdb, msvc_label(build), notes)
