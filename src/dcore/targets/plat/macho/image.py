"""Mach-O parsing (64-bit executables, dylibs, objects; universal binaries pick their first
supported slice; dSYM bundles carry a __DWARF segment).

Mach-O is simpler than it looks: the header names the CPU and file kind, LC_SEGMENT_64
commands carry every section with its link-time address, LC_BUILD_VERSION names the SDK.
"""

from __future__ import annotations

import struct

from ...image import NativeImage, Section, _u32, _u64

MACHO_MAGICS = {0xFEEDFACF: "little", 0xCFFAEDFE: "big"}
FAT_MAGICS = {b"\xca\xfe\xba\xbe": 32, b"\xca\xfe\xba\xbf": 64}  # big-endian on disk, always
CPU_ARCH = {0x01000007: "x86_64", 0x0100000C: "aarch64", 0x00000007: "x86"}

LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_MACOSX = 0x24

PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "Mac Catalyst"}


def _vers(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}" + (f".{v & 0xFF}" if v & 0xFF else "")


def sniff(head: bytes) -> str | None:
    """The arch a Mach-O header names, from the first bytes alone (fat: the first slice)."""
    if len(head) < 12:
        return None
    if head[:4] in FAT_MAGICS:
        return CPU_ARCH.get(int.from_bytes(head[8:12], "big"))
    if _u32(head, 0) in MACHO_MAGICS:
        return CPU_ARCH.get(_u32(head, 4))
    return None


def _parse_fat(data: bytes, is64: int) -> NativeImage | None:
    n = int.from_bytes(data[4:8], "big")
    off = 8
    best = None
    for _ in range(min(n, 64)):
        cputype = int.from_bytes(data[off:off + 4], "big")
        if is64 == 64:
            slice_off = int.from_bytes(data[off + 8:off + 16], "big")
            size = int.from_bytes(data[off + 16:off + 24], "big")
            off += 32
        else:
            slice_off = int.from_bytes(data[off + 8:off + 12], "big")
            size = int.from_bytes(data[off + 12:off + 16], "big")
            off += 20
        if cputype not in CPU_ARCH:
            continue
        image = parse(data[slice_off:slice_off + size])
        if image is not None:
            best = image
            break
    if best is not None:
        best.notes.append("universal binary: the first supported slice")
    return best


def parse(data: bytes) -> NativeImage | None:
    return parse_python(data)


def parse_python(data: bytes) -> NativeImage | None:
    """The pure-Python parser for thin and fat Mach-O files."""
    if len(data) < 32:
        return None
    if data[:4] in FAT_MAGICS:
        return _parse_fat(data, FAT_MAGICS[data[:4]])
    magic = _u32(data, 0)
    if magic not in MACHO_MAGICS or MACHO_MAGICS[magic] != "little":
        return None  # 64-bit little-endian only for now (every Mac since 10.6)
    cputype, filetype = _u32(data, 4), _u32(data, 12)
    if cputype not in CPU_ARCH:
        return None
    ncmds, flags = _u32(data, 16), _u32(data, 24)
    kind = {2: "exe", 6: "shared", 1: "object", 8: "exe"}.get(filetype)
    if kind is None:
        return None
    sections: list[Section] = []
    has_debug = False
    base = entry = 0
    sdk = ""
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = _u32(data, off), _u32(data, off + 4)
        if cmdsize < 8:
            break
        if cmd == LC_SEGMENT_64 and off + 72 <= len(data):
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize = _u64(data, off + 24), _u64(data, off + 32)
            fileoff, filesize = _u64(data, off + 40), _u64(data, off + 48)
            nsects = _u32(data, off + 64)
            if segname == "__DWARF":
                has_debug = True
            if segname == "__TEXT" and vmaddr:
                base = base or vmaddr
            so = off + 72
            for _s in range(min(nsects, 512)):
                if so + 80 > len(data) or so + 80 > off + cmdsize:
                    break
                sname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                addr, size = _u64(data, so + 32), _u64(data, so + 40)
                secoff, secflags = _u32(data, so + 48), _u32(data, so + 64)
                if size:
                    stype = secflags & 0xFF
                    sk = ("bss" if stype == 0x1 else "code" if sname in ("__text", "__stubs", "__stub_helper")
                          else "rodata" if sname.startswith("__c") or sname in ("__const", "__TEXT")
                          else "data")
                    sections.append(Section(sname, addr, size, secoff if stype != 0x1 else 0, sk))
                so += 80
        elif cmd == LC_MAIN and off + 16 <= len(data):
            entry = base + _u64(data, off + 8)
        elif cmd == LC_BUILD_VERSION and off + 24 <= len(data):
            sdk = f"{PLATFORMS.get(_u32(data, off + 8), '?')} SDK {_vers(_u32(data, off + 16))}"
        elif cmd == LC_VERSION_MIN_MACOSX and off + 16 <= len(data):
            sdk = f"macOS SDK {_vers(_u32(data, off + 12))}"
        off += cmdsize
    if kind != "object" and flags & 0x200000:
        kind = "pie"
    notes = []
    if sdk:
        notes.append(f"built against the {sdk}")
    if kind in ("exe", "pie", "shared") and not has_debug:
        notes.append("no __DWARF here: a .dSYM next to the binary carries the symbols")
    return NativeImage("macho", CPU_ARCH[cputype], 64, kind, base, entry, sections, has_debug,
                       "dwarf" if has_debug else "", None, "", notes)
