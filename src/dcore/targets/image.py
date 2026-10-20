"""The image model every platform pack fills: sections, base, entry, debug info, compiler label.

The address convention: `vaddr` is the *link-time* address — ELF sh_addr, PE ImageBase+RVA,
Mach-O segment vmaddr — which is also what DWARF/PDB and a backend report for a non-relocated
image. Candidates are compared symbolically, so a PIE load bias never enters the picture.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field


class NativeError(ValueError):
    """A file this build can't work with (yet); shown to the user as is."""


@dataclass
class Section:
    name: str
    vaddr: int
    size: int
    offset: int  # file offset of the bytes (meaningless for bss)
    kind: str  # code | rodata | data | bss


@dataclass
class NativeImage:
    format: str  # "elf" | "pe" | "macho"
    arch: str  # "x86" | "x86_64" | "aarch64"
    bits: int
    kind: str  # exe | pie | shared | dll | object
    image_base: int  # link-time base (0 for objects and link-time-0 PIEs)
    entry: int  # link-time entry address, 0 when none
    sections: list[Section]
    has_debug: bool
    debug_kind: str  # "dwarf" | "pdb" | "dsym" | ""
    pdb: dict | None  # {"path", "guid", "age"} when a CodeView RSDS record exists
    compiler: str  # best-effort label, "" when unknown
    notes: list[str] = field(default_factory=list)

    def section_at(self, addr: int) -> Section | None:
        for s in self.sections:
            if s.vaddr <= addr < s.vaddr + s.size:
                return s
        return None

    def to_dict(self) -> dict:
        return {"format": self.format, "arch": self.arch, "bits": self.bits, "kind": self.kind,
                "image_base": self.image_base, "entry": self.entry, "has_debug": self.has_debug,
                "debug_kind": self.debug_kind, "pdb": self.pdb, "compiler": self.compiler,
                "notes": self.notes, "sections": [vars(s) for s in self.sections]}


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


_CLANG = re.compile(rb"clang version ([\d.]+)")
_GCC = re.compile(rb"GCC:?\s*(?:\(GNU\)\s*)?([\d.]+)")


def compiler_from_comment(comment: bytes) -> str:
    """A compiler label from a `.comment`-style section (GCC/clang banners, NDK included)."""
    if not comment:
        return ""
    if (m := _CLANG.search(comment)):
        return "clang " + m.group(1).decode()
    if (m := _GCC.search(comment)):
        return "gcc " + m.group(1).decode()
    first = comment.split(b"\0", 1)[0].strip()
    text = first.decode("ascii", "replace")
    return text if 0 < len(text) < 80 and any(c.isdigit() for c in text) else ""


def read_bytes(data: bytes, image: NativeImage, addr: int, size: int) -> bytes | None:
    """The bytes at a virtual address inside a loaded image (None for bss or when truncated)."""
    sec = image.section_at(addr)
    if sec is None or sec.kind == "bss":
        return None
    at = sec.offset + (addr - sec.vaddr)
    end = at + size
    if at < 0 or end > len(data):
        return None
    return data[at:end]


def describe(image: NativeImage) -> str:
    """One line for the user: what kind of program this is."""
    kind = {"exe": "executable", "pie": "executable (PIE)", "shared": "shared library",
            "dll": "DLL", "object": "object file"}.get(image.kind, image.kind)
    debug = {"dwarf": "DWARF", "pdb": "PDB", "dsym": "dSYM"}.get(image.debug_kind, "no debug info")
    fmt = {"macho": "Mach-O"}.get(image.format, image.format.upper())
    return f"{fmt} {image.arch} {kind}, {debug}" + (f", {image.compiler}" if image.compiler else "")
