"""COFF object reading (MSVC / clang-cl): a function's bytes + relocations out of a .obj / .o.

The Windows counterpart of ``plat/elf/object.py``; the model lives in ``targets/objects.py``.
Two things are peculiar to this container and handled here rather than by the judge:

- **the addend lives in the bytes**: COFF relocations carry no addend, so the field at the site
  is read (signed for the REL32 family — a call site's field is -4, which is exactly what the
  Reconstructor writes for the target side);
- **section-relative references** (IMAGE_REL_AMD64_SECTION, what a compiler uses for local
  statics and function addresses in tables) are resolved to the named symbol at that offset,
  the way a by-name reference would be encoded — the same trick the ELF reader plays.

Symbol names are canonicalized for the judge: ``__imp_foo`` (a dllimport call) reads as
``foo``, because the target side names an IAT call by its import.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from ...objects import FunctionObj, Reloc

MACHINES = {0x8664: "x86_64", 0x14C: "x86", 0xAA64: "aarch64"}

# (arch, type) -> (offset from the site, length, bitmask to clear) — IMAGE_REL_AMD64_* numbers.
# Anything not listed masks the 4 bytes at the site, right for the whole REL32 family.
_MASKS: dict[tuple[str, int], tuple[int, int, int]] = {
    ("x86_64", 0x1): (0, 8, 0xFFFFFFFFFFFFFFFF),  # ADDR64
    ("x86_64", 0x2): (0, 4, 0xFFFFFFFF),  # ADDR32
    ("x86_64", 0x3): (0, 4, 0xFFFFFFFF),  # ADDR32NB
    ("x86_64", 0xA): (0, 4, 0xFFFFFFFF),  # SECTION (offset within the target's section)
    ("x86_64", 0xB): (0, 4, 0xFFFFFFFF),  # SECREL
    ("x86", 0x6): (0, 4, 0xFFFFFFFF),  # DIR32
    ("x86", 0x7): (0, 4, 0xFFFFFFFF),  # DIR32NB
    ("x86", 0xA): (0, 4, 0xFFFFFFFF),  # SECTION
    ("x86", 0xB): (0, 4, 0xFFFFFFFF),  # SECREL
}

# the REL32 family: the -4 (and the _n cousins' deeper bias) lives in the type, not the field
_REL32 = {("x86_64", t) for t in (0x4, 0x5, 0x6, 0x7, 0x8, 0x9)} | {("x86", 0x14)}


@dataclass
class _Sym:
    index: int
    name: str
    value: int
    section: int  # 1-based section index; 0 undefined, -1 absolute, -2 debug
    type: int
    cls: int  # 0 end, 1 null, 2 external, 3 static, ...
    is_section: bool  # a section symbol (static, empty name): a section-relative base


@dataclass
class _Section:
    name: str
    size: int
    chars: int
    raw: int
    reloc_at: int
    nreloc: int


class _Coff:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 20:
            raise ValueError("not a COFF object")
        self.machine = struct.unpack_from("<H", data, 0)[0]
        if self.machine not in MACHINES:
            raise ValueError(f"unsupported COFF machine {self.machine:#x}")
        nsec = struct.unpack_from("<H", data, 2)[0]
        symptr, nsyms = struct.unpack_from("<II", data, 8)
        if not symptr or not nsyms:
            raise ValueError("COFF object without a symbol table")
        self._strtab = symptr + 18 * nsyms
        self.sections: list[_Section] = []
        for i in range(nsec):
            o = 20 + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            if name.startswith("/"):  # long name: an offset into the string table
                name = self._string(int(name[1:]) or 0)
            vsize, vaddr, rawsize, rawptr, relptr = struct.unpack_from("<IIIII", data, o + 8)
            nreloc = struct.unpack_from("<H", data, o + 32)[0]
            chars = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append(_Section(name, vsize or rawsize, chars, rawptr, relptr, nreloc))
        self.symbols: list[_Sym] = []
        i = 0
        while i < nsyms:
            o = symptr + 18 * i
            if o + 18 > len(data):
                break
            raw_name = data[o:o + 8]
            if raw_name[:4] == b"\0\0\0\0":
                name = self._string(struct.unpack_from("<I", raw_name, 4)[0])
            else:
                name = raw_name.rstrip(b"\0").decode("ascii", "replace")
            value = struct.unpack_from("<I", data, o + 8)[0]
            section, typ = struct.unpack_from("<hH", data, o + 12)
            cls, naux = struct.unpack_from("<BB", data, o + 16)
            self.symbols.append(_Sym(i, name, value, section, typ, cls,
                                     is_section=(cls == 3 and section > 0
                                                 and (not name or (name.startswith(".") and value == 0)))))
            i += 1 + naux
        self.by_name: dict[str, _Sym] = {s.name: s for s in self.symbols if s.name}
        # aux records make a symbol's index differ from its position in the list: map by index
        self.by_index: dict[int, _Sym] = {s.index: s for s in self.symbols}

    def _string(self, off: int) -> str:
        at = self._strtab + off
        end = self.data.index(b"\0", at) if b"\0" in self.data[at:at + 256] else at + 64
        return self.data[at:end].decode("ascii", "replace")

    def section_bytes(self, sec: _Section) -> bytes:
        return self.data[sec.raw:sec.raw + sec.size]

    def relocs_of(self, sec_index: int) -> list[tuple[int, int, int]]:
        """(site offset within the section, symbol index, type) for one section."""
        sec = self.sections[sec_index - 1]
        out = []
        for k in range(sec.nreloc):
            o = sec.reloc_at + 10 * k
            if o + 10 > len(self.data):
                break
            va, symidx, typ = struct.unpack_from("<IIH", self.data, o)
            out.append((va, symidx, typ))
        return out

    def is_code(self, section: int) -> bool:
        return 1 <= section <= len(self.sections) and bool(self.sections[section - 1].chars & 0x20)

    def next_start(self, sec_index: int, off: int, limit: int) -> int:
        starts = [s.value for s in self.symbols
                  if s.section == sec_index and s.name and s.value > off and not s.is_section]
        return min(starts) if starts else limit

    def named_at(self, sec_index: int, off: int) -> tuple[str, int] | None:
        """(name, residual) of the named symbol covering `off` in a section, exact starts first."""
        best = None
        for s in self.symbols:
            if s.section != sec_index or not s.name or s.is_section or s.name[0] in ".$@":
                continue
            if s.value <= off:
                rank = (s.value == off, s.cls == 2)
                if best is None or rank > best[0]:
                    best = (rank, s.name, off - s.value)
        return (best[1], best[2]) if best else None


def _canonical(name: str) -> str:
    """`__imp_foo` is a dllimport call to `foo`; the target side names the import."""
    return name[len("__imp_"):] if name.startswith("__imp_") else name


def _field(sec: bytes, off: int, table: dict, arch: str, rtype: int, signed: bool) -> int:
    delta, length, mask = table.get((arch, rtype), (0, 4, 0xFFFFFFFF))
    at = off + delta
    if at < 0 or at + length > len(sec):
        return 0
    v = int.from_bytes(sec[at:at + length], "little") & mask
    if signed and v & (1 << (8 * length - 1)):
        v -= 1 << (8 * length)
    return v


def list_functions(data: bytes) -> list[str]:
    """Every function symbol defined in the object's code sections."""
    coff = _Coff(data)
    return [s.name for s in coff.symbols
            if s.name and s.section > 0 and coff.is_code(s.section) and s.name[0] not in ".$/@"
            and (s.type & 0x20 or s.cls in (2, 3))]


def extract_function(data: bytes, name: str) -> FunctionObj | None:
    coff = _Coff(data)
    arch = MACHINES[coff.machine]
    sym = coff.by_name.get(name)
    if sym is None:  # x86 C names carry a leading underscore; try both spellings
        sym = coff.by_name.get("_" + name) or coff.by_name.get(name.lstrip("_"))
    if sym is None:
        # IDA's dedup display name (Print_4488) has no parameter list, while the object's symbol is
        # the mangled ?Print_4488@…; exact lookup can never match. Fall back to a unique code symbol
        # carrying the same leaf, which is what the submission defined.
        leaf = name.rsplit("::", 1)[-1].split("(", 1)[0]
        if leaf:
            pat = re.compile(rf"(?:^|[?@_]){re.escape(leaf)}(?:@|$)")
            hits = [s for s in coff.symbols
                    if s.section > 0 and coff.is_code(s.section) and pat.search(s.name)]
            if len(hits) == 1:
                sym = hits[0]
    if sym is None or sym.section <= 0 or not coff.is_code(sym.section):
        return None
    sec = coff.sections[sym.section - 1]
    code_all = coff.section_bytes(sec)
    start = sym.value
    end = min(coff.next_start(sym.section, start, sec.size), sec.size)
    rel_sites = [va for va, _s, _t in coff.relocs_of(sym.section) if va >= start]
    while (end - 4 >= start + 4 and code_all[end - 4:end] == b"\0\0\0\0"
           and not any(end - 4 <= va < end for va in rel_sites)):  # trailing alignment, never a reloc
        # a reloc's field is zeroed in the unlinked object (a trailing `jmp rel32` tail call is
        # the classic case): eating it truncates the function and the differ can't decode the stub
        end -= 4
    if end <= start:
        return None
    code = code_all[start:end]

    relocs: list[Reloc] = []
    for va, symidx, rtype in coff.relocs_of(sym.section):
        if not (start <= va < end):
            continue
        site = va - start
        target = coff.by_index.get(symidx)
        if target is None:
            continue
        signed = (arch, rtype) in _REL32
        if target.is_section or not target.name:
            # a section-relative reference: resolve to what a by-name reference would look like
            ref_sec = target.section if target.section > 0 else None
            off_in_sec = _field(code, site, _MASKS, arch, rtype, signed=False)
            named = coff.named_at(ref_sec, off_in_sec) if ref_sec else None
            if named:
                sym_name, residual = named
                relocs.append(Reloc(site, rtype, _canonical(sym_name), residual - 4 if signed else residual))
            elif ref_sec:
                sec_name = coff.sections[ref_sec - 1].name
                relocs.append(Reloc(site, rtype, sec_name + (f"+0x{off_in_sec:x}" if off_in_sec else ""), 0))
            continue
        addend = _field(code, site, _MASKS, arch, rtype, signed=signed)
        if signed:  # the REL32 family carries its -4 bias in its type, not in the field: the target
            addend -= 4  # side records it explicitly, so normalize to the same convention
        relocs.append(Reloc(site, rtype, _canonical(target.name), addend))
    relocs.sort(key=lambda r: r.offset)
    return FunctionObj(name=name, arch=arch, big_endian=False, code=code, relocs=relocs, masks=_MASKS)
