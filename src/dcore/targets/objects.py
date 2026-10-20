"""The object model the judge compares: a function's bytes plus its symbolic relocations.

A *reader* per platform pack (``plat/elf/object.py``, ``plat/pe/object.py``) turns a real object
file into these; the judge only ever compares two of them, so the type numbers inside ``Reloc``
are the container's own — the pack guarantees both sides speak the same numbering
(``PlatPack.reloc_type``). Masking widths are the reader's table: the same type number can mean
different field sizes across containers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Reloc:
    offset: int  # relative to function start
    type: int
    symbol: str
    addend: int  # only meaningful (and only compared) for non-section symbols
    # Absolute destination reconstructed from the linked image (target side only).
    # Object readers leave it None: their symbol name is resolved through SymbolTable.
    target_ea: int | None = None

    def key(self) -> tuple:
        return (self.offset, self.type, self.symbol, self.addend)

    def to_json(self) -> list:
        return [self.offset, self.type, self.symbol, self.addend]

    @staticmethod
    def from_json(v: list) -> Reloc:
        return Reloc(*v)


@dataclass
class FunctionObj:
    name: str
    arch: str
    big_endian: bool
    code: bytes
    relocs: list[Reloc] = field(default_factory=list)
    masks: dict | None = None  # (arch, type) -> (offset, length, bitmask); the reader's table
    base_ea: int | None = None  # absolute address of code[0] on the target side

    def normalized(self) -> bytes:
        return mask_relocs(self.code, self.relocs, self.arch, self.big_endian, self.masks)

    def fingerprint(self) -> str:
        """Hash of masked bytes + symbolic relocs. Equal fingerprints == matching function."""
        h = hashlib.sha256(self.normalized())
        for r in sorted(self.relocs, key=Reloc.key):
            h.update(repr(r.key()).encode())
        return h.hexdigest()


def mask_relocs(code: bytes, relocs: list[Reloc], arch: str, big_endian: bool,
                table: dict | None = None) -> bytes:
    buf = bytearray(code)
    for r in relocs:
        delta, length, mask = (table or {}).get((arch, r.type), (0, 4, 0xFFFFFFFF))
        start = r.offset + delta
        if start < 0 or start + length > len(buf):
            continue
        order = "big" if big_endian else "little"
        val = int.from_bytes(buf[start : start + length], order)
        buf[start : start + length] = (val & ~mask & ((1 << (8 * length)) - 1)).to_bytes(length, order)
    return bytes(buf)
