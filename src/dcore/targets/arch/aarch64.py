"""aarch64: capstone ARM64 — the ISA the android and macho packs lean on.

Not ready: an AArch64 reference is usually *two* instructions (ADRP + ADD/LDR page/offset
pairs), branches are ±128MB with different ranges for B/BL and B.cond, and literals load via
LDR-literal. Rebuilding those relocations faithfully is its own phase — `ready` stays False so
nothing judges on a half-decoded operand.
"""

from __future__ import annotations

import capstone

from . import ArchPack, RelocKind


class Aarch64Pack(ArchPack):
    key = "aarch64"
    ready = False

    def disassembler(self) -> capstone.Cs | None:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        return md

    def reloc_kinds(self) -> dict[str, RelocKind]:
        return {"page": RelocKind("adrp-imm", 4, 0, "pc"), "branch": RelocKind("bl-imm", 4, 0, "branch"),
                "abs64": RelocKind("movz/movk", 8, 0, "abs")}

    def reconstruct(self, reco, code: bytes, ea: int) -> list:
        return []  # see the module docstring: ADRP/ADD pairing lands with aarch64's own phase


PACK = Aarch64Pack()
