"""x86 (32-bit): capstone 32-bit — the ISA the ELF and PE packs started on.

Not ready: 32-bit references come in cdecl/stdcall/fastcall flavours, absolute addresses and
GOT-based position-independent code, so the operand rules need their own careful pass (and the
MSVC ABI on PE adds decorated names). Better to refuse than to judge garbage — `ready` is what
the plan consults.
"""

from __future__ import annotations

import capstone

from . import ArchPack, RelocKind


class X86Pack(ArchPack):
    key = "x86"
    ready = False

    def disassembler(self) -> capstone.Cs | None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        return md

    def reloc_kinds(self) -> dict[str, RelocKind]:
        return {"pc": RelocKind("rel32", 4, -4, "pc")}

    def reconstruct(self, reco, code: bytes, ea: int) -> list:
        return []  # see the module docstring: operand rules land with x86's own phase


PACK = X86Pack()
