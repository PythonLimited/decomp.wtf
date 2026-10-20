"""x86_64: capstone 64-bit, and the operand rules that rebuild a linked image's references.

A call or jump that leaves the function is a PC-relative 32-bit reference; a memory operand
based on RIP is a PC-relative reference to whatever it lands on. Both are what the compiler
emitted as R_X86_64_PC32 (or the container's spelling of it), so the target side reconstructs
exactly those and the object side already has them.
"""

from __future__ import annotations

import capstone

from . import ArchPack, RelocKind

_IMM, _MEM, _RIP = capstone.x86.X86_OP_IMM, capstone.x86.X86_OP_MEM, capstone.x86.X86_REG_RIP


class X86_64Pack(ArchPack):
    key = "x86_64"
    ready = True

    def disassembler(self) -> capstone.Cs | None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        return md

    def reloc_kinds(self) -> dict[str, RelocKind]:
        return {"pc": RelocKind("pc32", 4, -4, "pc")}

    def reconstruct(self, reco, code: bytes, ea: int) -> list:
        md = self.disassembler()
        plat = reco.plat
        pc32 = plat.reloc_type(reco.image.arch, "pc")
        relocs = []
        end = ea + len(code)
        for ins in md.disasm(code, ea):
            if ins.group(capstone.CS_GRP_CALL) or ins.group(capstone.CS_GRP_JUMP):
                op = ins.operands[0] if ins.operands else None
                # A known function start is external even when IDA's size includes it
                # (padding/merged neighbours).  A destination inside this function and not a
                # function start is a local label; the judge synthesizes its reference.
                if op is not None and op.type == _IMM and (
                        op.imm in reco.functions or not (ea <= op.imm < end)):
                    name = reco.function_name(op.imm) or f"sub_{op.imm:x}"
                    relocs.append(reco.Reloc(ins.address + ins.size - 4 - ea, pc32, name, -4,
                                             target_ea=op.imm))
                    continue
            for op in ins.operands:
                if op.type == _MEM and op.mem.base == _RIP:  # rip-relative memory
                    target = ins.address + ins.size + op.mem.disp
                    name = reco.data_name(target) or f"data_{target:x}"
                    relocs.append(reco.Reloc(ins.address + ins.disp_offset - ea, pc32, name, -4,
                                             target_ea=target))
        return relocs


PACK = X86_64Pack()
