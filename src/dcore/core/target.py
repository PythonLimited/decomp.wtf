"""Rebuild a function's relocatable view from the shipped binary.

The candidate side of the judge is a real object file (the platform pack ships its reader —
elfobj for ELF today; COFF and Mach-O land with their phases). The target side is a *loaded*
image, so its relocations are reconstructed from what the linker resolved: direct call and
jump targets, RIP-relative data references, thunks that forward to an import. Which operands
count is the arch pack's business; how names are spelled is the platform pack's, so both sides
line up in the judge.
"""

from __future__ import annotations

from ..targets import arch_pack, formats, plat_pack
from ..targets.objects import FunctionObj, Reloc  # the object reader the judge uses today  # the model; readers live with each platform pack


class Reconstructor:
    """Names and reconstructs target views for one image (built once per project)."""

    Reloc = Reloc  # arch packs build these; the class moves to the platform pack's object reader

    def __init__(self, data: bytes, image: formats.NativeImage, functions: dict[int, dict],
                 strings: dict[int, str] | None = None, imports: dict[int, str] | None = None,
                 aliases: dict[int, str] | None = None, data_names: dict[int, str] | None = None):
        self.data = data
        self.image = image
        self.functions: dict[int, dict] = dict(functions)
        self.strings = dict(strings or {})
        self.aliases = dict(aliases or {})
        self.data_names = dict(data_names or {})  # named globals/statics from the sweep
        self.plat = plat_pack(image.format)
        self.arch = arch_pack(image.arch)
        self.imports = {ea: self.plat.import_base(name) for ea, name in (imports or {}).items()}
        self._thunks: dict[int, str | None] = {}

    # ------------------------------------------------------------------ names

    def function_name(self, ea: int) -> str | None:
        if ea in self._thunks:
            return self._thunks[ea]
        name: str | None
        if ea in self.aliases:
            name = self.aliases[ea]
        elif ea in self.imports:
            name = self.imports[ea]
        else:
            fn = self.functions.get(ea)
            if fn is not None:
                name = fn.get("display") or fn.get("name") or None
                if name and name.startswith("sub_"):
                    # IDA may auto-name a jump thunk `sub_...`; prefer what it forwards to.
                    name = self._thunk_name(ea, 0) or name
            else:
                name = self._thunk_name(ea, 0)
        self._thunks[ea] = name
        return name

    def _thunk_name(self, ea: int, depth: int) -> str | None:
        """A small jump thunk reads as its final target (import or function).

        MSVC/linkers emit `jmp [rip+IAT]` and `jmp target` stubs at addresses IDA may not
        name.  A call to such a stub is link-equivalent to a call to the import/function it
        forwards to, so the judge can compare destinations instead of synthetic `sub_` names.
        """
        if depth > 2 or self.image.arch not in ("x86_64", "x86"):
            return None
        code = formats.read_bytes(self.data, self.image, ea, 24)
        if not code:
            return None
        import capstone
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if self.image.arch == "x86_64" else capstone.CS_MODE_32)
        md.detail = True
        insns = list(md.disasm(code, ea))
        if not insns:
            return None
        first = insns[0]
        target: int | None = None
        if first.mnemonic.startswith("jmp") and first.operands:
            op = first.operands[0]
            if op.type == X86_OP_IMM:
                target = int(op.imm)
            elif op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    target = first.address + first.size + op.mem.disp
                elif op.mem.base == 0:
                    target = int(op.mem.disp)
        elif (first.mnemonic.startswith("mov") and first.operands
              and first.operands[0].type == X86_OP_REG and first.operands[1].type == X86_OP_MEM
              and first.operands[1].mem.base == X86_REG_RIP
              and len(insns) > 1 and insns[1].mnemonic.startswith("jmp")
              and insns[1].operands and insns[1].operands[0].type == X86_OP_REG
              and insns[1].operands[0].reg == first.operands[0].reg):
            # mov rax, [rip+IAT]; jmp rax
            target = first.address + first.size + first.operands[1].mem.disp
        if target is None:
            return None
        if target in self.imports:
            return self.imports[target]
        if target in self.aliases:
            return self.aliases[target]
        fn = self.functions.get(target)
        if fn is not None:
            return fn.get("display") or fn.get("name") or None
        return self._thunk_name(target, depth + 1)

    def data_name(self, addr: int) -> str | None:
        if addr in self.aliases:
            return self.aliases[addr]
        if addr in self.imports:
            return self.imports[addr]
        if addr in self.data_names:  # the debug info named this global: the agent should see it
            return self.data_names[addr]
        if addr in self.strings:
            pass  # an anonymous string: the section's name is the honest answer (see below)
        elif (fn := self.functions.get(addr)) is not None:
            return fn.get("display") or fn.get("name") or None
        sec = self.image.section_at(addr)
        if sec is None:
            return None
        # keep the offset inside the section: a compiler's reloc reads `.rodata+0x4`, and dropping
        # the +off made identical references look different (float constants, string literals)
        off = addr - sec.vaddr
        return self.plat.section_alias(sec.name) + (f"+0x{off:x}" if off else "")

    # ------------------------------------------------------------------ reconstruction

    def view(self, fn: dict) -> FunctionObj | None:
        """The target FunctionObj for one merged-analysis function record."""
        ea, size = fn["ea"], fn["size"]
        code = formats.read_bytes(self.data, self.image, ea, size)
        if code is None:
            return None
        return FunctionObj(fn.get("name") or f"sub_{ea:x}", self.image.arch, False, code,
                           self.reconstruct(code, ea), base_ea=ea)

    def reconstruct(self, code: bytes, ea: int) -> list:
        """The relocations a compiler would have emitted for this code, from resolved references."""
        if not self.arch.ready:
            return []  # the arch pack isn't ready yet (x86, aarch64): refuse rather than judge garbage
        return self.arch.reconstruct(self, code, ea)


def import_aliases(functions: dict[int, dict], imports: dict[int, str]) -> dict[int, str]:
    """Thunks like `.printf` (a jump to an import stub) should read as the import's name,
    because that is the name a recompiled call would use."""
    return {ea: name.split("@", 1)[0] or name for ea, name in imports.items()}
