"""The ELF platform pack: Linux and friends — System V ABI, DWARF, gcc/clang, glibc/musl.

A container pack does the four things the core refuses to know: parse the image, spell names
the way the object side spells them, say what debug info convention this world uses, and say
which compilers build it. Everything ISA-shaped lives in the arch pack instead.
"""

from __future__ import annotations

from pathlib import Path

from .. import PlatPack
from . import dwarf as dwarf_mod
from . import image as image_mod


class ElfPack(PlatPack):
    key = "elf"
    family = "elf"

    def supports(self, arch: str) -> bool:
        return arch in ("x86", "x86_64", "aarch64")

    def sniff(self, head: bytes) -> str | None:
        return image_mod.sniff(head)

    def identify(self, data: bytes):
        return image_mod.parse(data)

    def object_reader(self):
        from . import object as object_mod

        return object_mod

    def reloc_type(self, arch: str, kind: str) -> int:
        # R_X86_64_PC32 / R_386_PC32 share the number 2; the AArch64 family differs and lands with
        # its arch pack (whose `ready` gate keeps judging away until then)
        if arch == "aarch64":
            raise NotImplementedError("aarch64 reloc numbers land with its arch pack")
        return {"pc": 2, "branch": 4, "abs": 1, "abs64": 1}[kind]

    # ---------------------------------------------------------------- names

    def section_alias(self, name: str) -> str:
        """elfobj collapses `.rodata.str1.1` and friends to `.rodata`; the target side must too."""
        if name.startswith(".text."):
            return name[len(".text."):]
        if name.count(".") > 1:
            return "." + name.split(".")[1]
        return name

    def import_base(self, name: str) -> str:
        """`printf@@GLIBC_2.2.5` -> `printf` (what source code would name it)."""
        return name.split("@", 1)[0] or name

    # ---------------------------------------------------------------- facts

    def debug_units(self, binary: Path):
        """DWARF units and their producers (pyelftools)."""
        return dwarf_mod.analyze(binary)

    # ---------------------------------------------------------------- toolchain

    def toolchain(self, arch: str, guess: str) -> dict:
        triple = {"x86_64": "x86_64-linux-gnu", "x86": "i686-linux-gnu", "aarch64": "aarch64-linux-gnu"}[arch]
        return {"driver": f"gcc / clang++ / zig cc -target {triple}", "note": ""}


PACK = ElfPack()
