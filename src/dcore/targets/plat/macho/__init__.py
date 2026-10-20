"""The Mach-O platform pack: macOS — Itanium ABI, DWARF (inline in a .dSYM), Apple clang.

macOS is the easy compile side when the tool runs on a Mac (system clang is right there) and
the hard debug side (release binaries ship symbol-less; the .dSYM next to them carries the
DWARF, and the pack reads it when handed one).
"""

from __future__ import annotations

from pathlib import Path

from .. import PlatPack
from . import image as image_mod


class MachoPack(PlatPack):
    key = "macho"
    family = "macho"

    def supports(self, arch: str) -> bool:
        return arch in ("x86_64", "aarch64")

    def sniff(self, head: bytes) -> str | None:
        return image_mod.sniff(head)

    def identify(self, data: bytes):
        return image_mod.parse(data)

    def reloc_type(self, kind: str) -> int:
        # X86_64_RELOC_SIGNED (1) for pc-relative; the ARM64 family numbers land with its pack.
        return {"pc": 1, "branch": 2, "abs": 0, "abs64": 0}[kind]

    # ---------------------------------------------------------------- facts

    def debug_units(self, binary: Path):
        """Mach-O DWARF: the same reader as ELF (pyelftools reads both), pointed at the .dSYM
        when the binary itself has no __DWARF segment."""
        from ..elf import dwarf as dwarf_mod

        for candidate in (binary, binary.with_suffix(".dSYM/Contents/Resources/DWARF/" + binary.stem)):
            if Path(candidate).is_file():
                units = dwarf_mod.analyze(candidate)
                if units.get("functions") or units.get("compile_units"):
                    return units
        return None

    # ---------------------------------------------------------------- toolchain

    def toolchain(self, arch: str, guess: str) -> dict:
        target = {"x86_64": "x86_64-apple-macos", "aarch64": "arm64-apple-macos"}[arch]
        return {"driver": f"clang -target {target} (system clang is the original compiler here)",
                "note": ""}


PACK = MachoPack()
