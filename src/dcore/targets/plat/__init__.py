"""The platform pack protocol: container, ABI, debug info, toolchain — one shipped world each.

A platform pack is the module that knows what an ELF, a PE, a Mach-O or an Android ``.so``
*is*: how to parse an image into sections, how names are spelled in it, which debug info
convention it uses, which compiler builds it, and which libc/CRT names mark glue.

:class:`PlatPack` is the base; skins subclass it — ``android`` is an ELF with NDK
toolchains and bionic fingerprints, so it inherits the parsing and overrides three hooks.
Each module exposes a module-level ``PACK``.
"""

from __future__ import annotations

from pathlib import Path


class PlatPack:
    """Base class for ``targets/plat/<plat>.py`` modules (each exposes a module-level PACK)."""

    key = ""
    family = ""  # the parsing family it shares ("elf" for android)

    # ---------------------------------------------------------------- container

    def supports(self, arch: str) -> bool:
        """Does this pack handle that ISA? (narrows MATRIX per build)"""
        return True

    def sniff(self, head: bytes) -> str | None:
        """The arch this image's first bytes name, without a full parse (the import dispatcher)."""
        return None

    def identify(self, data: bytes) -> object | None:
        """Parse an image header into ``dcore.targets.image.NativeImage`` (or None)."""
        raise NotImplementedError

    def object_kind(self, arch: str) -> str:
        """The object format the judge's candidate side will parse: "elf" | "coff" | "macho"."""
        return self.family or self.key

    def object_reader(self):
        """The module that reads a candidate object of this container (FunctionObj/Reloc)."""
        raise NotImplementedError(f"{self.key} has no object reader yet")

    def reloc_type(self, arch: str, kind: str) -> int:
        """This container's number for an arch-level reloc kind ("pc", "abs", "branch").

        Both judge sides read the same container, so its numbering is what the Reloc records —
        and it is per machine (x64 REL32 is 4; x86's is 0x14)."""
        raise NotImplementedError(f"{self.key} has no reloc mapping yet")

    # ---------------------------------------------------------------- names

    def section_alias(self, name: str) -> str:
        """Collapse a section name the way the *object side* spells it (``.rodata.str1.1``)."""
        return name

    def import_base(self, name: str) -> str:
        """Strip versioning from an imported symbol (``printf@@GLIBC_2.2.5`` -> ``printf``)."""
        return name.split("@", 1)[0] or name

    # ---------------------------------------------------------------- facts about the binary

    def debug_units(self, binary: Path):
        """Debug info as analysis units — DWARF for ELF, PDB for PE (later), dSYM for Mach-O.

        Returns ``(units, producers)`` or ``None`` when this pack has nothing to add; the
        analysis merge treats it as enrichment either way."""
        return None

    # ---------------------------------------------------------------- toolchain

    def toolchain(self, arch: str, guess: str) -> dict:
        """How to build C for ``arch`` on this platform: {"driver": ..., "note": ...}.

        The core's compiler resolver calls this and layers user overrides on top; the pack
        owns the platform facts (system clang, NDK clang, msvc-wine, …)."""
        return {"driver": "", "note": ""}
