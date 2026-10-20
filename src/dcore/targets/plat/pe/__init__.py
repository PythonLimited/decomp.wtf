"""The PE platform pack: Windows — MSVC ABI, PDB debug info, cl.exe / msvc-wine.

The candidate side of the judge is a COFF object here (``object_kind`` = "coff"), whose reader
lives in ``object.py`` — that plus the msvc-wine toolchain is the Windows phase of the build.
What already works: parsing (sections, debug directory, Rich header → MSVC label) and the
import dispatcher.
"""

from __future__ import annotations

from .. import PlatPack
from . import image as image_mod


class PePack(PlatPack):
    key = "pe"
    family = "pe"

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
        # IMAGE_REL_AMD64_REL32 (4) vs IMAGE_REL_I386_REL32 (0x14): the same reference, different
        # numbering per machine — the Reconstructor and the COFF reader must agree per arch.
        if arch == "x86":
            return {"pc": 0x14, "branch": 0x14, "abs": 0x6, "abs64": 0x6}[kind]
        return {"pc": 4, "branch": 4, "abs": 2, "abs64": 1}[kind]  # IMAGE_REL_AMD64_REL32 / ADDR32 / ADDR64

    # ---------------------------------------------------------------- toolchain

    def toolchain(self, arch: str, guess: str) -> dict:
        triple = f"{arch}-pc-windows-msvc"
        driver = (f"cl first, then clang-cl, then clang --target={triple} --driver-mode=cl — all "
                  f"MSVC-style; probes spell flags /O2, /GS, /EHsc")
        note = (f"the binary was built with {guess or 'an unnamed MSVC'}; for byte-exact output the "
                f"driver must be that cl build — build the msvc-wine image (docker/msvc-wine, tag "
                f"dcore-msvc-wine:2015u3) and set it as the project image, driver cl")
        return {"driver": driver, "note": note}


PACK = PePack()
