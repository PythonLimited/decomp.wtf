"""Android: an ELF skin — the NDK's clang toolchains and bionic's fingerprints on top of `elf`.

Same container, same DWARF, same ABI (Itanium, like Linux); what changes is who built it (an
NDK clang, whose version the DWARF producer names) and which libc names mark glue. This is the
whole argument for skins: two overrides and a matrix line, not a fork of the ELF pack.
"""

from __future__ import annotations

import re

from ..elf import ElfPack

_NDK = re.compile(r"NDK|android")

# bionic (Android's libc) symbols that mark library code, besides the standard libc set the
# core's glue policy already knows.
BIONIC_MARKERS = ("__android_log", "__system_property", "_ZN7android", "AAssetManager", "__cxa_")


class AndroidPack(ElfPack):
    key = "android"

    def supports(self, arch: str) -> bool:
        return arch in ("x86_64", "aarch64")

    def toolchain(self, arch: str, guess: str) -> dict:
        if guess and _NDK.search(guess):
            note = f"the binary names its toolchain already: {guess}"
        else:
            note = ("Android .so files are built with the NDK's clang; match the NDK release that "
                    "shipped that clang (the DWARF producer names it)")
        triple = {"x86_64": "x86_64-linux-android", "aarch64": "aarch64-linux-android"}[arch]
        return {"driver": f"the NDK's clang++ --target={triple}", "note": note}


PACK = AndroidPack()
