"""Target = arch × plat — and the pack registry that composes them.

Nothing in the core loop may know what an ELF or an x86 is: a project resolves one
:class:`Target` (e.g. ``pe × x86_64``) and talks to it through the two pack protocols:

- :mod:`dcore.targets.arch` — ISA: which operands are references, reloc kinds, disassembler
- :mod:`dcore.targets.plat` — container/ABI: image parsing, name conventions, debug info,
  toolchains, libc/CRT fingerprints

:data:`MATRIX` declares the combinations that exist (each is a real shipped world); adding
``win × aarch64`` later is one line. ``android`` and other skins are plain subclasses of a
base platform pack, so bundling ("x86_64 with android") is just composition.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module

from .plat import PlatPack

ARCHES = ("x86", "x86_64", "aarch64")
PLATS = ("elf", "pe", "macho", "android")

#: every (plat, arch) pair that is a real world. Skins inherit their family's arches.
MATRIX: dict[str, tuple[str, ...]] = {
    "elf": ("x86", "x86_64", "aarch64"),
    "pe": ("x86", "x86_64"),
    "macho": ("x86_64", "aarch64"),
    "android": ("x86_64", "aarch64"),
}


@dataclass(frozen=True)
class Target:
    plat: str
    arch: str

    def __str__(self) -> str:
        return f"{self.plat} × {self.arch}"


def resolve(plat: str, arch: str, *, log=print) -> Target:
    """The target for this pair, or a clear error naming what the matrix holds."""
    plat = {"linux": "elf", "windows": "pe", "win": "pe", "macos": "macho", "osx": "macho"}.get(plat, plat)
    arch = {"amd64": "x86_64", "arm64": "aarch64", "x64": "x86_64"}.get(arch, arch)
    if plat not in MATRIX:
        raise LookupError(f"no platform pack for {plat!r} (have: {', '.join(MATRIX)})")
    if arch not in MATRIX[plat]:
        raise LookupError(f"{plat} has no {arch} variant (have: {', '.join(MATRIX[plat])})")
    return Target(plat, arch)


def plat_pack(plat: str) -> PlatPack:
    """The platform pack module for a key. ``android`` is a skin over ``elf``."""
    return import_module(f".plat.{plat}", __name__).PACK


def arch_pack(arch: str):
    """The arch pack module for an ISA."""
    return import_module(f".arch.{arch}", __name__).PACK


def packs() -> list[tuple[str, list[str]]]:
    """What this build can actually do — for a doctor command or a picker."""
    out = []
    for plat, arches in MATRIX.items():
        try:
            pack = plat_pack(plat)
        except Exception:
            continue
        out.append((plat, [a for a in arches if pack.supports(a)]))
    return out
