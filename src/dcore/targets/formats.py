"""The import dispatcher: ask each platform pack whether it recognizes these bytes.

This is all that's left of the old monolithic `formats`: the model lives in `image.py`, the
per-format parsing in `plat/<plat>/image.py`, and the packs answer in `targets.MATRIX` order.
Nothing here knows what an ELF header looks like.
"""

from __future__ import annotations

from pathlib import Path

from . import plat_pack
from .image import NativeError, NativeImage, Section, describe, read_bytes

#: the packs the dispatcher tries, most-specific first
_ORDER = ("elf", "pe", "macho")


def identify(data: bytes) -> NativeImage | None:
    """The program in these bytes, or None when no platform pack claims it."""
    for key in _ORDER:
        try:
            image = plat_pack(key).identify(data)
        except Exception:
            continue
        if image is not None:
            return image
    return None


def identify_path(path: str | Path) -> NativeImage:
    """Read and identify a file on disk; raises NativeError when no pack claims it."""
    data = Path(path).read_bytes()
    image = identify(data)
    if image is None:
        raise NativeError(f"{Path(path).name} isn't a program this build can read (ELF, PE or Mach-O — "
                          f"x86, x86_64 or aarch64)")
    return image


def looks_native(head: bytes) -> tuple[str, str] | None:
    """Quick check from the first bytes: (plat key, arch) for dispatch before a full parse."""
    for key in _ORDER:
        try:
            arch = plat_pack(key).sniff(head)
        except Exception:
            continue
        if arch:
            return key, arch
    return None
