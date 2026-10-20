"""Work out what the user picked: a native program (ELF, PE or Mach-O) to plan."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..targets import formats

PLATFORMS = {"native": "Native program"}
SMALL = 64 * 1024 * 1024  # programs are read whole; anything bigger is read in place


@dataclass
class Picked:
    platform: str  # native
    data: bytes | Path  # what we store: the bytes, or the path when the file is big
    filename: str  # name to store it under in the project folder
    info: dict
    big_endian: bool = False


def identify(src: bytes | Path, name: str = "") -> Picked:
    """The program the user picked (bytes or a file). Raises NativeError for anything else."""
    if isinstance(src, (str, Path)):
        path = Path(src)
        name = name or path.name
        if path.stat().st_size <= SMALL:
            return identify(path.read_bytes(), name)
        with open(path, "rb") as f:
            native_kind = formats.looks_native(f.read(4096))
        if native_kind:
            fmt, arch = native_kind
            info = {"title": Path(name).stem or "program", "platform": "native", "format": fmt, "arch": arch,
                    "kind": "", "compiler_guess": "", "debug": "", "size": path.stat().st_size}
            return Picked("native", path, Path(name).name or path.name, info)
        raise formats.NativeError("this file is too big to read here and its first bytes don't look like a "
                                  "program this build can plan (ELF, PE or Mach-O)")
    image = formats.identify(src)
    if image is not None:
        info = {"title": Path(name).stem or "program", "platform": "native", "format": image.format,
                "arch": image.arch, "kind": image.kind, "compiler_guess": image.compiler,
                "debug": image.debug_kind, "size": len(src)}
        fallback = {"pe": "game.exe", "macho": "program.dylib"}.get(image.format, "program.elf")
        return Picked("native", src, Path(name).name or fallback, info)
    raise formats.NativeError("this isn't a program this build can read: pick an ELF, PE or Mach-O file "
                              "(Linux, Windows, macOS, Android) — x86, x86_64 or aarch64")
