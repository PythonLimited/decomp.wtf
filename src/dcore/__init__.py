"""dcore: the core loop — nothing here knows what an ELF or an x86 is."""

from __future__ import annotations

import sys

__version__ = "0.1.0"


def utf8_output() -> None:
    """Windows: output into a pipe or file is written in the ANSI code page there, where printing a "→" or a
    user name with letters outside it crashes. Write UTF-8 instead."""
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if stream is not None and not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")


__all__ = ["__version__", "utf8_output"]
