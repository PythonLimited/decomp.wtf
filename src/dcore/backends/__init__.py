"""The analysis backend protocol: names, pseudocode seeds, cross-references.

A backend is *enrichment*: the loop, the plan and the judge work without one (bytes +
reconstructed relocations + a compiled object are enough to match a function). What a
backend adds is what only a database knows — real names from a PDB/DWARF, Hex-Rays or
Ghidra pseudocode to seed autopilot, xrefs, strings, and the ability to reuse an analysis
that already exists (``orion_s.exe.i64``).

The contract is ours, not any MCP server's tool schema: :class:`Analysis` is the dozen
verbs the pipeline actually uses. ``ida`` implements it over ida-mcp (or idalib);
``ghidra`` will implement it over a Ghidra MCP server or pyghidra — the adapters absorb
whatever shape that tooling has, and the loop keeps seeing one interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path


@dataclass
class FunctionInfo:
    ea: int
    name: str
    size: int
    provenance: str = "ida"  # ida | flirt | auto | ghidra | …
    source_file: str = ""    # the original unit, when the database knows it
    display: str = ""        # demangled, if the backend can


@dataclass
class Sweep:
    """Everything one backend pass can tell us about a binary, in our own words."""

    functions: list[FunctionInfo] = field(default_factory=list)
    imports: dict[int, str] = field(default_factory=dict)
    exports: dict[int, str] = field(default_factory=dict)
    strings: dict[int, str] = field(default_factory=dict)
    markers: list[str] = field(default_factory=list)
    files: dict[str, dict] = field(default_factory=dict)   # unit path -> {functions, bytes}
    counts: dict[str, int] = field(default_factory=dict)
    backend: str = ""
    database: str = ""  # the opened .i64/.idb/gpr, when one was used


class Analysis:
    """Base class for ``backends/<name>.py`` modules (each exposes a module-level BACKEND)."""

    key = ""
    ready = False

    def available(self) -> bool:
        """Is this backend installed and runnable right now?"""
        return False

    # ---------------------------------------------------------------- lifecycle

    def open(self, binary: Path, *, database: Path | None = None, timeout: float = 1800, log=print) -> dict:
        """Open a binary — or an existing database — and return the backend's own handle info."""
        raise NotImplementedError

    def close(self, instance: str = "") -> None:
        pass

    def save(self, instance: str = "") -> None:
        pass

    # ---------------------------------------------------------------- facts

    def sweep(self, binary: Path, *, cache_dir: Path, force: bool = False, log=print) -> Sweep:
        """One full pass: functions, names, imports, strings, unit attribution. Cached per binary."""
        raise NotImplementedError

    # ---------------------------------------------------------------- enrichment

    def pseudocode(self, addresses: list[int], *, log=print) -> dict[int, str]:
        """Decompiler text per address (Hex-Rays / Ghidra), for seeding the autopilot."""
        return {}

    def xrefs(self, ea: int) -> dict:
        """Who calls / references this address."""
        return {}

    def disasm(self, ea: int, count: int = 32) -> str:
        return ""

    def rename(self, ea: int, name: str) -> None:
        pass


def backend(key: str) -> Analysis:
    """The adapter for a backend key. Missing/not-installed engines raise a clear error."""
    mod = import_module(f".{key}", __name__)
    return mod.BACKEND


def available() -> list[str]:
    out = []
    for key in ("ida", "ghidra"):
        try:
            if backend(key).available():
                out.append(key)
        except Exception:
            continue
    return out
