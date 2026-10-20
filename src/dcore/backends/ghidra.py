"""Ghidra as an analysis backend — the second one, landing after IDA is fully wired.

The plan: wrap a Ghidra MCP server (or pyghidra in-process, which needs no server) behind the
same :class:`dcore.backends.Analysis` verbs as ``ida.py``. What Ghidra brings that IDA doesn't:
a free, scriptable decompiler (the seeds for autopilot), and headless installs on machines that
don't have IDA. What it costs: a Java runtime and a second database format. Nothing in the core
loop changes either way — provenance on the analysis records just reads "ghidra".
"""

from __future__ import annotations

from pathlib import Path

from . import Analysis


class GhidraBackend(Analysis):
    key = "ghidra"
    ready = False

    def available(self) -> bool:
        return False  # until the adapter lands, the plan says so instead of failing at compile time

    def open(self, binary: Path, *, database: Path | None = None, timeout: float = 1800, log=print) -> dict:
        raise NotImplementedError("Ghidra support is a later phase (see this module's docstring)")

    def sweep(self, binary: Path, *, cache_dir: Path, force: bool = False, log=print):
        raise NotImplementedError("Ghidra support is a later phase (see this module's docstring)")


BACKEND = GhidraBackend()
