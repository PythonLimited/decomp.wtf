"""IDA as an analysis backend. The adapter is thin on purpose: the contract is ours.

- ``session.py`` speaks MCP-over-stdio to ida-mcp (open/close/save/execute_python);
- ``sweep.py`` is the one-pass analysis the plan is built from (functions, imports, strings,
  unit attribution), cached per binary — and it opens the user's own `.i64` when handed one;
- ``fetch_pseudocode`` pulls Hex-Rays drafts for the autopilot's free matches.

A second backend (``ghidra.py``) implements the same class and the loop never learns its name.
"""

from __future__ import annotations

from pathlib import Path

from .. import Analysis
from . import session as _session
from . import sweep as _sweep


class IdaBackend(Analysis):
    key = "ida"
    ready = True

    def available(self) -> bool:
        return _session.available()

    # ---------------------------------------------------------------- lifecycle

    def open(self, binary: Path, *, database: Path | None = None, timeout: float = 1800, log=print) -> dict:
        """One-shot open, for probing what a database holds; the engine keeps its own long-lived
        session for seeds (see NativeEngine._ida_session) — folding that in here is a later pass."""
        with _session.IdaSession(log=log) as session:
            return _session.open_database(session, Path(database or binary), timeout=timeout, log=log)

    def save(self, instance: str = "") -> None:
        raise NotImplementedError("save through the engine's session until the lifecycle moves here")

    # ---------------------------------------------------------------- facts

    def sweep(self, binary: Path, *, cache_dir: Path, force: bool = False, log=print) -> dict:
        """The one-pass analysis (cached per binary; `.i64` honored via the engine's `db` plumbing)."""
        return _sweep.export_analysis(Path(binary), Path(cache_dir), force=force, log=log)

    # ---------------------------------------------------------------- enrichment

    def pseudocode(self, binary: Path, cache_dir: Path, addresses: list[int], *, log=print) -> dict[int, str]:
        """Hex-Rays text per address, cached; it is what the autopilot tries for free."""
        return _sweep.fetch_pseudocode(Path(binary), Path(cache_dir), list(addresses), log=log)


BACKEND = IdaBackend()
