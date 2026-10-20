"""The plan: which files to decompile, which to only declare (interface), which to leave out.

The plan lives in the project config: every node of the analysis' file graph has a treatment.
Excluding a file cascades — it provides nothing, not even declarations, so everything that
transitively calls into it can no longer compile; decompile nodes in that closure are excluded
too (the UI previews the cascade before committing). Interface nodes don't compile at all, so
they stop the cascade. Confirming the plan is what turns the analysis into claimable functions.
"""

from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path

from . import scoring
from .network import NetworkError
from . import analyze as analyze_mod
from ..targets import formats

TREATMENTS = ("decompile", "interface", "exclude")
STATUS = {"decompile": "open", "interface": "interface", "exclude": "excluded"}

# Paths that look like borrowed code (system/toolchain sources) rather than the program's own.
_SYSTEM = ("/usr/", "/opt/", "/Library/", "/Applications/", "C:\\Program Files", "C:\\Windows",
           "\\include\\", "\\lib\\", "sysdeps", "glibc", "libc++", "libstdc++", "musl")


class PlanError(NetworkError):
    """A plan change that can't be applied; shown to the user as is."""


def load(net, slug: str) -> dict:
    """The stored plan, or a fresh default."""
    cfg = net.cfg(net._project(slug))
    return cfg.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}


def treatments_of(plan: dict, paths) -> dict[str, str]:
    """path -> treatment, defaulting every node to decompile."""
    return {p: (plan["nodes"].get(p) or {}).get("treatment", "decompile") for p in paths}


def function_overrides(plan: dict) -> dict[tuple[str, int], str]:
    """(unit, ea) -> treatment for functions picked out of their file's own treatment."""
    out: dict[tuple[str, int], str] = {}
    for path, node in (plan.get("nodes") or {}).items():
        for key, treatment in (node.get("functions") or {}).items():
            try:
                out[(path, int(key))] = treatment
            except (TypeError, ValueError):
                continue
    return out


def glue_treatment(plan: dict) -> str | None:
    """The plan's one switch for the linker's own code (PLT / CRT / extern slots), if set."""
    treatment = (plan or {}).get("glue")
    return treatment if treatment in TREATMENTS else None


def set_glue(net, slug: str, treatment: str) -> dict:
    """One switch for all the import machinery at once — the .plt trampolines, CRT init/fini and
    the extern slots — wherever it sits. Individual function picks still win over it."""
    if treatment not in TREATMENTS:
        raise PlanError(f"unknown treatment {treatment!r}")
    analysis = analyze_mod.load(net, slug)
    if analysis is None:
        raise PlanError("run the analysis first")
    n = sum(1 for f in analysis["functions"] if f.get("glue"))

    def change(cfg):
        plan = cfg.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}
        cfg["plan"] = plan
        plan["glue"] = treatment

    net._update_cfg(slug, change)
    return {"glue": treatment, "functions": n}


def set_function(net, slug: str, path: str, ea: int, treatment: str) -> dict:
    """Treat one function differently from its file: pull a stub out of an excluded unit, or park a
    single instantiation without touching the rest. Callers keep getting its declaration from the
    generated headers, so there is no cascade for a single function."""
    if treatment not in TREATMENTS:
        raise PlanError(f"unknown treatment {treatment!r}")
    analysis = analyze_mod.load(net, slug)
    if analysis is None:
        raise PlanError("run the analysis first")
    files = analysis["graph"]["files"]
    if path not in files:
        raise PlanError(f"no file {path!r} in this project")
    if ea not in files[path]["functions"]:
        raise PlanError("that function is not part of this file")
    proj = net._project(slug)
    row = net.store.one("SELECT status FROM functions WHERE project_id=? AND unit=? AND vram=?",
                        proj["id"], path, ea)
    if row is not None and row["status"] == "matched":
        raise PlanError("this function is matched: it stays in the plan")

    def change(cfg):
        plan = cfg.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}
        cfg["plan"] = plan
        plan["nodes"].setdefault(path, {}).setdefault("functions", {})[str(ea)] = treatment

    net._update_cfg(slug, change)
    return {"path": path, "ea": ea, "treatment": treatment}


def suggested(analysis: dict) -> dict[str, str]:
    """Treatments the analysis suggests: borrowed code (system paths, FLIRT-only nodes) and
    units that were built from assembly as interface, everything else decompile."""
    by_ea = {f["ea"]: f for f in analysis["functions"]}
    out: dict[str, str] = {}
    for path, node in analysis["graph"]["files"].items():
        fns = [by_ea[ea] for ea in node["functions"] if ea in by_ea]
        library = bool(fns) and all(f["lib"] for f in fns)
        borrowed = any(marker in path for marker in _SYSTEM) if path else False
        asm = bool(fns) and all((f.get("language") or "c") == "asm" for f in fns)
        if library or borrowed or asm:
            out[path] = "interface"
    return out


def effective(analysis: dict, plan: dict) -> dict[str, str]:
    """path -> the treatment actually in force: what the user stored, else the analysis' suggestion,
    else decompile. The plan screen shows this; confirm() and the cascades must use the same thing,
    or the UI lies about what will be claimable."""
    sug = suggested(analysis)
    return {p: (plan["nodes"].get(p) or {}).get("treatment") or sug.get(p) or "decompile"
            for p in analysis["graph"]["files"]}


def cascade(graph_data: dict, treatments: dict[str, str], root: str) -> list[str]:
    """The decompile nodes an `exclude` of `root` forces to become excluded as well.

    Walks callers upward; interface and already-excluded nodes don't compile, so the walk
    stops at them. Nothing but `root` is changed here — the caller decides what to apply.
    """
    forced: list[str] = []
    seen = {root}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for caller in graph_data["dependents"].get(node, ()):
            if caller in seen:
                continue
            seen.add(caller)
            if treatments.get(caller, "decompile") in ("interface", "exclude"):
                continue  # doesn't compile: nothing to force through it
            forced.append(caller)
            queue.append(caller)
    return sorted(forced)


def _matched_units(net, slug: str) -> set[str]:
    proj = net._project(slug)
    return {r["unit"] for r in net.store.all(
        "SELECT DISTINCT unit FROM functions WHERE project_id=? AND status='matched'", proj["id"]) if r["unit"]}


def set_treatment(net, slug: str, path: str, treatment: str) -> dict:
    """Change one node's treatment (excluding also excludes what depends on it), store the plan.

    Raises PlanError when the change would take matched work out of the plan. Returns
    {"forced": [...]}: the files the change dragged along.
    """
    if treatment not in TREATMENTS:
        raise PlanError(f"unknown treatment {treatment!r}")
    analysis = analyze_mod.load(net, slug)
    if analysis is None:
        raise PlanError("run the analysis first")
    files = analysis["graph"]["files"]
    if path not in files:
        raise PlanError(f"no file {path!r} in this project")
    plan = load(net, slug)
    forced = cascade(analysis["graph"], effective(analysis, plan), path) if treatment == "exclude" else []
    losing = [p for p in [path, *forced] if p in _matched_units(net, slug)]
    if losing:
        raise PlanError("can't take files with matched functions out of the plan: " + ", ".join(sorted(losing)[:6]))

    def change(cfg):
        plan = cfg.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}
        cfg["plan"] = plan
        nodes = plan["nodes"]
        nodes.setdefault(path, {})["treatment"] = treatment
        nodes[path].pop("functions", None)  # a file-level choice supersedes per-function picks
        for p in forced:
            nodes.setdefault(p, {})["treatment"] = "exclude"
            nodes[p].pop("functions", None)

    net._update_cfg(slug, change)
    return {"forced": forced}


def preview_many(graph_data: dict, treatments: dict[str, str], paths: list[str], treatment: str) -> list[str]:
    """The forced exclusions of applying `treatment` to many paths, simulated in order."""
    sim = dict(treatments)
    forced: list[str] = []
    for path in paths:
        if treatment == "exclude":
            for f in cascade(graph_data, sim, path):
                if f not in forced:
                    forced.append(f)
                sim[f] = "exclude"
        sim[path] = treatment
    return sorted(forced)


def set_many(net, slug: str, paths: list[str], treatment: str) -> dict:
    """Apply one treatment to many files (a directory, a selection) in a single plan edit."""
    if treatment not in TREATMENTS:
        raise PlanError(f"unknown treatment {treatment!r}")
    analysis = analyze_mod.load(net, slug)
    if analysis is None:
        raise PlanError("run the analysis first")
    files = analysis["graph"]["files"]
    unknown = [p for p in paths if p not in files]
    if unknown:
        raise PlanError(f"no file {unknown[0]!r} in this project")
    plan = load(net, slug)
    treatments = effective(analysis, plan)
    forced = [f for f in preview_many(analysis["graph"], treatments, paths, treatment) if f not in paths]
    losing = [p for p in [*paths, *forced] if p in _matched_units(net, slug)]
    if losing:
        raise PlanError("can't take files with matched functions out of the plan: " + ", ".join(sorted(losing)[:6]))

    def change(cfg):
        plan = cfg.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}
        cfg["plan"] = plan
        nodes = plan["nodes"]
        for p in paths:
            nodes.setdefault(p, {})["treatment"] = treatment
            nodes[p].pop("functions", None)  # a file-level choice supersedes per-function picks
        for p in forced:
            nodes.setdefault(p, {})["treatment"] = "exclude"
            nodes[p].pop("functions", None)

    net._update_cfg(slug, change)
    return {"forced": forced}


def _unique_name(fn: dict, used: set[str]) -> str:
    base = (fn.get("display") or fn.get("name") or f"sub_{fn['ea']:x}").strip() or f"sub_{fn['ea']:x}"
    if base not in used:
        return base
    unit = Path(fn.get("file") or "?").name or "?"
    candidate, n = f"{base}@{unit}", 2
    while candidate in used:
        candidate, n = f"{base}@{unit}#{n}", n + 1
    return candidate


def confirm(net, slug: str, *, log=print) -> dict:
    """Apply the plan: every node's functions become rows (open/interface/excluded) with identity,
    status and an instruction count. Target bytes, disassembly text and unit headers all
    materialize on first use. Matched rows are never touched."""
    proj = net._project(slug)
    cfg = net.cfg(proj)
    analysis = analyze_mod.load(net, slug)
    if analysis is None:
        raise PlanError("run the analysis first")
    files = analysis["graph"]["files"]
    plan = load(net, slug)
    treatments = effective(analysis, plan)
    overrides = function_overrides(plan)
    glue = glue_treatment(plan)
    binary = Path(proj["root"]) / cfg["binary"]["file"]
    data = binary.read_bytes()
    image = formats.identify(data)
    if image is None:
        raise PlanError("the imported binary is gone or unreadable")
    arch = cfg["arch"]
    by_ea = {f["ea"]: f for f in analysis["functions"]}
    rows = [dict(r) for r in net.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])]

    def better(a: dict, b: dict) -> dict:
        """Which of two rows at the same address to keep: a match wins, else the older row."""
        if (a["status"] == "matched") != (b["status"] == "matched"):
            return a if a["status"] == "matched" else b
        return a if a["id"] < b["id"] else b

    # Identity is the address (unit + vram), not the name: re-confirming must update the rows that
    # are already there, never re-add them under suffixed names. Rows that share an address are
    # duplicates (an earlier bug created them); the losers are pruned unless they hold a match.
    by_pos: dict[tuple[str, int], dict] = {}
    dupes: list[dict] = []
    for row in rows:
        if row["vram"] is None:
            continue  # can't place it by address; leave it alone
        key = (row["unit"] or "", row["vram"])
        cur = by_pos.get(key)
        if cur is None:
            by_pos[key] = row
            continue
        keep = better(cur, row)
        drop = row if keep is cur else cur
        by_pos[key] = keep
        if drop["status"] != "matched":
            dupes.append(drop)
    current = {(path, ea) for path, node in files.items() for ea in node["functions"] if ea in by_ea}
    stale = [r for key, r in by_pos.items() if key not in current and r["status"] != "matched"]
    removed = dupes + stale
    removed_ids = {r["id"] for r in removed}
    used = {r["name"] for r in rows if r["id"] not in removed_ids}
    missing = 0
    updates, inserts = [], []
    for path, node in sorted(files.items()):
        default = treatments.get(path, "decompile")
        for ea in node["functions"]:
            fn = by_ea.get(ea)
            if fn is None:
                continue
            # precedence: the function's own pick > the machinery switch (for plt/crt/extern) >
            # its file's treatment; library glue inside a file being decompiled stays declared,
            # never claimed
            treat = overrides.get((path, ea)) or (glue if fn.get("glue") else None) or default
            st = STATUS[treat]
            if st == "open" and fn.get("lib"):
                st = "library"
            row = by_pos.get((path, ea))
            if row is not None:
                if row["status"] != "matched":  # re-confirm: matched rows are never touched
                    updates.append((st, path, row["id"]))
                continue
            code = formats.read_bytes(data, image, ea, fn["size"])
            if code is None:
                missing += 1
                continue
            name = _unique_name(fn, used)
            used.add(name)
            meta = json.dumps({"symbol": fn["name"], "demangled": fn["demangled"], "provenance": fn["provenance"],
                               "lib": fn["lib"], "signature": fn["signature"], "line": fn["line"],
                               "language": fn.get("language") or "c", "linkage": fn.get("linkage"),
                               "inline": fn.get("inline") or [], "cu": fn.get("cu")})
            # lean rows: identity, status and an instruction count. The target bytes and the
            # disassembly text materialize on demand (Network._ensure_row_code/_ensure_row_asm);
            # baking them for every function was the confirm's whole cost.
            inserts.append((proj["id"], name, fn["size"],
                            scoring.count_instructions(arch, code, bool(proj["big_endian"])),
                            None, "[]", "", None, path, fn["ea"], st, meta))

    # unit headers are NOT generated here: they materialize the first time a unit is touched
    # (Network._context), so a 6,433-unit binary doesn't pay 13+ minutes of eager rendering
    now = time.time()
    with net.store.tx() as db:
        for r in removed:  # stale rows and address-duplicates (matched rows are never in here)
            db.execute("DELETE FROM claims WHERE function_id=?", (r["id"],))
            db.execute("DELETE FROM notes WHERE function_id=?", (r["id"],))
            db.execute("DELETE FROM functions WHERE id=?", (r["id"],))
        for status, path, fid in updates:
            db.execute("UPDATE functions SET status=?, unit=? WHERE id=?", (status, path, fid))
        db.executemany(
            "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,status,meta) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", inserts)
        net._event(db, proj["id"], None, "plan",
                   f"confirmed: {len(inserts)} added, {len(updates)} re-treated, {len(removed)} removed, "
                   f"{missing} linker entries without code")

    def change(cfg2):
        plan = cfg2.get("plan") or {"version": 1, "nodes": {}, "confirmed_at": None}
        cfg2["plan"] = plan
        plan["confirmed_at"] = now

    net._update_cfg(slug, change)
    rows = net.store.all("SELECT status, COUNT(*) AS n FROM functions WHERE project_id=? GROUP BY status", proj["id"])
    counts = {r["status"]: r["n"] for r in rows}
    log(f"plan confirmed: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        + (f" ({len(removed)} stale/duplicate rows removed)" if removed else ""))
    return {**counts, "missing": missing, "removed": len(removed)}
