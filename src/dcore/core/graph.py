"""The file-level dependency graph: what the plan must consider together.

Functions belong to files (DWARF compile units; IDA's file info; a synthetic node when
neither exists). Call edges between functions become edges between files. The plan uses
this for two things: showing what a file depends on, and cascading an exclusion — a
fully excluded file provides nothing, not even declarations, so everything that calls
into it must be excluded too (interface nodes, which don't compile, stop the cascade).
"""

from __future__ import annotations

from collections import defaultdict, deque

UNKNOWN = "(no debug info)"


def build(functions: list[dict], edges: list[dict]) -> dict:
    """File-level view of the call graph.

    `functions`: merged records with ea/file/size/lib; `edges`: [{"ea": caller, "to": [callee ea]}].
    Returns {"files": {path: {"functions": [ea], "bytes", "library"}}, "deps", "dependents"}.
    """
    by_ea = {f["ea"]: f for f in functions}
    files: dict[str, dict] = {}
    for f in functions:
        node = files.setdefault(f.get("file") or UNKNOWN, {"functions": [], "bytes": 0, "library": 0})
        node["functions"].append(f["ea"])
        node["bytes"] += f.get("size") or 0
        node["library"] += 1 if f.get("lib") else 0
    deps: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        src = by_ea.get(edge.get("ea"))
        if src is None or src.get("file") is None:
            continue
        for to in edge.get("to", []):
            dst = by_ea.get(to)
            if dst is None or dst.get("file") is None:
                continue
            if src["file"] != dst["file"]:
                deps[src["file"]].add(dst["file"])
    dependents: dict[str, set[str]] = defaultdict(set)
    for a, bs in deps.items():
        for b in bs:
            dependents[b].add(a)
    return {"files": files,
            "deps": {k: sorted(v) for k, v in sorted(deps.items())},
            "dependents": {k: sorted(v) for k, v in sorted(dependents.items())}}


def closure(dependents: dict, roots: list[str]) -> set[str]:
    """Every node that transitively depends on any of `roots` (the roots themselves included)."""
    seen: set[str] = set(roots)
    queue = deque(seen)
    while queue:
        node = queue.popleft()
        for up in dependents.get(node, ()):
            if up not in seen:
                seen.add(up)
                queue.append(up)
    return seen
