"""Structured per-unit header entries: the declarations a unit needs, as facts.

Headers are generated artifacts (context + these entries + the registry projection); this table is
the editable layer behind them. The day's text-edit bug family (markers, strip semantics, stale
`old` strings, regeneration clobbering) only exists because headers used to be editable text —
entries remove it by construction: renders are pure.

Kinds: prototype | static | alias | include | note | raw. `note` renders as a comment; `include`
takes a freestanding header name (`cstdarg` / `<cstdarg>`); everything else is C/C++ text passed
through the same fence as header edits (no pragmas, asm, incbin or non-freestanding includes).
Removal is a tombstone (`removed_at`), so history survives.
"""

from __future__ import annotations

import re
import time

from .compiler import SourceRejected, check_header
from .network import NetworkError

KINDS = ("prototype", "static", "alias", "include", "note", "raw")
_FREESTANDING = ("cstdarg", "cstddef", "cstdint", "stdarg.h", "stddef.h", "stdint.h",
                 "intrin.h", "immintrin.h", "xmmintrin.h", "emmintrin.h")
_WORDS = re.compile(r"[A-Za-z_]\w*")


def declared_name(body: str) -> str:
    """Best-effort identifier the entry declares: the token before '(' for functions, the last token
    otherwise. A listing/dedup convenience only — the body always is the truth."""
    masked = re.sub(r"//[^\n]*|/\*.*?\*/", " ", body or "", flags=re.S)
    m = re.search(r"([A-Za-z_]\w*)\s*\(", masked)
    if m:
        return m.group(1)
    names = _WORDS.findall(masked)
    return names[-1] if names else ""


def _normalize_include(body: str) -> str:
    name = (body or "").strip().strip("<>").strip()
    if name not in _FREESTANDING:
        raise NetworkError(f"only the freestanding headers can be included as entries "
                           f"({', '.join(_FREESTANDING)}); everything else belongs in raw declarations")
    return name


def add(net, slug: str, unit: str, kind: str, body: str, agent=None, note: str = "",
        ord: float | None = None) -> dict:
    """Journal one entry (validated by the same fence header edits pass). Returns the stored row.
    `ord` pins the render position: restores and replacements pass the entry's old position so a
    rejected edit really is a no-op and an accepted edit does not silently move a declaration behind
    something that needs it."""
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        raise NetworkError(f"entry kind must be one of: {', '.join(KINDS)}")
    body = (body or "").strip()
    if not body:
        raise NetworkError("an entry needs a body")
    if kind == "include":
        body = _normalize_include(body)
        rendered = body  # the bare header name: the fact; render() adds the #include
    elif kind == "note":
        rendered = body  # the raw text: the fact; render() comments it out
    else:
        try:
            check_header(body + "\n")
        except SourceRejected as e:
            raise NetworkError(str(e)) from e
        bare = re.sub(r"//[^\n]*|/\*.*?\*/", " ", body, flags=re.S).strip()
        # a preprocessor directive is a whole line, never a declaration: `#define X` must not become
        # `#define X;` (C2008) — the declaration entries around it still get their semicolon
        rendered = body if (not bare or bare.startswith("#") or body.endswith(";") or body.endswith("}")) \
            else body + ";"
    name = "" if kind in ("note", "include") else declared_name(body)
    proj = net._project(slug)
    if proj is None:
        raise NetworkError(f"no project {slug!r}")
    with net.store.tx() as db:
        cur = db.execute(
            "INSERT INTO context_entries(project_id, unit, kind, name, body, agent_id, created_at, ord) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (proj["id"], unit or "", kind, name, rendered, getattr(agent, "id", None), time.time(), ord))
        entry_id = cur.lastrowid
        net._event(db, proj["id"], getattr(agent, "id", None), "entry",
                   f"{kind} entry #{entry_id} in {unit or 'the base header'}: {name or body[:40]}")
    return {"id": entry_id, "unit": unit or "", "kind": kind, "name": name, "body": rendered, "ord": ord}


def remove(net, slug: str, unit: str, *, entry_id: int | None = None, name: str | None = None,
           agent=None) -> dict:
    """Tombstone one live entry (by id or by declared name). Returns what was removed."""
    proj = net._project(slug)
    if proj is None:
        raise NetworkError(f"no project {slug!r}")
    with net.store.tx() as db:
        if entry_id is not None:
            row = db.execute("SELECT * FROM context_entries WHERE id=? AND project_id=? AND removed_at IS NULL",
                             (entry_id, proj["id"])).fetchone()
        elif name:
            rows = db.execute(
                "SELECT * FROM context_entries WHERE project_id=? AND unit=? AND name=? AND removed_at IS NULL "
                "ORDER BY id DESC LIMIT 1", (proj["id"], unit or "", name)).fetchall()
            row = rows[0] if rows else None
        else:
            raise NetworkError("removing an entry needs its id or its declared name")
        if row is None:
            which = f" #{entry_id}" if entry_id is not None else f" {name!r}"
            raise NetworkError(f"no live entry in {unit or 'the base header'} matches{which} — it may already "
                               f"have been removed (or rolled back by an earlier edit); list_decls shows the "
                               f"live ids")
        db.execute("UPDATE context_entries SET removed_at=? WHERE id=?", (time.time(), row["id"]))
        net._event(db, proj["id"], getattr(agent, "id", None), "entry",
                   f"removed {row['kind']} entry #{row['id']} ({row['name'] or row['body'][:40]})")
        return {"id": row["id"], "unit": row["unit"], "kind": row["kind"], "name": row["name"],
                "body": row["body"], "ord": row["ord"]}


def restore(net, slug: str, unit: str, entry_id: int, agent=None) -> dict:
    """Un-tombstone exactly the row a rejected edit removed. Restoring by adding a fresh row changes
    ids and, when a batch is retried, multiplies duplicate definitions (the OSMemory wedge); the same
    row with the same id and ord is the true no-op."""
    proj = net._project(slug)
    if proj is None:
        raise NetworkError(f"no project {slug!r}")
    with net.store.tx() as db:
        row = db.execute("SELECT * FROM context_entries WHERE id=? AND project_id=?",
                         (entry_id, proj["id"])).fetchone()
        if row is None or (row["unit"] or "") != (unit or ""):
            raise NetworkError(f"entry #{entry_id} does not belong to {unit or 'the base header'}")
        if row["removed_at"] is not None:
            db.execute("UPDATE context_entries SET removed_at=NULL WHERE id=?", (row["id"],))
            net._event(db, proj["id"], getattr(agent, "id", None), "entry",
                       f"restored {row['kind']} entry #{row['id']} ({row['name'] or row['body'][:40]})")
        return {"id": row["id"], "unit": row["unit"], "kind": row["kind"], "name": row["name"],
                "body": row["body"], "ord": row["ord"]}


def list_for(net, slug: str, unit: str, kind: str | None = None) -> list[dict]:
    """The live entries of one unit in render order: an explicit ord (a restored/replaced entry keeps
    its old place), else insertion order."""
    proj = net._project(slug)
    if proj is None:
        raise NetworkError(f"no project {slug!r}")
    sql = ("SELECT id, unit, kind, name, body, created_at, ord FROM context_entries "
           "WHERE project_id=? AND unit=? AND removed_at IS NULL")
    args: list = [proj["id"], unit or ""]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    sql += " ORDER BY COALESCE(ord, id), id"
    return [dict(r) for r in net.store.all(sql, *args)]


def position(entry: dict) -> float:
    """The render position to give a restore/replacement of this entry."""
    return entry["ord"] if entry.get("ord") is not None else entry["id"]


def file_scope_qualified_call(body: str) -> tuple[str, str] | None:
    """(qualified name, member name) when the body declares/calls `Ns::Class::f(...)` at file scope.
    A qualified name at file scope is never valid C++ unless its namespace/class is in scope — for a
    class member that means it belongs INSIDE the class, and writing it as a free prototype is the
    mistake that poisons unit headers. Occurrences inside braces (namespace/class wrappers) are fine."""
    masked = re.sub(r"//[^\n]*|/\*.*?\*/", " ", body or "", flags=re.S)
    masked = re.sub(r'"(?:\\.|[^"\\])*"', '""', masked)
    top, depth = [], 0
    for ch in masked:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            top.append(ch)
    m = re.search(r"(?<![A-Za-z0-9_?@:])((?:[A-Za-z_]\w*::)+([A-Za-z_]\w*))\s*\(", "".join(top))
    return (m.group(1), m.group(2)) if m else None


def render(entries: list[dict]) -> list[str]:
    """The header lines for these entries (pure; called by the unit renderer)."""
    lines = []
    for e in entries:
        if e["kind"] == "include":
            lines.append(f"#include <{e['body']}>")
        elif e["kind"] == "note":
            lines.append(f"/* {e['body']} */")
        else:
            lines.append(e["body"])
    return lines
