"""The central type registry: one shared definition per class/struct/enum, agents can edit it.

The registry is the source of truth for the types the reconstructed code compiles against; the
per-file headers are generated *projections* of it (which types this file's functions name), so
there is nothing to merge per file and no place for two spellings of one class to drift apart.
It starts as the binary's own debug info (analysis["types"]) when there is any; on a stripped
binary it starts empty and grows from what the agents work out — and every agent sees every other
agent's contribution the moment it lands.

Nothing lands unverified: an edit is applied to a *candidate* registry, every matched function
whose compile environment would change is recompiled and re-judged byte-for-byte, and the edit is
kept only if they all still match. A rejected edit reports the functions that broke.

Entries are plain JSON in `.decomp-wtf/native/registry.json` — contributions only, layered over
the (regenerated) analysis, so a re-analysis can never eat an agent's work.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:  # POSIX advisory lock; Windows keeps the atomic replace below
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

from .network import NetworkError
from . import interfaces

_SCALARS = {"void", "bool", "char", "signed char", "unsigned char", "short", "unsigned short",
            "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long",
            "signed long", "signed long long", "float", "double", "long double", "wchar_t",
            "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "__int64", "__int32",
            "__int16", "__int8",
            "unsigned __int64", "unsigned __int32", "unsigned __int16", "unsigned __int8",
            "signed __int64", "signed __int32", "signed __int16", "signed __int8",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t"}
_STD_INCLUDES = {"vector": "vector", "list": "list", "forward_list": "forward_list", "deque": "deque",
                 "map": "map", "multimap": "map", "set": "set", "multiset": "set",
                 "unordered_map": "unordered_map", "unordered_set": "unordered_set",
                 "string": "string", "wstring": "string", "basic_string": "string",
                 "pair": "utility", "tuple": "tuple", "array": "array",
                 "unique_ptr": "memory", "shared_ptr": "memory", "weak_ptr": "memory", "allocator": "memory",
                 "optional": "optional", "variant": "variant", "function": "functional",
                 "stringstream": "sstream", "ostringstream": "sstream", "istringstream": "sstream",
                 "wstringstream": "sstream", "queue": "queue", "stack": "stack",
                 "priority_queue": "queue", "bitset": "bitset", "complex": "complex"}
_ENTRY_KINDS = ("struct", "class", "union", "enum", "typedef")


def path_of(net, slug: str) -> Path:
    proj = net._project(slug)
    return Path(proj["root"]) / ".decomp-wtf" / "native" / "registry.json"


_PROCESS_LOCK = threading.RLock()  # serializes threads; fcntl serializes processes
_LOCK_STATE = threading.local()


@contextmanager
def _registry_lock(net, slug: str):
    """Serialize a read-modify-write of registry.json across processes and threads.

    `os.replace` already makes a single write atomic; the lock closes the larger window where
    two agents both load, both stage, and the second save silently drops the first edit. It is
    reentrant inside one thread: a save triggered from a monkeypatched `os.replace` must not
    deadlock on its own lock."""
    with _PROCESS_LOCK:
        depth = getattr(_LOCK_STATE, "depth", 0)
        if depth:  # same thread already holds the file lock
            _LOCK_STATE.depth = depth + 1
            try:
                yield
            finally:
                _LOCK_STATE.depth = depth
            return
        p = path_of(net, slug).with_name("registry.lock")
        p.parent.mkdir(parents=True, exist_ok=True)
        if fcntl is None:  # pragma: no cover - Windows
            yield
            return
        with p.open("a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            _LOCK_STATE.depth = 1
            try:
                yield
            finally:
                _LOCK_STATE.depth = 0
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _write(net, slug: str, data: dict) -> None:
    p = path_of(net, slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    # a per-writer tmp name: two concurrent saves (two agents staging at once) used to share
    # registry.json.tmp — the first replace consumed it and the second raised FileNotFoundError
    tmp = p.with_name(f"{p.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)  # readers never see a half-written registry


def load(net, slug: str) -> dict:
    p = path_of(net, slug)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data.get("types"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "types": {}}


def save(net, slug: str, data: dict) -> None:
    with _registry_lock(net, slug):
        _write(net, slug, data)


def opaque_text(data: dict) -> str:
    """The project-global opaque prelude: third-party stubs/aliases stored once in the registry and
    rendered before every unit's type block. A class method may name an alias (`yield_context`), and
    C++ will not forgive a declaration after use."""
    entries = data.get("opaque") or {}
    return "\n\n".join(str(e.get("decl") or "").strip() for e in entries.values()
                       if str(e.get("decl") or "").strip())


def key_of(t: dict) -> str:
    return "::".join([*(t.get("ns") or []), t.get("name") or ""])


def split_key(key: str) -> tuple[list[str], str]:
    parts = [p for p in (key or "").split("::") if p]
    return (parts[:-1], parts[-1]) if parts else ([], "")


# ---------------------------------------------------------------- the lock (edit sessions)

LOCK_TTL = 600.0   # a held session: long enough for a batch of edits, short enough to self-heal
LOCK_WAIT = 120.0  # how long an edit or a lock attempt blocks before saying who's in the way


def _types_of(data: dict) -> dict:
    return (data or {}).get("types") or {}


def _live_lock(data: dict, now: float | None = None) -> dict | None:
    lock = data.get("lock")
    if isinstance(lock, dict) and lock.get("expires", 0) > (time.time() if now is None else now):
        return lock
    return None


def lock(net, slug: str, agent, wait: float = LOCK_WAIT) -> dict:
    """Take the registry for a batch of edits. While held, other edits wait their turn (bounded)
    and the holder stages several changes that are verified *once*, on commit — one gate run
    instead of one per edit. Leased: it expires by itself if the holder goes quiet."""
    deadline = time.time() + max(0.0, float(wait))
    while True:
        with _registry_lock(net, slug):
            data = load(net, slug)
            now = time.time()
            holder = _live_lock(data, now)
            if holder is None:
                stale = data.get("lock")  # an expired one: take it over, the previous holder is gone
                token = secrets.token_urlsafe(9)
                data["types"] = _types_of(data)
                data["lock"] = {"owner": getattr(agent, "id", None), "name": getattr(agent, "name", "?"),
                                "token": token, "since": now, "expires": now + LOCK_TTL,
                                "staged": {"version": data.get("version", 1), "types": dict(_types_of(data))}}
                save(net, slug, data)
                return {"ok": True, "token": token,
                        "took_over": bool(stale and stale.get("name"))}
        if now >= deadline:
            return {"ok": False, "busy": holder.get("name") or "another agent",
                    "since": holder.get("since"), "expires": holder.get("expires")}
        time.sleep(0.5)


def stage(net, slug: str, token: str, action: str, args: dict) -> dict:
    """One edit inside a held session: validated against the staged state right away, but NOT
    verified — the gate runs once, on commit, over the whole batch."""
    analysis = net.native.analysis(net._project(slug))
    if not analysis:
        raise RegistryError("no analysis yet — analyze the project first")
    with _registry_lock(net, slug):
        data = load(net, slug)
        holder = _live_lock(data)
        if holder is None or holder.get("token") != token:
            raise RegistryError("you don't hold the registry lock (it expired or was never taken) — "
                                "lock_registry again and re-stage your edits")
        prev = holder.get("staged") or {}
        holder["staged"] = plan_change(analysis, prev, action, args)
        holder["expires"] = time.time() + LOCK_TTL
        save(net, slug, data)
    return {"ok": True, "staged_types": len(_types_of(holder["staged"])),
            "note": change_note(prev, holder["staged"])}


def unlock(net, slug: str, token: str, commit: bool = True) -> dict:
    """End a session: commit verifies the whole batch (every matched function whose compile
    environment the staged edits change must still re-judge byte-identical — a rejection keeps
    the staged edits so the holder can fix them), abort throws the batch away unseen."""
    engine = net.native
    proj = net._project(slug)
    analysis = engine.analysis(proj)
    if not analysis:
        raise RegistryError("no analysis yet — analyze the project first")
    data = load(net, slug)
    holder = _live_lock(data)
    if holder is None or holder.get("token") != token:
        raise RegistryError("you don't hold the registry lock (it expired?) — nothing was committed")
    if not commit:
        n = len(_types_of(holder.get("staged") or {}))
        data.pop("lock", None)
        save(net, slug, data)
        return {"ok": True, "aborted": True, "discarded": n, "rechecked": 0, "units": [], "failures": []}
    _, by_unit, units_set = _matched_context(net, proj)
    staged = holder.get("staged") or {"version": 1, "types": {}}
    note = change_note(data, staged)
    gate = _gate(net, slug, proj, analysis, by_unit, units_set, data, staged)
    if gate["failures"]:  # keep the lock and the staged edits: fix and commit again
        holder["expires"] = time.time() + LOCK_TTL
        save(net, slug, data)
        return {"ok": False, "rechecked": gate["checked"], "skipped": gate["skipped"],
                "units": gate["touched"], "failures": gate["failures"], "kept": True, "note": note}
    previous = _types_of(data)
    data["types"] = _types_of(staged)
    data.pop("lock", None)
    save(net, slug, data)
    _refresh(net, slug, proj, analysis, gate["touched"], by_unit, "session commit")
    backend = _write_through(net, slug, analysis, previous, data["types"])
    out = {"ok": True, "rechecked": gate["checked"], "skipped": gate["skipped"],
           "units": gate["touched"], "failures": [], "note": note}
    if backend:
        out["backend"] = backend
    return out


def _matched_context(net, proj) -> tuple[list, dict, set]:
    rows = net.store.all(
        "SELECT * FROM functions WHERE project_id=? AND status='matched' AND matched_source IS NOT NULL",
        proj["id"])
    units = net._unit_contexts(proj["id"])
    by_unit: dict[str, list] = {}
    for r in rows:
        if r["unit"]:
            # group by the unit the function *compiles under*: a mega-unit like "(no debug info)"
            # falls back to the project-wide header, and probing its raw 100k-function projection
            # is the same wall _context avoids
            by_unit.setdefault(net._effective_unit(r, units), []).append(r)
    return rows, by_unit, units


# ---------------------------------------------------------------- merged view

def view(analysis: dict, overrides: dict | None = None) -> list[dict]:
    """The registry as agents and headers see it: the debug info's types, with agent contributions
    layered over them (same key = full replacement) plus the contributions the debug info doesn't
    know at all. Every entry carries its origin."""
    out: dict[str, dict] = {}
    order: list[str] = []
    for t in analysis.get("types") or []:
        k = key_of(t)
        if k and k not in out:
            out[k] = {**t, "key": k, "origin": t.get("origin") or "dwarf"}
            order.append(k)
    for k, t in ((overrides or {}).get("types") or {}).items():
        if t.get("hidden"):  # a tombstone (move/hide left it here): the base entry stops rendering
            out.pop(k, None)
            if k in order:
                order.remove(k)
            continue
        if k in out and not any(t.get(f) for f in ("name", "kind", "members", "statics", "methods", "size")):
            # a note-only carrier (a covered override was pruned after a database sync): the
            # content is the base's, the note is the agent's — layer it, don't replace anything
            out[k] = {**out[k], "note": t.get("note")}
            continue
        entry = {**t, "key": k, "origin": t.get("origin") or "agent"}
        if k not in out:
            order.append(k)
        out[k] = entry
    return [out[k] for k in order]


def find(entries: list[dict], name: str) -> dict | None:
    """By bare name or qualified key; bare names must be unambiguous."""
    want = (name or "").strip()
    if not want:
        return None
    hits = [t for t in entries if key_of(t) == want]
    if hits:
        return hits[0]
    hits = [t for t in entries if t.get("name") == want]
    if len(hits) == 1:
        return hits[0]
    return None


def candidates(entries: list[dict], name: str) -> list[str]:
    """Every key a bare name could mean (the tool shows these instead of guessing)."""
    want = (name or "").strip()
    return sorted(key_of(t) for t in entries if key_of(t) == want or t.get("name") == want)


def search(entries: list[dict], query: str = "", *, ns: str = "", member: str = "",
           kind: str = "", limit: int = 20) -> list[dict]:
    """Types by name fragment, namespace, member (name or type), or kind. Exact and prefix matches
    rank first; the caller narrows with more filters when the list is long."""
    q = (query or "").strip().lower()
    out: list[tuple[int, dict]] = []
    for t in entries:
        key = key_of(t)
        if ns and not key.startswith(ns.strip(":") + "::"):
            continue
        if kind and t.get("kind") != kind:
            continue
        if member:
            m = member.strip().lower()
            if not any(m in (x.get("name") or "").lower() or m in (x.get("type") or "").lower()
                       for x in t.get("members") or []):
                continue
        rank = 0
        if q:
            low = key.lower()
            if low == q:
                rank = 0
            elif low.startswith(q):
                rank = 1
            elif q in low:
                rank = 2
            elif any(q in (m.get("name") or "").lower() or q in (m.get("type") or "").lower()
                     for m in t.get("members") or []):
                rank = 3
            else:
                continue
        out.append((rank, t))
    out.sort(key=lambda rt: (rt[0], key_of(rt[1])))
    return [t for _r, t in out[:max(1, limit)]]


def usage_by(net, slug: str, analysis: dict, entries: list[dict]) -> dict[str, list[str]]:
    """{bare type name: matched functions whose source mentions it} — who would a change touch."""
    proj = net._project(slug)
    rows = net.store.all(
        "SELECT name, matched_source FROM functions WHERE project_id=? AND status='matched' "
        "AND matched_source IS NOT NULL", proj["id"])
    out: dict[str, list[str]] = {}
    for t in entries:
        name = t.get("name") or ""
        if not name or "<" in name:
            continue
        pat = re.compile(rf"(?<!\w){re.escape(name)}(?![\w])")
        users = [r["name"] for r in rows if pat.search(r["matched_source"] or "")]
        if users:
            out[name] = users
    return out


def describe(entry: dict, used_by: list[str] | None = None) -> str:
    """One registry entry as agent text: layout, origin, and who a change would re-verify."""
    key = key_of(entry)
    kind = entry.get("kind") or "struct"
    size = entry.get("size")
    head = f"{key} — {kind}"
    if size:
        head += f", size 0x{int(size):x}"
    head += f" ({'the binary\'s debug info' if entry.get('origin') == 'dwarf' else entry.get('origin') or 'agent'})"
    lines = [head]
    if entry.get("decl"):
        lines.append(entry["decl"])
    else:
        for m in sorted(entry.get("members") or [], key=lambda m: int(m.get("off") or 0)):
            mname = (m.get("name") or "?").strip()
            mtype = (m.get("type") or "?").strip()
            if mname.startswith("_vptr"):
                mname, mtype = "_vptr", "void *"
            lines.append(f"  +0x{int(m.get('off') or 0):02x}  {mtype} {mname}")
        for s in entry.get("statics") or []:
            sname = (s.get("name") or "") if isinstance(s, dict) else str(s)
            stype = (s.get("type") or "").strip() if isinstance(s, dict) else ""
            lines.append(f"  static  {stype} {sname}".rstrip())
        methods = entry.get("methods") or []
        if methods:
            def sig(m: dict) -> str:
                params = ", ".join(m.get("params") or [])
                return f"{m.get('name') or '?'}({params})"
            lines.append(f"  {len(methods)} method(s): " + ", ".join(sig(m) for m in methods[:10])
                         + (" …" if len(methods) > 10 else ""))
    if entry.get("note"):
        lines.append(f"note: {entry['note']}")
    if used_by:
        shown = ", ".join(used_by[:8]) + (f" (+{len(used_by) - 8} more)" if len(used_by) > 8 else "")
        lines.append(f"used by {len(used_by)} matched function(s): {shown}")
        lines.append("edit_type re-verifies these against the change before it is kept")
    else:
        lines.append("no matched function mentions it yet")
    return "\n".join(lines)


# ---------------------------------------------------------------- type spellings

def _check_base(text: str, depth: int = 0) -> str | None:
    t = " ".join((text or "").split())
    if not t or depth > 6:
        return None if t else "empty type"
    # peel arrays, then pointers/references, then const/volatile qualifiers
    while True:
        m = re.match(r"^(.*?)\s*\[\s*(\d+)\s*\]$", t)
        if not m:
            break
        t = m.group(1).strip()
    while t.endswith("*") or t.endswith("&"):
        t = t[:-1].strip()
    t = re.sub(r"^(?:const|volatile)\s+", "", t)
    t = re.sub(r"\s+(?:const|volatile)$", "", t).strip()
    if not t:
        return "empty type"
    if t in _SCALARS:
        return None
    m = re.match(r"^std::(\w+)\s*(<.*>)?$", t)
    if m:
        if m.group(2) is None:
            return None  # std::string, std::wstring, std::stringstream …
        if not m.group(1) or m.group(1) not in _STD_INCLUDES and not m.group(1)[0].isalpha():
            return f"unknown std type {t!r}"
        inner = m.group(2)[1:-1]
        for arg in _split_args(inner):
            why = _check_base(arg, depth + 1)
            if why:
                return why
        return None
    if re.match(r"^[\w:<>,\s*&]+\(\s*(?:\w+::)?\*\s*\)\s*\(.*\)$", t):
        return None  # function pointer: void (*)(int), int (Foo::*)(char)
    if re.match(r"^[\w:<>,\s*&]+\(.*\)$", t):
        return None  # function type: void(), int(char) — a legal template argument
    if re.match(r"^[A-Za-z_]\w*(?:::\w+)*$", t):
        return None  # a class/typedef name: fine, it gets declared or forward-declared
    return f"{t!r} is not a type this registry can spell (scalars, names, pointers, arrays, std::… )"


def _split_args(inner: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [a for a in out if a]


def check_type(text: str) -> str | None:
    """None when the spelling is acceptable, else the reason (shown to the agent). Parentheses are
    legal in a type (`void (*)(int)`, `std::function<void()>`, a template argument), so they are not
    code by themselves; `;{}` still are, and a malformed declarator is caught by the compile gate."""
    if text is not None and re.search(r"[;{}]", text or ""):
        return "a type, not code (no ; { })"
    return _check_base(text)


def std_includes(text: str) -> list[str]:
    """The `#include <…>` lines a block of declarations needs for the std types it spells."""
    heads = set()
    for m in re.finditer(r"\bstd::(\w+)", text or ""):
        head = _STD_INCLUDES.get(m.group(1))
        if head and re.search(rf"\b(?:class|struct)\s+{re.escape(m.group(1))}\b", text or ""):
            continue  # a hand-written minimal std declaration: including the real one would redefine it
        if head:
            heads.add(head)
    for bare in ("ostringstream", "istringstream", "stringstream", "wstringstream"):
        if re.search(rf"\b{bare}\b", text or ""):
            heads.add("sstream")
    if re.search(r"\bstd::(?:map|multimap|set|multiset)\b", text or ""):
        heads.add("utility")
    if re.search(r"\bsize_t\b", text or ""):
        heads.add("cstddef")
    if re.search(r"\b(?:u?int(?:8|16|32|64)_t|intptr_t|uintptr_t)\b", text or ""):
        heads.add("cstdint")
    if re.search(r"\b(?:__gnuc_va_list|va_list)\b", text or ""):
        heads.add("cstdarg")
    return [f"#include <{h}>" for h in sorted(heads)]


# ---------------------------------------------------------------- compile headers

_FORCED = re.compile(r"(?:/[*#]|//)\s*types?\s*:\s*([^\n*]+)")
_HEADER_EXT = (".h", ".hpp", ".hh", ".hxx", ".h++")


def declared_names(source: str) -> set[str]:
    """The types the source (or the base header) itself *defines* — the projection must not also
    declare them, or a file still carrying its own scaffolding would fail to compile against the
    registry. A bare forward declaration (`class Mutex;`) is not a definition: it must not shadow the
    registry's full type, or the compile sees an incomplete class while the real one sits unrendered
    (the Mutex case: seed forward-declares it, registry owns the 48-byte definition). Comments and
    strings are masked first so prose can't shadow a type."""
    return {m.group(2) for m in _TYPE_DEF.finditer(_mask(source or "")) if m.group(2)}


_TYPE_DEF = re.compile(r"(?<![\w:.>])(class|struct|union|enum(?:\s+class)?)\s+"
                       r"(?:([A-Za-z_]\w*)(\s*<[^{};]{0,120}>)?\s*)?(?:final\s*)?(?::[^{;]{0,120})?\{")
_TYPEDEF_KEY = re.compile(r"(?<![\w:])typedef\b")
_USING_ALIAS = re.compile(r"(?<![\w:])using\s+([A-Za-z_]\w*)\s*=")


def _mask(source: str) -> str:
    """A copy of the source with comments and string/char literal bodies blanked, so type detection
    can't be fooled by a `struct` inside a comment or a format string."""
    out, i, n = list(source), 0, len(source)
    while i < n:
        c = source[i]
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j < 0 else j
        elif c == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            j = n if j < 0 else j + 2
        elif c in "\"'":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == c:
                    j += 1
                    break
                if source[j] == "\n":
                    break
                j += 1
        else:
            i += 1
            continue
        for k in range(i, min(j, n)):
            out[k] = " "
        i = j
    return "".join(out)


_NS_OPEN = re.compile(r"\bnamespace\s+(?:[A-Za-z_]\w*(?:::\w+)*\s*)?\{|\bextern\s*\{")


def type_blocks(source: str) -> list[str]:
    """Type definitions a submission carries itself ('struct City', 'typedef u32', ...), in source order.

    Types belong in the registry so every function compiles against the same layout; a submission
    carrying its own copy is refused rather than compiled. A `namespace`/`extern "C"` wrapper is
    transparent (that's how real scaffolding is spelled), while a function body is not: a local
    struct inside the function, a mention (`struct Foo *p`) or a forward declaration is the
    function's own business.
    """
    masked = _mask(source or "")
    ns_braces = {m.end() - 1 for m in _NS_OPEN.finditer(masked)}
    depth, d, stack = [], 0, []
    for i, ch in enumerate(masked):
        depth.append(d)
        if ch == "{":
            ns = i in ns_braces
            stack.append(ns)
            if not ns:
                d += 1
        elif ch == "}" and stack:
            if not stack.pop():
                d = max(0, d - 1)
    depth.append(d)

    found: list[tuple[int, str]] = []
    for m in _TYPE_DEF.finditer(masked):
        if depth[m.start()] != 0:
            continue
        stmt = masked[:m.start()].rsplit(";", 1)[-1].rsplit("}", 1)[-1]
        if re.search(r"(?<![\w])typedef\b", stmt):
            continue  # `typedef struct {…} Foo;` is reported once, as the typedef
        kind = " ".join(m.group(1).split())
        name = ((m.group(2) or "") + (m.group(3) or "").strip()).strip()
        found.append((m.start(), f"{kind} {name}" if name else f"an unnamed {kind}"))
    for m in _TYPEDEF_KEY.finditer(masked):
        if depth[m.start()] != 0:
            continue
        j, d2 = m.end(), 0
        while j < len(masked):
            c = masked[j]
            if c == "{":
                d2 += 1
            elif c == "}":
                d2 -= 1
            elif c == ";" and d2 <= 0:
                break
            j += 1
        names = re.findall(r"[A-Za-z_]\w*", masked[m.end():j])
        fnptr = re.search(r"\(\s*[*&]+\s*([A-Za-z_]\w*)", masked[m.end():j])  # typedef void (*Callback)(int)
        label = fnptr.group(1) if fnptr else (names[-1] if names else "")
        found.append((m.start(), f"typedef {label}" if label else "typedef"))
    for m in _USING_ALIAS.finditer(masked):
        if depth[m.start()] == 0:
            found.append((m.start(), f"using {m.group(1)} ="))
    return [label for _, label in sorted(found)]


def extra_content(source: str, display: str) -> list[str]:
    """What a submission carries *around* its function. A submission is exactly one definition — its
    first line starts it, its closing brace ends it — because everything else is the projection's
    job (the context header declares, the registry defines the types). Returns human findings;
    [] means the source is just the function.
    """
    masked = _mask(source or "")
    tail = len(masked.rstrip()) - 1
    if tail < 0:
        return ["this submission is empty"]
    if masked[tail] != "}":
        return [f"this isn't a complete function definition: it ends with `{masked[tail]}`, "
                f"not the function's closing brace"]
    stack, open_at = [], 0
    for i, ch in enumerate(masked):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            open_at = stack.pop()
            if i == tail:
                break
    prefix = masked[:open_at]
    found: list[str] = []
    if "#" in prefix:
        found.append("a preprocessor line (#include/#define) before the function")
    if ";" in prefix:
        found.append("a declaration or table before the function (code ending in `;`)")
    depth, colon, stray = 0, -1, False
    for i, ch in enumerate(prefix):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0 and colon < 0:
            colon = i  # a constructor's init list: braces after it are initializers, not bodies
        elif ch == "{" and depth == 0 and (colon < 0 or i < colon):
            stray = True
    if stray:
        found.append("another block before its body (a second function? a namespace wrapper? — a helper "
                     "folds into the body, or lives in the shared header via edit_context)")
    try:
        from . import export as export_mod

        parsed = export_mod._split_display(display)
    except ImportError:  # pragma: no cover
        parsed = None
    name = parsed[1] if parsed else ""
    if name and name not in prefix:
        found.append(f"the text before the body doesn't name {name} — write its signature "
                     f"(fully qualified, no namespace wrappers)")
    return found


def def_key(meta: dict, name: str) -> tuple:
    try:
        from . import export as export_mod
        return export_mod._split_display(meta.get("demangled") or name) or (name,)
    except ImportError:  # pragma: no cover
        return (name,)


def header_defs(net, slug: str, analysis: dict, overrides: dict) -> list[tuple[tuple, str]]:
    """The functions the original kept defined in headers (DWARF files them under the .h): their
    matched definitions in consolidated form, as (signature key, inline definition). A compile
    that *sees* the member ctor defined — not just declared — reproduces the original's call shape
    (GCC skips exception cleanups it can prove unnecessary), which is how the original .cpp files
    were built. The key lets a compile skip the function it is itself compiling."""
    try:
        from . import export as export_mod
    except ImportError:  # pragma: no cover
        return []
    proj = net._project(slug)
    rows = net.store.all(
        "SELECT * FROM functions WHERE project_id=? AND status='matched' AND matched_source IS NOT NULL "
        "AND unit != ''", proj["id"])
    pseudo = {"types": view(analysis, overrides), "arch": analysis.get("arch")}
    ptr = 4 if str(analysis.get("arch") or "").lower() in ("i386", "x86", "arm") else 8
    out: list[tuple[tuple, str]] = []
    seen: set[tuple] = set()
    for r in rows:
        if Path(r["unit"]).suffix.lower() not in _HEADER_EXT:
            continue
        meta = json.loads(r["meta"] or "{}")
        display = meta.get("demangled") or r["name"]
        placed = [export_mod._place(c, display, pseudo, prefix="inline ")
                  for c in export_mod.extract_definitions(r["matched_source"], display) if c["tail_at"] >= 0]
        if not placed:
            continue
        best = export_mod._renamed(placed[0], r["matched_source"], pseudo, ptr) or placed[0]
        key = def_key(meta, r["name"])
        if key in seen:
            continue
        seen.add(key)
        out.append((key, best))
    return out


def salvage_entries(net, slug: str, analysis: dict, overrides: dict, texts: list[str],
                    declared: set[str] | None = None) -> list[dict]:
    """Entries for names the texts reference but the registry doesn't describe (static members of
    pruned classes, like TraceLogDefault): the matched sources declared them once. Verbatim `decl`
    entries — a proposal the re-judge still decides on. `declared` skips names the base header
    already declares, so nothing is declared twice."""
    try:
        from . import export as export_mod
    except ImportError:  # pragma: no cover
        return []
    proj = net._project(slug)
    rows = net.store.all(
        "SELECT matched_source FROM functions WHERE project_id=? AND status='matched' "
        "AND matched_source IS NOT NULL", proj["id"])
    entries = export_mod._salvage_entries(view(analysis, overrides), list(texts),
                                          [r["matched_source"] for r in rows], declared=declared)
    return list(entries.values())


def _top_level_call(line: str) -> bool:
    depth = 0
    for ch in line:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif ch == "(" and depth == 0:
            return True
    return False


def _drop_unresolved_prototypes(text: str) -> str:
    """A header-only unit has no generated type block, so a qualified prototype cannot be
    completed (`boost::system::error_code`). Comment it out instead of making the unit fail."""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        paths = set(re.findall(r"(?<![\w:])(?:[A-Za-z_]\w*::)+[A-Za-z_]\w*", s))
        if (_top_level_call(s) and ";" in s and any(not p.startswith("std::") for p in paths)
                and not s.startswith(("using ", "typedef ", "/*"))):
            out.append("// skipped prototype without a type block")
        else:
            out.append(line)
    return "\n".join(out)


def _drop_libc_prototypes(text: str) -> str:
    """A frozen ELF header may carry IDA's `long long strtol`; libc says `long` on LP64.
    The platform header owns it, so drop the manual declaration."""
    names = {"strtol", "strtoul", "strtoll", "strtoull", "atoi", "atol", "atof",
             "strtod", "strtof", "malloc", "calloc", "realloc", "free", "signal"}
    out = []
    for line in (text or "").splitlines():
        if re.search(r"\b(" + "|".join(names) + r")\s*\(", line) and line.strip().endswith(";"):
            continue
        out.append(line)
    return "\n".join(out)


def _fix_legacy_template_prototypes(legacy: str) -> str:
    """A frozen header may carry `namespace boost { void throw_exception<E>(...) }` without the
    primary template. That is not a declaration we can repair locally; comment it out rather
    than make the whole unit unparsable."""
    out = []
    for line in (legacy or "").splitlines():
        if ("namespace " in line and "<" in line and "template <" not in line
                and re.search(r"\b\w+<[^<>]*>\s*\(", line)):
            line = "// skipped library template specialization"
        out.append(line)
    return "\n".join(out)


def _drop_shadowed_prototypes(legacy: str, base: str) -> str:
    """Drop legacy prototypes whose function is already declared by the live callee context.

    The frozen header can carry an older return type (`void SetDebugFileName`) while the
    analysis says `void *`; emitting both is C2373. The base is the function's own callee
    environment, so it owns the prototype.
    """
    names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", base or ""))
    out = []
    for line in (legacy or "").splitlines():
        s = line.strip()
        m = re.match(r"^(?:[\w:<>,*&~]+\s+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;$", s)
        if (m and m.group(1) in names
                and not re.match(r"^(?:class|struct|union|enum|typedef|using|namespace)\b", s)):
            continue
        out.append(line)
    return "\n".join(out)


def header_for(analysis: dict, base: str, source: str, overrides: dict, *,
               exclude: set[str] | None = None, inline_defs: list[tuple[tuple, str]] | None = None,
               skip: tuple | None = None, salvaged: list[dict] | None = None,
               entries: str = "", legacy: str = "", types: list[dict] | None = None,
               prelude: str = "", full: bool = True) -> str:
    """The header a candidate compiles against: the base (stored context, edit_context edits and
    all) without a previously generated types block, plus the unit's structured entries, plus a
    fresh *recursive* projection of every registry entry the base and the source name. The source
    is the query — an agent using `self` of some class pulls its layout, that layout's member
    types, their layouts, and so on, with forward declarations wherever a definition would be.
    Types the source declares itself are left out. A `/* types: A, B */` comment force-pulls entries
    whose names don't appear literally (rare; the normal path needs no enumeration). `inline_defs`
    carry the matched header-unit definitions (minus `skip`, the one being compiled right now);
    `salvaged` the verbatim declarations for pruned classes the code still references. `entries`
    are the unit's structured declarations — rendered inside `visible` BEFORE the shadow check so
    they shadow the projection exactly like hand-written header text always has. `prelude` is
    project-global opaque text (third-party stubs and aliases) rendered *before* the type block: a
    class method may name an alias, and a declaration after use does not compile."""
    visible = interfaces.strip_types(base)
    if entries:
        # entries come FIRST: a promoted type must be declared before the legacy context that uses it
        # (declaration after use is the one ordering C/C++ never forgives; early is always safe)
        visible = entries.strip() + "\n\n" + visible
    # The legacy visible text is output-only: it carries agent declarations (`i_pString`) that
    # have not been promoted yet, but it must not seed the type closure — the unit-wide prototypes
    # would drag unrelated classes back in.
    seed_visible = visible
    if legacy:
        legacy = _fix_legacy_template_prototypes(legacy)
        if str(analysis.get("format") or "").lower() != "pe":
            legacy = _drop_libc_prototypes(legacy)
        legacy = _drop_shadowed_prototypes(legacy, visible)
        if legacy.strip():
            visible = legacy.strip() + "\n\n" + visible
    # the base header's own declarations shadow the registry too: a class an agent wrote into the
    # header must not get a second definition from the projection (C2011) - the base is the ground
    # truth of this compile unit, and it is what makes hand-written classes and registry entries
    # able to hand over to each other one edit at a time
    prelude = (prelude or "").strip()
    shadow = ((exclude or set()) | declared_names(source)
              | declared_names((prelude + "\n" if prelude else "") + visible))
    types = view(analysis, overrides) if types is None else types
    if salvaged:
        have = {key_of(t) for t in types}
        types = types + [t for t in salvaged if key_of(t) not in have]
    bare: dict[str, dict] = {}
    for t in types:
        bare.setdefault(t.get("name") or "", t)

    def def_ok(key) -> bool:
        """A def rides along unless the source's own declarations make it impossible: its class is
        shadowed, or the class holds a shadowed class by value (the projection omits the shadowed
        definition, so the def could not compile)."""
        cls = key[0].rsplit("::", 1)[-1] if key else ""
        if not cls or cls in shadow:
            return False
        t = bare.get(cls)
        if t is None:
            return True  # the registry doesn't describe it: nothing to contradict the def
        for m in t.get("members") or []:
            base, _ = interfaces._base_of(m.get("type") or "")
            if base.rsplit("::", 1)[-1] in shadow:
                return False
        return True

    # a source still declaring its own classes can't see inline header definitions for those
    # classes (the definitions would dangle without the class — the source's copy is the class)
    defs = [text for key, text in (inline_defs or []) if key != skip and def_ok(key)]
    seed = (prelude + "\n" if prelude else "") + seed_visible + "\n" + source + "".join("\n" + t for t in defs)
    # Comments are not type uses. The function's own signature comment can carry an IDA
    # spelling (`DynamicArray<...,156,16>`) that would otherwise pull a bogus template
    # specialisation (and its callee graph) into the header.
    seed = re.sub(r"/\*.*?\*/", " ", seed, flags=re.S)
    seed = re.sub(r"//[^\n]*", " ", seed)
    source_wo_comments = re.sub(r"/\*.*?\*/", " ", source or "", flags=re.S)
    source_wo_comments = re.sub(r"//[^\n]*", " ", source_wo_comments)
    # Inline definitions ride along in this same header, so a method they define is "used" even
    # when the function's own source never names it (`Config::getRegionName` was declared without
    # its `const` because only the appended definition mentioned it).
    usage = source_wo_comments + "".join("\n" + t for t in defs)
    for chunk in _FORCED.findall(source or ""):
        seed += "\n" + chunk
    aliases = set(_USING_ALIAS.findall(_mask((prelude + "\n" if prelude else "") + visible)))
    block = interfaces.type_block(analysis, seed, types=types,
                                  exclude=shadow, full=full,
                                  usage=usage, aliases=aliases)
    if not block:
        visible = _drop_unresolved_prototypes(visible)
    before = (prelude + "\n\n") if prelude else ""
    if block and "namespace std {" not in visible:
        # Types first avoids a legacy context naming `google::…` before the block declares it.
        # A hand-written minimal STL (`namespace std { class vector … }`) must stay before the
        # block, though: the block's real std template would otherwise redefine it.
        out = before + block + "\n\n" + visible.rstrip() + "\n"
    else:
        out = before + visible.rstrip() + "\n"
        if block:
            out += "\n" + block + "\n"
    if defs:
        out += ("\n/* the original kept these definitions in this header */\n\n"
                + "\n\n".join(defs) + "\n")
    forwards = interfaces.std_forwards(out)
    if forwards:
        out = "\n".join(forwards) + "\n" + out
    heads = std_includes(out)
    if heads:
        out = "\n".join(heads) + "\n" + out
    return out


# ---------------------------------------------------------------- entry edits (pure)

class RegistryError(NetworkError):
    pass


def _entry_for(entries: list[dict], name: str) -> dict | None:
    t = find(entries, name)
    return t


def _split_params(raw: str) -> list[str]:
    """Split a parameter list on top-level commas only. Template arguments and function pointers
    contain commas too (`std::pair<int, int>`, `void (*)(int, int)`), so a plain `.split(",")`
    turns one opaque/templated parameter into several and mangles the declaration wrong."""
    raw = (raw or "").strip()
    if raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1].strip()
    if raw in ("", "void"):
        return []
    out, cur, depth = [], "", 0
    for ch in raw:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _as_member(member: str, mtype: str, at, count) -> dict:
    why = check_type(mtype)
    if why:
        raise RegistryError(f"member type: {why}")
    mname = (member or "").strip()
    if not re.match(r"^[A-Za-z_]\w*$", mname):
        raise RegistryError(f"{member!r} is not a member name")
    if at is None and at != 0:
        raise RegistryError("at= (the byte offset from the assembly, e.g. [rdi+8] -> at=8) is required")
    try:
        off = int(at)
    except (TypeError, ValueError):
        raise RegistryError(f"at={at!r} is not an offset") from None
    if off < 0 or off > 0x100000:
        raise RegistryError(f"offset 0x{off:x} looks wrong")
    mtype = mtype.strip()
    n = int(count or 1)
    if n > 1 and not re.search(r"\[\d+\]\s*$", mtype):
        mtype = f"{mtype}[{n}]"
    return {"name": mname, "type": mtype, "off": off}


def _member_delta(key: str, old: dict, new: dict) -> str:
    om = {int(m.get("off") or 0): m for m in old.get("members") or []}
    nm = {int(m.get("off") or 0): m for m in new.get("members") or []}
    bits = []
    for off in sorted(set(nm) | set(om)):
        o, n = om.get(off), nm.get(off)
        if o is None:
            bits.append(f"added {n.get('name')} ({(n.get('type') or '?')}) at +0x{off:x}")
        elif n is None:
            bits.append(f"dropped {o.get('name')} from +0x{off:x}")
        elif (o.get("name"), o.get("type")) != (n.get("name"), n.get("type")):
            bits.append(f"replaced {o.get('name')} ({(o.get('type') or '?')}) with {n.get('name')} "
                        f"({(n.get('type') or '?')}) at +0x{off:x}")
    if new.get("size") and old.get("size") != new.get("size"):
        bits.append(f"size 0x{int(old.get('size') or 0):x} -> 0x{int(new['size']):x}")
    if not bits and old.get("decl") != new.get("decl"):
        bits.append("declaration updated")
    return f"{key}: " + ", ".join(bits) if bits else ""


def change_note(before: dict, after: dict) -> str:
    """One line saying what an edit actually changed — the offset-anchored truth. A `set_member`
    at an occupied offset *replaces* that member (nothing shifts silently), so the result text
    names the casualty right away instead of leaving it to the gate's rejection."""
    bt, at_ = _types_of(before), _types_of(after)
    parts = []
    for key in sorted(set(bt) | set(at_)):
        o, n = bt.get(key), at_.get(key)
        if o is None and n is not None:
            parts.append(f"{key}: declared ({n.get('kind') or 'struct'})")
        elif n is None and o is not None:
            parts.append(f"{key}: removed")
        elif o != n:
            d = _member_delta(key, o, n)
            if d:
                parts.append(d)
    return "; ".join(parts)[:400]


def plan_change(analysis: dict, overrides: dict, action: str, args: dict) -> dict:
    """The candidate overrides for one requested edit — pure, so the gate and the tests share it."""
    entries = view(analysis, overrides)
    data = json.loads(json.dumps(overrides or {"version": 1, "types": {}}))
    data.setdefault("types", {})
    name = (args.get("name") or "").strip()
    note = (args.get("note") or "").strip()
    t = _entry_for(entries, name) if name else None

    def base_entry(t: dict) -> dict:
        """A private, deep copy of the entry being edited: DWARF entries come from the cached
        analysis, and editing their member dicts in place would silently corrupt it (the 'old'
        view of a change must stay the old view). The stored override is layered on top so a
        note-only carrier doesn't replace the content the edit builds on."""
        key = key_of(t)
        entry = json.loads(json.dumps({k: v for k, v in t.items() if k not in ("origin", "key")}))
        stored = data["types"].get(key)
        if stored:
            entry.update({k: v for k, v in stored.items() if k != "origin"})
        return entry

    def put(key: str, entry: dict) -> None:
        entry = {k: v for k, v in entry.items() if k not in ("origin", "key")}
        base = dict(data["types"].get(key) or {})
        base.update(entry)
        if note:
            base["note"] = note
        base["origin"] = "agent"
        base["updated"] = time.time()
        data["types"][key] = base

    if action == "declare":
        if not name:
            raise RegistryError("name= is required, e.g. name='ACME::Aurora::Core::DoubleLinkNode'")
        kind = (args.get("kind") or "struct").strip()
        if kind not in _ENTRY_KINDS:
            raise RegistryError(f"kind= must be one of {', '.join(_ENTRY_KINDS)}")
        ns, bare = split_key(name)
        if not bare:
            raise RegistryError(f"{name!r} has no type name")
        if t is not None and t.get("origin") == "dwarf":
            raise RegistryError(f"{key_of(t)} already exists in the debug info — edit it instead of declaring it")
        size = args.get("size")
        entry = {"name": bare, "ns": ns, "kind": kind, "members": [], "statics": [], "methods": []}
        if size not in (None, ""):
            try:
                entry["size"] = int(size)
            except (TypeError, ValueError):
                raise RegistryError(f"size={size!r} is not a number of bytes") from None
        put(key_of(entry), entry)
    elif action == "set_kind":
        if t is None:
            raise RegistryError(f"no type {name!r} — declare it first")
        kind = (args.get("kind") or "").strip()
        if kind not in _ENTRY_KINDS:
            raise RegistryError(f"kind= must be one of {', '.join(_ENTRY_KINDS)}")
        key = key_of(t)
        entry = base_entry(t)
        entry["kind"] = kind
        put(key, entry)
    elif action == "set_member":
        if t is None:
            raise RegistryError(f"no type {name!r} — declare it first")
        key = key_of(t)
        entry = base_entry(t)
        member = args.get("member") or ""
        entries_new = [m for m in entry.get("members") or [] if int(m.get("off") or 0) != int(args.get("at") or 0)]
        entries_new.append(_as_member(member, args.get("mtype") or "", args.get("at"), args.get("count")))
        entries_new.sort(key=lambda m: int(m.get("off") or 0))
        entry["members"] = entries_new
        put(key, entry)
    elif action == "remove_method":
        if t is None:
            raise RegistryError(f"no type {name!r}")
        key = key_of(t)
        entry = base_entry(t)
        mname = (args.get("member") or "").strip()
        if not re.match(r"^[~A-Za-z_]\w*$", mname):
            raise RegistryError(f"member={mname!r} is not a method name")
        raw = (args.get("params") or "").strip()
        params = _split_params(raw)
        methods = entry.get("methods") or []
        kept = [m for m in methods
                if not (m.get("name") == mname
                        and (not params or [p.strip() for p in m.get("params") or []] == params))]
        if len(kept) == len(methods):
            overload = f" with params ({', '.join(params)})" if params else ""
            raise RegistryError(f"{key} has no method {mname}{overload} to remove")
        entry["methods"] = kept
        put(key, entry)
    elif action == "set_method":
        if t is None:
            raise RegistryError(f"no type {name!r} — declare it first")
        key = key_of(t)
        entry = base_entry(t)
        mname = (args.get("member") or "").strip()
        if not re.match(r"^[~A-Za-z_]\w*$", mname):
            raise RegistryError(f"member={mname!r} is not a method name")
        ret = (args.get("mtype") or "").strip()
        raw = (args.get("params") or "").strip()
        params = _split_params(raw)
        for bit in ([ret] if ret else []) + params:
            why = check_type(bit)
            if why:
                raise RegistryError(f"method type: {why}")
        existing = next((x for x in entry.get("methods") or []
                         if x.get("name") == mname and (x.get("params") or []) == params), None)
        m: dict = dict(existing) if existing else {"name": mname, "params": params}
        if ret:
            m["ret"] = ret
        for flag in ("static", "virtual", "const"):
            value = args.get(flag)
            if value in (None, ""):
                continue  # unspecified: keep the existing method's access/linkage/flags
            if str(value).lower() in ("1", "true", "yes", "on"):
                m[flag] = True
            else:
                m.pop(flag, None)
        entry["methods"] = [x for x in entry.get("methods") or []
                            if not (x.get("name") == mname and (x.get("params") or []) == params)] + [m]
        put(key, entry)
    elif action == "set_static":
        if t is None:
            raise RegistryError(f"no type {name!r} — declare it first")
        key = key_of(t)
        entry = base_entry(t)
        sname = (args.get("member") or "").strip()
        if not re.match(r"^[A-Za-z_]\w*$", sname):
            raise RegistryError(f"member={sname!r} is not a static member name")
        stype = (args.get("mtype") or "").strip()
        why = check_type(stype)
        if why:
            raise RegistryError(f"static member type: {why}")
        visibility = (args.get("visibility") or "").strip()
        if visibility not in ("", "default", "hidden", "protected"):
            raise RegistryError(f"unsupported visibility {visibility!r}")
        entry["statics"] = [x for x in entry.get("statics") or []
                            if (x.get("name") if isinstance(x, dict) else str(x)) != sname]
        static = {"name": sname, "type": stype}
        if visibility:
            static["visibility"] = visibility
        entry["statics"].append(static)
        put(key, entry)
    elif action == "rename_member":
        if t is None:
            raise RegistryError(f"no type {name!r}")
        key = key_of(t)
        entry = base_entry(t)
        old = args.get("member") or ""
        new = (args.get("new_name") or "").strip()
        if not re.match(r"^[A-Za-z_]\w*$", new):
            raise RegistryError(f"new_name={new!r} is not a member name")
        hit = False
        for m in entry.get("members") or []:
            if m.get("name") == old or (old.startswith("0x") and int(m.get("off") or 0) == int(old, 16)):
                m["name"] = new
                hit = True
        if not hit:
            raise RegistryError(f"{old!r} is not a member of {key}")
        put(key, entry)
    elif action == "remove_member":
        if t is None:
            raise RegistryError(f"no type {name!r}")
        key = key_of(t)
        entry = base_entry(t)
        old = args.get("member") or ""
        members = sorted(entry.get("members") or [], key=lambda m: int(m.get("off") or 0))
        for i, m in enumerate(members):
            if m.get("name") != old:
                continue
            off = int(m.get("off") or 0)
            end = int(members[i + 1]["off"]) if i + 1 < len(members) else int(entry.get("size") or off + 8)
            m["name"] = f"_gap{off:x}"
            m["type"] = "unsigned char"
            m["count"] = max(1, end - off)
            m["type"] = f"unsigned char[{max(1, end - off)}]"
            m.pop("count", None)
            put(key, entry)
            break
        else:
            raise RegistryError(f"{old!r} is not a member of {key}")
    elif action == "set_size":
        if t is None:
            raise RegistryError(f"no type {name!r}")
        key = key_of(t)
        entry = base_entry(t)
        try:
            entry["size"] = int(args.get("size"))
        except (TypeError, ValueError):
            raise RegistryError("size= must be a number of bytes") from None
        put(key, entry)
    elif action == "move":
        if t is None:
            raise RegistryError(f"no type {name!r}")
        scope = (args.get("scope") or "").strip()
        ns = [p for p in scope.split("::") if p] if scope not in ("", "(global)", "global") else []
        old_key = key_of(t)
        if t.get("origin") == "dwarf" and old_key not in data["types"]:
            raise RegistryError(f"{old_key} is where the debug info puts it — namespace moves are for "
                                f"types agents declared")
        data["types"].pop(old_key, None)
        new_key = "::".join([*ns, t["name"]])
        put(new_key, {**t, "ns": ns})
        if new_key != old_key:
            # the analysis's base entry lives at old_key and would keep rendering (C2011 when the
            # agent then declares the moved type itself): leave a tombstone view() honors
            data["types"][old_key] = {"hidden": True, "origin": "agent", "updated": time.time()}
    elif action == "hide":
        if t is None:
            raise RegistryError(f"no type {name!r} to hide")
        key = key_of(t)
        stored = data["types"].get(key)
        keep = None
        if stored is not None and not stored.get("hidden"):  # an override's content must survive unhide
            keep = {k: v for k, v in stored.items() if k not in ("origin", "updated")}
        data["types"][key] = {"hidden": True, "origin": "agent", "updated": time.time(),
                              **({"entry": keep} if keep else {})}
    elif action == "unhide":
        key = (name or "").strip()
        cur = data["types"].get(key)
        if not (isinstance(cur, dict) and cur.get("hidden")):
            raise RegistryError(f"nothing hidden at {name!r} — unhide takes the exact qualified key")
        if isinstance(cur.get("entry"), dict):
            data["types"][key] = {**cur["entry"], "origin": "agent", "updated": time.time()}
        else:
            data["types"].pop(key)  # a base the debug info carries comes back by itself
    elif action == "merge":
        other = _entry_for(entries, args.get("other") or "")
        if t is None or other is None:
            raise RegistryError("merge needs name= and other= (two existing types)")
        if "dwarf" in (t.get("origin"), other.get("origin")):
            raise RegistryError("the debug info already distinguishes these types; edit them instead of merging")
        into, src = t, other
        if key_of(src) not in data["types"] or key_of(into) not in data["types"]:
            raise RegistryError("merge works on agent-declared types")
        entry = dict(data["types"][key_of(into)])
        have = {int(m.get("off") or 0) for m in entry.get("members") or []}
        for m in src.get("members") or []:
            if int(m.get("off") or 0) not in have:
                entry.setdefault("members", []).append(m)
        entry["members"] = sorted(entry.get("members") or [], key=lambda m: int(m.get("off") or 0))
        seen = {(m.get("name"), m.get("type")) for m in entry.get("methods") or []}
        for m in src.get("methods") or []:
            if (m.get("name"), m.get("type")) not in seen:
                entry.setdefault("methods", []).append(m)
        if not entry.get("size") and src.get("size"):
            entry["size"] = src["size"]
        data["types"].pop(key_of(src), None)
        put(key_of(into), entry)
    else:
        raise RegistryError(f"unknown action {action!r}: declare, set_member, rename_member, remove_member, "
                            f"set_method, remove_method, set_size, move, merge")
    return data


# ---------------------------------------------------------------- the gate

def _verify_one(engine, proj, fn, header: str, source: str) -> tuple[bool, str]:
    res = engine.compile_fn(fn, proj, header, source, raw_header=True)  # the header is already final
    if not res.ok:
        return False, " ".join((res.log or "the compiler refused it").strip().split())[:300]
    cand, verdict, problems = engine.evaluate(fn, proj, res.obj)
    if cand is None:
        return False, "compiled, but its symbol isn't in the object"
    if verdict is None:
        return False, "compiled, but couldn't be judged"
    if verdict:
        return True, ""
    return False, ("; ".join(problems[:3]) if problems else "the bytes differ")[:300]


def _consolidated_forms(fn, meta: dict, analysis: dict, overrides: dict) -> list[str]:
    """The matched source re-shaped the way the export would ship it (scaffolding stripped, names
    rewritten onto the *candidate* registry's canonical layout): a source still carrying its own
    declarations must be judged in the form it will live in, or a registry edit would look inert."""
    try:
        from . import export as export_mod
    except ImportError:  # pragma: no cover
        return []
    pseudo = {"types": view(analysis, overrides), "arch": analysis.get("arch")}
    display = meta.get("demangled") or fn["name"]
    placed = [export_mod._place(c, display, pseudo)
              for c in export_mod.extract_definitions(fn["matched_source"], display) if c["tail_at"] >= 0]
    ptr = 4 if str(analysis.get("arch") or "").lower() in ("i386", "x86", "arm") else 8
    renamed = export_mod._renamed(placed[0], fn["matched_source"], pseudo, ptr) if placed else None
    return [t for t in (renamed,) if t] + placed


def _unit_header(analysis: dict, unit: str, language: str, types: list[dict]) -> str:
    """The one unit renderer: types first, then the callee context (interfaces.unit_header).

    This used to be a second implementation that appended the type block after the
    prototypes, so `_refresh` and the first-touch path could disagree on ordering."""
    return interfaces.unit_header(analysis, unit, language=language, types=types)


def unit_language(analysis: dict, unit: str, rows: list) -> str:
    """C++ when anything that compiles against the unit is C++ (matched rows first, then the
    unit's own functions by the same rule header generation uses); the project-wide header
    answers with the project's language."""
    if rows:
        return "c++" if any(json.loads(r["meta"] or "{}").get("language") == "c++" for r in rows) else "c"
    by_ea = {f["ea"]: f for f in analysis["functions"]}
    if unit:
        node = (analysis.get("graph", {}).get("files") or {}).get(unit) or {}
        eas = node.get("functions") or []
    else:
        eas = list(by_ea)
    return "c++" if any((by_ea.get(ea) or {}).get("language") == "c++" for ea in eas) else "c"


def _sync_state(net, slug: str) -> dict:
    """The write-through's memory: which types still owe the IDA database a write and why the last
    attempt failed. Kept in the settings table (single-row upsert: race-free, unlike rewriting the
    registry file around a commit)."""
    store = getattr(net, "store", None)
    if store is None:  # minimal fakes (tests) don't carry a store; the ledger is auxiliary
        return {}
    row = store.one("SELECT value FROM settings WHERE key=?", f"sync:{slug}")
    if row:
        try:
            data = json.loads(row["value"])
            return data if isinstance(data, dict) else {}
        except ValueError:
            pass
    return {}


def _sync_save(net, slug: str, state: dict) -> None:
    store = getattr(net, "store", None)
    if store is None:
        return
    with store.tx() as db:
        db.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (f"sync:{slug}", json.dumps(state)))


def _ida_db_held(net, slug: str) -> bool:
    """A fast, read-only check before the expensive IDA open: `lsof` sees the database held by the
    user's IDA Pro. If it is, the write queues immediately instead of blocking the HTTP request for
    the open timeout."""
    if os.name == "nt":
        return False
    lsof = shutil.which("lsof")
    if not lsof:
        return False
    try:
        from . import analyze as analyze_mod
        proj = net._project(slug)
        path = analyze_mod.ida_source(Path(proj["root"]), net.cfg(proj))
        res = subprocess.run([lsof, "-t", str(path)], capture_output=True, text=True, timeout=2)
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def _ida_recently_busy(state: dict, now: float | None = None) -> bool:
    """A database held by IDA Pro fails after a long open timeout. Retrying that on every type edit
    makes the drawer's Save look hung, so a recent "can't open" is treated as busy for two minutes;
    the pending keys stay queued and the next attempt after the cooldown retries."""
    err = str(state.get("last_error") or "").lower()
    if not err or not any(s in err for s in ("another ida", "can't be opened", "open in ida", "1228")):
        return False
    last = float(state.get("last_try_at") or 0)
    return (now if now is not None else time.time()) - last < 120


def _write_through(net, slug: str, analysis: dict, before: dict, after: dict) -> str:
    """Committed types go into IDA's database (the .i64), not only registry.json: the same
    declarations the header projection renders are parsed into the local type library and the
    database is saved once per batch. Without a backend this is a no-op and the JSON stays
    the store; the compile gate has already passed either way.

    Failures queue: the pending type keys ride in the settings table and every later write retries
    them — a database held by another IDA instance costs visibility, never the edits."""
    engine = getattr(net, "native", None)
    if engine is None or not engine.ida_ready():
        return ""
    state = _sync_state(net, slug)
    pending = sorted(set(state.get("pending") or [])
                     | {key_of(t) for k, t in after.items() if before.get(k) != t})
    targets = [t for k, t in after.items() if key_of(t) in pending]
    if not targets:
        return ""
    if _ida_db_held(net, slug):
        _sync_save(net, slug, {"pending": pending,
                               "last_error": "the IDA database is open in another process (lsof)",
                               "last_try_at": state.get("last_try_at", 0)})
        return (f"not written to the IDA database yet ({len(pending)} type(s) queued — the database is "
                f"open in another process; it retries on the next write once it is closed)")
    if _ida_recently_busy(state):
        return (f"not written to the IDA database yet ({len(pending)} type(s) queued — the database was "
                f"recently busy in another IDA instance; the queued types retry on the next write after "
                f"the cooldown)")
    from . import interfaces

    seed = "\n".join(key_of(t).rsplit("::", 1)[-1] for t in targets)
    decls = interfaces.type_block(analysis, seed, types=targets, exclude=set(), full=True)
    if not decls.strip():
        return ""
    try:
        res = engine.ida_apply_decls(slug, decls)
        if not res.get("ok", True):
            raise RegistryError(str(res.get("error") or "parse failed"))
        saved = engine.ida_save(slug, force=True)
    except Exception as exc:  # the commit itself succeeded; the database write is queued
        _sync_save(net, slug, {"pending": pending, "last_error": str(exc), "last_try_at": time.time()})
        return (f"not written to the IDA database yet ({len(pending)} type(s) queued — the database may "
                f"be open in IDA Professional): {exc}")
    _sync_save(net, slug, {"pending": [], "last_ok_at": time.time(), "last": pending})
    return (f"{len(targets)} type(s) written to the IDA database"
            + ("" if saved else " (flush deferred to close)"))


def _gate(net, slug: str, proj, analysis: dict, by_unit: dict, units_set: set,
          old_overrides: dict, candidate: dict) -> dict:
    """Recompile every matched function whose compile environment the candidate changes and
    re-judge it — the one acceptance test, shared by single edits and session commits.
    Returns {"failures", "checked", "touched"}."""
    engine = net.native
    old_view = view(analysis, old_overrides)
    new_view = view(analysis, candidate)
    defs = header_defs(net, slug, analysis, candidate)  # the original's inline header definitions
    defs_old = header_defs(net, slug, analysis, old_overrides)
    defs_stable = defs == defs_old

    failures: list[dict] = []
    checked = 0
    skipped = 0
    touched: list[str] = []
    probe_cache: dict[tuple[str, str], str] = {}
    stored_cache: dict[str, str] = {}

    def stored_for(unit: str) -> str:
        """The stored header (edit_context edits included) the candidate compile builds on."""
        if unit not in stored_cache:
            stored_cache[unit] = net._context(proj["id"], unit if unit in units_set else "")["header"]
        return stored_cache[unit]

    def probe(unit: str, language: str) -> tuple[str, str]:
        """Fallback probe for units without a per-function analysis record."""
        key = (unit, language)
        if key not in probe_cache:
            text = "\n".join(interfaces.context_block(analysis, [unit], language=language))
            text += "\n" + "\n".join((r["matched_source"] or "") for r in by_unit.get(unit, []))
            old = interfaces.type_block(analysis, text, types=old_view, full=True)
            new = interfaces.type_block(analysis, text, types=new_view, full=True)
            probe_cache[key] = (old, new)
        return probe_cache[key]

    def probe_fn(unit: str, fn) -> tuple[str, str]:
        """Does this function's actual compile projection change? Seeded from its own callees,
        source, entries and inline definitions — the same inputs `_render_header` uses."""
        key = fn["id"]
        if key in probe_cache:
            return probe_cache[key]
        meta = json.loads(fn["meta"] or "{}")
        form = fn["matched_source"] or ""
        stored = stored_for(unit)
        old = engine._render_header(fn, proj, stored, form, overrides=old_overrides)
        new = engine._render_header(fn, proj, stored, form, overrides=candidate)
        probe_cache[key] = (old, new)
        return old, new

    for unit, fns in sorted(by_unit.items()):
        changed = False
        for fn in fns:
            meta = json.loads(fn["meta"] or "{}")
            fn_language = "c++" if meta.get("language") == "c++" else "c"
            old_header, new_header = (probe_fn(unit, fn) if fn_language == "c++"
                                      else probe(unit, fn_language))
            if old_header != new_header:
                changed = True
                break
        if not changed:
            continue
        touched.append(unit)
        for fn in fns:
            meta = json.loads(fn["meta"] or "{}")
            fn_language = "c++" if meta.get("language") == "c++" else "c"
            afn = engine.analysis_function(proj, fn)
            base = ("\n".join(interfaces.function_context(analysis, afn, language="c++"))
                    if fn_language == "c++" and afn is not None else stored_for(unit))
            full = engine.has_callers(fn, proj) if fn_language == "c++" else True
            key = def_key(meta, fn["name"])
            # judge the form the code will live in: the consolidated definition when extraction
            # yields one (the saved source may be decoupled from the registry by its own
            # scaffolding, and would wave through edits the consolidated code can't survive)
            forms = _consolidated_forms(fn, meta, analysis, candidate)
            attempts = forms if forms else [fn["matched_source"]]
            good, why = False, "nothing to verify"
            for form in attempts:
                declared = declared_names(base)
                salvage_new = salvage_entries(net, slug, analysis, candidate, [base, form], declared=declared)
                # the unit's entries are part of every compile: a promoted type (OSMemoryHandle) lives
                # there, not in the stored seed. Omitting them judged a header no compile ever sees.
                entries_text = engine._unit_entries_text(proj, fn)
                legacy = (interfaces.strip_types(stored_for(unit))
                          if fn_language == "c++" and afn is not None else "")
                header = header_for(analysis, base, form, candidate, inline_defs=defs, skip=key,
                                    salvaged=salvage_new, entries=entries_text, legacy=legacy,
                                    full=full, prelude=opaque_text(candidate))
                # the dependency proof: render the OLD view against the SAME auxiliary inputs; when
                # the compiled header is byte-identical, this function cannot have been affected -
                # no compile. (Auxiliary inputs must be identical too, or the baseline isn't "old".)
                if defs_stable:
                    salvage_old = salvage_entries(net, slug, analysis, old_overrides, [base, form],
                                                  declared=declared)
                    if salvage_new == salvage_old:
                        baseline = header_for(analysis, base, form, candidate, types=old_view,
                                              inline_defs=defs, skip=key, salvaged=salvage_new,
                                              entries=entries_text, legacy=legacy, full=full,
                                              prelude=opaque_text(old_overrides))
                        if header == baseline:
                            good, why = True, "unaffected: the compiled header is unchanged"
                            skipped += 1
                            break
                good, why = _verify_one(engine, proj, fn, header, form)
                if good:
                    break
            checked += 1
            if not good:
                failures.append({"name": fn["name"], "unit": unit, "why": why})
    return {"failures": failures, "checked": checked, "skipped": skipped, "touched": touched}


def _refresh(net, slug: str, proj, analysis: dict, touched: list[str], by_unit: dict, label: str) -> None:
    """The headers agents compile against are projections: refresh the generated ones — from the
    registry as it stands at this moment (a concurrent edit may already sit on top of ours)."""
    final_view = view(analysis, load(net, slug))
    now = time.time()
    with net.store.tx() as db:
        version = db.execute("SELECT MAX(version) AS v FROM context_versions WHERE project_id=?",
                             (proj["id"],)).fetchone()["v"] or 0
        for unit in touched:
            language = unit_language(analysis, unit, by_unit.get(unit) or [])
            fresh = _unit_header(analysis, unit, language, final_view)
            latest = db.execute("SELECT version, header, agent_id FROM context_versions "
                                "WHERE project_id=? AND unit=? ORDER BY version DESC LIMIT 1",
                                (proj["id"], unit)).fetchone()
            header = fresh
            if latest is not None and latest["header"] != fresh:
                # a refresh replaces the generated block and nothing else: hand-written decls and
                # the agent's layout outside the markers are this unit's ground truth — rewriting
                # the whole header silently dropped them (an agent rebuilt the OSMemory header
                # by hand after a regeneration ate its declarations)
                head = interfaces.strip_types(latest["header"]).strip()
                block = ""
                if interfaces._TYPE_MARK_BEGIN in fresh:
                    start = fresh.index(interfaces._TYPE_MARK_BEGIN)
                    end = fresh.index(interfaces._TYPE_MARK_END, start) + len(interfaces._TYPE_MARK_END)
                    block = fresh[start:end].strip()
                header = (head + "\n\n" + block + "\n") if head and block else \
                         (head + "\n" if head else fresh)
            if latest is not None and latest["header"] == header:
                continue
            version += 1
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (proj["id"], version, header, None, f"regenerated (types: {label})", now, unit))


def _await_free(net, slug: str, wait: float | None = None) -> None:
    """An edit waits for a held session instead of racing against it (the holder is verifying a
    batch; colliding would only burn compiles). Bounded; then it says who is in the way."""
    deadline = time.time() + (LOCK_WAIT if wait is None else max(0.0, float(wait)))
    while True:
        holder = _live_lock(load(net, slug))
        if holder is None:
            return
        if time.time() >= deadline:
            raise RegistryError(
                f"{holder.get('name') or 'another agent'} is editing the registry right now "
                f"(expires in {int(max(0, holder.get('expires', 0) - time.time()))}s) — try again shortly, "
                f"or take the lock yourself with lock_registry and stage your edits")
        time.sleep(0.5)


def apply(net, slug: str, action: str, wait: float | None = None, **args) -> dict:
    """Propose one edit; keep it only if every matched function whose compile environment changes
    still recompiles and re-judges byte-identical. Returns {"ok", "rechecked", "units", "failures"}.
    Waits for a held edit session; concurrent single edits compare-and-swap instead of clobbering."""
    engine = net.native
    proj = net._project(slug)
    analysis = engine.analysis(proj)
    if not analysis:
        raise RegistryError("no analysis yet — analyze the project first")
    _await_free(net, slug, wait)  # a session holder is mid-verification: waiting beats racing
    _, by_unit, units_set = _matched_context(net, proj)

    for _attempt in range(3):
        overrides = load(net, slug)
        snapshot = json.dumps(_types_of(overrides), sort_keys=True)
        candidate = plan_change(analysis, overrides, action, args)
        note = change_note(overrides, candidate)
        gate = _gate(net, slug, proj, analysis, by_unit, units_set, overrides, candidate)
        if gate["failures"]:
            return {"ok": False, "rechecked": gate["checked"], "skipped": gate["skipped"],
                    "units": gate["touched"], "failures": gate["failures"], "note": note}
        current = load(net, slug)
        if json.dumps(_types_of(current), sort_keys=True) != snapshot or _live_lock(current):
            time.sleep(0.5)  # someone contributed or took the lock meanwhile: re-apply and re-test
            continue
        current["types"] = _types_of(candidate)
        save(net, slug, current)
        break
    else:
        raise RegistryError("the registry is being edited heavily right now; re-read it and retry")
    _refresh(net, slug, proj, analysis, gate["touched"], by_unit, action)
    out = {"ok": True, "rechecked": gate["checked"], "skipped": gate["skipped"],
           "units": gate["touched"], "failures": [], "note": note}
    backend = _write_through(net, slug, analysis, _types_of(overrides), _types_of(candidate))
    if backend:
        out["backend"] = backend
    return out
