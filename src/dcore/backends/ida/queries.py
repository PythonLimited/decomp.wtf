"""Read-only IDA lookups for agents: the curated query surface.

Each action builds one IDAPython snippet that prints a single `DECOMP_QUERY <json>` marker line;
the app runs it through the project's long-lived IDA session (the read twin of the registry write
path) and renders the JSON back as compact text. Read-only by contract: nothing here writes to or
re-analyzes the database.

Actions: xrefs, disasm, decompile, types, globals, strings, segments.
"""

from __future__ import annotations

import json

ACTIONS = ("xrefs", "disasm", "decompile", "types", "globals", "strings", "segments")
MARKER = "DECOMP_QUERY "
CAP = 200  # hard cap on items/lines per answer; the tool's count may ask for less

_PRELUDE = r"""
import json, idautils, idc, ida_name, ida_funcs, ida_segment

def dq_demangle(name):
    try:
        return ida_name.demangle_name(name, 0) or ""
    except Exception:
        return ""

def dq_fn(ea):
    f = ida_funcs.get_func(ea)
    if f:
        raw = ida_funcs.get_func_name(f.start_ea) or ""
        return {"ea": f.start_ea, "name": dq_demangle(raw) or raw}
    raw = ida_name.get_ea_name(ea) or ""
    return {"ea": ea, "name": dq_demangle(raw) or raw}

def dq_find(q):
    q = (q or "").strip()
    if not q:
        return idc.BADADDR
    try:
        if q.lower().startswith("0x") or (len(q) >= 4 and all(c in "0123456789abcdefABCDEF" for c in q)):
            return int(q, 16)
    except Exception:
        pass
    ea = idc.get_name_ea_simple(q)
    if ea != idc.BADADDR:
        return ea
    try:
        f = db.functions.get_by_name(q)
        if f:
            return f.start_ea
    except Exception:
        pass
    low = q.lower()
    for ea2, name in idautils.Names():
        if name == q or name.lower() == low:
            return ea2
    for ea2, name in idautils.Names():
        if low and low in name.lower():
            return ea2
    for ea2, name in idautils.Names():
        dn = dq_demangle(name).lower()
        if low and low in dn:
            return ea2
    return idc.BADADDR

def dq_kind(x):
    if getattr(x, "is_call", False):
        return "call"
    if getattr(x, "is_jump", False):
        return "jump"
    if getattr(x, "is_read", False):
        return "read"
    if getattr(x, "is_write", False):
        return "write"
    if getattr(x, "is_flow", False):
        return "flow"
    t = getattr(x, "type", None)
    try:
        n = int(t)
    except Exception:
        return str(t or "").lower()
    return {0: "unknown", 1: "read", 2: "write", 3: "offset", 4: "imm", 16: "call", 17: "call",
            18: "jump", 19: "jump", 21: "flow"}.get(n, "xref%d" % n)

def dq_emit(payload):
    print("__MARKER__" + json.dumps(payload))
"""

_XREFS = r"""
t = dq_find(__QUERY__)
if t == idc.BADADDR:
    dq_emit({"error": "not found in this database: " + __QUERY__})
else:
    to = []
    for x in db.xrefs.to_ea(t):
        if len(to) >= __COUNT__:
            break
        to.append({"ea": int(x.from_ea), "kind": dq_kind(x), "from": dq_fn(int(x.from_ea))})
    frm = []
    f = ida_funcs.get_func(t)
    seen = set()
    if f:
        ea = f.start_ea
        while ea != idc.BADADDR and ea < f.end_ea and ea < f.start_ea + 0x20000 and len(frm) < __COUNT__:
            for x in db.xrefs.from_ea(ea):
                key = (int(x.to_ea), dq_kind(x))
                if key in seen:
                    continue
                seen.add(key)
                frm.append({"ea": int(x.to_ea), "kind": key[1], "at": ea, "to": dq_fn(int(x.to_ea))})
                if len(frm) >= __COUNT__:
                    break
            ea = idc.next_head(ea, f.end_ea)
    else:
        for x in db.xrefs.from_ea(t):
            if len(frm) >= __COUNT__:
                break
            frm.append({"ea": int(x.to_ea), "kind": dq_kind(x), "at": t, "to": dq_fn(int(x.to_ea))})
    dq_emit({"target": dq_fn(t), "to": to, "from": frm})
"""

_DISASM = r"""
t = dq_find(__QUERY__)
if t == idc.BADADDR:
    dq_emit({"error": "not found in this database: " + __QUERY__})
else:
    f = ida_funcs.get_func(t)
    lines = []
    ea = t
    # a function name (or its start) gives the WHOLE body in one call - chunking a 74-instruction
    # listing by hand makes agents re-read it every turn; an interior address is a plain window
    whole = f is not None and f.start_ea == t
    cap = max(__COUNT__, 400) if whole else __COUNT__
    stop = f.end_ea if whole else idc.get_segm_end(t)
    while ea != idc.BADADDR and len(lines) < cap and ea < stop:
        lines.append({"ea": ea, "text": idc.generate_disasm_line(ea, 0) or ""})
        nxt = idc.next_head(ea, stop)
        if nxt == ea:
            break
        ea = nxt
    dq_emit({"start": t, "at": dq_fn(t), "lines": lines})
"""

_DECOMPILE = r"""
t = dq_find(__QUERY__)
f = ida_funcs.get_func(t) if t != idc.BADADDR else None
if not f:
    dq_emit({"error": "no function at " + __QUERY__})
else:
    try:
        text = "\n".join(str(line) for line in db.functions.get_pseudocode(f).to_text())
        dq_emit({"function": dq_fn(f.start_ea), "pseudocode": text[:40000]})
    except Exception as exc:
        dq_emit({"error": "Hex-Rays failed: " + repr(exc)})
"""

_TYPES = r"""
q = (__QUERY__ or "").strip()
out = []
def dq_members(tif):
    try:
        members = []
        for m in db.types.get_members(tif):
            mt = getattr(m, "type", None)
            try:
                mtype = (mt.get_type_name() if mt is not None else "") or (str(mt) if mt is not None else "")
            except Exception:
                mtype = ""
            members.append({"name": getattr(m, "name", ""), "offset": getattr(m, "offset", None), "type": mtype})
            if len(members) >= 64:
                break
        return members
    except Exception:
        return []

tif = db.types.get_by_name(q) if q else None
if tif is not None:
    out.append({"name": tif.get_type_name() or q, "members": dq_members(tif)})
else:
    low = q.lower()
    for t in db.types.get_all():
        name = t.get_type_name() or ""
        if not low or low in name.lower():
            out.append({"name": name, "members": []})
            if len(out) >= __COUNT__:
                break
dq_emit({"query": q, "matches": out})
"""

_GLOBALS = r"""
low = (__QUERY__ or "").lower()
out = []
for ea, name in idautils.Names():
    if ida_funcs.get_func(ea):
        continue
    if low and low not in name.lower():
        continue
    try:
        typ = idc.get_type(ea) or ""
    except Exception:
        typ = ""
    out.append({"ea": ea, "name": name, "type": typ})
    if len(out) >= __COUNT__:
        break
dq_emit({"filter": __QUERY__, "items": out})
"""

_STRINGS = r"""
low = (__QUERY__ or "").lower()
out = []
for s in idautils.Strings():
    try:
        value = str(s)
    except Exception:
        continue
    if low and low not in value.lower():
        continue
    out.append({"ea": int(s.ea), "value": value[:300]})
    if len(out) >= __COUNT__:
        break
dq_emit({"filter": __QUERY__, "items": out})
"""

_SEGMENTS = r"""
out = []
for ea in idautils.Segments():
    seg = ida_segment.getseg(ea)
    if seg is None:
        continue
    perm = int(getattr(seg, "perm", 0))
    out.append({"start": int(seg.start_ea), "end": int(seg.end_ea),
                "name": ida_segment.get_segm_name(seg),
                "class": ida_segment.get_segm_class(seg),
                "perm": ("r" if perm & 4 else "-") + ("w" if perm & 2 else "-") + ("x" if perm & 1 else "-")})
dq_emit({"segments": out})
"""

_BODIES = {"xrefs": _XREFS, "disasm": _DISASM, "decompile": _DECOMPILE, "types": _TYPES,
           "globals": _GLOBALS, "strings": _STRINGS, "segments": _SEGMENTS}


def build(action: str, query: str = "", count: int = 40) -> str:
    """The IDAPython snippet for one lookup (always prints exactly one DECOMP_QUERY line)."""
    if action not in _BODIES:
        raise ValueError(f"unknown IDA lookup {action!r}; one of: {', '.join(ACTIONS)}")
    n = max(1, min(int(count or 40), CAP))
    body = _BODIES[action].replace("__QUERY__", json.dumps(query or "")).replace("__COUNT__", str(n))
    return _PRELUDE.replace("__MARKER__", MARKER) + body


def result(stdout: str) -> dict | None:
    """The payload from the snippet's marker line (None when it never printed one)."""
    payload = None
    for line in (stdout or "").splitlines():
        if line.startswith(MARKER):
            try:
                payload = json.loads(line[len(MARKER):])
            except ValueError:
                payload = None
    return payload if isinstance(payload, dict) else None


def render(action: str, payload: dict) -> str:
    """The agent-facing text for one payload (compact, capped)."""
    if payload.get("error"):
        return f"IDA: {payload['error']}"
    if action == "xrefs":
        t = payload.get("target") or {}
        head = f"references around 0x{t.get('ea', 0):08X} {t.get('name') or ''}".rstrip()
        lines = [head]
        to = payload.get("to") or []
        lines.append(f"referenced by ({len(to)}):")
        for x in to:
            fr = x.get("from") or {}
            lines.append(f"  0x{x['ea']:08X}  {x.get('kind', ''):<10} from {fr.get('name') or '?'} (0x{fr.get('ea', 0):08X})")
        frm = payload.get("from") or []
        lines.append(f"references ({len(frm)}):")
        for x in frm:
            dst = x.get("to") or {}
            lines.append(f"  0x{x['ea']:08X}  {x.get('kind', ''):<10} -> {dst.get('name') or '?'} (0x{dst.get('ea', 0):08X}) at 0x{x.get('at', 0):08X}")
        return "\n".join(lines)
    if action == "disasm":
        at = payload.get("at") or {}
        lines = [f"disassembly at 0x{at.get('ea', 0):08X} {at.get('name') or ''}".rstrip(), "```asm"]
        lines += [f"0x{line['ea']:08X}  {line.get('text', '')}" for line in payload.get("lines") or []]
        lines.append("```")
        return "\n".join(lines)
    if action == "decompile":
        fn = payload.get("function") or {}
        return (f"Hex-Rays pseudocode for {fn.get('name') or '?'} (0x{fn.get('ea', 0):08X}; drafts are wrong on "
                f"types and names - the bytes decide):\n```c\n{payload.get('pseudocode') or ''}\n```")
    if action == "types":
        q = payload.get("query") or ""
        matches = payload.get("matches") or []
        if not matches:
            return f"IDA has no type matching {q!r}"
        blocks = []
        for m in matches:
            lines = [m.get("name") or "?"]
            for mem in m.get("members") or []:
                off = mem.get("offset")
                where = f"+0x{off:02X}" if isinstance(off, int) else "     "
                lines.append(f"  {where}  {mem.get('name') or '?':<24} {mem.get('type') or ''}".rstrip())
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks)
    if action == "globals":
        items = payload.get("items") or []
        lines = [f"named data matching {payload.get('filter')!r} ({len(items)}):"]
        lines += [f"  0x{x['ea']:08X}  {x.get('type') or '(no type)':<32} {x.get('name')}" for x in items]
        return "\n".join(lines)
    if action == "strings":
        items = payload.get("items") or []
        lines = [f"strings matching {payload.get('filter')!r} ({len(items)}):"]
        lines += [f"  0x{x['ea']:08X}  {json.dumps(x.get('value', ''))}" for x in items]
        return "\n".join(lines)
    if action == "segments":
        segs = payload.get("segments") or []
        lines = [f"segments ({len(segs)}):"]
        lines += [f"  0x{s['start']:08X}-0x{s['end']:08X}  {s.get('perm', '---')}  {s.get('class') or '':<12} {s.get('name')}" for s in segs]
        return "\n".join(lines)
    return json.dumps(payload)[:4000]
