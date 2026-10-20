"""Analysis: IDA's sweep + the DWARF picture, merged into what the plan works on.

`analyze` runs once per binary (cached; IDA is paid for once), names every function through
the ladder (DWARF → FLIRT/IDA → auto `sub_`), attributes functions to their original source
file, folds call edges to the file level, and records what each compile unit was built with
(producer strings) for compiler resolution.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path

from ..targets.plat.elf import dwarf as dwarf_mod
from . import graph
from ..backends.ida import sweep as ida_export
from ..backends.ida.session import sha256_file

MERGED_SCHEMA = 17  # 17: type rows carry bases, bitfields, alignment, class/struct hints and methods; 16: mangled linkage rides even without debug entries (the resolver's mangled spellings); 15: '?'-globals in the data sweep


def ida_source(root: Path, cfg: dict, log=None) -> Path:
    """The file IDA opens for this project: the configured .i64/.idb when it is there, else the
    binary itself (with a word when the configured database has gone missing)."""
    binary = Path(root) / cfg["binary"]["file"]
    db = (cfg.get("ida") or {}).get("database") or ""
    if not db:
        return binary
    path = Path(db).expanduser()
    if path.is_file():
        return path
    if log:
        log(f"IDA: the configured database {path.name} is gone; analyzing the binary instead")
    return binary


def db_stamp(root: Path, cfg: dict) -> str:
    """The current identity of the database this project analyzes ("" when it's just the binary):
    a merged analysis records the stamp it saw, so comparing the two says — with one stat —
    whether the database changed since (an agent's write-through, a human editing in IDA)."""
    if not (cfg.get("ida") or {}).get("database"):
        return ""
    source = ida_source(root, cfg)
    return "" if source == Path(root) / cfg["binary"]["file"] else ida_export.db_key(source)


# Names no human wrote: IDA's automatic naming (`sub_140001000`, `nullsub_5`, `loc_...`,
# `byte_...`) and thunk spellings like `.printf`.
_AUTO = re.compile(r"^(?:sub|nullsub|j_|loc|unk|unknown|byte|word|dword|qword|off|asc|str|flt|dbl|def|seg)_?[0-9A-Fa-f]*$"
                   r"|^\.\w+$")

# Compiler/library glue that lives inside the program's own compile units or the linker's
# bookkeeping: std/boost template instantiations, operator new/delete, static init and sanitizer
# hooks, thunk spellings, and — by the section they sit in — PLT stubs and CRT init/fini.
# None of it is the program's logic, so the plan confirms those functions as "library": shown,
# never claimable, never counted as work.
_THUNK = re.compile(r"^(?:non-virtual|virtual) thunk to'?")
_GLUE = re.compile(
    r"^(?:std|__gnu_cxx|boost|__cxxabiv1|__gnu_internal)::"
    r"|^operator (?:new|delete)"
    r"|^(?:__static_initialization_and_destruction|_GLOBAL__sub_|__cxx_global_var_init|__gthread_|"
    r"__cxa_|_Unwind_|__clang_|__asan_|__ubsan_|__msan_|__tsan_|__sanitizer_|__x86\.|_dl_)"
    r"|^(?:register_tm_clones|deregister_tm_clones|__do_global_dtors_aux|frame_dummy|_start|_init|_fini|"
    r"__libc_csu_init|__libc_csu_fini)$")
_GLUE_SECTIONS = re.compile(r"^\.plt|^\.got|^\.init|^\.fini")
_CRT_NAMES = re.compile(r"^(?:register_tm_clones|deregister_tm_clones|__do_global_dtors_aux|frame_dummy|_start|"
                        r"_init|_fini|__libc_csu_init|__libc_csu_fini)$")

# DWARF sometimes says it outright: the function's decl_file is a toolchain header
# (libstdc++/libc++/glibc include trees), not one of the program's files.
_BORROWED_FILE = ("/include/c++/", "/boost/", "libstdc++", "libc++", "sysdeps", "glibc", "musl", "\\include\\")


def is_auto_name(name: str) -> bool:
    return bool(_AUTO.match(name or ""))


def library_name(name: str) -> bool:
    """True for names no human wrote in this program: library templates, runtime hooks, CRT stubs.

    Thunk spellings come out of c++filt as `` `non-virtual thunk to'boost::… ``: strip the
    decoration, then judge the target."""
    name = (name or "").strip().lstrip("`")
    m = _THUNK.match(name)
    if m:
        name = name[m.end():].lstrip("'")
    return bool(_GLUE.match(name) or _CRT_NAMES.match(name))


def borrowed_file(path: str | None) -> bool:
    """DWARF's own answer, where it gives one: declared in a toolchain header."""
    return bool(path) and any(marker in path for marker in _BORROWED_FILE)


def glue_section(ea: int, sections) -> str:
    """Which piece of linker machinery this address is, by the section it sits in:
    "plt" trampoline, "crt" init/fini, "extern" import slot — else ""."""
    for s in sections or ():
        lo = s.get("vaddr") or 0
        if lo <= ea < lo + (s.get("size") or 0):
            name = s.get("name") or ""
            if not _GLUE_SECTIONS.match(name):
                continue
            if name.startswith(".plt"):
                return "plt"
            if name.startswith(".got"):
                return "extern"
            return "crt"
    return ""


def glue_class(ea: int, name: str, display: str, imports: set, sections) -> str:
    """The import machinery's kind, from the strongest signal: the section, IDA's import table,
    then the CRT names. Empty for anything that might be the program's own code."""
    cls = glue_section(ea, sections)
    if cls:
        return cls
    if ea in imports:
        return "extern"
    if _CRT_NAMES.match((display or name or "").strip().lstrip("`")):
        return "crt"
    return ""


def seeds(cfg: dict, functions: list[dict], data: bytes) -> dict | None:
    """PE seed inventory: `.pdata` function boundaries, imports, TLS and load-config hooks.

    MSVC emits a `.pdata` entry per function and per EH funclet, and ICF folds identical
    bodies, so a begin is `covered` (the sweep has a function there), `inside` (it lies in a
    known function) or `missing`.  The tables are parsed in pure Python; non-PE targets have
    no seed inventory yet."""
    if cfg.get("format") != "pe":
        return None
    from ..targets.plat.pe import seeds as pe_seeds

    info = pe_seeds.parse(data)
    if info is None:
        return None
    eas = {f["ea"] for f in functions}
    ranges = sorted((f["ea"], f["end"]) for f in functions)
    starts = [r[0] for r in ranges]
    covered = inside = 0
    missing: list[int] = []
    for begin, _end, _unwind in info["pdata"]:
        if begin in eas:
            covered += 1
            continue
        i = bisect.bisect_right(starts, begin) - 1
        if i >= 0 and begin < ranges[i][1]:
            inside += 1  # a funclet or a folded chunk, not an independent function
        else:
            missing.append(begin)
    return {
        "pdata_count": len(info["pdata"]),
        "pdata_covered": covered,
        "pdata_inside": inside,
        "pdata_missing": missing[:4096],
        "import_dlls": info["import_dlls"],
        "imports": info["imports"],
        "delay_dlls": info["delay_dlls"],
        "exports": info["exports"],
        "tls_callbacks": info["tls_callbacks"],
        "cfg_check": info["cfg_check"],
        "security_cookie": info["security_cookie"],
    }


def compiler_groups(compile_units: list[dict], dwarf_functions: list[dict]) -> list[dict]:
    """Group compile units by (producer, flags), ranked by the number of functions they contribute —
    not by unit count. A big binary usually vendors more third-party C files than it has game C++
    translation units (MySQL alone can outnumber the game's merged units), so the unit-count winner
    is often the wrong default for the code the user actually decompiles."""
    counts = Counter(f.get("cu") for f in dwarf_functions if f.get("cu"))
    groups: dict[tuple, dict] = {}
    for cu in compile_units:
        if not cu.get("compiler"):
            continue
        key = (cu["compiler"], tuple(cu.get("flags") or ()))
        entry = groups.setdefault(key, {"compiler": cu["compiler"], "flags": list(cu.get("flags") or ()),
                                        "units": 0, "functions": 0, "example": cu.get("path")})
        entry["units"] += 1
        entry["functions"] += counts.get(cu.get("path"), 0)
    return sorted(groups.values(), key=lambda c: (-c["functions"], -c["units"], c["compiler"]))


def compile_unit_map(compile_units: list[dict]) -> dict[str, dict]:
    """CU path -> the producer/flags that built it. A function's line file can be a header; the CU
    is the only reliable key for "which compiler built this code"."""
    return {cu["path"]: {"compiler": cu["compiler"], "flags": list(cu.get("flags") or [])}
            for cu in compile_units if cu.get("path") and cu.get("compiler")}


def merge(ida_data: dict, dwarf_data: dict, cfg: dict) -> dict:
    """The merged analysis: functions with names/files/provenance/inline frames, edges, file graph."""
    d_funcs = [f for f in dwarf_data.get("functions", []) if f.get("kind") == "function"]
    by_low = {f["low"]: f for f in d_funcs}
    sections = (cfg.get("image") or {}).get("sections") or []
    imports = {im.get("ea") for im in ida_data.get("imports") or [] if im.get("ea") is not None}

    def dwarf_at(ea: int) -> dict | None:
        exact = by_low.get(ea)
        if exact is not None:
            return exact
        return next((f for f in d_funcs if f["low"] <= ea < f["end"]), None)

    functions: list[dict] = []
    for fn in ida_data.get("functions", []):
        ea, end = fn.get("ea"), fn.get("end")
        if ea is None or not end or end <= ea:
            continue  # no body (imports, gap entries)
        dfun = dwarf_at(ea)
        name = (dfun or {}).get("name") or fn.get("name") or ""
        demangled = fn.get("demangled") or ""
        provenance = ("dwarf" if (dfun or {}).get("name")
                      else "flirt" if fn.get("lib")
                      else "auto" if is_auto_name(fn.get("name") or "")
                      else "ida" if fn.get("name")
                      else "auto")
        # "Which file is this function part of?" — the line table's answer first: a template body
        # belongs to the header it was declared in (that is how IDA's tree reads too), not to
        # whichever .cpp's object emitted the copy; only then the compile unit.
        file = (dfun or {}).get("line_file") or (dfun or {}).get("cu") or fn.get("file") or None
        language = (dfun or {}).get("language")
        if not language:
            symbol = str((dfun or {}).get("linkage") or name or "")
            language = "c++" if symbol.startswith(("_Z", "?")) else "c"  # mangling is decisive
        demangled = fn.get("demangled") or ""
        display = demangled or name
        # not the program's logic, from the strongest signal available: IDA's own library match
        # (FLIRT), the import table it listed, the section (PLT/GOT/init/fini), the line
        # table / decl_file pointing into a toolchain header — and, where none of those speak,
        # the symbol name. `glue` keeps *which* machinery it is, for the one-switch control.
        borrowed = borrowed_file((dfun or {}).get("line_file") or (dfun or {}).get("decl_file"))
        glue = glue_class(ea, name, display, imports, sections)
        lib = bool(fn.get("lib")) or bool(glue) or borrowed or library_name(display)
        functions.append({
            "ea": ea, "end": end, "size": end - ea,
            # the disassembly spells functions mangled; keep that spelling as the linkage even when
            # no debug entry carries it (IDA's own name is the mangled one for MSVC targets, and an
            # agent copying it out of the listing could not resolve it back)
            "name": name,
            "linkage": (dfun or {}).get("linkage")
                       or (fn.get("name") if str(fn.get("name") or "").startswith(("_Z", "?")) else None),
            "demangled": demangled,
            "display": display, "file": file, "provenance": provenance,
            "cu": (dfun or {}).get("cu"),
            "language": language,
            "lib": lib, "glue": glue or None, "signature": fn.get("signature") or "",
            "line": (dfun or {}).get("decl_line") or fn.get("line"),
            "inline": (dfun or {}).get("inlines") or [],
        })
    merged_edges: dict[int, set[int]] = {}
    for e in ida_data.get("edges") or []:
        to = {t for t in (e.get("to") or []) if t and t != e.get("ea")}
        if to:
            merged_edges.setdefault(e["ea"], set()).update(to)
    edges = [{"ea": ea, "to": sorted(to)} for ea, to in sorted(merged_edges.items())]

    compilers_list = compiler_groups(dwarf_data.get("compile_units") or [], d_funcs)
    unit_compilers = compile_unit_map(dwarf_data.get("compile_units") or [])

    types = (dwarf_data.get("types")
             or [{**t, "origin": t.get("origin") or "ida"} for t in (ida_data.get("types") or [])])
    _attach_methods(types, functions)

    return {
        "schema": MERGED_SCHEMA,
        "format": cfg.get("format"), "arch": cfg.get("arch"),
        "generated_at": time.time(),
        "functions": functions, "edges": edges,
        "graph": graph.build(functions, edges),
        "compilers": compilers_list,
        "unit_compilers": unit_compilers,
        "types": types,
        "dwarf_units": len(dwarf_data.get("compile_units") or []),
        "imports": ida_data.get("imports") or [], "exports": ida_data.get("exports") or [],
        "strings": ida_data.get("strings") or [],
        "data": (ida_data.get("data") or [])[:400000],
        "ida": ida_data.get("ida") or {},
    }


def _top_level_parts(text: str, sep: str) -> list[str]:
    """Split on `sep` only outside `<...>`, `(...)` and `[...]`."""
    parts: list[str] = []
    start = angle = paren = bracket = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif angle == 0 and paren == 0 and bracket == 0 and text.startswith(sep, i):
            parts.append(text[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _method_from_display(display: str, signature: str) -> tuple[str, dict] | None:
    """(class path, method dict) from IDA's demangled function name and raw signature."""
    display = (display or "").strip()
    if "::" not in display or not display.endswith(")"):
        return None
    depth = 0
    open_paren = -1
    for i in range(len(display) - 1, -1, -1):
        if display[i] == ")":
            depth += 1
        elif display[i] == "(":
            depth -= 1
            if depth == 0:
                open_paren = i
                break
    if open_paren <= 0:
        return None
    head = display[:open_paren].strip()
    params_text = display[open_paren + 1:-1].strip()
    parts = _top_level_parts(head, "::")
    if len(parts) < 2:
        return None
    class_path, name = "::".join(parts[:-1]).strip(), parts[-1].strip()
    if not class_path or not name:
        return None
    params = [p.strip() for p in _top_level_parts(params_text, ",") if p.strip()]
    if params == ["void"]:
        params = []
    variadic = any(p == "..." for p in params)
    if variadic:
        params = [p for p in params if p != "..."]
    ctor = name == class_path.rsplit("::", 1)[-1]
    dtor = name.startswith("~")
    ret = ""
    if signature and "(" in signature:
        ret = signature[:signature.find("(")].strip()
        ret = re.sub(r"\b(?:__fastcall|__stdcall|__cdecl|__thiscall|__vectorcall|__clrcall)\b", "", ret).strip()
    if ctor or dtor:
        ret = ""
    static = bool(signature) and not re.search(r"\bthis\b", signature)
    const = bool(re.search(r"\)\s*const\b", signature))
    return class_path, {"name": name, "params": params, "ret": ret,
                        "static": static, "const": const, "variadic": variadic,
                        "virtual": False}


def _this_type(signature: str) -> str | None:
    """The type of an IDA signature's explicit `this` (None for a static/free function)."""
    m = re.search(r"([A-Za-z_][\w:<> ,*&]*?)\s*\*\s*(?:const\s+)?this\b", signature or "")
    if not m:
        return None
    t = re.sub(r"^(?:const\s+)?(?:class|struct)\s+", "", m.group(1).strip()).strip()
    return " ".join(t.split()) or None


def _attach_methods(types: list[dict], functions: list[dict]) -> None:
    """Fill each type's `methods` from the class-qualified signatures already in the sweep.

    A PDB often lists data members but not member functions.  The function table does carry
    them (`Class::Method(...)`); this makes the rendered class declare the methods its own
    source calls, without a manual `add_method` per function.
    """
    by_key = {"::".join([*(t.get("ns") or []), t.get("name") or ""]): t for t in types
              if t.get("name")}
    for fn in functions:
        if fn.get("language") != "c++":
            continue
        parsed = _method_from_display(fn.get("display") or "", fn.get("signature") or "")
        if parsed is None:
            continue
        class_path, method = parsed
        this_type = _this_type(fn.get("signature") or "")
        if this_type:
            class_leaf = _top_level_parts(class_path, "::")[-1].strip()
            this_leaf = _top_level_parts(this_type, "::")[-1].strip()
            # IDA sometimes attributes a method to the wrong class in the demangled display
            # (a TrophyContextHandle method showed up as DynamicArray<String,2,16>::data).
            # Compare the template head only: the same method's signature may spell the
            # specialization as 156,16 while the display says 2,16 (an IDA type artifact).
            if (this_type != class_path
                    and this_leaf.split("<", 1)[0] != class_leaf.split("<", 1)[0]):
                continue
        t = by_key.get(class_path)
        if t is None:
            continue
        base = _top_level_parts(class_path, "::")[-1].strip()
        if "<" in base:
            # Inside a class template, constructors/destructors use the injected class name
            # without the template arguments.
            head = base.split("<", 1)[0]
            if method["name"] == base:
                method["name"] = head
            elif method["name"] == "~" + base:
                method["name"] = "~" + head
        methods = t.setdefault("methods", [])
        key = (method["name"], tuple(method["params"]), method["static"], method["const"])
        if any((m.get("name"), tuple(m.get("params") or []), bool(m.get("static")),
                bool(m.get("const"))) == key for m in methods):
            continue
        methods.append(method)


def _type_delta(old: dict, new: dict) -> dict[str, int]:
    """How many types the database refresh added, removed or changed (keyed by name+namespace,
    compared by content so an edit of one member counts once)."""
    def keyed(analysis: dict) -> dict[str, str]:
        out: dict[str, str] = {}
        for t in analysis.get("types") or []:
            key = "::".join([*(t.get("ns") or []), t.get("name") or ""])
            try:
                blob = json.dumps({k: v for k, v in t.items() if k != "origin"}, sort_keys=True)
            except (TypeError, ValueError):
                continue
            out[key] = hashlib.sha1(blob.encode()).hexdigest()
        return out
    a, b = keyed(old), keyed(new)
    return {"added": sum(1 for k in b if k not in a),
            "removed": sum(1 for k in a if k not in b),
            "changed": sum(1 for k in b if k in a and a[k] != b[k])}


def _covered(entry: dict, by: dict) -> bool:
    """Whether the base entry carries everything this override had — then the override's content
    is redundant and whatever the base (the database) says on top becomes visible."""
    def plain(t: dict) -> dict:
        return {k: v for k, v in (t or {}).items() if k not in ("origin", "key", "updated")}
    a, b = plain(entry), plain(by)
    for field in ("name", "ns", "kind"):
        if (a.get(field) or None) != (b.get(field) or None):
            return False
    if a.get("size") is not None and b.get("size") is not None and int(b["size"]) < int(a["size"]):
        return False

    def elems(seq) -> set[str]:
        return {json.dumps(e, sort_keys=True) for e in seq or []}
    return all(elems(a.get(field)) <= elems(b.get(field)) for field in ("members", "statics", "methods"))


def _prune_covered_overrides(net, slug: str, overrides: dict, analysis: dict) -> int:
    """Overrides whose content the refreshed base carries in full are dropped: the database is the
    authority, and a human's edit to a type agents had written through would otherwise stay
    invisible under a redundant override (agent edit -> .i64, human extends it there, sync).
    A note in a covered override survives as a note-only carrier layered over the base."""
    from . import registry as registry_mod
    base: dict[str, dict] = {}
    for t in analysis.get("types") or []:
        base.setdefault("::".join([*(t.get("ns") or []), t.get("name") or ""]), t)
    dropped = 0
    for key in list((overrides.get("types") or {}).keys()):
        entry = overrides["types"][key]
        cover = base.get(key)
        if cover is None or not _covered(entry, cover):
            continue
        note = (entry.get("note") or "").strip()
        if note:  # the note lives nowhere else: carry it over the base's content
            overrides["types"][key] = {"note": note, "origin": "agent", "updated": time.time()}
        else:
            overrides["types"].pop(key)
        dropped += 1
    if dropped:
        registry_mod.save(net, slug, overrides)
    return dropped


def _adopt(net, proj, old: dict, new: dict, log=print) -> dict:
    """A re-analysis over a changed database: carry the differences into what dcore holds —
    renamed functions into the rows, the stored headers and the sources; changed types into the
    stored unit headers — and re-check the matches the new environment can break. Best effort:
    the merged analysis is already written; this keeps the rest of the caches in line with it."""
    from . import interfaces
    from . import registry as registry_mod

    slug = proj["slug"]
    stats = {"names": 0, "rows": 0, "headers": 0, "sources": 0, "units": 0, "pruned": 0,
             "types": {"added": 0, "removed": 0, "changed": 0}, "rechecked": 0, "reopened": []}

    words: dict[str, str] = {}
    old_by_ea = {f["ea"]: f for f in old.get("functions") or []}
    for f in new.get("functions") or []:
        prev = old_by_ea.get(f.get("ea"))
        if prev is None:
            continue
        for field in ("display", "name"):
            a, b = (prev.get(field) or "").strip(), (f.get(field) or "").strip()
            if a and b and a != b:
                words.setdefault(a, b)
    if words:
        from .network import apply_word_renames, rename_words
        pairs = rename_words(words)
        stats["names"] = len(pairs)
        with net.store.tx() as db:  # the rows' display names follow the database's
            for r in db.execute("SELECT id, name FROM functions WHERE project_id=?",
                                (proj["id"],)).fetchall():
                renamed = apply_word_renames(r["name"] or "", pairs)
                if renamed != (r["name"] or ""):
                    db.execute("UPDATE functions SET name=? WHERE id=?", (renamed, r["id"]))
                    stats["rows"] += 1
        text = net.adopt_renames(proj, words)
        stats["headers"] += text["headers"]
        stats["sources"] += text["sources"]

    stats["types"] = _type_delta(old, new)
    overrides = registry_mod.load(net, slug)
    stats["pruned"] = _prune_covered_overrides(net, slug, overrides, new)
    old_view, new_view = registry_mod.view(old, overrides), registry_mod.view(new, overrides)
    rows = net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched' "
                         "AND matched_source IS NOT NULL", proj["id"])
    units = net._unit_contexts(proj["id"])
    by_unit: dict[str, list] = {}
    for r in rows:
        by_unit.setdefault(net._effective_unit(r, units), []).append(r)

    # which stored headers has the new environment changed? — the same probe the edit gate
    # runs: the unit's context text and its matched sources rendered under both registries.
    # Rendering depends on the two type views alone, so equal views are a provable no-op — and
    # probing anyway burned hours on ORION (a regex per type per unit, tens of millions of them).
    touched: list[str] = []
    if old_view != new_view:
        for unit in sorted({""} | net._stored_units(proj["id"]) | set(by_unit)):
            lang = registry_mod.unit_language(new, unit, by_unit.get(unit) or [])
            text = "\n".join(interfaces.context_block(new, [unit], language=lang))
            text += "\n" + "\n".join((r["matched_source"] or "") for r in by_unit.get(unit) or [])
            before = interfaces.type_block(old, text, types=old_view, full=True)
            after = interfaces.type_block(new, text, types=new_view, full=True)
            if before != after:
                touched.append(unit)
    if touched:
        registry_mod._refresh(net, slug, proj, new, touched, by_unit, "database sync")
        stats["units"] = len(touched)
        affected = [r for u in touched for r in (by_unit.get(u) or [])]
        if affected:  # a database edit can invalidate a match: recompile and re-judge it
            def header_for(fn):
                return net._context(proj["id"], net._effective_unit(fn, units))["header"]
            broken = net.regression_test(proj, None, only=affected, header_for=header_for)
            stats["rechecked"] = len(affected)
            if broken:
                stats["reopened"] = [name for name, _ in broken]
                with net.store.tx() as db:
                    for name, _ in broken:
                        db.execute("UPDATE functions SET status='open' WHERE project_id=? AND name=? "
                                   "AND status='matched'", (proj["id"], name))

    t = stats["types"]
    if (stats["names"] or stats["units"] or stats["pruned"] or t["added"] or t["removed"] or t["changed"]
            or stats["reopened"]):
        line = (f"database sync: {stats['names']} name(s) adopted ({stats['rows']} row(s), "
                f"{stats['headers']} stored header(s), {stats['sources']} source(s)); types "
                f"+{t['added']}/-{t['removed']}/~{t['changed']}"
                + (f"; {stats['pruned']} override(s) the database now carries" if stats["pruned"] else "")
                + f"; {stats['units']} unit header(s) regenerated, {stats['rechecked']} match(es) re-checked"
                + (f", {len(stats['reopened'])} reopened" if stats["reopened"] else ""))
        log(line)
        with net.store.tx() as db:
            net._event(db, proj["id"], None, "analysis", line)
    return stats


def analyze(net, slug: str, *, force: bool = False, log=print) -> dict:
    """Run (or reuse) the analysis of a native project's binary; updates the project config.

    A merged result is only reused while the binary *and* the IDA database it was derived from
    are unchanged: a database edited since (an agent's write-through, a human in IDA) makes the
    analysis stale, and the re-run adopts the differences instead of silently serving them."""
    proj = net._project(slug)
    cfg = net.cfg(proj)
    root = Path(proj["root"])
    binary = root / cfg["binary"]["file"]
    cache_dir = root / ".decomp-wtf" / "native"
    merged_path = cache_dir / "analysis.json"
    sha = sha256_file(binary)
    previous = None
    if merged_path.exists():
        try:
            previous = json.loads(merged_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
    if (not force and previous is not None
            and previous.get("schema") == MERGED_SCHEMA and previous.get("sha256") == sha
            and (previous.get("ida") or {}).get("source_key", "") == db_stamp(root, cfg)):
        log("analysis: using the cached result")
        return previous
    source = ida_source(root, cfg, log=log)
    ida_data = ida_export.export_analysis(binary, cache_dir, db=source if source != binary else None,
                                          force=force, log=log)
    dwarf_data = dwarf_mod.analyze(binary) if cfg.get("format") == "elf" else {}
    merged = merge(ida_data, dwarf_data, cfg)
    seed_info = seeds(cfg, merged["functions"], binary.read_bytes())
    if seed_info:
        merged["seeds"] = seed_info
    merged["sha256"] = sha
    merged_path.write_text(json.dumps(merged), encoding="utf-8")
    if previous is not None and previous.get("sha256") == sha:
        # the same program, a different database: carry what the edits there imply into the
        # rows, the texts and the matches — best effort; the merged file is already written
        try:
            _adopt(net, proj, previous, merged, log=log)
        except Exception as exc:
            log(f"database sync: adoption failed: {exc}")
    engine = getattr(net, "native", None)  # caches built from the file we just replaced
    if engine is not None:
        engine._analysis.pop(proj["slug"], None)
        engine._recons.pop(proj["slug"], None)
        engine._adj_key = None

    def change(c):
        summary = {"file": str(merged_path.relative_to(root)), "generated_at": merged["generated_at"],
                   "functions": len(merged["functions"]), "files": len(merged["graph"]["files"]),
                   "edges": sum(len(e["to"]) for e in merged["edges"]),
                   "dwarf_units": merged["dwarf_units"], "compilers": merged["compilers"][:8],
                   "ida": bool(merged.get("ida")),
                   "source_key": (merged.get("ida") or {}).get("source_key", "")}
        if merged.get("seeds"):
            s = merged["seeds"]
            summary["seeds"] = {"pdata": s["pdata_count"], "pdata_covered": s["pdata_covered"],
                                "pdata_inside": s["pdata_inside"],
                                "pdata_missing": len(s["pdata_missing"]), "imports": s["imports"],
                                "import_dlls": s["import_dlls"], "delay_dlls": s["delay_dlls"],
                                "exports": s["exports"], "tls_callbacks": len(s["tls_callbacks"])}
        c["analysis"] = summary
        compiler = c.setdefault("compiler", {})
        if merged["compilers"] and not compiler.get("guess"):
            compiler["guess"] = merged["compilers"][0]["compiler"]
        compiler["flags"] = compiler.get("flags") or \
            (merged["compilers"][0]["flags"] if merged["compilers"] else [])
        if merged.get("unit_compilers"):
            # Per-CU defaults are only safe on a fresh project. A project with matches has flags
            # pinned by those matches; rewriting them here would invalidate work silently.
            has_matches = net.store.one(
                "SELECT 1 AS x FROM functions f JOIN projects p ON p.id=f.project_id "
                "WHERE p.slug=? AND f.status='matched' LIMIT 1", slug)
            if not has_matches:
                compiler["cu"] = merged["unit_compilers"]
    net._update_cfg(slug, change)
    note = f"{len(merged['functions'])} functions in {len(merged['graph']['files'])} files"
    if merged.get("seeds"):
        s = merged["seeds"]
        gaps = len(s["pdata_missing"])
        note += (f" · pdata {s['pdata_covered']}/{s['pdata_count']} exact, {s['pdata_inside']} funclets"
                 + (f", {gaps} gaps" if gaps else ""))
    with net.store.tx() as db:
        net._event(db, proj["id"], None, "analysis", note)
    line = (f"analysis: {len(merged['functions'])} functions, {len(merged['graph']['files'])} files, "
            f"{sum(len(e['to']) for e in merged['edges'])} call edges")
    if merged.get("seeds"):
        s = merged["seeds"]
        gaps = len(s["pdata_missing"])
        line += (f"; pdata {s['pdata_covered']}/{s['pdata_count']} exact, {s['pdata_inside']} funclets"
                 + (f", {gaps} gaps" if gaps else ""))
    log(line)
    return merged


def load(net, slug: str) -> dict | None:
    """The cached merged analysis, when it exists and matches the binary."""
    proj = net._project(slug)
    cfg = net.cfg(proj)
    path = Path(proj["root"]) / (cfg.get("analysis") or {}).get("file", ".decomp-wtf/native/analysis.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    binary = Path(proj["root"]) / cfg["binary"]["file"]
    if not binary.exists() or data.get("sha256") != sha256_file(binary):
        return None
    return data
