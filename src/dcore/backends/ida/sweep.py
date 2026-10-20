"""The IDAPython sweeps decomp.wtf runs through the IDA MCP bridge, and what their answers mean.

One sweep writes the whole analysis — functions with signatures, names and debug file/line,
call edges, imports, exports, strings — to a JSON file in the project's cache; later sweeps
fetch single functions' Hex-Rays pseudocode lazily, so opening a huge binary stays cheap
until agents actually work on a function.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import session as ida
from .session import IdaError

# The full sweep. Runs against the database opened by open_database: `db` is the ida-domain
# Database (the IDA MCP server's API), with classic IDAPython for what it doesn't cover.
_SWEEP = r'''
import json
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc

out_path = __OUT__
functions = []
callees = {}
for func in db.functions:
    ea = func.start_ea
    end = func.end_ea
    try:
        name = db.functions.get_name(func) or ""
    except Exception:
        name = ""
    signature = ""
    try:
        signature = db.functions.get_signature(func) or ""
    except Exception:
        pass
    demangled = ""
    try:
        demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)) or ""
    except Exception:
        pass
    lib = False
    try:
        lib = bool(idc.get_func_flags(ea) & ida_funcs.FUNC_LIB)
    except Exception:
        pass
    source, line = None, None
    try:
        source = idaapi.get_sourcefile(ea) or None
        value = idaapi.get_source_linnum(ea)
        line = None if value in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) else int(value)
    except Exception:
        pass
    cal = []
    try:
        cal = [f.start_ea for f in db.functions.get_callees(func)]
    except Exception:
        pass
    functions.append({"ea": ea, "end": end, "name": name, "signature": signature,
                      "demangled": demangled, "lib": lib, "file": source, "line": line})
    if cal:
        callees[ea] = cal

imports = []
try:
    for i in range(idaapi.get_import_module_qty()):
        module = idaapi.get_import_module_name(i) or ""
        def _collect(ea, name, ordinal, module=module):
            imports.append({"module": module, "name": name or ("#%d" % ordinal), "ea": ea})
            return True
        idaapi.enum_import_names(i, _collect)
except Exception:
    pass

exports = []
try:
    for index, ordinal, ea, name in idautils.Entries():
        exports.append({"name": name or ("#%d" % ordinal), "ea": ea})
except Exception:
    pass

strings = []
try:
    for s in idautils.Strings():
        if len(strings) >= 20000:
            break
        try:
            text = str(s)
        except Exception:
            continue
        if 0 < len(text) <= 400:
            strings.append({"ea": s.ea, "text": text})
except Exception:
    pass

# Named data (statics, globals): a function that reads one compiles a reference to its symbol,
# and an agent can't declare what it can't see. IDA carries the name and, usually, the type.
_AUTO_DATA = ("loc_", "sub_", "byte_", "word_", "dword_", "qword_", "unk_", "nullsub_", "j_",
              "jpt_", "off_", "flt_", "dbl_", "asc_", "str_", "stru_", "def_", "seg_", "algn_")
data = []
try:
    import ida_segment
    for ea, name in idautils.Names():
        if len(data) >= 400000:
            break
        if not name or name[0] in ".@" or name.startswith(_AUTO_DATA) \
                or name.startswith(("??_", "__real@", "__xmm@")):
            continue  # RTTI/vftable/float-constant decorations are auto; a single '?' may be a
            # real mangled global IDA couldn't demangle (an agent asking for s_memoryTagStack
            # saw `?enable_@DebugMemoryTag@…@@2_NA` in the disassembly: that name must survive)
        seg = ida_segment.getseg(ea)
        if seg is None or (seg.perm & 1):  # code segments are the functions' territory
            continue
        typ = ""
        try:
            typ = idc.get_type(ea) or ""
        except Exception:
            pass
        data.append({"ea": ea, "name": name, "type": typ})
except Exception:
    pass

# Unnamed data referenced by functions with debug info. IDA leaves file-scope statics
# (`counter`, `s_pInstance`) without a name even though code reads them; a rebuilt header
# names them, and the judge needs an address to point the agent at. The synthetic `data_<ea>`
# spelling makes the address visible/readable; `name_data` supplies the semantic name.
try:
    named_eas = {int(d["ea"]) for d in data}
    unnamed: dict[int, dict] = {}
    for func in db.functions:
        if len(unnamed) >= 400000:
            break
        try:
            if not idaapi.get_sourcefile(func.start_ea):
                continue
            for insn in db.instructions.get_between(func.start_ea, func.end_ea):
                for ea in db.xrefs.data_refs_from_ea(insn.ea):
                    if ea in unnamed or ea in named_eas:
                        continue
                    seg = ida_segment.getseg(ea)
                    if seg is None or (seg.perm & 1):  # code segments are the functions' territory
                        continue
                    if idc.get_name(ea):
                        continue
                    typ = ""
                    try:
                        typ = idc.get_type(ea) or ""
                    except Exception:
                        pass
                    unnamed[int(ea)] = {"ea": int(ea), "name": f"data_{int(ea):x}", "type": typ}
        except Exception:
            continue
    data.extend(unnamed.values())
except Exception:
    pass

# The database's types, in the shape dwarf.py emits (name/ns/size/kind/members with byte
# offsets) so agents and the registry treat both sources alike. Structs and unions only.
#
# Bounds matter here: a PDB-fused til can carry *millions* of named types (every typedef,
# template instantiation and pointer abbreviation), and enumeration is per-item calls over
# the bridge — unbounded it runs for tens of minutes. ORION's real numbers set the envelope
# (134s full sweep, 89,446 UDTs): the scan cap is the runaway bound, the output cap keeps
# any single analysis.json sane. The follow-up that makes both caps obsolete: select types
# by the names that actually appear in the function signatures this same sweep collects.
types = []
types_scanned = 0
try:
    import ida_typeinf
    import re

    # IDA's UDT flags don't distinguish `class` from `struct`, but MSVC's mangled names do:
    # a type used in a signature is preceded by V (class) or U (struct).  Collect hints from
    # the function names this sweep already has; an ambiguous or unseen leaf stays a struct
    # and can be edited in the registry.
    path_hints = {}
    template_hints = {}
    for fn in functions:
        mangled = fn.get("name") or ""
        for match in re.finditer(r"[VU]([A-Za-z_]\w*(?:@[A-Za-z_]\w*)+)", mangled):
            path_hints.setdefault(match.group(1), set()).add(match.group(0)[0])
        for match in re.finditer(r"[VU]\?\$([A-Za-z_]\w*)@", mangled):
            template_hints.setdefault(match.group(1), set()).add(match.group(0)[0])

    def _split_type_name(name):
        head = name.split("<", 1)[0]
        tail = name[len(head):]
        parts = [p for p in head.split("::") if p]
        if not parts:
            return [], name
        return parts[:-1], parts[-1] + tail

    for tif in db.types.get_all():
        types_scanned += 1
        if types_scanned > 2000000:
            break
        try:
            name = tif.get_type_name() or ""
            if not name or not tif.is_udt() or tif.is_decl_udt():
                continue
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                continue
            bases = []
            members = []
            methods = []
            vftable = False
            for m in udt:
                mname = (m.name or "").strip()
                printed = m.type._print() if m.type else ""
                if m.is_baseclass():
                    bases.append({"name": m.type.get_type_name() if m.type else "",
                                  "type": printed, "off": m.offset // 8,
                                  "virtual": bool(m.is_virtbase())})
                    continue
                if m.is_vftable():
                    vftable = True
                    continue
                if m.is_method():
                    methods.append({"name": mname, "type": printed})
                    continue
                if not mname and not m.is_anonymous_udm():
                    continue
                is_bit = bool(m.is_bitfield())
                base_type = printed.split(":", 1)[0].strip() if is_bit else printed
                members.append({"name": mname or "_anonymous",
                                "off": m.offset // 8,
                                "type": base_type,
                                "size": (m.size + 7) // 8 if m.size else 0,
                                "is_bitfield": is_bit,
                                "bit_start": m.offset if is_bit else None,
                                "bit_size": m.size if is_bit else None})
            ns, bare = _split_type_name(name)
            if "<" in bare:
                hint = template_hints.get(re.sub(r"<.*$", "", bare), set())
            else:
                path = "@".join([bare] + list(reversed(ns)))
                hint = path_hints.get(path, set())
            kind = "union" if tif.is_union() else ("class" if hint == {"V"} else "struct")
            types.append({"name": bare, "ns": ns, "size": tif.get_size(),
                          "align": tif.get_alignment(), "kind": kind,
                          "bases": bases, "vftable": vftable,
                          "members": members, "statics": [], "methods": methods})
        except Exception:
            continue
        if len(types) >= 100000:
            break
except Exception:
    pass

processor = ""
try:
    processor = idaapi.get_inf_attr(idaapi.INF_PROCNAME) or ""
except Exception:
    pass

payload = {"schema": __SCHEMA__, "processor": processor, "functions": functions,
           "edges": [{"ea": k, "to": v} for k, v in callees.items()],
           "imports": imports, "exports": exports, "strings": strings, "types": types,
           "data": data}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
print("DECOMPNET_EXPORT " + json.dumps({"path": out_path, "functions": len(functions),
                                        "imports": len(imports), "exports": len(exports),
                                        "strings": len(strings), "types": len(types),
                                        "types_scanned": types_scanned, "data": len(data),
                                        "processor": processor}))
'''

# Hex-Rays for specific functions, written to a file (pseudocode can be large, and stdout
# through MCP is not a good channel for it).
_PSEUDO = r'''
import json

eas = __EAS__
out_path = __OUT__
result = {}
for ea in eas:
    try:
        func = db.functions.get_at(ea)
        if func is None:
            for f in db.functions:
                if f.start_ea == ea:
                    func = f
                    break
        if func is None:
            result[str(ea)] = None
            continue
        result[str(ea)] = "\n".join(db.functions.get_pseudocode(func).to_text())
    except Exception as e:
        result[str(ea)] = None
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh)
print("DECOMPNET_PSEUDO " + json.dumps({"path": out_path, "functions": len(result)}))
'''


def _parse_marker(stdout: str, marker: str) -> dict | None:
    for line in reversed((stdout or "").splitlines()):
        if line.startswith(marker + " "):
            try:
                data = json.loads(line[len(marker) + 1:])
            except ValueError:
                return None
            return data if isinstance(data, dict) else None
    return None


SCHEMA = 9  # bump whenever the sweep's payload changes shape (3: types; 4: caps; 5: data names;
            # 6: the data cap 100k→400k — 84% of ORION's first 100k were auto 'a…' string names, so
            # the address-ordered cutoff dropped real statics; a cap change must bust the cache too;
            # 7: mangled '?'-globals ride — only RTTI/vftable/float-constant decorations are dropped;
            # 8: bases, bitfields, alignment, class-vs-struct hints, methods/vftable;
            # 9: unnamed data referenced by debug functions, as synthetic data_<ea> entries)


def _cached(cache: Path) -> dict | None:
    """The cached analysis, when it exists and was written by the current schema."""
    if not cache.exists():
        return None
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if data.get("schema") == SCHEMA else None


def db_key(db: Path) -> str:
    """The database's identity (path, size, mtime): a different or re-saved .i64 re-sweeps instead
    of serving a cache built from another layout."""
    try:
        st = Path(db).stat()
    except OSError:
        return "gone"
    return hashlib.sha1(f"{db}:{st.st_size}:{st.st_mtime_ns}".encode()).hexdigest()[:8]


def export_analysis(binary: Path, cache_dir: Path, *, db: Path | None = None,
                    force: bool = False, log=print) -> dict:
    """Analyse `binary` with IDA once, cache the result next to the project, and return it.

    The cache key is the binary's sha256, so re-imports, app restarts and repeated plan edits
    never pay IDA again; `force` re-runs the sweep (an IDA version change is a new cache dir).
    With `db`, the user's own IDA database is opened instead of the binary — no auto-analysis —
    and the cache key includes the database's identity, so switching databases re-sweeps.
    """
    binary, cache_dir = Path(binary), Path(cache_dir)
    source = Path(db) if db else binary
    key = ida.sha256_file(binary)[:16] + (f"-db{db_key(source)}" if db else "")
    cache = cache_dir / f"ida-{key}.json"
    cached = None if force else _cached(cache)
    if cached is not None:
        log(f"IDA: using the cached analysis ({cache.name})")
        if db is not None and not (cached.get("ida") or {}).get("source_key"):
            cached["ida"] = {**(cached.get("ida") or {}), "source": str(source), "source_key": db_key(source)}
            cache.write_text(json.dumps(cached), encoding="utf-8")
        return cached
    cache_dir.mkdir(parents=True, exist_ok=True)
    sweep = _SWEEP.replace("__OUT__", repr(str(cache))).replace("__SCHEMA__", str(SCHEMA))
    with ida.IdaSession(log=log) as session:
        info = ida.open_database(session, source, log=log)
        try:
            res = ida.execute_python(session, sweep, timeout=1800)
        finally:
            ida.close_database(session)
    summary = _parse_marker(res.get("stdout") or "", "DECOMPNET_EXPORT")
    if summary is None:
        tail = (res.get("stderr") or res.get("stdout") or "").strip()[-600:]
        raise IdaError("IDA's export sweep didn't finish: " + (tail or "no output"))
    # Opening a database bumps its mtime, so the cache lives under the state the next idle
    # lookup will see — the post-close stat — or no cache would ever be hit twice.
    source_key = db_key(source) if db else ""
    final_key = ida.sha256_file(binary)[:16] + (f"-db{source_key}" if db else "")
    if final_key != key:
        final = cache_dir / f"ida-{final_key}.json"
        if cache.exists():
            cache.replace(final)
        cache = final
    analysis = json.loads(cache.read_text(encoding="utf-8"))
    analysis["ida"] = {"backend": info.get("backend"), "generated_at": time.time(), "counts": summary,
                       "source": str(source), "source_key": source_key}
    cache.write_text(json.dumps(analysis), encoding="utf-8")
    log(f"IDA: {summary['functions']} functions, {summary['imports']} imports, "
        f"{summary['exports']} exports, {summary['strings']} strings, "
        f"{summary.get('types', 0)} types ({summary['processor']})")
    return analysis


def _pseudo_cache(cache_dir: Path, eas: list[int]) -> Path:
    key = hashlib.sha1(",".join(str(e) for e in sorted(eas)).encode()).hexdigest()[:12]
    return Path(cache_dir) / f"pseudo-{key}.json"


def pseudocode_cached(cache_dir: Path, eas: list[int]) -> dict[int, str | None] | None:
    """The cached pseudocode for these addresses, or None when it hasn't been fetched yet."""
    cache = _pseudo_cache(cache_dir, eas)
    if not cache.exists():
        return None
    try:
        return {int(k): v for k, v in json.loads(cache.read_text(encoding="utf-8")).items()}
    except (OSError, ValueError):
        return None


def pseudocode_batch(session: ida.IdaSession, cache_dir: Path, eas: list[int], *,
                     timeout: float = 300) -> dict[int, str | None]:
    """Hex-Rays for these addresses on an already-open database (cache first, then one sweep)."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = pseudocode_cached(cache_dir, eas)
    if cached is not None:
        return cached
    cache = _pseudo_cache(cache_dir, eas)
    code = _PSEUDO.replace("__EAS__", repr(sorted(eas))).replace("__OUT__", repr(str(cache)))
    res = ida.execute_python(session, code, timeout=timeout)
    if _parse_marker(res.get("stdout") or "", "DECOMPNET_PSEUDO") is None or not cache.exists():
        return {}
    return {int(k): v for k, v in json.loads(cache.read_text(encoding="utf-8")).items()}


def fetch_pseudocode(binary: Path, cache_dir: Path, eas: list[int], *, timeout: float = 900,
                     log=print) -> dict[int, str | None]:
    """Hex-Rays for these addresses, opening its own session (tests and one-off calls)."""
    cached = pseudocode_cached(cache_dir, eas)
    if cached is not None:
        return cached
    with ida.IdaSession(log=log) as session:
        ida.open_database(session, binary, log=log)
        try:
            return pseudocode_batch(session, cache_dir, eas, timeout=timeout)
        finally:
            ida.close_database(session)
