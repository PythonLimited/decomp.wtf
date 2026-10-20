"""Reconstruct matched native functions into a source tree.

Every function in the tree was proven byte-identical by the judge once; this exporter keeps that
proof as the acceptance test. The agents' per-function scaffolding (hand-declared classes, their
own headers, namespace wrappers) is stripped off with signature-anchored extraction, the class
definitions come from the binary's own debug info (analysis["types"] — layouts, member-function
inventory, static/const/virtual), and every function is recompiled against the reconstructed
headers and re-judged byte-for-byte before it is written. A function that doesn't re-verify keeps
its place in the report instead of the tree — consolidation never breaks a match, and never
pretends: nothing is trusted that the same judge didn't just confirm.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

from . import interfaces
from . import registry

_LIFETIME = re.compile(r"^(?:_GLOBAL__sub_[ID]|__static_initialization_and_destruction_0)")
_HEADER_EXT = (".h", ".hpp", ".hh", ".hxx", ".h++")


class ExportError(RuntimeError):
    pass


# ---------------------------------------------------------------- text surgery

def _scan(text: str, i: int, opener: str, closer: str) -> int | None:
    """Index of the closer matching text[i] (== opener), skipping strings, chars and comments."""
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            q, i = c, i + 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    break
                i += 1
        elif c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _split_display(display: str) -> tuple[str, str] | None:
    """('ACME::Aurora::Core::DoubleLink', 'pushFront') from the demangled spelling (which may carry a
    trailing `@file.cpp` and a parameter list; `operator()` keeps its parentheses)."""
    d = re.split(r"@\S+$", (display or "").strip())[0].strip()
    if d.endswith(")"):
        depth = 0
        for i in range(len(d) - 1, -1, -1):
            if d[i] == ")":
                depth += 1
            elif d[i] == "(":
                depth -= 1
                if depth == 0:
                    d = d[:i].strip()
                    break
    if not d:
        return None
    if "::" not in d:
        return ("", d)
    qual, tail = d.rsplit("::", 1)
    return (qual.strip(), tail.strip())


def extract_definitions(source: str, display: str) -> list[dict]:
    """Candidate definitions of `display` inside a matched source: [{"text", "tail_at"}].

    The definition is found by signature anchor (the function's tail name + a parenthesized list
    followed by `{`) and its body by brace balance; everything the agent wrote around it — the
    hand-declared classes, the includes, the namespace blocks — is simply not returned. Lifecycle
    functions (`_GLOBAL__sub_I_*` and friends) have no callable signature: their file-level source
    *is* the scaffolding a translation unit needs, so it is returned whole (tail_at -1)."""
    parsed = _split_display(display)
    if parsed is None:
        return []
    _qual, tail = parsed
    if _LIFETIME.match(tail):
        return [{"text": source.strip(), "tail_at": -1}]
    out, seen = [], set()
    for m in reversed(list(re.finditer(rf"(?<![\w]){re.escape(tail)}\s*\(", source))):
        close = _scan(source, m.end() - 1, "(", ")")
        if close is None:
            continue
        j, brace = close + 1, None
        while j < len(source):
            c = source[j]
            if c == "(":  # constructor init lists hold calls like `head_()`
                j2 = _scan(source, j, "(", ")")
                if j2 is None:
                    break
                j = j2
            elif c == "{":
                brace = j
                break
            elif c == ";":
                break
            j += 1
        if brace is None:
            continue
        end = _scan(source, brace, "{", "}")
        if end is None:
            continue
        start = m.start()
        while start > 0 and source[start - 1] not in "{};#":
            start -= 1
        raw = source[start:end + 1]
        lead = len(raw) - len(raw.lstrip())
        text = raw.strip()
        if text and text not in seen:
            seen.add(text)
            out.append({"text": text, "tail_at": m.start() - start - lead})
    return out


def _type_index(analysis: dict) -> dict[str, dict]:
    return {"::".join([*(t.get("ns") or []), t["name"]]): t for t in analysis.get("types") or []}


def _wrap(text: str, ns: list[str]) -> str:
    if not ns:
        return text
    return " ".join(f"namespace {p} {{" for p in ns) + "\n" + text + "\n" + "}" * len(ns)


def _place(cand: dict, display: str, analysis: dict, prefix: str = "") -> str:
    """A top-level-compilable definition: qualify it with its class when the text is relative, and
    wrap the namespaces it belongs to."""
    text, tail_at = cand["text"], cand["tail_at"]
    if tail_at < 0:
        return text
    parsed = _split_display(display)
    qual = parsed[0] if parsed else ""
    t = _type_index(analysis).get(qual)
    if t is not None:
        ns = t.get("ns") or []
        sig = text[:tail_at]
        if f"{qual}::" in sig:
            return prefix + text
        if "::" in sig:  # relative qualification (`DoubleLink::push`): needs its namespaces
            return _wrap(prefix + text, ns)
        # written in-class style: give it the class qualification
        return prefix + text[:tail_at] + qual + "::" + text[tail_at:]
    if qual:
        return _wrap(prefix + text, qual.split("::"))
    return prefix + text


# ---------------------------------------------------------------- renaming onto the canonical layout

_SIZES = {"char": 1, "bool": 1, "signed char": 1, "unsigned char": 1, "int8_t": 1, "uint8_t": 1,
          "short": 2, "unsigned short": 2, "int16_t": 2, "uint16_t": 2,
          "int": 4, "unsigned int": 4, "float": 4, "int32_t": 4, "uint32_t": 4, "wchar_t": 4,
          "long": 8, "unsigned long": 8, "long long": 8, "unsigned long long": 8, "double": 8,
          "int64_t": 8, "uint64_t": 8, "size_t": 8, "ssize_t": 8, "ptrdiff_t": 8}
_MEMBER_LINE = re.compile(r"^\s*(.+?)[\s*&]+([A-Za-z_]\w*)\s*(\[\d+\])?\s*;\s*(?://.*)?$")


def _sizeof(t: str, ptr: int) -> int | None:
    t = " ".join((t or "").split()).replace(" *", "*").replace(" &", "&")
    if not t:
        return None
    if t.endswith("*") or t.endswith("&"):
        return ptr
    m = re.match(r"^(.*)\[(\d+)\]$", t)
    if m:
        inner = _sizeof(m.group(1), ptr)
        return inner * int(m.group(2)) if inner else None
    t = t.replace("const ", "").replace("volatile ", "").strip()
    return _SIZES.get(t)


def _agent_layout(source: str, cls_name: str, ptr: int, sizes: dict[str, int]) -> list[tuple[str, int, int]] | None:
    """[(member, offset, size)] from the agent's own `class NAME { ... }` declaration, None when a
    member size isn't computable (primitives from the table, classes from the debug info). A
    `virtual` anywhere in the body means the compiler put a vptr at offset 0 — counted here so the
    offsets line up with the canonical layout."""
    for m in re.finditer(rf"\b(?:class|struct)\s+{re.escape(cls_name)}\s*(?::[^;{{]*)?\{{", source):
        end = _scan(source, m.end() - 1, "{", "}")
        if end is None:
            continue
        body = source[m.end():end]
        off = ptr if "virtual" in body else 0
        members: list[tuple[str, int, int]] = []
        for line in body.splitlines():
            mm = _MEMBER_LINE.match(line.strip())
            if not mm:
                continue
            head = line.strip()[:mm.start(2)]  # type text up to the member name, separator included
            mtype = mm.group(1).strip() + (" *" if ("*" in head or "&" in head) else "")
            if "(" in line.strip() or mtype.startswith(("static", "virtual", "typedef", "using")):
                continue  # methods, ctors, statics: no data offset to track
            size = _sizeof(mtype + (mm.group(3) or ""), ptr)
            if size is None:
                size = sizes.get(mtype)  # another class: its DWARF size decides where the next member sits
            if size is None:
                return None
            align = min(size, 8)
            off = (off + align - 1) // align * align
            members.append((mm.group(2), off, size))
            off += size
        return members
    return None


def _renamed(text: str, source: str, analysis: dict, ptr: int) -> str | None:
    """The same definition with the agent's invented member names mapped onto the canonical DWARF
    names at the same offset *and* size. Only exact matches rename; the judge decides if it holds."""
    by_bare: dict[str, list[dict]] = {}
    sizes: dict[str, int] = {}
    for t in analysis.get("types") or []:
        by_bare.setdefault(t["name"], []).append(t)
        if t.get("size") and t["name"] not in sizes:
            sizes[t["name"]] = int(t["size"])
    owners = set()
    for m in re.finditer(r"\b(?:class|struct)\s+([A-Za-z_]\w*)", source):
        owners.add(m.group(1))  # every class the source declares: the renamed members may belong
        #                          to one the definition itself never names (`pop` touches next_)
    renames: dict[str, str] = {}
    for owner in owners:
        ts = by_bare.get(owner)
        if not ts or len(ts) != 1:
            continue
        t = ts[0]
        agent = _agent_layout(source, owner, ptr, sizes)
        if not agent:
            continue
        members = t.get("members") or []
        canon: dict[int, tuple[str, int]] = {}
        for i, mm in enumerate(members):
            off = int(mm.get("off") or 0)
            nxt = int(members[i + 1]["off"]) if i + 1 < len(members) else int(t.get("size") or 0)
            canon[off] = ((mm.get("name") or ""), nxt - off)
        for name, off, size in agent:
            tgt = canon.get(off)
            if tgt is None or not re.match(r"^[A-Za-z_]\w*$", name):
                continue
            tname, tsize = tgt
            if tname == name or tname.startswith("_vptr") or not re.match(r"^[A-Za-z_]\w*$", tname):
                continue
            if tsize != size:
                continue
            renames[name] = tname
    if not renames:
        return None
    out = text
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        out = re.sub(rf"\b{re.escape(old)}\b", new, out)
    return out if out != text else None


def _salvage_entries(types_view: list[dict], texts: list[str], sources: list[str],
                     declared: set[str] | None = None) -> dict[str, dict]:
    """{key: entry} for classes the texts reference but the types view doesn't describe (static
    members of pruned classes, like TraceLogDefault): the most common spelling the matched sources
    themselves used, carried as verbatim `decl` text. A proposal — the re-judge gate decides.
    Names the base header already declares are left alone (no duplicate declarations)."""
    known_bare = {t.get("name") for t in types_view} | (declared or set())
    refs: dict[str, list[str]] = {}
    for text in texts:
        for m in re.finditer(r"(?<![\w:])((?:[A-Za-z_]\w*::)+)([A-Za-z_]\w*)\b(?!\s*\()", text):
            path, member = m.group(1).rstrip(":"), m.group(2)
            cls = path.rsplit("::", 1)[-1]
            if cls in known_bare or member.startswith(("operator", "~")) or member == cls:
                continue
            refs.setdefault(cls, path.rsplit("::", 1)[0].split("::") if "::" in path else [])
    out: dict[str, dict] = {}
    for cls, ns in sorted(refs.items()):
        seen: dict[str, int] = {}
        for src in sources:
            for m in re.finditer(rf"\b(?:class|struct)\s+{re.escape(cls)}\s*(?::[^;{{]*)?\{{", src):
                end = _scan(src, m.end() - 1, "{", "}")
                if end is None:
                    continue
                decl = src[m.start():end + 1].strip().rstrip(";") + ";"
                seen[decl] = seen.get(decl, 0) + 1
        if not seen:
            continue
        out["::".join([*ns, cls])] = {
            "name": cls, "ns": ns, "kind": "struct", "origin": "salvage",
            "decl": max(seen.items(), key=lambda kv: kv[1])[0]}
    return out


def _salvage_declarations(types_view: list[dict], texts: list[str], sources: list[str],
                          declared: set[str] | None = None) -> str:
    """The salvaged entries rendered as header text (the export's own copy of the proposal)."""
    entries = _salvage_entries(types_view, texts, sources, declared=declared)
    if not entries:
        return ""
    return ("/* referenced by the code, absent from the debug info: these spellings come from the\n"
            " * matched sources themselves and were re-judged like everything else */\n"
            + "\n\n".join(_wrap(t["decl"], t.get("ns") or []) for t in entries.values()))


# ---------------------------------------------------------------- verification

def _verify(engine, proj, fn, header: str, source: str) -> tuple[bool, str]:
    """Recompile one function against a reconstructed header and re-judge it — the same judge that
    accepted it in the first place. Returns (verdict, why-not)."""
    res = engine.compile_fn(fn, proj, header, source, raw_header=True)  # the header is already final
    if not res.ok:
        why = " ".join((res.log or "the compiler refused it").strip().split())
        return False, "doesn't compile: " + why[:280]
    cand, verdict, problems = engine.evaluate(fn, proj, res.obj)
    if cand is None:
        return False, "compiled, but its symbol isn't in the object (a declaration's types must have changed)"
    if verdict is None:
        return False, "compiled, but couldn't be judged (no target view left)"
    if verdict:
        return True, ""
    detail = "; ".join(problems[:3]) if problems else "the bytes differ"
    return False, "no longer byte-identical: " + detail[:280]


def _verify_inline(engine, proj, fn, header: str, text: str) -> tuple[bool, str]:
    """Header functions ship as `inline` — that is how the original kept them. But an inline
    function nothing uses is not emitted at all, so when the symbol vanishes, the same body without
    the keyword still proves the bytes (the keyword does not change the generated code)."""
    good, why = _verify(engine, proj, fn, header, text)
    if not good and "symbol isn't in the object" in why and "inline " in text:
        good2, why2 = _verify(engine, proj, fn, header, text.replace("inline ", "", 1))
        if good2:
            return True, ""
        return False, why2
    return good, why


# ---------------------------------------------------------------- the tree

def _rel_units(rows) -> dict[str, str]:
    """unit path -> path in the tree (the units' common directory prefix is stripped)."""
    units = sorted({r["unit"] for r in rows if r["unit"] and "/" in r["unit"]})
    if not units:
        return {}
    parts = [Path(u).parts for u in units]
    common = []
    for i in range(min(len(p) for p in parts)):
        c = parts[0][i]
        if all(p[i] == c for p in parts):
            common.append(c)
        else:
            break
    return {u: Path(*Path(u).parts[len(common):]).as_posix() for u in units}


def _sanitize(name: str) -> str:
    return (re.sub(r"\W+", "_", name).strip("_") or "function")[:80]


def export_native(net, slug: str, out: Path, log=print) -> dict:
    """Build the tree in `out` from the project's matched functions; every function that ships was
    re-judged byte-identical against the reconstructed headers right here, right now."""
    engine = net.native
    proj = net._project(slug)
    cfg = net.cfg(proj)
    analysis = engine.analysis(proj)
    if not analysis:
        raise ExportError("no analysis yet — run Analyze on the project first")
    rows = net.store.all(
        "SELECT * FROM functions WHERE project_id=? AND status='matched' AND matched_source IS NOT NULL "
        "ORDER BY vram", proj["id"])
    if not rows:
        raise ExportError("nothing is matched yet — there is no verified source to export")
    ptr = 4 if str(analysis.get("arch") or "").lower() in ("i386", "x86", "arm") else 8
    rels = _rel_units(rows)

    groups: dict[str, dict] = {}
    rest_rows: list = []
    for r in rows:
        rel = rels.get(r["unit"])
        if rel is None:
            rest_rows.append(r)
            continue
        key = Path(rel).stem
        g = groups.setdefault(key, {"units": set(), "rows": []})
        g["units"].add(r["unit"])
        g["rows"].append(r)

    files: dict[str, str] = {}
    report = {"t": time.time(), "slug": slug, "binary": (cfg.get("binary") or {}).get("name"),
              "base_sha256": (cfg.get("binary") or {}).get("sha256"),
              "files": {}, "fallback": [], "functions": {"total": len(rows), "verified": 0, "raw": 0}}
    rest_units: set[str] = set()

    def _ship_raw(p: dict) -> None:
        row = p["row"]
        files[f"src/_rest/{_sanitize(row['name'])}.cpp"] = f'#include "_rest.h"\n\n{p["raw"]}\n'
        rest_units.add(row["unit"] or "")
        report["functions"]["raw"] += 1

    for key, g in sorted(groups.items()):
        units = sorted(g["units"])
        lang = "c++" if any((json.loads(r["meta"] or "{}").get("language") == "c++") for r in g["rows"]) else "c"
        # The context base is the *stored* header — the environment the project actually verified
        # against, agents' edit_context edits included — minus its generated types block, which is
        # rebuilt below from the closure. (A fresh regeneration used to drop those edits; the
        # TraceLogDefault declaration an agent had added to the header vanished with it.)
        units_set = net._unit_contexts(proj["id"])
        primary = next((u for u in units if Path(u).suffix.lower() not in _HEADER_EXT), units[0])
        stored = net._context(proj["id"], primary if primary in units_set else "")["header"]
        visible = interfaces.strip_types(stored).rstrip("\n")
        if not visible.strip():  # no stored header (never confirmed): regenerate it
            visible = "\n".join(interfaces.context_block(analysis, units, language=lang)).rstrip("\n")

        parsed: list[dict] = []
        closure: list[str] = []
        for r in g["rows"]:
            meta = json.loads(r["meta"] or "{}")
            display = meta.get("demangled") or r["name"]
            rel = rels[r["unit"]]
            inline = Path(rel).suffix.lower() in _HEADER_EXT
            cands = extract_definitions(r["matched_source"], display)
            whole = any(c["tail_at"] < 0 for c in cands)
            placed = [_place(c, display, analysis, prefix="inline " if inline else "")
                      for c in cands if c["tail_at"] >= 0]
            rename = None
            for c in cands:
                if c["tail_at"] >= 0:
                    # the prefix belongs inside the namespace wrap, on the definition itself
                    rename = _renamed(_place(c, display, analysis, prefix="inline " if inline else ""),
                                      r["matched_source"], analysis, ptr)
                    break
            parsed.append({"row": r, "display": display, "inline": inline, "rel": rel,
                           "placed": placed, "rename": rename, "whole": whole,
                           "raw": r["matched_source"].strip()})
            closure += placed or [r["matched_source"]]

        types_view = registry.view(analysis, registry.load(net, slug))  # agent contributions included
        type_part = interfaces.type_block(analysis, visible + "\n" + "\n".join(closure),
                                          types=types_view, full=True)
        salvage = _salvage_declarations(types_view, closure, [r["matched_source"] for r in rows],
                                        declared=registry.declared_names(visible))
        extra_part = "\n".join(x for x in (type_part, salvage) if x)
        base_text = visible + "\n\n" + extra_part + "\n" if extra_part else visible + "\n"
        context_only = visible + "\n"

        # 1. the header's own functions: verified against the base header, then inlined into it
        inline_texts: list[str] = []
        inline_seen: set[tuple] = set()
        for p in parsed:
            if not p["inline"]:
                continue
            attempts = ([] if p["whole"] else [(t, "definition") for t in p["placed"]]
                        + ([(p["rename"], "renamed")] if p["rename"] else []))
            ok, last = None, ""
            for text, _kind in attempts:
                good, why = _verify_inline(engine, proj, p["row"], base_text, text)
                if good:
                    ok = text
                    break
                last = why
            if ok is None:
                good, why = _verify(engine, proj, p["row"], context_only, p["raw"])
                if good:
                    _ship_raw(p)
                    continue
                last = why or last
                report["fallback"].append({"name": p["row"]["name"], "unit": p["row"]["unit"], "reason": last})
                continue
            # D0/D1 and friends are two symbols the one source definition produces: inline it once
            sig_key = _split_display(p["display"]) or (p["display"],)
            if sig_key not in inline_seen:
                inline_seen.add(sig_key)
                inline_texts.append(ok)
            report["functions"]["verified"] += 1

        full_text = visible
        if extra_part:
            full_text += "\n\n" + extra_part
        if inline_texts:
            full_text += "\n\n/* the original kept these definitions in this header */\n\n" + "\n\n".join(inline_texts)
        full_text += "\n"
        full_text = _with_providers(full_text)
        files[f"include/{key}.h"] = full_text
        report["files"][key] = {"header": f"include/{key}.h", "functions": len(g["rows"])}

        # 2. the file's own functions: verified against the header they now stand in
        bodies: list[str] = []
        cpp_rel = next((p["rel"] for p in parsed if not p["inline"]), None)
        for p in parsed:
            if p["inline"]:
                continue
            attempts = ([] if p["whole"] else [(t, "definition") for t in p["placed"]]
                        + ([(p["rename"], "renamed")] if p["rename"] else []))
            ok, last = None, ""
            for text, _kind in attempts:
                good, why = _verify(engine, proj, p["row"], full_text, text)
                if good:
                    ok = text
                    break
                last = why
            if ok is None:
                good, why = _verify(engine, proj, p["row"], context_only, p["raw"])
                if good:
                    _ship_raw(p)
                    continue
                last = why or last
                report["fallback"].append({"name": p["row"]["name"], "unit": p["row"]["unit"], "reason": last})
                continue
            bodies.append(f"// {p['display']}\n{ok}")
            report["functions"]["verified"] += 1
        if bodies and cpp_rel:
            files[cpp_rel] = f'#include "{key}.h"\n\n' + "\n\n".join(bodies) + "\n"

    # 3. functions whose unit has no file association at all (no debug info, stripped names)
    for r in rest_rows:
        rest_units.add(r["unit"] or "")
        good, why = _verify(engine, proj, r, "\n".join(interfaces.context_block(
            analysis, [r["unit"]] if r["unit"] else [], language="c++" if (json.loads(r["meta"] or "{}").get("language") == "c++") else "c")) + "\n",
            r["matched_source"].strip())
        if good:
            p = {"row": r, "raw": r["matched_source"].strip()}
            _ship_raw(p)
        else:
            report["fallback"].append({"name": r["name"], "unit": r["unit"], "reason": why})

    if rest_units:
        units = sorted(u for u in rest_units if u)
        lang = "c++" if any((json.loads(r["meta"] or "{}").get("language") == "c++") for r in rows
                            if r["unit"] in rest_units) else "c"
        files["include/_rest.h"] = (
            "/* kept-as-written sources: the declarations they call into */\n"
            + "\n".join(interfaces.context_block(analysis, units, language=lang)) + "\n")

    # 4. write the tree
    if out.exists():
        for child in out.iterdir():
            if child.name != ".git":
                shutil.rmtree(child) if child.is_dir() else child.unlink()
    out.mkdir(parents=True, exist_ok=True)
    for rel, text in sorted(files.items()):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    report["identical"] = not report["fallback"]
    _write_readme(out, proj, analysis, cfg, report)
    (out / "reconstruct.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    log(f"reconstructed {report['functions']['verified']} function(s) into {out} "
        f"({report['functions']['raw']} kept as written, {len(report['fallback'])} not re-verified)")
    return {"path": str(out), "identical": report["identical"], "matched": report["functions"]["verified"],
            "functions": report["functions"]["total"], "fallback": report["fallback"]}


def _with_providers(text: str) -> str:
    """Put the demand-driven std includes/forwards in front of an exported header.

    Export used to write the raw type block; a `std::vector` member then had no provider, or a
    minimal hand-written declaration came after its first use. The compile path already does
    this in `registry.header_for`; the exporter must produce the same text."""
    heads = registry.std_includes(text)
    forwards = interfaces.std_forwards(text)
    prelude = "\n".join([*heads, *forwards])
    return (prelude + "\n" + text) if prelude else text


def _write_readme(out: Path, proj, analysis: dict, cfg: dict, report: dict) -> None:
    binary = (cfg.get("binary") or {})
    types = len(analysis.get("types") or [])
    (out / "README.md").write_text(f"""# {proj['name']} — reconstructed source

{report['functions']['verified']} of {report['functions']['total']} matched functions were recompiled against
these headers and re-judged byte-identical to the original `{binary.get('name') or 'binary'}` before being
written; {report['functions']['raw']} are kept exactly as they were matched (their own declarations), and
{len(report['fallback'])} did not re-verify and live only in `reconstruct.json`.

## Layout

| Path | What it is |
| :-- | :-- |
| `include/<file>.h` | One header per original source file: what its functions call into, the class layouts from the binary's debug info ({types} types), and the inline definitions the original kept there. |
| `src/<file>.cpp` | The decompiled definitions, stripped of per-function scaffolding, standing on the reconstructed headers. |
| `src/_rest/` | Functions with no debug-info file association, or sources that were only valid with their own scaffolding: kept as written against `include/_rest.h`. |
| `reconstruct.json` | Per-function verdicts and the list of anything that didn't re-verify. |

## Why you can trust it

Every function here passed the same test that matched it: compiled with the original's flags and
byte-compared (including reference positions) against the original binary. Nothing was carried over on
the strength of a name or a guess.

The class layouts are the original's own debug info — member names, offsets and sizes, static/const/
virtual members. Where a function's body used invented member names, offsets and sizes were lined up
and the names rewritten; those functions carry the verification verdict of the rewritten form.

{proj['name']} and its code belong to their rights holder: keep this tree to yourself unless you have the
right to share it.
""", encoding="utf-8")
