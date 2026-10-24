"""What DWARF in an ELF tells us that IDA alone doesn't expose well.

pyelftools (already a dependency) reads compile units: the original source file paths, the
producer string (compiler + often the flags each unit was built with), the functions a unit
defines with their exact ranges, and the DWARF inline trees that say which helper was
inlined where and from which source line. The plan's file tree is built from compile units,
the compiler-resolution step reads producer flags, and the per-function briefs show inline
frames so an agent knows what the original source looked like around a call.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

_REF_FORMS = {"DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4", "DW_FORM_ref8", "DW_FORM_ref_udata"}
_Flags = re.compile(r"(?:(?<=\s)|^)(-[\w=.,:/+-]+)")

# DW_AT_language values -> the language the CU is compiled as. The output language follows
# the original TU (a C++ method must be written as C++ so its symbol mangles the same way);
# unknown values fall back to the file extension.
_LANGUAGES = {0x0001: "c", 0x0002: "c", 0x000C: "c", 0x001D: "c", 0x002C: "c",
              0x0004: "c++", 0x0019: "c++", 0x001A: "c++", 0x0021: "c++", 0x002A: "c++", 0x002B: "c++",
              0x8001: "asm", 0x0031: "asm"}
_CXX_EXT = (".cc", ".cpp", ".cxx", ".cp", ".c++", ".C")


def _language(top, path: str) -> str:
    value = _attr(top, "DW_AT_language")
    if isinstance(value, int) and value in _LANGUAGES:
        return _LANGUAGES[value]
    if path.endswith(_CXX_EXT):
        return "c++"
    lower = path.lower()
    if lower.endswith((".s", ".asm")):
        return "asm"
    if lower.endswith(".c"):
        return "c"
    return ""


def _attr(die, key):
    a = die.attributes.get(key)
    return a.value if a is not None else None


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _range(die) -> tuple[int, int] | None:
    """(low, end) of a DIE with a low_pc, handling the two high_pc forms."""
    low = _attr(die, "DW_AT_low_pc")
    if low is None:
        return None
    high = die.attributes.get("DW_AT_high_pc")
    if high is None:
        return None
    if describe_form_class(high.form) == "address":
        end = high.value
    else:
        end = low + high.value
    return (low, end) if end > low else None


def _follow(dw, cu, die, limit: int = 8):
    """Resolve DW_AT_specification / DW_AT_abstract_origin chains (C++ declarations live apart)."""
    seen = set()
    while die is not None and id(die) not in seen and limit > 0:
        seen.add(id(die))
        limit -= 1
        ref = die.attributes.get("DW_AT_specification") or die.attributes.get("DW_AT_abstract_origin")
        if ref is None:
            return die
        offset = ref.value
        if ref.form in _REF_FORMS:
            offset += cu.cu_offset
        try:
            die = dw.get_DIE_from_refaddr(offset)
        except Exception:
            return None
    return None


def _names(dw, cu, die) -> tuple[str | None, str | None]:
    """(name, linkage name) of a DIE, following declaration/abstract-origin chains."""
    resolved = _follow(dw, cu, die)
    for node in (die, resolved):
        if node is None:
            continue
        name = _text(_attr(node, "DW_AT_name"))
        linkage = _text(_attr(node, "DW_AT_linkage_name") or _attr(node, "DW_AT_MIPS_linkage_name"))
        if name or linkage:
            return name, linkage
    return None, None


def _dirs(cu, dw):
    """The CU's line-program file table: index -> absolute path (index 0 is the CU itself)."""
    top = cu.get_top_DIE()
    cu_name = _text(_attr(top, "DW_AT_name")) or ""
    comp_dir = _text(_attr(top, "DW_AT_comp_dir")) or ""
    table: dict[int, str] = {}

    def absolute(name: str, base: str) -> str:
        if name.startswith("/") or (len(name) > 2 and name[1] == ":"):
            return name
        if base and not (base.startswith("/") or (len(base) > 2 and base[1] == ":")):
            base = str(Path(comp_dir) / base)  # directory tables are relative to the CU's directory
        return str(Path(base) / name) if base else name

    table[0] = absolute(cu_name, comp_dir)
    try:
        lp = dw.line_program_for_CU(cu)
    except Exception:
        return table
    header = lp.header if lp is not None else None
    if header is None:
        return table
    include = [_text(d) or "" for d in (header.get("include_directory") or [])]
    for index, entry in enumerate(header.get("file_entry") or [], start=1):
        name = _text(getattr(entry, "name", None)) or ""
        dir_index = getattr(entry, "dir_index", 0) or 0
        base = include[dir_index - 1] if 0 < dir_index <= len(include) else comp_dir
        table[index] = absolute(name, base)
    return table


def _line_rows(dw, cu) -> list[tuple[int, int]]:
    """(address, file index) transitions from the CU's line program. This is what associates a
    function with a file the way IDA's tree does: a template body is listed under its header,
    not under whichever .cpp happened to emit this copy."""
    try:
        lp = dw.line_program_for_CU(cu)
    except Exception:
        return []
    if lp is None:
        return []
    rows: list[tuple[int, int]] = []
    try:
        for entry in lp.get_entries():
            st = entry.state
            if st is None or st.end_sequence or st.address is None or st.file is None:
                continue
            rows.append((st.address, st.file))
    except Exception:
        return []
    rows.sort()
    return rows


def _types(dw, cu) -> list[dict]:
    """Structs and classes with their real member names, offsets and sizes — what agents otherwise
    re-derive from `[rdi+8]` per function (and drift apart on across files)."""
    out: list[dict] = []
    top = cu.get_top_DIE()

    def name_of(die) -> str:
        a = die.attributes.get("DW_AT_name")
        if a is None or a.value is None:
            return ""
        v = a.value
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)

    def type_ref(die):
        a = die.attributes.get("DW_AT_type")
        if a is None or a.value is None:
            return None
        try:
            return dw.get_DIE_from_refaddr(a.value + cu.cu_offset, cu)
        except Exception:
            return None

    def type_text(die, depth=0) -> str:
        t = type_ref(die)
        if t is None or depth > 3:
            return ""
        if t.tag == "DW_TAG_pointer_type":
            inner = type_text(t, depth + 1) or "void"
            return inner + "*" if inner.endswith("*") else inner + " *"
        if t.tag in ("DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            inner = type_text(t, depth + 1) or "int"
            sym = "&&" if t.tag == "DW_TAG_rvalue_reference_type" else "&"
            return inner + sym if inner.endswith(("*", "&")) else inner + f" {sym}"
        if t.tag == "DW_TAG_const_type":
            return "const " + (type_text(t, depth + 1) or "int")
        if t.tag == "DW_TAG_array_type":
            elem = type_text(t, depth + 1) or "unsigned char"
            n = 1
            for child in t.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    ub = child.attributes.get("DW_AT_upper_bound")
                    if ub is not None and ub.value is not None:
                        n = int(ub.value) + 1
            return f"{elem}[{n}]"
        if t.tag in ("DW_TAG_base_type", "DW_TAG_typedef", "DW_TAG_structure_type", "DW_TAG_class_type",
                     "DW_TAG_union_type", "DW_TAG_enumeration_type"):
            return name_of(t)
        if t.tag == "DW_TAG_subroutine_type":
            return "void *"
        return name_of(t) or ""

    def member_offset(m):
        loc = m.attributes.get("DW_AT_data_member_location")
        if loc is None or loc.value is None:
            return 0
        v = loc.value
        if isinstance(v, int):
            return v
        try:  # DWARF4+: a location expression, in practice DW_OP_plus_uconst
            b = bytes(v) if not isinstance(v, bytes) else v
            i = b.find(0x23)
            if i < 0:
                return 0
            val = shift = 0
            i += 1
            while i < len(b):
                val |= (b[i] & 0x7F) << shift
                shift += 7
                if not (b[i] & 0x80):
                    break
                i += 1
            return val
        except Exception:
            return 0

    def walk(die, ns):
        for child in die.iter_children():
            if child.tag == "DW_TAG_namespace":
                nm = name_of(child)
                walk(child, ns + [nm] if nm else ns)
                continue
            if child.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                nm = name_of(child)
                size_attr = child.attributes.get("DW_AT_byte_size")
                if nm and size_attr is not None and size_attr.value:
                    members = []
                    statics = []
                    methods = []
                    bases = []
                    for m in child.iter_children():
                        if m.tag == "DW_TAG_inheritance":
                            virt = _attr(m, "DW_AT_virtuality")
                            acc = _attr(m, "DW_AT_accessibility")
                            bases.append({
                                "type": type_text(m),
                                "virtual": bool(virt),
                                "access": (int(acc) if acc is not None else 1),
                            })
                            continue
                        if m.tag == "DW_TAG_subprogram":
                            mn = name_of(m)
                            if not mn:
                                continue
                            linkage = _text(_attr(m, "DW_AT_linkage_name") or _attr(m, "DW_AT_MIPS_linkage_name")) or ""
                            obj = m.attributes.get("DW_AT_object_pointer")
                            this_off = None
                            if obj is not None and obj.value is not None:
                                this_off = obj.value + (cu.cu_offset if obj.form in _REF_FORMS else 0)
                            const_this = False
                            if this_off is not None:
                                try:  # `this` is pointer to [const] Class: the const lives one hop in
                                    this_die = dw.get_DIE_from_refaddr(this_off, cu)
                                    pt = type_ref(this_die)
                                    inner = type_ref(pt) if pt is not None else None
                                    const_this = inner is not None and inner.tag == "DW_TAG_const_type"
                                except Exception:
                                    const_this = False
                            params = []
                            variadic = False
                            for p in m.iter_children():
                                if p.tag == "DW_TAG_unspecified_parameters":
                                    variadic = True
                                    continue
                                if p.tag != "DW_TAG_formal_parameter":
                                    continue
                                if this_off is not None and p.offset == this_off:
                                    continue  # the implicit this-pointer is not a written parameter
                                if p.attributes.get("DW_AT_artificial"):
                                    continue  # `this` on some compilers, __in_chrg on destructors
                                params.append(type_text(p))
                            virt = _attr(m, "DW_AT_virtuality")
                            acc = _attr(m, "DW_AT_accessibility")
                            methods.append({
                                "name": mn, "linkage": linkage,
                                "static": this_off is None,
                                "const": const_this or linkage.startswith("_ZNK"),
                                "virtual": bool(virt),  # 1 virtual, 2 pure
                                "access": (int(acc) if acc is not None else 1),
                                "ret": type_text(m) if m.attributes.get("DW_AT_type") else "",
                                "params": params,
                                "variadic": variadic,
                            })
                            continue
                        if m.tag != "DW_TAG_member":
                            continue
                        if m.attributes.get("DW_AT_artificial"):
                            continue  # the compiler's vptr/base bookkeeping, not source
                        if m.attributes.get("DW_AT_declaration"):
                            mn = name_of(m)
                            if mn:
                                # static data members: no offset, but their type is what a
                                # reconstructed class needs to declare them
                                statics.append({"name": mn, "type": type_text(m)})
                            continue
                        member = {"name": name_of(m), "off": member_offset(m),
                                  "type": type_text(m)}
                        if m.attributes.get("DW_AT_bit_size") is not None:
                            member["bit_size"] = int(m.attributes["DW_AT_bit_size"].value)
                        if m.attributes.get("DW_AT_bit_offset") is not None:
                            member["bit_offset"] = int(m.attributes["DW_AT_bit_offset"].value)
                        members.append(member)
                    members.sort(key=lambda x: x["off"])
                    align = _attr(child, "DW_AT_alignment")
                    out.append({"name": nm, "ns": list(ns), "size": int(size_attr.value),
                                "align": int(align) if align is not None else None,
                                "kind": "class" if child.tag == "DW_TAG_class_type" else "struct",
                                "bases": bases, "members": members, "statics": statics,
                                "methods": methods})
                walk(child, ns)  # nested classes keep their enclosing namespaces
                continue
            walk(child, ns)

    walk(top, [])
    return out


def _producer(text: str) -> tuple[str, list[str]]:
    """'GNU C17 12.2.0 -O2 -fPIC' -> ('GNU C17 12.2.0', ['-O2', '-fPIC'])."""
    text = (text or "").strip()
    if not text:
        return "", []
    flags = _Flags.findall(text)
    head = text
    for flag in flags:
        at = head.find(flag)
        if at > 0:
            head = head[:at]
            break
    compiler = " ".join(head.split())
    return compiler, flags


def analyze(path: str | Path) -> dict:
    """The DWARF picture of an ELF: compile units, functions with exact ranges, inline frames.

    Returns {"compile_units": [...], "functions": [...], "by_low": {addr: index}} where each
    function has name/linkage/range/cu plus its inline frames (which helper, from where).
    Returns empty collections when the file has no DWARF at all.
    """
    path = Path(path)
    out: dict = {"compile_units": [], "functions": [], "types": []}
    types_seen: dict[tuple[str, str], dict] = {}
    try:
        fh = open(path, "rb")
    except OSError:
        return out
    with fh:
        try:
            elf = ELFFile(fh)
            if not elf.has_dwarf_info():
                return out
            dw = elf.get_dwarf_info()
        except Exception:
            return out
        for cu in dw.iter_CUs():
            top = cu.get_top_DIE()
            producer = _text(_attr(top, "DW_AT_producer")) or ""
            compiler, flags = _producer(producer)
            files = _dirs(cu, dw)
            unit = {"path": files.get(0, ""), "files": sorted(set(files.values())),
                    "producer": producer, "compiler": compiler, "flags": flags,
                    "language": _language(top, files.get(0, "")), "cu_offset": cu.cu_offset}
            out["compile_units"].append(unit)
            for t in _types(dw, cu):
                key = ("::".join(t["ns"]), t["name"])
                prev = types_seen.get(key)
                if prev is None:
                    types_seen[key] = t
                    continue
                # the same class shows up in every CU that mentions it; keep the copy with the
                # most member detail and union in the methods the other copies knew about
                winner, loser = (t, prev) if len(t["members"]) > len(prev["members"]) else (prev, t)
                have = {(m.get("linkage") or m["name"]) for m in winner["methods"]}
                for m in loser["methods"]:
                    if (m.get("linkage") or m["name"]) not in have:
                        winner["methods"].append(m)
                if loser["statics"] and not winner["statics"]:
                    winner["statics"] = loser["statics"]
                types_seen[key] = winner
            subs: list[dict] = []
            inlines: list[dict] = []
            line_rows = _line_rows(dw, cu)
            line_addrs = [r[0] for r in line_rows]
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    span = _range(die)
                    if span is None:
                        continue  # a declaration or an abstract instance
                    name, linkage = _names(dw, cu, die)
                    decl = _attr(die, "DW_AT_decl_file")
                    i = bisect_right(line_addrs, span[0]) - 1
                    line_file = files.get(line_rows[i][1]) if i >= 0 else None
                    entry = {"name": name, "linkage": linkage, "low": span[0], "end": span[1],
                             "cu": unit["path"], "language": unit["language"],
                             "decl_file": files.get(decl) if decl is not None else None,
                             "line_file": line_file,
                             "decl_line": _attr(die, "DW_AT_decl_line"), "inlines": []}
                    subs.append(entry)
                elif die.tag == "DW_TAG_inlined_subroutine":
                    span = _range(die)
                    if span is None:
                        continue
                    name, linkage = _names(dw, cu, die)
                    call_file = _attr(die, "DW_AT_call_file")
                    inlines.append({"name": name, "linkage": linkage, "low": span[0], "end": span[1],
                                    "call_file": files.get(call_file) if call_file is not None else None,
                                    "call_line": _attr(die, "DW_AT_call_line")})
            # Nesting without depth attributes: an inline belongs to the subprogram whose
            # range contains it (innermost subprogram wins; nested inlines inherit it too).
            for inline in inlines:
                owner = None
                for sub in subs:
                    if sub["low"] <= inline["low"] < sub["end"]:
                        if owner is None or sub["low"] > owner["low"]:
                            owner = sub
                if owner is not None:
                    owner["inlines"].append(inline)
                    out["functions"].append({**inline, "cu": unit["path"], "kind": "inline",
                                             "enclosing": owner["name"] or owner.get("linkage")})
            for sub in subs:
                out["functions"].append({**sub, "kind": "function"})
    out["by_low"] = {f["low"]: i for i, f in enumerate(out["functions"]) if f["kind"] == "function"}
    out["types"] = list(types_seen.values())
    return out
