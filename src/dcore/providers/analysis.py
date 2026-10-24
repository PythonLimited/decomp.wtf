"""Convert the current merged analysis facts into the provider-neutral model.

The adapter is intentionally one-way and read-only: it does not touch the registry,
the database, the compiler or the judge. It turns the functions/types/data/edges that
IDA + DWARF already produce into ``Fact`` entities and typed ``Reference`` edges, so the
new model can be exercised against real analysis output before any provider is replaced.

Type spellings still come from the providers (DWARF/IDA), so they go through
``typeparse``; unparseable spellings stay ``Named``/``Opaque`` instead of being guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from ..model import (
    Access,
    Base,
    Evidence,
    Fact,
    FunctionDecl,
    FunctionType,
    GlobalDecl,
    Layout,
    Member,
    Method,
    Named,
    Opaque,
    Pointer,
    Reference,
    ReferenceType,
    Scope,
    TemplateInstance,
    TypeDecl,
    TypeRef,
)
from .typeparse import TypeSizes, parse_type, sizes_for

#: The binary analysis gives one observed layout; the environment resolver later maps it
#: to the exact toolchain. This sentinel keeps that observation without inventing an env id.
BINARY_LAYOUT = "@binary"

_CC = re.compile(r"\b(__cdecl|__stdcall|__fastcall|__thiscall|__vectorcall|__clrcall)\b", re.I)
_ACCESS = {1: "public", 2: "protected", 3: "private"}


@dataclass(frozen=True, slots=True)
class ProviderFacts:
    """Read-only facts extracted from one merged analysis."""

    facts: tuple[Fact, ...] = ()
    references: tuple[Reference, ...] = ()
    function_ids: Mapping[int, str] = field(default_factory=dict)
    type_ids: Mapping[str, str] = field(default_factory=dict)
    global_ids: Mapping[int, str] = field(default_factory=dict)

    def __iter__(self):
        return iter(self.facts)

    def __len__(self) -> int:
        return len(self.facts)


def _qualified(t: Mapping) -> str:
    return "::".join([*(t.get("ns") or []), str(t.get("name") or "")]).strip(":")


def _type_id(t: Mapping) -> str:
    return "t:" + _qualified(t)


def _function_id(fn: Mapping) -> str:
    ea = fn.get("ea")
    if ea is not None:
        return f"f:0x{int(ea):x}"
    return "f:" + str(fn.get("linkage") or fn.get("name") or "?")


def _global_id(d: Mapping) -> str:
    ea = d.get("ea")
    if ea is not None:
        return f"g:0x{int(ea):x}"
    return "g:" + str(d.get("name") or "?")


def _access(value) -> Access:
    if isinstance(value, str) and value in ("public", "protected", "private"):
        return value  # type: ignore[return-value]
    return _ACCESS.get(value, "public")  # type: ignore[return-value]


def _split_top_level(text: str, sep: str = ",") -> list[str]:
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
            parts.append(text[start:i].strip())
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(text[start:].strip())
    return [p for p in parts if p]


def _paren_text(text: str) -> str:
    """The inside of the final balanced parentheses, or ''."""

    text = (text or "").strip()
    if not text.endswith(")"):
        return ""
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return text[i + 1:-1].strip()
    return ""


def _signature(fn: Mapping, sizes: TypeSizes) -> FunctionType:
    raw = str(fn.get("signature") or "")
    display = str(fn.get("display") or fn.get("name") or "")
    params_text = _paren_text(display)
    if not params_text and raw:
        params_text = _paren_text(raw)
    params: list[TypeRef] = []
    variadic = False
    for part in _split_top_level(params_text):
        if part == "...":
            variadic = True
            continue
        if part == "void":
            continue
        part = part.split("=", 1)[0].strip()  # drop a default argument
        if part:
            params.append(parse_type(part, sizes))

    ret_text = raw.split("(", 1)[0].strip() if raw else ""
    cc = "cdecl"
    if m := _CC.search(ret_text):
        cc = m.group(1).lstrip("_").lower()
    ret_text = _CC.sub("", ret_text).strip()
    ret = parse_type(ret_text, sizes) if ret_text else parse_type("void", sizes)
    return FunctionType(ret=ret, params=tuple(params), cc=cc, variadic=variadic)


def _owner(fn: Mapping, type_ids: Mapping[str, str], scopes: "_Scopes") -> str | None:
    display = str(fn.get("display") or "")
    base = display.split("(", 1)[0].strip()
    if "::" not in base:
        return None
    owner = base.rsplit("::", 1)[0].strip()
    if owner in type_ids:
        return type_ids[owner]
    # A free function in a namespace has a namespace path, not a class owner.
    scopes.namespace(owner.split("::"))
    return None


class _Scopes:
    """Namespace scope tree; class scopes are their TypeDecls."""

    def __init__(self) -> None:
        self.facts: list[Fact] = []
        self.ids: dict[str, str] = {}

    def namespace(self, parts) -> str | None:
        parent: str | None = None
        path: list[str] = []
        for part in (p for p in parts if p):
            path.append(str(part))
            key = "::".join(path)
            if key not in self.ids:
                sid = "s:" + key
                self.ids[key] = sid
                self.facts.append(Fact(
                    entity=Scope(sid, "namespace", str(part), parent),
                    origin="analysis", confidence=1.0,
                    evidence=(Evidence("analysis", f"namespace {key}"),),
                ))
            parent = self.ids[key]
        return parent


def _named_targets(ref: TypeRef):
    """Type IDs a reference points at; recurses through declarators/templates."""

    if isinstance(ref, Named):
        yield ref.id
    elif isinstance(ref, TemplateInstance):
        yield ref.template
        for arg in ref.args:
            if not isinstance(arg, int):
                yield from _named_targets(arg)
    elif isinstance(ref, (Pointer, ReferenceType)):
        yield from _named_targets(ref.to)
    elif hasattr(ref, "of"):
        yield from _named_targets(ref.of)  # type: ignore[attr-defined]
    elif isinstance(ref, FunctionType):
        yield from _named_targets(ref.ret)
        for param in ref.params:
            yield from _named_targets(param)


def from_analysis(analysis: Mapping, *, sizes: TypeSizes | None = None,
                  origin: str | None = None) -> ProviderFacts:
    """Build model facts from one merged analysis dict."""

    fmt = str(analysis.get("format") or "elf")
    arch = str(analysis.get("arch") or "x86_64")
    sizes = sizes or sizes_for(fmt, arch)
    default_origin = origin or ("dwarf" if analysis.get("dwarf_units") else "ida")

    scopes = _Scopes()
    facts: list[Fact] = []
    type_ids: dict[str, str] = {}
    function_ids: dict[int, str] = {}
    global_ids: dict[int, str] = {}

    for t in analysis.get("types") or []:
        if not isinstance(t, Mapping) or not t.get("name"):
            continue
        tid = _type_id(t)
        if tid in type_ids:
            continue
        scope = scopes.namespace(t.get("ns") or [])
        def base_type(b: Mapping) -> str:
            text = str(b.get("type") or b.get("name") or "")
            # DWARF often spells an inheritance by its bare name. Qualify it with the
            # declaring namespace so dependency ordering and rendering see the same type.
            if text and "::" not in text and " " not in text:
                ns = [str(p) for p in t.get("ns") or []]
                if ns:
                    return "::".join([*ns, text])
            return text

        bases = tuple(
            Base(parse_type(base_type(b), sizes),
                 _access(b.get("access")), bool(b.get("virtual")))
            for b in (t.get("bases") or []) if isinstance(b, Mapping)
        )
        members: list[Member] = []
        for m in t.get("members") or []:
            if not isinstance(m, Mapping) or not m.get("name"):
                continue
            members.append(Member(
                name=str(m["name"]),
                type=parse_type(str(m.get("type") or ""), sizes),
                offset=int(m["off"]) if m.get("off") is not None else None,
                bit_offset=(int(m["bit_offset"]) if m.get("bit_offset") is not None
                            else int(m["bit_start"]) if m.get("bit_start") is not None else None),
                bit_width=int(m["bit_size"]) if m.get("bit_size") is not None else None,
                access=_access(m.get("access")),
                static=False,
            ))
        for m in t.get("statics") or []:
            if not isinstance(m, Mapping) or not m.get("name"):
                continue
            members.append(Member(
                name=str(m["name"]),
                type=parse_type(str(m.get("type") or ""), sizes),
                offset=None, access=_access(m.get("access")), static=True,
            ))
        methods: list[Method] = []
        for m in t.get("methods") or []:
            if not isinstance(m, Mapping) or not m.get("name"):
                continue
            sig = _signature({
                "display": f"{m['name']}({', '.join(m.get('params') or [])})",
                "signature": (f"{m.get('ret') or 'void'} ({', '.join(m.get('params') or [])})"
                              if m.get("params") else f"{m.get('ret') or 'void'}()"),
            }, sizes)
            cc = "thiscall" if (not m.get("static") and arch == "x86") else sig.cc
            sig = FunctionType(ret=sig.ret, params=sig.params, cc=cc,
                               variadic=bool(m.get("variadic")))
            methods.append(Method(
                name=str(m["name"]), signature=sig,
                access=_access(m.get("access")),
                static=bool(m.get("static")), virtual=bool(m.get("virtual")),
                const=bool(m.get("const")),
            ))
        size = t.get("size")
        align = t.get("align")
        layout = {}
        if size is not None or align is not None:
            # 0 align means the provider did not record it; the probe skips it rather than
            # asserting a guessed alignment.
            layout = {BINARY_LAYOUT: Layout(int(size or 0), int(align or 0))}
        kind = str(t.get("kind") or "struct")
        if kind not in ("struct", "class", "union", "enum"):
            kind = "struct"
        decl = TypeDecl(
            id=tid, kind=kind, name=str(t["name"]), scope=scope,
            bases=bases, members=tuple(members), methods=tuple(methods),
            layout=layout,
            origin=str(t.get("origin") or default_origin),
        )
        type_ids[_qualified(t)] = tid
        facts.append(Fact(
            entity=decl, origin=decl.origin, confidence=0.95 if size is not None else 0.8,
            evidence=(Evidence(decl.origin, f"type {_qualified(t)}", None),),
        ))

    for fn in analysis.get("functions") or []:
        if not isinstance(fn, Mapping):
            continue
        ea = fn.get("ea")
        fid = _function_id(fn)
        if ea is not None:
            if int(ea) in function_ids:
                continue
            function_ids[int(ea)] = fid
        flags = set()
        if fn.get("lib"):
            flags.add("library")
        if fn.get("glue"):
            flags.add(str(fn["glue"]))
        decl = FunctionDecl(
            id=fid,
            name=str(fn.get("display") or fn.get("name") or fid),
            signature=_signature(fn, sizes),
            linkage=str(fn["linkage"]) if fn.get("linkage") else None,
            owner=_owner(fn, type_ids, scopes),
            storage="extern",
            flags=frozenset(flags),
            address=int(ea) if ea is not None else None,
            unit=str(fn.get("cu") or fn.get("file")) if (fn.get("cu") or fn.get("file")) else None,
        )
        origin_name = str(fn.get("provenance") or "ida")
        facts.append(Fact(
            entity=decl, origin=origin_name, confidence=1.0,
            evidence=(Evidence(origin_name, f"function {decl.name}",
                               f"0x{int(ea):x}" if ea is not None else None),),
        ))

    for d in analysis.get("data") or []:
        if not isinstance(d, Mapping) or not d.get("name"):
            continue
        ea = d.get("ea")
        gid = _global_id(d)
        if ea is not None:
            if int(ea) in global_ids:
                continue
            global_ids[int(ea)] = gid
        decl = GlobalDecl(
            id=gid, name=str(d["name"]),
            type=parse_type(str(d.get("type") or ""), sizes),
            linkage=str(d["name"]) if str(d["name"]).startswith(("_Z", "?")) else None,
            storage="extern",
            address=int(ea) if ea is not None else None,
        )
        facts.append(Fact(
            entity=decl, origin=str(d.get("origin") or "ida"),
            confidence=0.8 if d.get("type") else 0.55,
            evidence=(Evidence("ida", f"data {decl.name}",
                               f"0x{int(ea):x}" if ea is not None else None),),
        ))

    facts = scopes.facts + facts
    references: list[Reference] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    def add_ref(src: str, dst: str, kind: str, location: str | None = None) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, kind, location)
        if key in seen:
            return
        seen.add(key)
        references.append(Reference(src, dst, kind, location))

    for edge in analysis.get("edges") or []:
        src = function_ids.get(int(edge.get("ea"))) if edge.get("ea") is not None else None
        if src is None:
            continue
        for dst_ea in edge.get("to") or []:
            dst = function_ids.get(int(dst_ea)) if dst_ea is not None else None
            if dst is not None:
                add_ref(src, dst, "call", f"0x{int(edge['ea']):x}")

    for decl in facts:
        entity = decl.entity
        if isinstance(entity, TypeDecl):
            for base in entity.bases:
                for dst in _named_targets(base.type):
                    add_ref(entity.id, dst, "base", entity.name)
            for member in entity.members:
                for dst in _named_targets(member.type):
                    add_ref(entity.id, dst, "member", f"{entity.name}::{member.name}")
            for method in entity.methods:
                for dst in _named_targets(method.signature.ret):
                    add_ref(entity.id, dst, "type_use", f"{entity.name}::{method.name}")
                for param in method.signature.params:
                    for dst in _named_targets(param):
                        add_ref(entity.id, dst, "type_use", f"{entity.name}::{method.name}")
        elif isinstance(entity, FunctionDecl):
            for dst in _named_targets(entity.signature.ret):
                add_ref(entity.id, dst, "type_use", entity.name)
            for param in entity.signature.params:
                for dst in _named_targets(param):
                    add_ref(entity.id, dst, "type_use", entity.name)
        elif isinstance(entity, GlobalDecl):
            for dst in _named_targets(entity.type):
                add_ref(entity.id, dst, "type_use", entity.name)

    return ProviderFacts(
        facts=tuple(facts),
        references=tuple(references),
        function_ids=dict(function_ids),
        type_ids=dict(type_ids),
        global_ids=dict(global_ids),
    )
