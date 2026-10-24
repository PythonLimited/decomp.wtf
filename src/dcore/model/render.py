"""Canonical prelude and layout-probe rendering for the new model.

The renderer is a pure function of facts: one definition per entity, namespaces from
the scope tree, dependency-first type order, and no provider-specific text. It is not
the old per-function text merge; a function header will later be a dependency-closed
subset of this output.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from textwrap import indent

from .facts import Fact
from .types import (
    Array,
    Builtin,
    FunctionDecl,
    FunctionType,
    GlobalDecl,
    Member,
    Method,
    Named,
    Opaque,
    Pointer,
    Qualified,
    ReferenceType,
    Scope,
    TemplateInstance,
    TypeDecl,
    TypeRef,
)


class RenderError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Entities:
    types: Mapping[str, TypeDecl]
    scopes: Mapping[str, Scope]
    functions: Mapping[str, FunctionDecl]
    globals: Mapping[str, GlobalDecl]


def _collect(facts: Iterable[Fact]) -> _Entities:
    types: dict[str, TypeDecl] = {}
    scopes: dict[str, Scope] = {}
    functions: dict[str, FunctionDecl] = {}
    globals_: dict[str, GlobalDecl] = {}
    for fact in facts:
        entity = fact.entity
        if isinstance(entity, TypeDecl):
            types[entity.id] = entity
        elif isinstance(entity, Scope):
            scopes[entity.id] = entity
        elif isinstance(entity, FunctionDecl):
            functions[entity.id] = entity
        elif isinstance(entity, GlobalDecl):
            globals_[entity.id] = entity
    return _Entities(types, scopes, functions, globals_)


def _scope_path(scopes: Mapping[str, Scope], scope_id: str | None) -> list[str]:
    out: list[str] = []
    while scope_id:
        scope = scopes.get(scope_id)
        if scope is None:
            break
        out.append(scope.name)
        scope_id = scope.parent
    return list(reversed(out))


def _in_namespace(path: list[str], text: str) -> str:
    body = text
    for part in reversed(path):
        body = f"namespace {part} {{\n{indent(body, '    ')}\n}}"
    return body


def _builtin(ref: Builtin) -> str:
    return ref.name


def _type(ref: TypeRef) -> str:
    if isinstance(ref, Builtin):
        return _builtin(ref)
    if isinstance(ref, Named):
        return ref.id[2:] if ref.id.startswith("t:") else ref.id
    if isinstance(ref, Qualified):
        return f"{'const ' if ref.const else ''}{'volatile ' if ref.volatile else ''}{_type(ref.of)}"
    if isinstance(ref, Pointer):
        if isinstance(ref.to, FunctionType):
            ret = _type(ref.to.ret)
            params = ", ".join(_type(p) for p in ref.to.params)
            return f"{ret} (*{' const' if ref.const else ''})({params})"
        return f"{_type(ref.to)}*{' const' if ref.const else ''}"
    if isinstance(ref, ReferenceType):
        return f"{_type(ref.to)}{'&&' if ref.rvalue else '&'}"
    if isinstance(ref, Array):
        return f"{_type(ref.of)}[{'' if ref.count is None else ref.count}]"
    if isinstance(ref, FunctionType):
        return f"{_type(ref.ret)} ({', '.join(_type(p) for p in ref.params)})"
    if isinstance(ref, TemplateInstance):
        base = ref.template[2:] if ref.template.startswith("t:") else ref.template
        args = ", ".join(str(a) if isinstance(a, int) else _type(a) for a in ref.args)
        return f"{base}<{args}>"
    if isinstance(ref, Opaque):
        raise RenderError(f"unresolved opaque type (size {ref.size}, align {ref.align})")
    raise RenderError(f"unsupported type reference {ref!r}")


def _decl(ref: TypeRef, name: str) -> str:
    if not name:
        return _type(ref)
    if isinstance(ref, Named):
        return f"{_type(ref)} {name}"
    if isinstance(ref, Builtin):
        return f"{_type(ref)} {name}"
    if isinstance(ref, Qualified):
        return f"{'const ' if ref.const else ''}{'volatile ' if ref.volatile else ''}{_decl(ref.of, name)}"
    if isinstance(ref, Pointer):
        if isinstance(ref.to, FunctionType):
            params = ", ".join(_type(p) for p in ref.to.params)
            return f"{_type(ref.to.ret)} (*{' const ' if ref.const else ''}{name})({params})"
        return _decl(ref.to, f"*{' const ' if ref.const else ''}{name}")
    if isinstance(ref, ReferenceType):
        return _decl(ref.to, f"{'&&' if ref.rvalue else '&'}{name}")
    if isinstance(ref, Array):
        return _decl(ref.of, f"{name}[{'' if ref.count is None else ref.count}]")
    if isinstance(ref, FunctionType):
        return f"{_type(ref.ret)} {name}({', '.join(_type(p) for p in ref.params)})"
    if isinstance(ref, TemplateInstance):
        return f"{_type(ref)} {name}"
    if isinstance(ref, Opaque):
        raise RenderError(f"unresolved opaque type for {name}")
    raise RenderError(f"unsupported type reference {ref!r}")


def _by_value_deps(decl: TypeDecl) -> set[str]:
    deps: set[str] = set()

    def visit(ref: TypeRef) -> None:
        if isinstance(ref, Named):
            deps.add(ref.id)
        elif isinstance(ref, Qualified):
            visit(ref.of)
        elif isinstance(ref, Array):
            visit(ref.of)
        elif isinstance(ref, TemplateInstance):
            deps.add(ref.template)
        # pointers/references/function types do not require a complete type here

    for base in decl.bases:
        visit(base.type)
    for member in decl.members:
        if not member.static:
            visit(member.type)
    return deps


def _ordered_types(types: Mapping[str, TypeDecl]) -> list[TypeDecl]:
    out: list[TypeDecl] = []
    done: set[str] = set()
    active: set[str] = set()

    def visit(tid: str) -> None:
        if tid in done or tid in active or tid not in types:
            return
        active.add(tid)
        for dep in sorted(_by_value_deps(types[tid])):
            visit(dep)
        active.remove(tid)
        done.add(tid)
        out.append(types[tid])

    for tid in types:
        visit(tid)
    return out


def _access_items(decl: TypeDecl) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for member in decl.members:
        prefix = "static " if member.static else ""
        bit = f" : {member.bit_width}" if member.bit_width is not None else ""
        items.append((member.access, f"{prefix}{_decl(member.type, member.name)}{bit};"))
    for method in decl.methods:
        items.append((method.access, _method(method, decl.name)))
    return items


def _method(method: Method, owner: str) -> str:
    prefix = ("virtual " if method.virtual else "") + ("static " if method.static else "")
    if method.name.startswith("~") or method.name == owner:
        head = f"{prefix}{method.name}"
    else:
        head = f"{prefix}{_type(method.signature.ret)} {method.name}"
    params = ", ".join(_type(p) for p in method.signature.params)
    suffix = " const" if method.const else ""
    if method.noexcept:
        suffix += " noexcept"
    return f"{head}({params}){suffix};"


def _type_def(decl: TypeDecl) -> str:
    if decl.kind in ("typedef", "alias"):
        if decl.alias_of is None:
            raise RenderError(f"alias {decl.name} has no target")
        return f"using {decl.name} = {_type(decl.alias_of)};"
    if decl.kind == "enum":
        values = ", ".join(m.name for m in decl.members)
        return f"enum {decl.name} {{ {values} }};"
    if decl.kind == "template":
        raise RenderError(f"template type {decl.name} is not modelled yet")

    bases = ""
    if decl.bases:
        rendered = []
        for base in decl.bases:
            rendered.append(f"{'virtual ' if base.virtual else ''}{base.access} {_type(base.type)}")
        bases = " : " + ", ".join(rendered)

    default_access = "private" if decl.kind == "class" else "public"
    lines = [f"{decl.kind} {decl.name}{bases} {{"]
    current = default_access
    for access, text in _access_items(decl):
        if access != current:
            lines.append(f"{access}:")
            current = access
        lines.append(text)
    lines.append("};")
    return "\n".join(lines)


def _function_path(fn: FunctionDecl) -> tuple[list[str], str]:
    base = fn.name.split("(", 1)[0].strip()
    if "::" not in base:
        return [], base
    parts = [p for p in base.split("::") if p]
    return parts[:-1], parts[-1]


def _function_decl(fn: FunctionDecl, name: str) -> str:
    params = ", ".join(_type(p) for p in fn.signature.params)
    suffix = " noexcept" if "noexcept" in fn.flags else ""
    return f"{_type(fn.signature.ret)} {name}({params}){suffix};"


def _global_decl(decl: GlobalDecl) -> str:
    return f"extern {_decl(decl.type, decl.name)};"


def _stdlib_includes(entities: _Entities) -> list[str]:
    names: set[str] = set()

    def visit(ref: TypeRef) -> None:
        if isinstance(ref, Named):
            names.add(ref.id)
        elif isinstance(ref, TemplateInstance):
            names.add(ref.template)
            for arg in ref.args:
                if not isinstance(arg, int):
                    visit(arg)
        elif isinstance(ref, (Qualified, Pointer, ReferenceType)):
            visit(ref.to if not isinstance(ref, Qualified) else ref.of)
        elif isinstance(ref, Array):
            visit(ref.of)
        elif isinstance(ref, FunctionType):
            visit(ref.ret)
            for param in ref.params:
                visit(param)

    for decl in entities.types.values():
        for base in decl.bases:
            visit(base.type)
        for member in decl.members:
            visit(member.type)
        for method in decl.methods:
            visit(method.signature.ret)
            for param in method.signature.params:
                visit(param)
    for decl in entities.functions.values():
        visit(decl.signature.ret)
        for param in decl.signature.params:
            visit(param)
    for decl in entities.globals.values():
        visit(decl.type)

    out = ["#include <cstddef>", "#include <cstdint>"]
    for prefix, header in (
        ("t:std::vector", "vector"), ("t:std::string", "string"),
        ("t:std::map", "map"), ("t:std::unordered_map", "unordered_map"),
        ("t:std::shared_ptr", "memory"), ("t:std::unique_ptr", "memory"),
        ("t:std::array", "array"),
    ):
        if any(name == prefix or name.startswith(prefix + "<") for name in names):
            out.append(f"#include <{header}>")
    return out


def render_prelude(facts: Iterable[Fact], *, include_functions: bool = True) -> str:
    """One canonical declaration unit: includes, forward declarations, type definitions, prototypes."""

    entities = _collect(facts)
    lines = _stdlib_includes(entities)
    lines.append("")

    ordered = _ordered_types(entities.types)
    for decl in ordered:
        path = _scope_path(entities.scopes, decl.scope)
        if decl.kind in ("struct", "class", "union"):
            lines.append(_in_namespace(path, f"{decl.kind} {decl.name};"))
    if ordered:
        lines.append("")
    for decl in ordered:
        path = _scope_path(entities.scopes, decl.scope)
        lines.append(_in_namespace(path, _type_def(decl)))
        lines.append("")

    if include_functions:
        for fn in entities.functions.values():
            if fn.owner is not None or "library" in fn.flags:
                continue
            path, name = _function_path(fn)
            if path and path[0] == "std":
                continue
            lines.append(_in_namespace(path, _function_decl(fn, name)))
        for decl in entities.globals.values():
            path = []
            name = decl.name
            if "::" in name:
                path, name = name.split("::")[:-1], name.split("::")[-1]
            lines.append(_in_namespace(path, _global_decl(GlobalDecl(
                id=decl.id, name=name, type=decl.type, linkage=decl.linkage,
                storage=decl.storage, address=decl.address, unit=decl.unit))))
    return "\n".join(lines).rstrip() + "\n"


def render_layout_probes(facts: Iterable[Fact], *, environment: str | None = None) -> str:
    """`static_assert` probes for every observed layout; the target compiler is the authority."""

    entities = _collect(facts)
    lines: list[str] = []
    for decl in _ordered_types(entities.types):
        layout = (decl.layout.get(environment) if environment
                  else next(iter(decl.layout.values()), None))
        if layout is None or layout.size <= 0:
            continue
        qualified = "::" + decl.id[2:]
        lines.append(f'static_assert(sizeof({qualified}) == {layout.size}, "{decl.name} size");')
        if layout.align > 0:
            lines.append(f'static_assert(alignof({qualified}) == {layout.align}, "{decl.name} align");')
        if any(method.virtual for method in decl.methods) or any(b.virtual for b in decl.bases):
            continue  # offsetof is only conditionally supported for non-standard-layout types
        for member in decl.members:
            if member.static or member.offset is None or member.bit_width is not None:
                continue
            if member.access != "public":
                continue  # offsetof is a member access; private members would not compile
            lines.append(f'static_assert(offsetof({qualified}, {member.name}) == {member.offset}, '
                         f'"{decl.name}::{member.name}");')
    return "\n".join(lines) + ("\n" if lines else "")
