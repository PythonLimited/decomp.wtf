"""Provider-neutral type algebra and entity records.

This module is deliberately free of IDA, DWARF, compiler and renderer imports.
Providers translate their facts into these records; the resolver, renderer and
judge consume them. A type is a small algebra, not a flat enum: C++ qualifiers,
pointers, arrays, function types, templates and opaque fallbacks each have a
shape the rest of the model can inspect.

`Opaque` is the only "unknown layout" escape hatch. It is sized in bytes, not
bits; a real bitfield is a ``Member`` with ``bit_offset``/``bit_width``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping, TypeAlias

EntityId = str
Access = Literal["public", "protected", "private"]


@dataclass(frozen=True, slots=True)
class Builtin:
    """A compiler builtin: int, unsigned long, float, bool, void, ..."""

    name: str
    size: int
    align: int
    kind: Literal["int", "float", "bool", "void"]


@dataclass(frozen=True, slots=True)
class Named:
    """A reference to a declared type (struct/class/union/enum/typedef/template)."""

    id: EntityId


@dataclass(frozen=True, slots=True)
class Qualified:
    """``const``/``volatile`` applied to a type.

    Qualifiers are not a string suffix: they participate in overload resolution,
    mangling and (for some ABIs) calling conventions.
    """

    of: "TypeRef"
    const: bool = False
    volatile: bool = False


@dataclass(frozen=True, slots=True)
class Pointer:
    to: "TypeRef"
    const: bool = False


@dataclass(frozen=True, slots=True)
class ReferenceType:
    """A C++ lvalue/rvalue reference. Kept distinct from a pointer for rendering and ABI."""

    to: "TypeRef"
    rvalue: bool = False


@dataclass(frozen=True, slots=True)
class Array:
    of: "TypeRef"
    count: int | None = None  # None = incomplete array


@dataclass(frozen=True, slots=True)
class FunctionType:
    ret: "TypeRef"
    params: tuple["TypeRef", ...] = ()
    cc: str = "cdecl"  # cdecl/stdcall/thiscall/vectorcall/sysv64/win64/aapcs64...
    variadic: bool = False


@dataclass(frozen=True, slots=True)
class TemplateInstance:
    template: EntityId
    args: tuple["TypeRef | int", ...] = ()


@dataclass(frozen=True, slots=True)
class Opaque:
    """An unknown layout with a known ABI size/alignment.

    Use this for third-party or stripped types whose layout is not reconstructed.
    ``trivial`` is the Itanium/MSVC ABI class hint; by-value use needs it to be
    right, while pointer/reference use usually does not.
    """

    size: int
    align: int
    trivial: bool = True


TypeRef: TypeAlias = (
    Builtin | Named | Qualified | Pointer | ReferenceType | Array | FunctionType
    | TemplateInstance | Opaque
)


@dataclass(frozen=True, slots=True)
class Layout:
    """One environment's view of a type's ABI layout."""

    size: int
    align: int
    packed: bool = False


@dataclass(frozen=True, slots=True)
class Base:
    type: TypeRef
    access: Access = "public"
    virtual: bool = False


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    type: TypeRef
    offset: int | None = None
    bit_offset: int | None = None
    bit_width: int | None = None
    access: Access = "public"
    static: bool = False


@dataclass(frozen=True, slots=True)
class Method:
    name: str
    signature: FunctionType
    access: Access = "public"
    static: bool = False
    virtual: bool = False
    const: bool = False
    noexcept: bool = False
    vtable_slot: int | None = None
    body: EntityId | None = None  # an InlineBody entity, when the original kept one


@dataclass(frozen=True, slots=True)
class TypeDecl:
    id: EntityId
    kind: Literal["struct", "class", "union", "enum", "typedef", "alias", "template"]
    name: str
    scope: EntityId | None = None
    bases: tuple[Base, ...] = ()
    members: tuple[Member, ...] = ()
    methods: tuple[Method, ...] = ()
    alias_of: TypeRef | None = None
    layout: Mapping[str, Layout] = field(default_factory=dict)  # EnvironmentId -> Layout
    origin: str = ""


@dataclass(frozen=True, slots=True)
class FunctionDecl:
    id: EntityId
    name: str
    signature: FunctionType
    linkage: str | None = None
    owner: EntityId | None = None
    storage: Literal["extern", "static", "inline"] = "extern"
    flags: frozenset[str] = frozenset()  # virtual, const, noexcept, ...
    address: int | None = None
    unit: str | None = None
    body: EntityId | None = None


@dataclass(frozen=True, slots=True)
class GlobalDecl:
    id: EntityId
    name: str
    type: TypeRef
    linkage: str | None = None
    storage: Literal["extern", "static", "thread_local"] = "extern"
    address: int | None = None
    unit: str | None = None


@dataclass(frozen=True, slots=True)
class Scope:
    """A namespace/class/function scope. Scopes form a tree; type references do not."""

    id: EntityId
    kind: Literal["namespace", "class", "function"]
    name: str
    parent: EntityId | None = None


Entity: TypeAlias = TypeDecl | FunctionDecl | GlobalDecl | Scope
