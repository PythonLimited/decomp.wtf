"""Parse the type spellings the analysis providers emit into the model algebra.

This is deliberately not a C++ parser. It handles the declarator shapes DWARF/PDB/IDA
actually put in the merged analysis: builtins, pointers, references, arrays, function
pointers, qualifiers, and template spellings. Anything outside that surface stays a
``Named``/``Opaque`` fact instead of being guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import (
    Array,
    Builtin,
    FunctionType,
    Named,
    Opaque,
    Pointer,
    Qualified,
    ReferenceType,
    TemplateInstance,
    TypeRef,
)

_BUILTIN_WIDTHS = {
    "std::int8_t": 1, "int8_t": 1, "std::uint8_t": 1, "uint8_t": 1,
    "std::int16_t": 2, "int16_t": 2, "std::uint16_t": 2, "uint16_t": 2,
    "std::int32_t": 4, "int32_t": 4, "std::uint32_t": 4, "uint32_t": 4,
    "std::int64_t": 8, "int64_t": 8, "std::uint64_t": 8, "uint64_t": 8,
    "__int8": 1, "__int16": 2, "__int32": 4, "__int64": 8,
}


@dataclass(frozen=True, slots=True)
class TypeSizes:
    """ABI widths that are not universal across the first targets."""

    pointer: int = 8
    long: int = 8
    wchar: int = 4
    long_double: int = 16


def sizes_for(fmt: str, arch: str) -> TypeSizes:
    fmt = (fmt or "elf").lower()
    arch = {"amd64": "x86_64", "x64": "x86_64", "i386": "x86", "i686": "x86",
            "arm64": "aarch64"}.get((arch or "").lower(), (arch or "x86_64").lower())
    if fmt == "pe":
        return TypeSizes(pointer=8 if arch == "x86_64" else 4, long=4, wchar=2, long_double=8)
    if arch == "x86":
        return TypeSizes(pointer=4, long=4, wchar=4, long_double=12)
    return TypeSizes()


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    angle = paren = bracket = 0
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


def _builtin(name: str, sizes: TypeSizes) -> TypeRef | None:
    n = " ".join(name.split())
    width = _BUILTIN_WIDTHS.get(n)
    if width is not None:
        return Builtin(n, width, width, "int")
    unsigned = n.startswith("unsigned ")
    base = n[9:] if unsigned else n
    if base == "void":
        return Builtin("void", 0, 1, "void")
    if base == "bool":
        return Builtin("bool", 1, 1, "bool")
    if base in ("char", "signed char"):
        return Builtin(n, 1, 1, "int")
    if base == "unsigned char":
        return Builtin(n, 1, 1, "int")
    if base == "wchar_t":
        return Builtin(n, sizes.wchar, sizes.wchar, "int")
    if base == "char8_t":
        return Builtin(n, 1, 1, "int")
    if base == "char16_t":
        return Builtin(n, 2, 2, "int")
    if base == "char32_t":
        return Builtin(n, 4, 4, "int")
    if base in ("short", "short int", "signed short", "signed short int"):
        return Builtin(n, 2, 2, "int")
    if base in ("unsigned short", "unsigned short int"):
        return Builtin(n, 2, 2, "int")
    if base in ("int", "signed", "signed int"):
        return Builtin(n, 4, 4, "int")
    if base in ("unsigned", "unsigned int"):
        return Builtin(n, 4, 4, "int")
    if base in ("long", "long int", "signed long", "signed long int"):
        return Builtin(n, sizes.long, sizes.long, "int")
    if base in ("unsigned long", "unsigned long int"):
        return Builtin(n, sizes.long, sizes.long, "int")
    if base in ("long long", "long long int", "signed long long", "signed long long int"):
        return Builtin(n, 8, 8, "int")
    if base in ("unsigned long long", "unsigned long long int"):
        return Builtin(n, 8, 8, "int")
    if base == "float":
        return Builtin(n, 4, 4, "float")
    if base == "double":
        return Builtin(n, 8, 8, "float")
    if base == "long double":
        return Builtin(n, sizes.long_double, sizes.long_double, "float")
    if base in ("size_t", "std::size_t", "ptrdiff_t", "std::ptrdiff_t",
                "intptr_t", "std::intptr_t", "uintptr_t", "std::uintptr_t"):
        return Builtin(n, sizes.pointer, sizes.pointer, "int")
    if base in ("nullptr_t", "std::nullptr_t"):
        return Builtin(n, sizes.pointer, sizes.pointer, "int")
    return None


def parse_type(text: str, sizes: TypeSizes | None = None) -> TypeRef:
    """Best-effort provider spelling -> ``TypeRef``.

    Unknown names stay ``Named`` (or ``Opaque(0, 1)`` for an empty spelling), so an
    unresolved dependency is visible rather than silently assigned a size.
    """

    sizes = sizes or TypeSizes()
    t = " ".join((text or "").strip().split())
    if not t:
        return Opaque(0, 1)
    t = re.sub(r"\b(?:__restrict|__ptr32|__ptr64|__w64)\b", "", t)
    t = re.sub(r"^(?:struct|class|union|enum)\s+", "", t)
    t = t.strip()

    # Function pointer: void (*)(int, int) / int (*)(void)
    m = re.match(r"^(.*?)\(\s*\*\s*\)\s*\((.*)\)$", t)
    if m:
        ret = parse_type(m.group(1), sizes)
        params = _params(m.group(2), sizes)
        return Pointer(FunctionType(ret, params, variadic=False))

    # Array suffix first: int *[4] is an array of pointers.
    m = re.match(r"^(.*?)\s*\[(\d*)\]$", t)
    if m:
        return Array(parse_type(m.group(1), sizes), int(m.group(2)) if m.group(2) else None)

    # References and pointers at the outer declarator level. The qualifier after
    # the token belongs to that pointer (`char * const`), not to the pointee.
    m = re.match(r"^(.*?)(\s*)(&&|&|\*)(?:\s+(const|volatile))?$", t)
    if m:
        inner = parse_type(m.group(1), sizes)
        qualifier = m.group(4)
        if m.group(3) == "&&":
            return ReferenceType(inner, rvalue=True)
        if m.group(3) == "&":
            return ReferenceType(inner)
        pointer = Pointer(inner, const=qualifier == "const")
        return Qualified(pointer, volatile=True) if qualifier == "volatile" else pointer

    # Leading qualifiers.
    for qualifier in ("const", "volatile"):
        if t.startswith(qualifier + " "):
            inner = parse_type(t[len(qualifier) + 1:], sizes)
            return Qualified(inner, const=qualifier == "const", volatile=qualifier == "volatile")

    # Trailing qualifier without a pointer: int const.
    m = re.match(r"^(.*?)\s+(const|volatile)$", t)
    if m:
        inner = parse_type(m.group(1), sizes)
        return Qualified(inner, const=m.group(2) == "const", volatile=m.group(2) == "volatile")

    builtin = _builtin(t, sizes)
    if builtin is not None:
        return builtin

    # Template instance: keep the template and the arguments, not one opaque string.
    m = re.match(r"^([A-Za-z_][\w:]*(?:\s*::\s*[A-Za-z_]\w*)*)\s*<(.*)>$", t)
    if m:
        args = tuple(parse_type(a, sizes) if not re.fullmatch(r"-?\d+", a) else int(a)
                     for a in _split_top_level(m.group(2)))
        return TemplateInstance("t:" + m.group(1).replace(" ", ""), args)

    name = t.lstrip(":")
    return Named("t:" + name)


def _params(text: str, sizes: TypeSizes) -> tuple[TypeRef, ...]:
    params = [p for p in _split_top_level(text) if p and p != "void" and p != "..."]
    return tuple(parse_type(p.split("=", 1)[0].strip(), sizes) for p in params)
