"""Shared symbol/reference identity for the judge and the header renderer.

The judge compares *destinations*, not spellings.  This module is the single
place that turns an analysis' functions/data/imports (and, later, explicit
agent aliases) into a name/address universe both sides can resolve against.

Nothing here reads a binary or a database: it is a pure view over the merged
analysis dict, so the judge, the gate and the header renderer can share it
without importing the network/native layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Reference:
    """A resolved destination: an address, an import, a section+offset, or a name."""

    kind: str  # "addr" | "import" | "section" | "local" | "symbol"
    value: int | str
    offset: int = 0

    def key(self) -> tuple:
        return (self.kind, self.value, self.offset)

    def label(self) -> str:
        if self.kind == "addr":
            return f"0x{int(self.value):x}" + (f"+{self.offset:#x}" if self.offset else "")
        if self.kind == "section":
            return f"{self.value}" + (f"+{self.offset:#x}" if self.offset else "")
        if self.kind == "local":
            return f"local:{int(self.value):#x}"
        return str(self.value)


def _import_name(name: str) -> str:
    """Canonical import spelling: `.printf`, `__imp_printf`, `printf@8` -> `printf`."""
    s = (name or "").strip()
    if s.startswith("."):
        s = s[1:]
    if s.startswith("__imp_"):
        s = s[len("__imp_"):]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s


def _without_params(name: str) -> str:
    s = (name or "").strip()
    return s.split("(", 1)[0].rstrip() if "(" in s else s


def _mangled_global_name(name: str) -> str | None:
    """`?i_pString@@3QBDB` -> `i_pString`; `?g@ns@@3...` -> `ns::g`."""
    s = (name or "").strip()
    if not s.startswith("?") or "@@" not in s:
        return None
    base = s[1:].split("@@", 1)[0]
    parts = [p for p in base.split("@") if p]
    if not parts:
        return None
    return "::".join(reversed(parts)) if len(parts) > 1 else parts[0]


_CODE_REF = re.compile(r"^(?P<name>[^+]+?)(?:\+0x(?P<off>[0-9a-fA-F]+))?$")

# MSVC decorates member access in the mangled name (`Q` public, `I` protected, `A` private).
# The same vector/string instantiation built with another STL patchlevel differs only there;
# code and layout are identical, so the judge resolves the symbol to the same address.
_MSVC_ACCESS = re.compile(r"^(\?[^@]*@.*?@@)[QIA](.*)$")


def _without_msvc_access(name: str) -> str:
    m = _MSVC_ACCESS.match(name or "")
    return (m.group(1) + "Q" + m.group(2)) if m else (name or "")


# IDA/FLIRT names the MSVC x64 stack probe `_alloca_probe`, while the compiler emits calls to
# `__chkstk`. They are the same CRT routine; without the alias the judge reports two different
# destinations for identical bytes. An explicit analysis spelling still wins.
_CODE_ALIASES = {
    "__chkstk": ("_alloca_probe", "_chkstk"),
    "_chkstk": ("__chkstk", "_alloca_probe"),
    "___chkstk_ms": ("__chkstk", "_alloca_probe"),
    "_alloca_probe": ("__chkstk", "___chkstk_ms"),
}


class SymbolTable:
    """Name/address maps over one merged analysis.

    `aliases` is the explicit escape hatch for an address IDA never named:
    ``{"my_function": 0x140012340}``.  The same table drives the judge and the
    header renderer, so an alias is visible in both places.
    """

    def __init__(self, *, code_by_ea: dict[int, str], code_by_name: dict[str, int],
                 data_by_ea: dict[int, str], data_by_name: dict[str, int],
                 imports_by_ea: dict[int, str], imports_by_name: dict[str, int],
                 aliases: dict[str, int] | None = None,
                 import_aliases: dict[str, str] | None = None):
        self.code_by_ea = code_by_ea
        self.code_by_name = code_by_name
        self.data_by_ea = data_by_ea
        self.data_by_name = data_by_name
        self.imports_by_ea = imports_by_ea
        self.imports_by_name = imports_by_name
        self.aliases = dict(aliases or {})
        self.import_aliases = {_import_name(k): _import_name(v)
                               for k, v in (import_aliases or {}).items()}

    @classmethod
    def from_analysis(cls, analysis: dict | None, *, aliases: dict[str, int] | None = None,
                      data_aliases: dict[str, int] | None = None,
                      import_aliases: dict[str, str] | None = None) -> "SymbolTable":
        analysis = analysis or {}
        code_by_ea: dict[int, str] = {}
        code_by_name: dict[str, int] = {}
        for fn in analysis.get("functions") or []:
            try:
                ea = int(fn["ea"])
            except (KeyError, TypeError, ValueError):
                continue
            name = fn.get("linkage") or fn.get("name") or fn.get("display") or f"sub_{ea:x}"
            code_by_ea[ea] = name
            for spelling in (fn.get("name"), fn.get("display"), fn.get("linkage"), f"sub_{ea:x}"):
                if spelling:
                    code_by_name.setdefault(str(spelling), ea)
            display = fn.get("display")
            if display:
                code_by_name.setdefault(_without_params(str(display)), ea)

        for name, ea in list(code_by_name.items()):
            for alias in _CODE_ALIASES.get(name, ()):
                code_by_name.setdefault(alias, ea)
            access_free = _without_msvc_access(name)
            if access_free != name:
                code_by_name.setdefault(access_free, ea)

        data_by_ea: dict[int, str] = {}
        data_by_name: dict[str, int] = {}
        for d in analysis.get("data") or []:
            try:
                ea = int(d["ea"])
            except (KeyError, TypeError, ValueError):
                continue
            name = d.get("name") or f"data_{ea:x}"
            data_by_ea[ea] = str(name)
            for spelling in (name, f"data_{ea:x}"):
                data_by_name.setdefault(str(spelling), ea)
            unmangled = _mangled_global_name(str(name))
            if unmangled:
                # A rebuilt header can spell the same global with another pointer type
                # (`void *` vs `IMemoryAllocator *`); the qualified base name is the identity.
                data_by_name.setdefault(unmangled, ea)

        for name, ea in (data_aliases or {}).items():
            data_by_name[str(name)] = int(ea)

        imports_by_ea: dict[int, str] = {}
        imports_by_name: dict[str, int] = {}
        for im in analysis.get("imports") or []:
            try:
                ea = int(im["ea"])
            except (KeyError, TypeError, ValueError):
                continue
            name = _import_name(str(im.get("name") or ""))
            if not name:
                continue
            imports_by_ea[ea] = name
            imports_by_name.setdefault(name, ea)

        for name, ea in (aliases or {}).items():
            code_by_name[name] = int(ea)

        return cls(code_by_ea=code_by_ea, code_by_name=code_by_name,
                   data_by_ea=data_by_ea, data_by_name=data_by_name,
                   imports_by_ea=imports_by_ea, imports_by_name=imports_by_name,
                   aliases=aliases, import_aliases=import_aliases)

    # ------------------------------------------------------------------ lookup

    def resolve_code(self, name: str) -> int | None:
        """Absolute address a function spelling names, if the analysis knows it."""
        want = (name or "").strip()
        if not want:
            return None
        if want in self.code_by_name:
            return self.code_by_name[want]
        bare = _without_params(want)
        if bare in self.code_by_name:
            return self.code_by_name[bare]
        access_free = _without_msvc_access(bare)
        if access_free in self.code_by_name:
            return self.code_by_name[access_free]
        m = re.fullmatch(r"sub_([0-9a-fA-F]+)", want)
        if m:
            ea = int(m.group(1), 16)
            return ea if ea in self.code_by_ea else None
        return None

    def resolve_data(self, name: str) -> int | None:
        want = (name or "").strip()
        if not want:
            return None
        if want in self.data_by_name:
            return self.data_by_name[want]
        unmangled = _mangled_global_name(want)
        if unmangled and unmangled in self.data_by_name:
            return self.data_by_name[unmangled]
        m = re.fullmatch(r"data_([0-9a-fA-F]+)", want)
        if m:
            ea = int(m.group(1), 16)
            return ea if ea in self.data_by_ea else None
        return None

    def resolve_import(self, name: str) -> str | None:
        want = _import_name(name)
        if want in self.import_aliases:
            return self.import_aliases[want]
        return want if want in self.imports_by_name else None

    def reference(self, name: str, *, addend: int = 0, target_ea: int | None = None) -> Reference:
        """Best canonical reference for a symbol name (and optional absolute target)."""
        if target_ea is not None:
            return Reference("addr", int(target_ea))
        imp = self.resolve_import(name)
        if imp is not None:
            return Reference("import", imp)
        code = self.resolve_code(name)
        if code is not None:
            return Reference("addr", code, addend)
        data = self.resolve_data(name)
        if data is not None:
            return Reference("addr", data, addend)
        m = _CODE_REF.match((name or "").strip())
        if m and m.group("off"):
            sec, off = m.group("name"), int(m.group("off"), 16)
            return Reference("section", sec, off + addend)
        return Reference("symbol", (name or "").strip(), addend)
