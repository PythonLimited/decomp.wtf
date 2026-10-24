"""Resolve compile units to toolchain environments.

The analysis already carries the facts this needs:

* ``unit_compilers``: compile-unit path -> ``{compiler, flags}`` (DWARF producer).
* ``compilers``: project-level groups ranked by function count, used only as a
  fallback for units with no producer facts.
* ``functions``: each function's ``cu`` (compile unit), ``language`` and identity.

Resolution is per compile unit, not per project: one binary can vendor a GCC C
4.8.5 module and a GCC C++ 9.1.0 module, and their flags/layouts differ. The
report maps every function to the environment selected for its unit so callers
never have to re-derive "which compiler built this?" from the function name.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Mapping

from .environment import Environment, EnvironmentCandidate, Evidence, Toolchain

# GNU C++17 9.1.0 -O2 -fPIC
_GCC = re.compile(r"^GNU\s+(C(?:\+\+)?(?:\d+)?)\s+([0-9][0-9A-Za-z.+-]*)")
# clang version 12.0.0 / Apple clang version 15.0.0 (clang-1500...)
_CLANG = re.compile(r"(?i)(Apple\s+)?clang version\s+([0-9][0-9A-Za-z.+-]*)")
# Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24215.1 for x64
_MSVC = re.compile(
    r"(?i)Microsoft\s+\(R\)\s+(?:C/C\+\+\s+)?(?:Optimizing\s+)?Compiler\s+Version\s+"
    r"([0-9][0-9A-Za-z.]*)")
_GCC_FLAG = re.compile(r"(?:(?<=\s)|^)(-[A-Za-z][\w=.,:/+\[\]-]*)")
_MSVC_FLAG = re.compile(r"(?:(?<=\s)|^)(/[A-Za-z][\w:.-]*)")

_ARCH = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64",
         "i386": "x86", "i686": "x86", "x86": "x86", "x86_64": "x86_64"}
_TARGETS = {"elf": "{arch}-unknown-linux-gnu", "pe": "{arch}-pc-windows-msvc",
            "macho": "{arch}-apple-darwin"}


@dataclass(frozen=True, slots=True)
class Producer:
    """The parsed compiler identity from a DWARF/PDB producer string."""

    family: str
    version: str
    language: str | None
    flags: tuple[str, ...]
    raw: str

    @property
    def id(self) -> str:
        return f"{self.family}-{self.version}"


@dataclass(frozen=True, slots=True)
class UnitEnvironment:
    """One compile unit's environment decision."""

    unit: str
    language: str
    selected: Environment | None
    candidates: tuple[EnvironmentCandidate, ...]
    functions: tuple[str, ...] = ()
    missing_toolchain: bool = False
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolutionReport:
    """Per-unit environments and the function -> environment association."""

    units: Mapping[str, UnitEnvironment]
    functions: Mapping[str, str | None]  # function key -> Environment.id (None = unresolved)
    unresolved_units: tuple[str, ...] = ()

    def environment_for(self, function: str) -> Environment | None:
        env_id = self.functions.get(function)
        if env_id is None:
            return None
        for unit in self.units.values():
            if unit.selected is not None and unit.selected.id == env_id:
                return unit.selected
        return None


def function_key(fn: Mapping) -> str:
    """A stable-enough key for associating an analysis function with its environment.

    DB rows carry ``id``; raw analysis rows carry ``ea``. Name/linkage are the
    fallback for records that have neither.
    """

    for key in ("id", "ea", "linkage", "name"):
        value = fn.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def function_unit(fn: Mapping) -> str:
    """The compile unit a function belongs to.

    ``cu`` is the DWARF compile unit and is authoritative; ``unit`` is accepted
    for DB rows where the analysis row was flattened. A line/header file is not
    used here: a function defined in a header still belongs to the CU that emitted
    its copy.
    """

    return str(fn.get("cu") or fn.get("unit") or "")


def normalize_target(fmt: str, arch: str) -> str:
    a = _ARCH.get(str(arch or "").lower(), str(arch or "x86_64"))
    return _TARGETS.get(str(fmt or "elf").lower(), "{arch}").format(arch=a)


def _norm_target(text: str) -> str:
    return (text or "").lower().replace("-unknown-", "-")


def parse_producer(text: str) -> Producer | None:
    """Parse a compiler producer string without guessing from ``PATH``.

    Unknown producers return ``None``; the caller then falls back to a project
    default with low confidence and an explicit note.
    """

    raw = (text or "").strip()
    if not raw:
        return None
    if m := _GCC.match(raw):
        language = "c++" if "++" in m.group(1) else "c"
        return Producer("gcc", m.group(2), language, tuple(_GCC_FLAG.findall(raw[m.end():])), raw)
    if m := _CLANG.search(raw):
        family = "apple-clang" if m.group(1) else "clang"
        return Producer(family, m.group(2), None, tuple(_GCC_FLAG.findall(raw[m.end():])), raw)
    if m := _MSVC.search(raw):
        flags = tuple(_MSVC_FLAG.findall(raw[m.end():]))
        return Producer("msvc", m.group(1), None, flags, raw)
    return None


def canonical_toolchain_id(producer: Producer, target: str) -> str:
    return f"{producer.family}-{producer.version}-{_norm_target(target)}"


def _match_toolchains(catalog: Mapping[str, Toolchain], producer: Producer,
                      target: str, object_format: str) -> list[Toolchain]:
    """Exact target/version first, then family/version, then family.

    The fallback is deliberately visible in the confidence; it is not a silent
    "same family" substitution.
    """

    wanted = _norm_target(target)
    exact = [t for t in catalog.values()
             if t.family == producer.family and t.version == producer.version
             and t.object_format == object_format and _norm_target(t.target) == wanted]
    if exact:
        return exact
    version = [t for t in catalog.values()
               if t.family == producer.family and t.version == producer.version
               and t.object_format == object_format]
    if version:
        return version
    family = [t for t in catalog.values()
              if t.family == producer.family and t.object_format == object_format]
    return family


def _language_for(functions: list[Mapping], producer: Producer | None,
                  project_default: Environment | None) -> tuple[str, str | None]:
    """(language, conflict-note) for one unit."""

    langs = [str(f.get("language")) for f in functions if f.get("language") in ("c", "c++")]
    counts = Counter(langs)
    if len(counts) == 1:
        return next(iter(counts)), None
    if len(counts) > 1:
        picked = counts.most_common(1)[0][0]
        if producer and producer.language:
            picked = producer.language
        return picked, f"mixed function languages: {', '.join(sorted(counts))}"
    if producer and producer.language:
        return producer.language, None
    if project_default is not None:
        return project_default.language, None
    return "c++", None


def _project_default(analysis: Mapping, target: str, object_format: str,
                     catalog: Mapping[str, Toolchain]) -> Environment | None:
    groups = analysis.get("compilers") or []
    if not groups:
        return None
    first = groups[0] if isinstance(groups[0], Mapping) else {}
    producer = parse_producer(str(first.get("compiler") or ""))
    if producer is None:
        return None
    flags = tuple(str(f) for f in (first.get("flags") or ()))
    matches = _match_toolchains(catalog, producer, target, object_format)
    exact = [t for t in matches
             if t.version == producer.version and t.object_format == object_format
             and _norm_target(t.target) == _norm_target(target)]
    toolchain = exact[0].id if exact else canonical_toolchain_id(producer, target)
    langs = Counter(str(f.get("language")) for f in analysis.get("functions") or []
                    if isinstance(f, Mapping) and f.get("language") in ("c", "c++"))
    language = producer.language or (langs.most_common(1)[0][0] if langs else "c++")
    return Environment.create(
        toolchain, language, flags=flags, confidence=0.25,
        evidence=(Evidence("analysis-group", producer.raw, "project default"),),
    )


def _resolve_unit(unit: str, facts: Mapping, functions: list[Mapping], *,
                  analysis: Mapping, catalog: Mapping[str, Toolchain], target: str,
                  object_format: str, project_default: Environment | None) -> UnitEnvironment:
    notes: list[str] = []
    raw = str(facts.get("compiler") or "")
    producer = parse_producer(raw) if raw else None
    language, conflict = _language_for(functions, producer, project_default)
    if conflict:
        notes.append(conflict)

    if facts and "flags" in facts:
        flags = tuple(str(f) for f in (facts.get("flags") or ()))
    elif producer and producer.flags:
        flags = producer.flags
    elif not facts and project_default is not None:
        flags = project_default.flags
    else:
        flags = ()
        if producer:
            notes.append("producer did not record flags; compiler defaults assumed")

    keys = tuple(sorted(function_key(f) for f in functions))
    if producer is None:
        if project_default is None:
            notes.append("no compiler producer and no project default")
            return UnitEnvironment(unit, language, None, (), keys, notes=tuple(notes))
        env = Environment.create(
            project_default.toolchain, language, flags=flags,
            defines=project_default.defines, includes=project_default.includes,
            confidence=0.2,
            evidence=(Evidence("project-default", "no unit producer", unit),),
        )
        notes.append("environment inherited from the project default")
        return UnitEnvironment(unit, language, env,
                               (EnvironmentCandidate(env, 0.2, env.evidence),), keys,
                               notes=tuple(notes))

    matches = _match_toolchains(catalog, producer, target, object_format)
    exact_matches = [t for t in matches
                     if t.family == producer.family and t.version == producer.version
                     and t.object_format == object_format
                     and _norm_target(t.target) == _norm_target(target)]
    toolchain_id = (exact_matches[0].id if exact_matches
                    else canonical_toolchain_id(producer, target))
    if not matches:
        notes.append(f"toolchain {producer.id} is not in the catalog")
    elif not exact_matches:
        notes.append(f"no exact catalog match for {producer.id} / {target}; "
                     f"nearest is {matches[0].id} ({matches[0].target})")

    confidence = 0.9 if exact_matches else 0.65
    if not flags:
        confidence -= 0.05
    if conflict:
        confidence -= 0.1
    confidence = max(0.0, min(0.99, confidence))

    evidence = [Evidence("dwarf-producer", producer.raw, unit)]
    if exact_matches:
        evidence.append(Evidence("toolchain", exact_matches[0].id, "catalog"))
    elif matches:
        evidence.append(Evidence("toolchain-near", matches[0].id, "catalog"))
    if flags:
        evidence.append(Evidence("flags", " ".join(flags), unit))
    env = Environment.create(
        toolchain_id, language, flags=flags, confidence=confidence,
        evidence=tuple(evidence),
    )
    candidates = [EnvironmentCandidate(env, confidence, env.evidence)]
    for toolchain in matches:
        if toolchain.id == toolchain_id:
            continue
        # A same-family/version/target-adjacent build is a candidate, never the
        # selected environment. It is what probe_environment can test later.
        near = 0.5 if toolchain.version == producer.version else 0.35
        alt = Environment.create(
            toolchain.id, language, flags=flags, confidence=near,
            evidence=(Evidence("toolchain-near", toolchain.id, "catalog"),),
        )
        candidates.append(EnvironmentCandidate(alt, near, alt.evidence))
    candidates.sort(key=lambda c: (-c.confidence, c.environment.toolchain))
    return UnitEnvironment(
        unit=unit,
        language=language,
        selected=env,
        candidates=tuple(candidates),
        functions=keys,
        missing_toolchain=not exact_matches,
        notes=tuple(notes),
    )


def resolve_analysis(analysis: Mapping, *, catalog: Mapping[str, Toolchain] | None = None,
                     project_default: Environment | None = None,
                     target: str | None = None) -> ResolutionReport:
    """Resolve every compile unit and map every function to its environment.

    ``catalog`` is optional: without it, a canonical toolchain id is still
    produced so the environment and flag/language facts are usable, but the
    unit is marked ``missing_toolchain`` and confidence is lower.
    """

    catalog = dict(catalog or {})
    fmt = str(analysis.get("format") or "elf").lower()
    arch = str(analysis.get("arch") or "x86_64")
    target = target or normalize_target(fmt, arch)
    default = project_default or _project_default(analysis, target, fmt, catalog)

    unit_facts = analysis.get("unit_compilers") or {}
    functions_by_unit: dict[str, list[Mapping]] = defaultdict(list)
    for fn in analysis.get("functions") or []:
        if isinstance(fn, Mapping):
            functions_by_unit[function_unit(fn)].append(fn)

    units: dict[str, UnitEnvironment] = {}
    for unit in sorted(set(unit_facts) | set(functions_by_unit)):
        facts = unit_facts.get(unit) or {}
        units[unit] = _resolve_unit(
            unit, facts, functions_by_unit.get(unit, []),
            analysis=analysis, catalog=catalog, target=target,
            object_format=fmt, project_default=default,
        )

    functions: dict[str, str | None] = {}
    for unit in units.values():
        for key in unit.functions:
            functions[key] = unit.selected.id if unit.selected is not None else None

    unresolved = tuple(sorted(u.unit for u in units.values() if u.selected is None))
    return ResolutionReport(units=units, functions=functions, unresolved_units=unresolved)
