#!/usr/bin/env python3
"""Canary vertical slice: facts -> canonical prelude -> layout probes -> compile -> judge.

This is intentionally separate from the current registry/judge loop. It uses the real
GCC 9.1.0 canary and known source bodies, so a failure points at the model/renderer/
environment rather than at a reconstruction.

Run:
    tests/canary/build.sh gcc
    uv run python tests/canary/slice.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

from dcore.core.compiler import CompilerConfig, compile_source
from dcore.core.judge import compare
from dcore.core.target import Reconstructor
from dcore.model import (
    Environment,
    FunctionDecl,
    render_header,
    render_layout_probes,
    render_prelude,
    resolve_analysis,
)
from dcore.providers import from_analysis
from dcore.targets import formats, plat_pack
from dcore.targets.plat.elf import dwarf
from dcore.toolchains import catalog


def _gcc_analysis(path: Path) -> dict:
    data = dwarf.analyze(path)
    types = [t for t in data.get("types") or []
             if (t.get("ns") or [])[:2] == ["ACME", "Aurora"]]
    functions = [f for f in data.get("functions") or []
                 if f.get("low") is not None and f.get("linkage")]
    units = {
        cu["path"]: {"compiler": cu["producer"], "flags": list(cu["flags"])}
        for cu in data.get("compile_units") or []
        if cu.get("path") and cu.get("producer")
    }
    return {
        "format": "elf",
        "arch": "x86_64",
        "dwarf_units": len(data.get("compile_units") or []),
        "types": types,
        "functions": functions,
        "data": data.get("data") or [],
        "edges": data.get("edges") or [],
        "unit_compilers": units,
        "compilers": [
            {"compiler": cu["producer"], "flags": list(cu["flags"]),
             "units": 1, "functions": len(functions)}
            for cu in data.get("compile_units") or [] if cu.get("producer")
        ],
    }


def _target(path: Path, linkage: str):
    data = path.read_bytes()
    image = formats.identify_path(path)
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise SystemExit("target has no .symtab")
        functions: dict[int, dict] = {}
        wanted = None
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC" or not sym["st_value"]:
                continue
            entry = {"ea": int(sym["st_value"]), "size": int(sym["st_size"] or 0),
                     "name": sym.name, "display": sym.name}
            functions[entry["ea"]] = entry
            if sym.name == linkage:
                wanted = entry
    if wanted is None:
        raise SystemExit(f"target symbol not found: {linkage}")
    rec = Reconstructor(data, image, functions)
    target = rec.view(wanted)
    if target is None:
        raise SystemExit(f"could not read target function {linkage}")
    return target


def _environment(analysis: dict) -> Environment:
    report = resolve_analysis(analysis, catalog=catalog())
    resolved = [u for u in report.units.values() if u.selected is not None]
    if not resolved:
        raise SystemExit("resolver found no environment")
    return resolved[0].selected


def _compile_config(env: Environment, platform: str) -> CompilerConfig:
    return CompilerConfig(
        cmd=["g++", "-I{include}", *env.flags, "-c", "{src}", "-o", "{obj}"],
        timeout=180,
        sandbox="docker",
        image="gcc:9.1.0",
        platform=platform,
    )


CASES = [
    {
        "linkage": "_ZN4ACME6Aurora3addEii",
        "required": (),
        "body": """
namespace ACME { namespace Aurora {
int add(int a, int b) { return a + b; }
}}
""",
    },
    {
        "linkage": "_ZNK4ACME6Aurora6Widget3getEv",
        "required": ("t:ACME::Aurora::Widget",),
        "body": """
namespace ACME { namespace Aurora {
int Widget::get() const { return value; }
}}
""",
    },
    {
        "linkage": "_ZN4ACME6Aurora11flags_valueERKNS0_5FlagsE",
        "required": ("t:ACME::Aurora::Flags",),
        "body": """
namespace ACME { namespace Aurora {
unsigned int flags_value(const Flags& flags) {
    return static_cast<unsigned int>(flags.low)
        | (static_cast<unsigned int>(flags.high) << 3)
        | (static_cast<unsigned int>(flags.wide) << 8);
}
}}
""",
    },
    {
        "linkage": "_ZN4ACME6Aurora12call_virtualERKNS0_11VirtualBaseE",
        "required": ("t:ACME::Aurora::VirtualBase",),
        "body": """
namespace ACME { namespace Aurora {
int call_virtual(const VirtualBase& base) { return base.value(); }
}}
""",
    },
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canary", type=Path,
                    default=Path(__file__).parent / "build/gcc91/acme-canary")
    args = ap.parse_args()
    if not args.canary.exists():
        raise SystemExit(f"canary not found: {args.canary}; run tests/canary/build.sh gcc")

    analysis = _gcc_analysis(args.canary)
    env = _environment(analysis)
    facts = from_analysis(analysis)
    prelude = render_prelude(facts, include_functions=False)
    probes = render_layout_probes(facts, environment="@binary")

    out = args.canary.parent
    (out / "context.h").write_text(prelude, encoding="utf-8")
    (out / "layout_probes.h").write_text(probes, encoding="utf-8")
    print(f"environment: {env.toolchain}")
    print(f"flags: {' '.join(env.flags)}")
    print(f"prelude: {len(prelude.splitlines())} lines, probes: {len(probes.splitlines())} lines")
    by_linkage = {f.entity.linkage: f.entity.id for f in facts.facts
                  if isinstance(f.entity, FunctionDecl) and f.entity.linkage}

    cfg = _compile_config(env, "linux/amd64")
    layout = compile_source(cfg, prelude + "\n" + probes,
                            "int dcore_canary_layout_anchor = 0;",
                            source_name="layout.cpp")
    if not layout.ok:
        print("layout probe compile FAILED")
        print(layout.log)
        return 1
    print("layout probe compile: ok")

    reader = plat_pack("elf").object_reader()
    failed = 0
    for case in CASES:
        result = compile_source(cfg, prelude, case["body"], source_name="func.cpp")
        if not result.ok or result.obj is None:
            print(f"{case['linkage']}: compile FAILED")
            print(result.log)
            failed += 1
            continue
        candidate = reader.extract_function(result.obj, case["linkage"])
        if candidate is None:
            print(f"{case['linkage']}: candidate symbol missing")
            failed += 1
            continue

        fid = by_linkage.get(case["linkage"])
        if fid is None:
            print(f"{case['linkage']}: no function fact")
            failed += 1
            continue
        header = render_header(facts, fid, references=facts.references,
                               required=case["required"], include_functions=False)
        closure = compile_source(cfg, header, case["body"], source_name="func.cpp")
        if not closure.ok or closure.obj is None:
            print(f"{case['linkage']}: closure compile FAILED")
            print(closure.log)
            failed += 1
            continue
        closed = reader.extract_function(closure.obj, case["linkage"])
        same = (closed is not None and closed.code == candidate.code
                and [(r.offset, r.type, r.symbol, r.addend) for r in closed.relocs]
                == [(r.offset, r.type, r.symbol, r.addend) for r in candidate.relocs])
        print(f"  closure: {'identical' if same else 'DIFF'} "
              f"({len(header.splitlines())} lines)")
        if not same:
            failed += 1

        target = _target(args.canary, case["linkage"])
        verdict = compare(target, candidate)
        print(f"{case['linkage']}: {'MATCH' if verdict.match else 'diff'} "
              f"score={verdict.score}")
        if not verdict.match:
            print(f"  problems: {verdict.problems[:4]}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
