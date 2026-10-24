#!/usr/bin/env python3
"""VS2015 arm of the canary vertical slice.

The minimal PE canary is freestanding (`/NODEFAULTLIB`), so it needs no link
libraries. Functions are exported to give authoritative RVAs; the PDB supplies
types and code sizes. The candidate objects are compiled with the pinned VS2015
image and judged against the exported function bytes.

Run:
    tests/canary/build.sh msvc
    uv run python tests/canary/slice_msvc.py
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

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
from dcore.targets.plat.pe import seeds
from dcore.toolchains import catalog

MSVC_BANNER = "Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24210 for x64"
S_GPROC = re.compile(
    r"S_GPROC32[^\n]*`([^`]+)`\s*\n\s*parent = [^\n]*code size = (\d+)", re.S)
EXPORT_TO_PDB = {
    "?canary_widget@@YAHH@Z": "canary_widget",
    "?canary_flags@@YAIAEBUFlags@@@Z": "canary_flags",
    "?get@Widget@@QEBAHXZ": "Widget::get",
    "?set@Widget@@QEAAXH@Z": "Widget::set",
}
CASES = [
    {
        "linkage": "canary_add", "pdb_name": "canary_add", "required": (),
        "signature": "int (int, int)",
        "body": 'extern "C" int canary_add(int a, int b) { return a + b; }',
    },
    {
        "linkage": "?canary_widget@@YAHH@Z", "pdb_name": "canary_widget",
        "required": ("t:Widget",),
        "signature": "int (int)",
        "body": """
int canary_widget(int seed) {
    Widget widget;
    widget.value = seed;
    widget.set(widget.get() + 2);
    return widget.value;
}
""",
    },
    {
        "linkage": "?canary_flags@@YAIAEBUFlags@@@Z", "pdb_name": "canary_flags",
        "required": ("t:Flags",),
        "signature": "unsigned int (const Flags&)",
        "body": """
unsigned int canary_flags(const Flags& flags) {
    return static_cast<unsigned int>(flags.low)
        | (static_cast<unsigned int>(flags.high) << 3);
}
""",
    },
    {
        "linkage": "?get@Widget@@QEBAHXZ", "pdb_name": "Widget::get",
        "required": ("t:Widget",),
        "signature": "int ()",
        "body": "int Widget::get() const { return value; }",
    },
    {
        "linkage": "?set@Widget@@QEAAXH@Z", "pdb_name": "Widget::set",
        "required": ("t:Widget",),
        "signature": "void (int)",
        "body": "void Widget::set(int next) { value = next; }",
    },
]


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _rva_off(image, rva: int) -> int | None:
    for section in image.sections:
        base = section.vaddr - image.image_base
        if base <= rva < base + section.size:
            return section.offset + (rva - base)
    return None


def _cstring(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else len(data)].decode("latin-1")


def _exports(data: bytes, image) -> dict[str, int]:
    """Name -> VA for named exports. RVAs are authoritative for the linked PE."""

    pe = _u32(data, 0x3C)
    optional = pe + 24
    magic = _u16(data, optional)
    data_dir = optional + (112 if magic == 0x20B else 96)
    export_rva = _u32(data, data_dir)
    if not export_rva:
        return {}
    at = _rva_off(image, export_rva)
    if at is None:
        return {}
    count = _u32(data, at + 24)
    functions = _u32(data, at + 28)
    names = _u32(data, at + 32)
    ordinals = _u32(data, at + 36)
    names_at = _rva_off(image, names)
    ords_at = _rva_off(image, ordinals)
    funcs_at = _rva_off(image, functions)
    if names_at is None or ords_at is None or funcs_at is None:
        return {}
    out: dict[str, int] = {}
    for i in range(min(count, 10000)):
        name = _cstring(data, _rva_off(image, _u32(data, names_at + 4 * i)) or 0)
        ordinal = _u16(data, ords_at + 2 * i)
        func_rva = _u32(data, funcs_at + 4 * ordinal)
        if name and func_rva:
            out[name] = image.image_base + func_rva
    return out


def _code_sizes(pdb: Path, pdbutil: str) -> dict[str, int]:
    out = subprocess.run([pdbutil, "dump", "-symbols", str(pdb)],
                         capture_output=True, text=True, check=True).stdout
    return {name: int(size) for name, size in S_GPROC.findall(out)}


def _function_size(ea: int, pdata: list[tuple[int, int, int]]) -> int | None:
    for begin, end, _unwind in pdata:
        if begin <= ea < end:
            return end - begin
    return None


def _analysis(image, exports: dict[str, int], pdata, sizes: dict[str, int]) -> dict:
    def symbol(case: Mapping) -> dict:
        address = exports[case["linkage"]]
        return {
            "ea": address,
            "size": sizes.get(case["pdb_name"]) or _function_size(address, pdata),
            "name": case["pdb_name"], "display": case["pdb_name"],
            "signature": case["signature"], "linkage": case["linkage"],
            "cu": "src/canary_pe.cpp", "language": "c++", "provenance": "pdb",
        }

    return {
        "format": "pe",
        "arch": "x86_64",
        "dwarf_units": 0,
        "types": [
            {
                "name": "Widget", "ns": [], "size": 4, "align": None, "kind": "struct",
                "members": [{"name": "value", "off": 0, "type": "int"}],
                "statics": [], "bases": [],
                "methods": [
                    {"name": "get", "ret": "int", "params": [], "const": True,
                     "static": False, "virtual": False, "access": 1},
                    {"name": "set", "ret": "void", "params": ["int"], "const": False,
                     "static": False, "virtual": False, "access": 1},
                ],
            },
            {
                "name": "Flags", "ns": [], "size": 4, "align": None, "kind": "struct",
                "members": [
                    {"name": "low", "off": 0, "type": "unsigned int",
                     "bit_offset": 0, "bit_size": 3},
                    {"name": "high", "off": 0, "type": "unsigned int",
                     "bit_offset": 3, "bit_size": 5},
                ],
                "statics": [], "bases": [], "methods": [],
            },
        ],
        "functions": [symbol(case) for case in CASES],
        "data": [],
        "edges": [],
        "unit_compilers": {
            "src/canary_pe.cpp": {"compiler": MSVC_BANNER,
                                  "flags": ["/O2", "/GS-", "/GR-", "/EHs-c-"]},
        },
        "compilers": [{"compiler": MSVC_BANNER,
                       "flags": ["/O2", "/GS-", "/GR-", "/EHs-c-"],
                       "units": 1, "functions": len(CASES)}],
    }


def _target(path: Path, image, exports: dict[str, int], pdata, sizes: dict[str, int]):
    data = path.read_bytes()
    functions: dict[int, dict] = {}
    for name, ea in exports.items():
        size = sizes.get(EXPORT_TO_PDB.get(name, name)) or _function_size(ea, pdata)
        if size:
            functions[ea] = {"ea": ea, "size": int(size), "name": name, "display": name}
    rec = Reconstructor(data, image, functions)
    return rec, functions


def _environment(analysis: dict) -> Environment:
    report = resolve_analysis(analysis, catalog=catalog())
    resolved = [u for u in report.units.values() if u.selected is not None]
    if not resolved:
        raise SystemExit("resolver found no environment")
    return resolved[0].selected


def _compile_config(env: Environment) -> CompilerConfig:
    return CompilerConfig(
        cmd=["cl", "/nologo", "/I{include}", *env.flags,
             "/c", "{src}", "/Fo{obj}"],
        timeout=180,
        sandbox="docker",
        image="dcore-msvc-hangover:2015u3",
        platform="linux/arm64",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canary", type=Path,
                    default=Path(__file__).parent / "build/vs2015/acme-canary-min.exe")
    default_pdbutil = (shutil.which("llvm-pdbutil")
                       or next((p for p in ("/opt/homebrew/opt/llvm/bin/llvm-pdbutil",
                                            "/usr/local/opt/llvm/bin/llvm-pdbutil")
                                if Path(p).exists()), "llvm-pdbutil"))
    ap.add_argument("--pdbutil", default=default_pdbutil)
    args = ap.parse_args()
    if not args.canary.exists():
        raise SystemExit(f"canary not found: {args.canary}; run tests/canary/build.sh msvc")
    pdb = args.canary.with_suffix(".pdb")
    if not pdb.exists():
        raise SystemExit(f"PDB not found: {pdb}")

    data = args.canary.read_bytes()
    image = formats.identify_path(args.canary)
    exports = _exports(data, image)
    sizes = _code_sizes(pdb, args.pdbutil)
    pdata = (seeds.parse(data) or {}).get("pdata") or []

    analysis = _analysis(image, exports, pdata, sizes)
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

    cfg = _compile_config(env)
    layout = compile_source(cfg, prelude + "\n" + probes,
                            "int dcore_canary_layout_anchor = 0;",
                            source_name="layout.cpp")
    if not layout.ok:
        print("layout probe compile FAILED")
        print(layout.log)
        return 1
    print("layout probe compile: ok")

    reader = plat_pack("pe").object_reader()
    rec, functions = _target(args.canary, image, exports, pdata, sizes)
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

        target = rec.view(functions[exports[case["linkage"]]])
        if target is None:
            print(f"{case['linkage']}: target view missing")
            failed += 1
            continue
        verdict = compare(target, candidate)
        print(f"{case['linkage']}: {'MATCH' if verdict.match else 'diff'} "
              f"score={verdict.score}")
        if not verdict.match:
            print(f"  problems: {verdict.problems[:4]}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
