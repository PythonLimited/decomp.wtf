from __future__ import annotations

from pathlib import Path

import pytest

from dcore.model import resolve_analysis
from dcore.targets import formats
from dcore.toolchains import catalog

CANARY = Path(__file__).parent / "canary" / "build"
MSVC_PRODUCER = "Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24210 for x64"


def test_the_first_toolchain_catalog_has_the_two_targets():
    tools = catalog()
    assert set(tools) == {
        "gcc-9.1.0-x86_64-linux-gnu",
        "msvc-19.00.24210-x86_64-pc-windows-msvc",
    }
    gcc = tools["gcc-9.1.0-x86_64-linux-gnu"]
    msvc = tools["msvc-19.00.24210-x86_64-pc-windows-msvc"]
    assert (gcc.family, gcc.version, gcc.object_format) == ("gcc", "9.1.0", "elf")
    assert (msvc.family, msvc.version, msvc.object_format) == ("msvc", "19.00.24210", "pe")
    assert gcc.platform == "linux/amd64"
    assert msvc.platform == "linux/amd64"


def test_gcc_canary_resolves_to_the_gcc_descriptor():
    path = CANARY / "gcc91" / "acme-canary"
    if not path.exists():
        pytest.skip("GCC canary not built; run tests/canary/build.sh gcc")

    from dcore.targets.plat.elf import dwarf

    data = dwarf.analyze(path)
    units = {
        cu["path"]: {"compiler": cu["producer"], "flags": list(cu["flags"])}
        for cu in data["compile_units"]
        if cu.get("path") and cu.get("producer")
    }
    functions = [
        {"ea": f["low"], "name": f.get("name") or f.get("linkage"), "cu": f["cu"],
         "language": f.get("language")}
        for f in data["functions"] if f.get("kind") == "function"
    ]
    assert units and functions

    report = resolve_analysis({
        "format": "elf", "arch": "x86_64", "unit_compilers": units,
        "functions": functions, "compilers": [],
    }, catalog=catalog())

    unit = next(iter(report.units.values()))
    assert unit.selected is not None
    assert unit.selected.toolchain == "gcc-9.1.0-x86_64-linux-gnu"
    assert unit.selected.language == "c++"
    assert "-O2" in unit.selected.flags
    assert "-fPIC" in unit.selected.flags
    assert unit.missing_toolchain is False
    assert len(report.functions) == len(functions)
    assert all(env == unit.selected.id for env in report.functions.values())


def test_msvc_pe_canary_is_a_real_pe_and_resolves_to_the_msvc_descriptor():
    path = CANARY / "vs2015" / "acme-canary-min.exe"
    if not path.exists():
        pytest.skip("MSVC canary not built; run tests/canary/build.sh msvc")

    image = formats.identify_path(path)
    assert image.format == "pe"
    assert image.arch == "x86_64"

    report = resolve_analysis({
        "format": image.format,
        "arch": image.arch,
        "unit_compilers": {
            "src/canary_pe.cpp": {"compiler": MSVC_PRODUCER, "flags": ["/O2", "/GS-", "/GR-"]},
        },
        "functions": [
            {"ea": 0x140001000, "name": "main", "cu": "src/canary_pe.cpp", "language": "c++"},
        ],
        "compilers": [],
    }, catalog=catalog())

    unit = report.units["src/canary_pe.cpp"]
    assert unit.selected is not None
    assert unit.selected.toolchain == "msvc-19.00.24210-x86_64-pc-windows-msvc"
    assert unit.selected.language == "c++"
    assert unit.selected.flags == ("/O2", "/GS-", "/GR-")
    assert unit.missing_toolchain is False
    assert (CANARY / "vs2015" / "acme-canary-min.pdb").exists()
