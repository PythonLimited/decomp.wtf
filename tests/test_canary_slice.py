from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

from dcore.model import resolve_analysis
from dcore.targets import formats
from dcore.targets.plat.pe import seeds
from dcore.toolchains import catalog

CANARY = Path(__file__).parent / "canary" / "build" / "vs2015" / "acme-canary-min.exe"
PDB = CANARY.with_suffix(".pdb")


def _slice():
    spec = importlib.util.spec_from_file_location(
        "dcore_canary_slice_msvc", Path(__file__).parent / "canary" / "slice_msvc.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _pdbutil() -> str | None:
    return (shutil.which("llvm-pdbutil")
            or next((p for p in ("/opt/homebrew/opt/llvm/bin/llvm-pdbutil",
                                 "/usr/local/opt/llvm/bin/llvm-pdbutil")
                     if Path(p).exists()), None))


def test_msvc_canary_exports_and_pdb_code_sizes_are_usable():
    if not CANARY.exists() or not PDB.exists():
        pytest.skip("VS2015 canary not built; run tests/canary/build.sh msvc")
    pdbutil = _pdbutil()
    if pdbutil is None:
        pytest.skip("llvm-pdbutil not available")

    module = _slice()
    data = CANARY.read_bytes()
    image = formats.identify_path(CANARY)
    exports = module._exports(data, image)
    sizes = module._code_sizes(PDB, pdbutil)

    expected = {
        "canary_add", "?canary_widget@@YAHH@Z",
        "?canary_flags@@YAIAEBUFlags@@@Z",
        "?get@Widget@@QEBAHXZ", "?set@Widget@@QEAAXH@Z",
    }
    assert expected <= set(exports)
    assert sizes["canary_add"] == 4
    assert sizes["canary_widget"] == 40
    assert sizes["Widget::get"] == 3
    assert sizes["Widget::set"] == 3

    pdata = (seeds.parse(data) or {}).get("pdata") or []
    report = resolve_analysis(module._analysis(image, exports, pdata, sizes),
                              catalog=catalog())
    unit = next(iter(report.units.values()))
    assert unit.selected is not None
    assert unit.selected.toolchain == "msvc-19.00.24210-x86_64-pc-windows-msvc"
    assert unit.selected.language == "c++"
    assert unit.missing_toolchain is False
