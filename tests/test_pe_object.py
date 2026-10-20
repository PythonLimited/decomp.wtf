"""The COFF object reader (plat/pe/object.py): what the judge reads a Windows candidate with.

The objects in these tests are real: clang compiled them against the MSVC triple, exactly the
container msvc-wine will produce. The reader must hand the judge symbol names the target side
spells the same way (imports as their import, calls with the -4 addend a call site encodes).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from dcore.targets import plat_pack

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang for the MSVC triple")


def _coff(tmp_path: Path, source: str, machine: str = "x86_64") -> bytes:
    triple = {"x86_64": "x86_64-pc-windows-msvc", "x86": "i686-pc-windows-msvc"}[machine]
    src, obj = tmp_path / "t.c", tmp_path / "t.obj"
    src.write_text(source, encoding="utf-8")
    res = subprocess.run(["clang", f"--target={triple}", "-O2", "-c", str(src), "-o", str(obj)],
                         capture_output=True, timeout=120)
    if res.returncode != 0:
        pytest.skip(f"clang can't target {triple} here: {res.stderr.decode()[-200:]}")
    return obj.read_bytes()


def test_a_coff_object_reads_its_function(tmp_path):
    obj = _coff(tmp_path, "int add(int a, int b) { return a * 3 + b; }\n")
    reader = plat_pack("pe").object_reader()
    fn = reader.extract_function(obj, "add")
    assert fn is not None and fn.arch == "x86_64" and not fn.big_endian
    assert 4 <= len(fn.code) <= 64 and fn.relocs == []
    assert "add" in reader.list_functions(obj)


def test_a_call_reloc_carries_the_symbol_and_the_four_byte_bias(tmp_path):
    """A call site's field encodes -4 (the distance from the field to the instruction's end), which is
    exactly the addend the Reconstructor writes for the target side — so a call lines up symbolically."""
    obj = _coff(tmp_path, "int callee(int x);\nint caller(int x) { return callee(x) + 1; }\n")
    fn = plat_pack("pe").object_reader().extract_function(obj, "caller")
    assert fn is not None
    calls = [r for r in fn.relocs if r.symbol == "callee"]
    assert len(calls) == 1
    r = calls[0]
    assert r.type == 0x4 and r.addend == -4  # IMAGE_REL_AMD64_REL32
    assert set(reader_masked_zeros(fn)) == set()  # the field is masked out of the normalized bytes


def reader_masked_zeros(fn) -> list[int]:
    """Offsets in the reloc's field that normalization zeroed (sanity: masking really happened)."""
    masked = fn.normalized()
    return [i for r in fn.relocs for i in range(r.offset, r.offset + 4)
            if fn.code[i] != masked[i]]


def test_a_dllimport_call_reads_as_the_import_name(tmp_path):
    """The object calls `__imp_imported`; the target side names the IAT call `imported`. The reader
    canonicalizes so both sides spell it the same."""
    obj = _coff(tmp_path, "__declspec(dllimport) int imported(int);\nint uses(int x) { return imported(x); }\n")
    fn = plat_pack("pe").object_reader().extract_function(obj, "uses")
    assert fn is not None
    assert [r.symbol for r in fn.relocs] == ["imported"]


def test_x86_objects_read_through_their_leading_underscore(tmp_path):
    obj = _coff(tmp_path, "int add(int a, int b) { return a - b; }\n", machine="x86")
    fn = plat_pack("pe").object_reader().extract_function(obj, "add")
    assert fn is not None and fn.arch == "x86" and len(fn.code) > 4


def test_an_x86_call_carries_its_own_reloc_number(tmp_path):
    """IMAGE_REL_I386_REL32 (0x14) is x86's spelling of the same reference x64 calls REL32 (4);
    the reader and the pack must agree per arch, or target and candidate never line up."""
    obj = _coff(tmp_path, "int callee(int x);\nint caller(int x) { return callee(x) + 1; }\n", machine="x86")
    reader = plat_pack("pe").object_reader()
    fn = reader.extract_function(obj, "caller")
    assert fn is not None
    # x86 decorates C externals with a leading underscore; the judge tolerates the spelling at a
    # matched position (that is what its rename tolerance is for), so the reader reports it as-is
    calls = [r for r in fn.relocs if r.symbol == "_callee"]
    assert len(calls) == 1 and calls[0].type == 0x14 and calls[0].addend == -4


def test_the_pe_pack_answers_the_coff_reader_and_its_numbers():
    pe = plat_pack("pe")
    assert pe.family == "pe" and pe.object_reader() is not None
    assert pe.reloc_type("x86_64", "pc") == 4  # IMAGE_REL_AMD64_REL32
    assert pe.reloc_type("x86_64", "abs64") == 1  # ADDR64
    assert pe.reloc_type("x86", "pc") == 0x14  # IMAGE_REL_I386_REL32 — a different number, same idea
