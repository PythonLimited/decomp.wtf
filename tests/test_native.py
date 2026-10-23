"""Native mode: format identification and import plumbing.

Analysis (IDA + DWARF), the plan model and the per-function judge land with their phases;
these are the phase-0 tests: what a dropped ELF/PE is, and that importing one registers a
`native` project without touching any console path.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from dcore.targets import formats

SRC = """\
#include <stdio.h>

static int clamp_i(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int score_update(int *score, int delta, int max) {
    *score = clamp_i(*score + delta, 0, max);
    return *score;
}

int main(void) {
    int s = 0;
    printf("%d\\n", score_update(&s, 10, 100));
    return 0;
}
"""

CPP_SRC = """\
namespace game {
struct Player {
    int hp;
    virtual int update(int delta);
};
int Player::update(int delta) {
    hp += delta;
    if (hp < 0) hp = 0;
    return hp;
}
int free_fn(int x) { return x * 2; }
}
"""


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _build_elf(tmp_path: Path) -> bytes | None:
    """A small linked ELF with DWARF: zig can cross-link one anywhere (bundled libc); on Linux a
    system C compiler does it natively."""
    src = tmp_path / "hello.c"
    src.write_text(SRC)
    out = tmp_path / "hello"
    if (zig := shutil.which("zig")):
        cmd = [zig, "cc", "-target", "x86_64-linux-gnu", "-g", "-O2", str(src), "-o", str(out)]
    elif sys.platform.startswith("linux") and (cc := shutil.which("cc") or shutil.which("gcc")):
        cmd = [cc, "-g", "-O2", str(src), "-o", str(out)]
    else:
        return None
    try:
        _run(cmd)
    except subprocess.CalledProcessError:
        return None
    return out.read_bytes()


@pytest.fixture(scope="module")
def elf_bytes(tmp_path_factory) -> bytes:
    data = _build_elf(tmp_path_factory.mktemp("native"))
    if data is None:
        pytest.skip("needs zig or a Linux C compiler to build the ELF fixture")
    return data


@pytest.fixture(scope="module")
def elf_object(tmp_path_factory) -> bytes:
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("needs clang to cross-compile an ELF object")
    tmp = tmp_path_factory.mktemp("native-obj")
    src = tmp / "math.c"  # no libc headers: a cross-target -c needs no sysroot this way
    src.write_text("int add(int a, int b) { return a + b; }\nint sub(int a, int b) { return a - b; }\n")
    out = tmp / "math.o"
    try:
        _run([clang, "-target", "x86_64-unknown-linux-gnu", "-g", "-O2", "-c", str(src), "-o", str(out)])
    except subprocess.CalledProcessError:
        pytest.skip("this clang can't cross-compile for x86_64-unknown-linux-gnu")
    return out.read_bytes()


def _pe_bytes(build: int = 30319, extra: tuple[tuple[int, int], ...] = ()) -> bytes:
    """A minimal but valid PE32+ with a Rich header and a CodeView (RSDS) debug directory.

    `build` lands in a first entry (prodid 1, 3 objects); `extra` adds more (comp.id, count) entries —
    comp.id = high 16 bits product id + low 16 bits build, the real Rich layout."""
    image_base, pe_off, size_opt = 0x140000000, 0x80, 0xF0
    opt = pe_off + 24
    raw = bytearray(0x200 + 0x200)
    raw[0:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, pe_off)
    raw[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, pe_off + 4, 0x8664, 1, 0x5F000000, 0, 0, size_opt, 0x22)
    struct.pack_into("<H", raw, opt, 0x20B)
    struct.pack_into("<I", raw, opt + 16, 0x1000)
    struct.pack_into("<Q", raw, opt + 24, image_base)
    struct.pack_into("<I", raw, opt + 32, 0x1000)
    struct.pack_into("<I", raw, opt + 36, 0x200)
    struct.pack_into("<I", raw, opt + 56, 0x2000)
    struct.pack_into("<I", raw, opt + 60, 0x200)
    struct.pack_into("<H", raw, opt + 68, 3)
    struct.pack_into("<I", raw, opt + 108, 16)
    struct.pack_into("<II", raw, opt + 112 + 6 * 8, 0x1020, 28)  # debug directory
    struct.pack_into("<8sIIII", raw, opt + size_opt, b".rdata", 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", raw, opt + size_opt + 36, 0x40000040)
    blob = b"RSDS" + bytes(range(16)) + struct.pack("<I", 7) + b"C:\\game\\game.pdb\0"
    struct.pack_into("<IIHHIIII", raw, 0x220, 0, 0, 0, 0, 2, len(blob), 0x1040, 0x240)
    raw[0x240:0x240 + len(blob)] = blob
    key = 0x5A5A5A5A
    for i, w in enumerate((0x536E6144, 0, 0, 0)):  # "DanS" marker, XOR-encrypted
        struct.pack_into("<I", raw, 0x40 + 4 * i, w ^ key)
    entries = [((1 << 16) | build, 3), *extra]
    for i, (comp, count) in enumerate(entries):
        struct.pack_into("<II", raw, 0x50 + 8 * i, comp ^ key, count ^ key)
    rich = 0x50 + 8 * len(entries)
    raw[rich:rich + 4] = b"Rich"
    struct.pack_into("<I", raw, rich + 4, key)
    return bytes(raw)


# ------------------------------------------------------------------ identification


def test_identify_rejects_what_is_not_native():
    assert formats.identify(b"\x80\x37\x12\x40" + bytes(60)) is None  # N64 magic
    assert formats.identify(b"not a program at all") is None
    assert formats.identify(b"") is None


def test_identify_linked_elf(elf_bytes):
    image = formats.identify(elf_bytes)
    assert image is not None
    assert (image.format, image.arch, image.kind) == ("elf", "x86_64", "exe")
    assert image.has_debug and image.debug_kind == "dwarf"
    assert image.compiler  # zig's clang reports itself in .comment
    assert any(s.name == ".text" and s.kind == "code" for s in image.sections)
    assert image.image_base and image.entry
    assert "executable" in formats.describe(image) and "DWARF" in formats.describe(image)


def test_identify_elf_object(elf_object):
    image = formats.identify(elf_object)
    assert image is not None
    assert (image.format, image.kind, image.arch) == ("elf", "object", "x86_64")
    assert image.has_debug


def test_identify_pe_with_rich_header_and_pdb():
    image = formats.identify(_pe_bytes())
    assert image is not None
    assert (image.format, image.arch, image.kind) == ("pe", "x86_64", "exe")
    assert image.image_base == 0x140000000 and image.entry == 0x140001000
    assert image.has_debug and image.debug_kind == "pdb"
    assert image.pdb["path"] == "C:\\game\\game.pdb" and image.pdb["age"] == 7
    assert image.compiler == "MSVC 16.00 (VS2010)"  # Rich header build 30319
    assert any(s.name == ".rdata" for s in image.sections)


def test_rich_header_picks_the_dominant_toolset():
    """Real headers mix toolsets the way ORION's exe does: 6474 objects from cl 24215 (VS2015 U3),
    a couple from VS2013 (prodid 0xDD, build 21005 — richprint's example dword, 0x00DD520D) and a
    stray entry from something newer (build 30729). The compiler that built the binary is the
    dominant entry, never the highest build."""
    image = formats.identify(_pe_bytes(build=30319, extra=(
        ((0x0105 << 16) | 24215, 6474),
        ((0x00DD << 16) | 21005, 2),
        ((0x0109 << 16) | 30729, 1),
    )))
    assert image.compiler == "MSVC 19.00 (VS2015 U3)"


def test_looks_native_reads_headers_only(elf_bytes):
    assert formats.looks_native(elf_bytes[:4096]) == ("elf", "x86_64")
    assert formats.looks_native(_pe_bytes()[:4096]) == ("pe", "x86_64")
    assert formats.looks_native(b"\x7fELF" + bytes(60)) is None  # ELF, but not a native machine


# ------------------------------------------------------------------ import plumbing


def test_import_creates_a_native_project(tmp_path, elf_bytes):
    from dcore.core.engine import Engine

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    slug = net.import_rom(elf_bytes, confirmed=True, name="hello-native", log=lambda *_: None)
    ov = net.overview(slug)
    assert ov["kind"] == "native" and ov["platform_name"] == "Native program"
    assert ov["binary"]["format"] == "elf" and ov["binary"]["arch"] == "x86_64"
    assert ov["binary"]["debug"] == "dwarf" and ov["binary"]["compiler"]
    assert ov["functions"] == 0 and not ov["ready"]
    root = Path(net.project_row(slug)["root"])
    assert (root / "hello-native").read_bytes() == elf_bytes
    # the same bytes again: the same project, not a second copy
    assert net.import_rom(elf_bytes, confirmed=True, name="hello-native", log=lambda *_: None) == slug
    assert "Native program" in net.list_projects() or slug in net.list_projects()


def test_import_requires_the_own_copy_confirmation(tmp_path, elf_bytes):
    from dcore.core.engine import Engine
    from dcore.core.network import NetworkError

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    with pytest.raises(NetworkError, match="own"):
        net.import_rom(elf_bytes, name="hello-native", log=lambda *_: None)


def test_import_points_the_analysis_at_an_ida_database(tmp_path, elf_bytes):
    import json as _json

    from dcore.core.engine import Engine

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    game = tmp_path / "hello-native"
    game.write_bytes(elf_bytes)
    mine = tmp_path / "somewhere-else.i64"
    mine.write_bytes(b"IDA")
    slug = net.import_rom(game, confirmed=True, name=game.name, ida_db=str(mine), log=lambda *_: None)
    cfg = _json.loads(net.project_row(slug)["config"])
    assert cfg["ida"] == {"database": str(mine), "detected": False}
    # without the field, a database sitting next to the binary is picked up on its own
    other = tmp_path / "hello-two"
    other.write_bytes(elf_bytes + b"\x00")  # a different file, so it's a different project
    (tmp_path / "hello-two.i64").write_bytes(b"IDA")
    slug2 = net.import_rom(other, confirmed=True, name=other.name, log=lambda *_: None)
    cfg2 = _json.loads(net.project_row(slug2)["config"])
    assert cfg2["ida"]["detected"] is True and cfg2["ida"]["database"].endswith("hello-two.i64")


# ------------------------------------------------------------------ analysis: DWARF, merge, graph


def test_dwarf_pass_reads_units_functions_and_inlines(tmp_path, elf_bytes):
    from dcore.targets.plat.elf import dwarf

    binary = tmp_path / "hello"
    binary.write_bytes(elf_bytes)
    analysis = dwarf.analyze(binary)
    hello = next(cu for cu in analysis["compile_units"] if cu["path"].endswith("hello.c"))
    assert Path(hello["path"]).is_absolute() and "clang" in hello["compiler"]
    names = {f.get("name") for f in analysis["functions"]}
    assert {"score_update", "main"} <= names
    score = next(f for f in analysis["functions"] if f.get("name") == "score_update" and f["kind"] == "function")
    assert score["decl_line"] and score["end"] > score["low"]
    assert score["decl_file"].endswith("hello.c")
    assert score["line_file"].endswith("hello.c")  # the line table files it under its own source
    # clamp_i is either its own function or (at -O2) an inline frame inside score_update
    assert "clamp_i" in names or any(i.get("name") == "clamp_i" for i in score["inlines"])
    assert analysis["by_low"].get(score["low"]) is not None


def test_language_follows_the_original_translation_unit(tmp_path, elf_bytes):
    from dcore.targets.plat.elf import dwarf

    binary = tmp_path / "hello"
    binary.write_bytes(elf_bytes)
    analysis = dwarf.analyze(binary)
    hello = next(cu for cu in analysis["compile_units"] if cu["path"].endswith("hello.c"))
    assert hello["language"] == "c"
    score = next(f for f in analysis["functions"] if f.get("name") == "score_update" and f["kind"] == "function")
    assert score["language"] == "c" and score["linkage"] is None

    # C++: a namespaced class method; its CU is C++ and DWARF carries the mangled linkage name
    src = tmp_path / "game.cpp"
    src.write_text(CPP_SRC)
    out = tmp_path / "game.o"
    if (zig := shutil.which("zig")):
        cmd = [zig, "c++", "-target", "x86_64-linux-gnu", "-g", "-O2", "-c", str(src), "-o", str(out)]
    elif sys.platform.startswith("linux") and (cxx := shutil.which("c++") or shutil.which("g++")):
        cmd = [cxx, "-g", "-O2", "-c", str(src), "-o", str(out)]
    else:
        pytest.skip("needs zig or a Linux C++ compiler")
    try:
        _run(cmd)
    except subprocess.CalledProcessError:
        pytest.skip("the C++ fixture didn't compile")
    cpp = dwarf.analyze(out)
    cu = next(c for c in cpp["compile_units"] if c["path"].endswith("game.cpp"))
    assert cu["language"] == "c++"
    update = next(f for f in cpp["functions"]
                  if f["kind"] == "function" and (f.get("name") or "").endswith("update"))
    assert update["language"] == "c++" and update["linkage"].startswith("_Z")


def test_merge_prefers_dwarf_names_and_folds_edges():
    from dcore.core import analyze as analyze_mod

    ida = {"functions": [
        {"ea": 0x1000, "end": 0x1020, "name": "sub_1000", "demangled": "", "lib": False, "signature": "", "file": None, "line": None},
        {"ea": 0x1020, "end": 0x1050, "name": "known_lib", "demangled": "", "lib": True, "signature": "", "file": None, "line": None},
        {"ea": 0x1050, "end": 0x1050, "name": "empty", "demangled": "", "lib": False, "signature": "", "file": None, "line": None},
        {"ea": 0x1060, "end": 0x1080, "name": "_ZN4game6Player6updateEi", "demangled": "game::Player::update(int)",
         "lib": False, "signature": "", "file": None, "line": None},
    ], "edges": [{"ea": 0x1000, "to": [0x1020, 0x1020]}, {"ea": 0x1020, "to": [0x1000]}]}
    dwarf_data = {"functions": [
        {"kind": "function", "name": "player_update", "linkage": None, "low": 0x1000, "end": 0x1020,
         "cu": "/src/player.c", "decl_line": 12, "inlines": [{"name": "clamp", "low": 0x1004, "end": 0x1008,
                                                             "call_file": "/src/player.c", "call_line": 14}]},
        {"kind": "inline", "name": "clamp", "low": 0x1004, "end": 0x1008, "enclosing": "player_update"},
    ], "compile_units": [{"path": "/src/player.c", "compiler": "gcc 12.2.0", "flags": ["-O2"], "units": 1}]}
    merged = analyze_mod.merge(ida, dwarf_data, {"format": "elf", "arch": "x86_64"})
    by_ea = {f["ea"]: f for f in merged["functions"]}
    assert 0x1050 not in by_ea  # no body: skipped
    assert by_ea[0x1000]["name"] == "player_update" and by_ea[0x1000]["provenance"] == "dwarf"
    assert by_ea[0x1000]["file"] == "/src/player.c" and by_ea[0x1000]["inline"][0]["name"] == "clamp"
    assert by_ea[0x1020]["provenance"] == "flirt" and by_ea[0x1020]["lib"]
    assert by_ea[0x1000]["language"] == "c"  # DWARF CU without a language: a C name implies C
    assert by_ea[0x1060]["language"] == "c++"  # mangled name without DWARF: still C++
    assert by_ea[0x1060]["display"] == "game::Player::update(int)"
    assert merged["edges"] == [{"ea": 0x1000, "to": [0x1020]}, {"ea": 0x1020, "to": [0x1000]}]
    assert merged["compilers"][0]["compiler"] == "gcc 12.2.0" and merged["compilers"][0]["flags"] == ["-O2"]


def test_cascade_stops_at_interface():
    from dcore.core import plan

    graph_data = {"dependents": {"lib.c": ["mid.c"], "mid.c": ["app.c"], "other.c": ["app.c"]}}
    treatments = {"lib.c": "decompile", "mid.c": "decompile", "app.c": "decompile", "other.c": "decompile"}
    assert plan.cascade(graph_data, treatments, "lib.c") == ["app.c", "mid.c"]
    treatments["mid.c"] = "interface"  # doesn't compile: the cascade must stop there
    assert plan.cascade(graph_data, treatments, "lib.c") == []


def _native_project(tmp_path, elf_bytes):
    from dcore.core.engine import Engine

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    slug = net.import_rom(elf_bytes, confirmed=True, name="hello-native", log=lambda *_: None)
    root = Path(net.project_row(slug)["root"])
    return net, slug, root / "hello-native"


def _write_dwarf_analysis(net, slug, binary, tmp_path, cu_suffix: str, types: bool = False):
    """A merged analysis for one DWARF compile unit (C or C++), no IDA needed."""
    import json as _json

    from dcore.targets.plat.elf import dwarf
    from dcore.core import graph
    from dcore.backends.ida.session import sha256_file

    real = dwarf.analyze(binary)
    functions = []
    for f in real["functions"]:
        if f.get("kind") != "function" or not (f.get("cu") or "").endswith(cu_suffix):
            continue
        functions.append({"ea": f["low"], "end": f["end"], "size": f["end"] - f["low"],
                          "name": f["name"], "linkage": f.get("linkage"), "demangled": "",
                          "display": f["name"], "file": f.get("cu"), "provenance": "dwarf",
                          "lib": False, "language": "c++" if cu_suffix.endswith((".cpp", ".cc"))
                          else "c", "signature": "", "line": f.get("decl_line"),
                          "inline": f.get("inlines") or []})
    analysis = {"schema": 1, "format": "elf", "arch": "x86_64", "functions": functions,
                "edges": [], "graph": graph.build(functions, []), "compilers": [],
                "dwarf_units": 1, "imports": [], "exports": [], "strings": [], "ida": {},
                "sha256": sha256_file(binary), "generated_at": 0.0}
    if types:
        analysis["types"] = real.get("types") or []
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "analysis.json").write_text(_json.dumps(analysis))
    net._update_cfg(slug, lambda cfg: cfg.__setitem__("analysis", {"file": ".decomp-wtf/native/analysis.json"}))
    return analysis


def _cpp_fixture_compiler():
    if (zig := shutil.which("zig")):
        return f"{zig} c++ -target x86_64-linux-gnu", ["-g", "-O2"]
    if sys.platform.startswith("linux") and (cxx := shutil.which("c++") or shutil.which("g++")):
        return cxx, ["-g", "-O2"]
    return None


def _build_cpp_elf(tmp_path: Path) -> bytes | None:
    compiler = _cpp_fixture_compiler()
    if compiler is None:
        return None
    command, flags = compiler
    src = tmp_path / "game.cpp"
    src.write_text(CPP_SRC + "\nint main() { game::Player p; return p.update(1); }\n")
    out = tmp_path / "game-native"
    try:
        _run([*command.split(), *flags, str(src), "-o", str(out)])
    except subprocess.CalledProcessError:
        return None
    return out.read_bytes()


def _write_fake_analysis(net, slug, binary, tmp_path):
    """A merged analysis built from the fixture's real DWARF — no IDA needed for plan tests."""
    import json as _json

    from dcore.targets.plat.elf import dwarf
    from dcore.core import graph
    from dcore.backends.ida.session import sha256_file

    real = dwarf.analyze(binary)
    fns = {f["name"]: f for f in real["functions"]
           if f.get("kind") == "function" and (f.get("cu") or "").endswith("hello.c")}
    functions = [{"ea": f["low"], "end": f["end"], "size": f["end"] - f["low"], "name": name, "linkage": None,
                  "demangled": "", "display": name, "file": path, "provenance": "dwarf", "lib": False,
                  "language": "c", "signature": "", "line": f.get("decl_line"), "inline": f.get("inlines") or []}
                 for path, name, f in (("src/hello.c", "score_update", fns["score_update"]),
                                       ("src/main.c", "main", fns["main"]))]
    edges = [{"ea": fns["score_update"]["low"], "to": [fns["main"]["low"]]}]  # invented: hello calls main
    analysis = {"schema": 1, "format": "elf", "arch": "x86_64", "functions": functions, "edges": edges,
                "graph": graph.build(functions, edges), "compilers": [], "dwarf_units": 1,
                "imports": [], "exports": [], "strings": [], "ida": {},
                "sha256": sha256_file(binary), "generated_at": 0.0}
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "analysis.json").write_text(_json.dumps(analysis))
    net._update_cfg(slug, lambda cfg: cfg.__setitem__("analysis", {"file": ".decomp-wtf/native/analysis.json"}))
    return analysis


def test_name_function_alias_is_visible_to_the_symbol_table(tmp_path, elf_bytes):
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    agent, _ = net.local_agent("alias")
    row = net.project_row(slug)
    net.native.name_function(agent, row, "renamed_target", "0x401234", "IDA left it unnamed")
    table = net.native.symbol_table(row)
    assert table.resolve_code("renamed_target") == 0x401234
    assert net.cfg(net.project_row(slug))["symbol_aliases"]["renamed_target"] == 0x401234
    try:
        net.native.name_function(agent, row, "score_update", "0x401239")
    except NetworkError as e:
        assert "already resolves" in str(e)
    else:
        raise AssertionError("a conflicting alias must be refused")


def test_name_data_alias_is_visible_to_the_symbol_table(tmp_path, elf_bytes):
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    agent, _ = net.local_agent("data-alias")
    row = net.project_row(slug)
    net.native.name_data(agent, row, "counter", "0x5000", "IDA left it unnamed")
    table = net.native.symbol_table(row)
    assert table.resolve_data("counter") == 0x5000
    assert net.cfg(net.project_row(slug))["data_aliases"]["counter"] == 0x5000
    try:
        net.native.name_data(agent, row, "counter", "0x5008")
    except NetworkError as e:
        assert "already resolves" in str(e)
    else:
        raise AssertionError("a conflicting data alias must be refused")


def test_plan_treatments_cascade_and_confirm(tmp_path, elf_bytes):
    import json as _json

    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    forced = plan.set_treatment(net, slug, "src/main.c", "exclude")
    assert forced["forced"] == ["src/hello.c"]  # hello calls into main: it follows
    plan.set_treatment(net, slug, "src/hello.c", "decompile")
    assert plan.set_treatment(net, slug, "src/main.c", "interface")["forced"] == []
    counts = plan.confirm(net, slug, log=lambda *_: None)
    assert counts == {"open": 1, "interface": 1, "missing": 0, "removed": 0}
    rows = {r["name"]: r for r in net.store.all("SELECT name,status,target,asm,unit,meta FROM functions")}
    assert rows["score_update"]["status"] == "open" and rows["main"]["status"] == "interface"
    # lean rows: bytes and disassembly are NOT baked at confirm; they materialize on first use
    assert rows["score_update"]["target"] is None and rows["score_update"]["asm"] == ""
    row = net.store.one("SELECT * FROM functions WHERE name='score_update'")
    proj = net.project_row(slug)
    assert net._ensure_row_code(row, proj)  # from the binary
    assert "score_update" in net._asm_text(row, proj)  # from the cached bytes
    cached = net.store.one("SELECT target,asm FROM functions WHERE id=?", row["id"])
    assert cached["target"] and cached["asm"]  # both written back
    assert _json.loads(rows["score_update"]["meta"])["provenance"] == "dwarf"
    # the scheduler only ever hands out open functions
    agent, _ = net.local_agent("tester")
    claimed = net.claim_row(agent, slug, strategy="easiest")
    assert claimed["name"] == "score_update"
    # matched work pins its file: excluding it is refused
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched' WHERE name='score_update'")
    with pytest.raises(NetworkError, match="matched"):
        plan.set_treatment(net, slug, "src/hello.c", "exclude")


def test_interface_and_excluded_functions_leave_the_numbers(tmp_path, elf_bytes):
    """Every real function matched, yet the overview drew 22% next to a 100% score: interface rows
    counted as planned code (and the map showed them as open dots). Interface/excluded units — the
    plan says they are finished — are neither shown nor counted now."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.set_treatment(net, slug, "src/main.c", "interface")
    plan.confirm(net, slug, log=lambda *_: None)
    score_bytes = net.store.one("SELECT size FROM functions WHERE name='score_update'")["size"]
    ov = net.overview(slug)
    assert (ov["functions"], ov["matched"], ov["bytes"], ov["matched_bytes"]) == (1, 0, score_bytes, 0)
    assert [f["name"] for f in net.function_map(slug)] == ["score_update"]  # main is interface: no dot
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": flags}))
    agent, _ = net.local_agent("overview")
    net.claim(agent, slug, "score_update")
    source = (
        "static int clamp_i(int v, int lo, int hi) {\n"
        "    if (v < lo) return lo;\n"
        "    if (v > hi) return hi;\n"
        "    return v;\n"
        "}\n"
        "int score_update(int *score, int delta, int max) {\n"
        "    *score = clamp_i(*score + delta, 0, max);\n"
        "    return *score;\n"
        "}\n")
    assert net.attempt(agent, "score_update", source, slug)["matched"] is True
    ov = net.overview(slug)  # matching the only planned function is 100% of the planned code
    assert (ov["matched"], ov["bytes"], ov["matched_bytes"]) == (1, score_bytes, score_bytes)
    assert "1/1 functions matched (100.0% of code)" in net.list_projects()


def test_library_glue_is_classified():
    """std/boost instantiations, runtime hooks, thunk spellings and PLT/CRT stubs are not the
    program's logic: the analysis tags them so the plan can skip them."""
    from dcore.core import analyze as analyze_mod

    for name in ("std::__cxx11::basic_string<char>::~basic_string()",
                 "__gnu_cxx::new_allocator<int>::construct<int, int>(int *, int &&)",
                 "`non-virtual thunk to'boost::exception_detail::clone_impl<T>::~clone_impl()",
                 "`virtual thunk to'boost::exception_detail::error_info_injector<T>::~error_info_injector()",
                 "operator new(unsigned long)", "operator delete(void *, unsigned long)",
                 "_GLOBAL__sub_I_misc_utils.cpp", "__static_initialization_and_destruction_0(int, int)",
                 "register_tm_clones", "__gthread_active_p()"):
        assert analyze_mod.library_name(name), name
    for name in ("ACME::Aurora::Core::Crc32Utils::crc32(unsigned int, char const*, unsigned int)",
                 "common::tracekit::TraceLogStream::operator<<<uint>(uint const&)",
                 "ACME::Aurora::Core::BoostUtils::topologicalSort()", "main", "score_update"):
        assert not analyze_mod.library_name(name), name
    # ... and the other signals speak where names or sections do: IDA's import table, the section
    # the linker put the code in, and DWARF's decl_file pointing into a toolchain header
    cfg = {"image": {"sections": [{"name": ".plt", "vaddr": 0x1000, "size": 0x20},
                                  {"name": ".init", "vaddr": 0x1020, "size": 0x8},
                                  {"name": ".text", "vaddr": 0x2000, "size": 0x400}]}}
    ida = {"functions": [{"ea": 0x1000, "end": 0x1006, "name": "sub_1000"},
                         {"ea": 0x1020, "end": 0x1028, "name": "sub_1020"},
                         {"ea": 0x2000, "end": 0x2010, "name": "sub_2000"},
                         {"ea": 0x2100, "end": 0x2108, "name": "msync"},
                         {"ea": 0x2200, "end": 0x2210, "name": "sub_2200"},
                         {"ea": 0x2300, "end": 0x2310, "name": "sub_2300",
                          "demangled": "std::vector<int>::push_back(int const&)"},
                         {"ea": 0x2400, "end": 0x2430, "name": "register_tm_clones"}],
           "imports": [{"ea": 0x2100, "name": "msync", "module": ".dynsym"}]}
    dwarf = {"functions": [{"kind": "function", "low": 0x2200, "end": 0x2210, "name": "helper",
                            "cu": "src/a.cpp",
                            "line_file": "/opt/tool/gcc-8.1.0/include/c++/8.1.0/bits/stl_tree.h",
                            "decl_file": "/usr/include/c++/8/bits/char_traits.h"}]}
    merged = analyze_mod.merge(ida, dwarf, cfg)
    assert {f["ea"]: f["lib"] for f in merged["functions"]} == {
        0x1000: True, 0x1020: True, 0x2000: False, 0x2100: True, 0x2200: True, 0x2300: True, 0x2400: True}
    # ... and the machinery's kind is kept for the one-switch control
    assert {f["ea"]: f["glue"] for f in merged["functions"]} == {
        0x1000: "plt", 0x1020: "crt", 0x2000: None, 0x2100: "extern", 0x2200: None, 0x2300: None, 0x2400: "crt"}
    # ... and a function is filed where its line table says: the header, not the emitting .cpp
    files = {f["ea"]: f["file"] for f in merged["functions"]}
    assert files[0x2200].endswith("stl_tree.h") and files[0x2000] is None


def test_library_functions_are_not_work(tmp_path, elf_bytes):
    """A file kept decompile still holds hundreds of std/boost instantiations (libtoolsd: 628 of
    boost_utils.cpp's 638). Those confirm as "library": not claimable, not counted, not shown."""
    import json as _json

    from dcore.core import graph as graph_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    path = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    data = _json.loads(path.read_text())
    for f in data["functions"]:
        if f["name"] == "score_update":  # pretend it is std:: glue, inside main's file
            f["lib"] = True
            f["display"] = "std::vector<int>::push_back(int const&)"
            f["file"] = "src/main.c"
    data["graph"] = graph_mod.build(data["functions"], data["edges"])
    path.write_text(_json.dumps(data))
    counts = plan.confirm(net, slug, log=lambda *_: None)
    assert counts.get("library") == 1 and counts.get("open") == 1, counts
    rows = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert sorted(rows.values()) == ["library", "open"]
    glue = [n for n, st in rows.items() if st == "library"]
    assert glue and glue[0].startswith("std::vector")
    ov = net.overview(slug)  # the glue is planned code's shadow, not planned code
    assert ov["functions"] == 1 and ov["bytes"] == sum(
        r["size"] for r in net.store.all("SELECT size FROM functions WHERE status='open'"))
    # ... but it stays listed (the Library filter shows it): nothing IDA found is thrown away
    assert {f["name"]: f["status"] for f in net.function_map(slug)} == {glue[0]: "library", "main": "open"}
    agent, _ = net.local_agent("library")
    assert net.claim_row(agent, slug, strategy="easiest")["name"] == "main"


def test_functions_can_be_picked_out_of_a_unit(tmp_path, elf_bytes):
    """Every file unwraps into its functions, each selectable on its own: pull one out of an
    excluded file, and let a file-level choice supersede the picks again."""
    from dcore.core.network import NetworkError
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.set_treatment(net, slug, "src/hello.c", "exclude")
    plan.confirm(net, slug, log=lambda *_: None)
    assert {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")} == {
        "score_update": "excluded", "main": "open"}
    ea = net.store.one("SELECT vram FROM functions WHERE name='score_update'")["vram"]
    plan.set_function(net, slug, "src/hello.c", ea, "decompile")
    view = net.native.unit_functions(slug, "src/hello.c")
    assert {f["name"]: f["treatment"] for f in view["functions"]} == {"score_update": "decompile"}
    assert view["functions"][0]["status"] == "excluded"  # rows catch up on the next confirm
    plan.confirm(net, slug, log=lambda *_: None)
    assert net.store.one("SELECT status FROM functions WHERE name='score_update'")["status"] == "open"
    # a file-level choice supersedes the pick, and matched functions refuse to be picked away
    plan.set_many(net, slug, ["src/hello.c"], "interface")
    assert {f["name"]: f["treatment"] for f in net.native.unit_functions(slug, "src/hello.c")["functions"]} == {
        "score_update": "interface"}
    main_ea = net.store.one("SELECT vram FROM functions WHERE name='main'")["vram"]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched' WHERE name='main'")
    with pytest.raises(NetworkError, match="matched"):
        plan.set_function(net, slug, "src/main.c", main_ea, "exclude")


def test_the_import_machinery_has_one_switch(tmp_path, elf_bytes):
    """PLT trampolines, CRT glue and extern slots get one plan-wide switch; a function's own pick
    still beats it, and the file-level controls stay above both."""
    import json as _json

    from dcore.core.network import NetworkError
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    path = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    data = _json.loads(path.read_text())
    for f in data["functions"]:
        if f["name"] == "score_update":
            f["glue"] = "plt"
    path.write_text(_json.dumps(data))
    view = net.native.plan_view(slug)
    assert view["totals"]["machinery"] == {"plt": 1, "crt": 0, "extern": 0}
    plan.set_glue(net, slug, "exclude")
    assert plan.confirm(net, slug, log=lambda *_: None).get("excluded") == 1
    rows = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert rows == {"score_update": "excluded", "main": "open"}
    # the function's own pick wins over the switch ...
    ea = net.store.one("SELECT vram FROM functions WHERE name='score_update'")["vram"]
    plan.set_function(net, slug, "src/hello.c", ea, "decompile")
    plan.confirm(net, slug, log=lambda *_: None)
    assert net.store.one("SELECT status FROM functions WHERE name='score_update'")["status"] == "open"
    # ... and the switch can park the whole class even where files are decompiled
    plan.set_glue(net, slug, "interface")
    plan.set_many(net, slug, ["src/hello.c"], "decompile")  # clears the pick
    plan.confirm(net, slug, log=lambda *_: None)
    assert net.store.one("SELECT status FROM functions WHERE name='score_update'")["status"] == "interface"
    entry = net.native.unit_functions(slug, "src/hello.c")["functions"][0]
    assert entry["glue"] == "plt" and entry["treatment"] == "interface"


def test_a_matching_cross_compiler_beats_the_clang_fallback(monkeypatch):
    """Cross-format projects need a same-family driver where one is installed (e.g.
    x86_64-unknown-linux-gnu-g++) — clang --target= is only the last resort, and its note now
    says what the binary was built with."""
    from dcore.core import compilers

    monkeypatch.setattr(compilers, "_needs_triple", lambda fmt, arch: True)
    monkeypatch.setattr(compilers.shutil, "which",
                        lambda n: f"/opt/x/{n}" if n == "x86_64-unknown-linux-gnu-g++" else None)
    cmd, note = compilers._detect("GNU C++17 8.1.0", "c++", "elf", "x86_64")
    assert cmd == ["x86_64-unknown-linux-gnu-g++"] and "cross-building" in note
    monkeypatch.setattr(compilers.shutil, "which", lambda n: "/usr/bin/clang" if n == "clang" else None)
    cmd, note = compilers._detect("GNU C++17 8.1.0", "c++", "elf", "x86_64")
    assert cmd == ["clang", "--target=x86_64-unknown-linux-gnu"]
    assert "8.1.0" in note and "byte-exact" in note


def test_container_suggestions_are_offered_not_applied(monkeypatch):
    """The image is only ever *suggested* from the binary's compiler, and whether it's pulled is a
    plain local check that respects the TARGET's architecture — an arm64 image on an arm Mac must
    not read as ready for an x86_64 project."""
    import types

    from dcore.core import compilers

    assert compilers.suggested_image("GNU C++17 8.1.0") == "gcc:8.1.0"
    assert compilers.suggested_image("gcc 13.2.0") == "gcc:13.2.0"
    assert compilers.suggested_image("Apple clang version 15.0.0") == ""
    assert compilers.docker_platform("elf", "x86_64") == "linux/amd64"
    assert compilers.docker_platform("elf", "aarch64") == "linux/arm64"
    assert compilers.docker_platform("pe", "x86_64") == "linux/amd64"  # msvc-wine images are linux containers
    def runner(present: set[str]):
        """A fake docker that answers `image inspect --platform P` for the platforms that exist."""
        def run(cmd, **k):
            plat = cmd[cmd.index("--platform") + 1] if "--platform" in cmd else None
            ok = plat in present if plat else bool(present)
            return types.SimpleNamespace(returncode=0 if ok else 1,
                                         stdout=("amd64\n" if plat == "linux/amd64" else "arm64\n") if ok else "")
        return types.SimpleNamespace(run=run, TimeoutExpired=Exception)

    monkeypatch.setattr(compilers, "subprocess", runner({"linux/amd64"}))
    assert compilers.image_archs("gcc:8.1.0") == {"amd64"}
    assert compilers.image_present("gcc:8.1.0") is True
    assert compilers.image_present("gcc:8.1.0", "linux/amd64") is True
    assert compilers.image_present("gcc:8.1.0", "linux/arm64") is False  # wrong variant = not ready
    monkeypatch.setattr(compilers, "subprocess", runner(set()))
    assert compilers.image_present("gcc:8.1.0") is False


def test_get_context_previews_the_latest_failed_attempt(tmp_path, elf_bytes):
    """Failed attempts don't become best_source; get_context used to fall back to an empty seed and
    show a clean header while the real compile pulled a huge broken projection (Allocate). The
    preview now seeds from the latest attempt, even when it failed."""
    import json as _json
    import time as _time

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": ["game"], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    unit = net._unit_of(proj, "score_update")
    agent, _ = net.local_agent("preview")
    fn = dict(net.store.one("SELECT * FROM functions WHERE name='score_update'"))
    version = net._context(proj["id"], unit)["version"]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET meta=? WHERE id=?", ('{"language": "c++"}', fn["id"]))
        db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,context_version,source,created_at,via) "
                   "VALUES(?,?,?,?,?,?,?,?)",
                   (fn["id"], agent.id, None, 0, version,
                    "game::Player *score_update(game::Player *p) { return p; }", _time.time(), "agent"))
    view = net.get_context(slug, function="score_update")
    assert "struct Player {" in view and "int hp;" in view  # the failed attempt's types are previewed


def test_a_forward_declaration_does_not_shadow_the_registry_definition(tmp_path, elf_bytes):
    """A seed that forward-declares a class (`class Mutex;`) must not hide the registry's full
    definition: the compile then sees an incomplete type while the real one sits unrendered, which
    is what pushed agents into hand-rolled stand-ins (TagMutex). Only real definitions shadow."""
    import json as _json
    import time as _time

    from dcore.core import plan
    from dcore.core.registry import declared_names

    assert declared_names("class Mutex;") == set()
    assert declared_names("class Mutex { int x; };") == {"Mutex"}

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": ["game"], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    unit = net._unit_of(proj, "score_update")
    with net.store.tx() as db:
        version = net._next_version(db, proj["id"])
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (proj["id"], version, "namespace game { class Player; }\n", None, "test seed",
                    _time.time(), unit))
        db.execute("UPDATE functions SET best_source=?, meta=? WHERE name='score_update'",
                   ("game::Player *score_update(game::Player *p) { return p; }", '{"language": "c++"}'))
    view = net.get_context(slug, function="score_update")
    assert "struct Player {" in view and "int hp;" in view  # the registry definition renders anyway


def test_a_rosetta_crash_is_retried_then_classified(tmp_path, monkeypatch):
    """The wine container under Docker Desktop's Rosetta crashes intermittently ('invalid gdt
    selector') — the host's x86 translation, not the C. compile_source retries twice; a persistent
    crash comes back flagged infra so callers never blame the code."""
    import subprocess

    from dcore.core import compiler

    calls = {"n": 0}

    def fake_exec(cfg, work, argv, timeout, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return subprocess.CompletedProcess(argv, 1, "", "rosetta error: invalid gdt selector index 5\n")
        (work / "func.o").write_bytes(b"\x7fELF" + bytes(60))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(compiler, "_exec", fake_exec)
    res = compiler.compile_source(compiler.CompilerConfig(cmd=["fake"], sandbox="none"),
                                  "int marker;\n", "int f(void) { return 0; }\n")
    assert res.ok and calls["n"] == 2  # the intermittent crash was retried, the code untouched

    calls["n"] = 0

    def always_crash(cfg, work, argv, timeout, **kw):
        calls["n"] += 1
        return subprocess.CompletedProcess(argv, 1, "", "rosetta error: invalid gdt selector index 5\n")

    monkeypatch.setattr(compiler, "_exec", always_crash)
    res = compiler.compile_source(compiler.CompilerConfig(cmd=["fake"], sandbox="none"),
                                  "int marker;\n", "int f(void) { return 0; }\n")
    assert not res.ok and res.infra and calls["n"] == 3
    assert "not your code" in res.log and "Rosetta" in res.log


def test_a_zeroed_object_is_retried_and_flagged_as_a_toolchain_failure(tmp_path, monkeypatch):
    """wine under Rosetta sometimes exits 0 after writing a zero-filled .obj ('COFF machine 0x0'),
    which used to crash compile_and_diff with a traceback. The object header is checked now: retry,
    then report it as a toolchain failure, not a compile error."""
    import subprocess

    from dcore.core import compiler

    calls = {"n": 0}

    def fake_exec(cfg, work, argv, timeout, **kw):
        calls["n"] += 1
        (work / "func.o").write_bytes(bytes(64))  # the compiler died mid-write
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(compiler, "_exec", fake_exec)
    res = compiler.compile_source(compiler.CompilerConfig(cmd=["fake"], sandbox="none"),
                                  "int marker;\n", "int f(void) { return 0; }\n")
    assert not res.ok and res.infra and calls["n"] == 3
    assert "INVALID OBJECT" in res.log and "not your code" in res.log
    assert compiler.valid_object(b"\x64\x86" + bytes(24))  # x86-64 COFF
    assert not compiler.valid_object(bytes(64))
    assert not compiler.valid_object(b"\x64\x86")  # too short to be a COFF header


def test_an_infra_crash_does_not_consume_an_attempt(tmp_path, elf_bytes, monkeypatch):
    """A crash before the compiler runs must not increment attempts or overwrite the best source —
    otherwise the stall nudge and the GUI ('best attempt didn't compile') fire on a host problem."""
    from dcore.core import plan
    from dcore.core.compiler import CompileResult

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("infra")
    before = net.store.one("SELECT attempts FROM functions WHERE name='score_update'")["attempts"]
    monkeypatch.setattr(net, "_compile", lambda *a, **k: CompileResult(
        False, None, "rosetta error: invalid gdt selector index 5", infra=True))
    out = net.attempt(agent, "score_update", "int score_update(int *s, int d, int m) { return 0; }")
    assert out["infra"] and "not your code" in out["text"] and out["score"] is None
    assert net.store.one("SELECT attempts FROM functions WHERE name='score_update'")["attempts"] == before
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id="
                         "(SELECT id FROM functions WHERE name='score_update')")["n"] == 0


def test_a_container_image_compiles_where_the_host_cannot(tmp_path, elf_bytes, monkeypatch):
    """compiler.image moves the compile into a container (e.g. the binary's exact gcc:8.1.0): the
    driver lives inside the image — chosen by the binary's family, never looked up on PATH — and the
    whole invocation goes through docker with the work dir mounted at /work."""
    import types

    from dcore.core.network import NetworkError
    from dcore.core.compiler import CompileResult, CompilerConfig, _wrap
    from dcore.core import compilers
    from dcore.core import native as nativeengine_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)

    def change(cfg):
        compiler = cfg.setdefault("compiler", {})
        compiler.update({"image": "gcc:8.1.0"})
        compiler.pop("flags", None)  # unset: detection may supply the binary's flags
        cfg.setdefault("analysis", {})["compilers"] = [
            {"compiler": "GNU C++17 8.1.0", "flags": ["-O2"], "units": 1, "example": "x"}]
    net._update_cfg(slug, change)

    def no_popen(*a, **k):
        raise AssertionError("an already-pulled image must not be pulled again")

    def fake_run(cmd, **k):
        plat = cmd[cmd.index("--platform") + 1] if "--platform" in cmd else None
        ok = plat == "linux/amd64"
        return types.SimpleNamespace(returncode=0 if ok else 1, stdout="amd64\n" if ok else "")
    fake_sp = types.SimpleNamespace(run=fake_run, TimeoutExpired=Exception, PIPE=0, STDOUT=0, Popen=no_popen)
    monkeypatch.setattr(compilers, "subprocess", fake_sp)
    monkeypatch.setattr(nativeengine_mod, "subprocess", fake_sp)
    monkeypatch.setattr(compilers.shutil, "which", lambda n: "/usr/bin/docker" if n == "docker" else None)
    c = compilers.resolve(net, slug, "c++")
    assert c.sandbox == "docker" and c.image == "gcc:8.1.0" and c.command == ["g++"]
    assert c.platform == "linux/amd64"  # the target's arch, not this Mac's
    assert "gcc:8.1.0" in c.note and c.flags == ["-O2"]
    # an explicit empty flag list means "compiler defaults", not "use the detected flags"
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"flags": []}))
    assert compilers.resolve(net, slug, "c++").flags == []
    assert net.native.compiler_view(slug)["image_ready"] is True
    assert "already pulled for linux/amd64" in net.native.pull_image(slug, log=lambda *_: None)
    monkeypatch.setattr(compilers.shutil, "which", lambda n: None)
    with pytest.raises(NetworkError, match="docker"):
        compilers.resolve(net, slug, "c++")  # loud, not a silent fallback
    monkeypatch.setattr(compilers.shutil, "which", lambda n: "/usr/bin/docker" if n == "docker" else None)

    # the wrapped argv puts the driver and the /work paths inside the container, on the target's arch
    argv = _wrap(CompilerConfig(cmd=["g++"], sandbox="docker", image="gcc:8.1.0", platform="linux/amd64"),
                 Path("/tmp/w"), ["g++", "-c", "/work/func.cpp", "-o", "/work/func.o"])
    assert argv[:2] == ["docker", "run"]
    assert argv[argv.index("--platform"):argv.index("--platform") + 2] == ["--platform", "linux/amd64"]
    assert argv[argv.index("gcc:8.1.0") + 1:] == ["g++", "-c", "/work/func.cpp", "-o", "/work/func.o"]

    # ... and the compile path carries the container all the way to the invocation
    monkeypatch.setattr(compilers.shutil, "which", lambda n: "/usr/bin/docker" if n == "docker" else None)
    seen = {}
    monkeypatch.setattr(nativeengine_mod, "compile_source",
                        lambda cfg, header, source, **kw: (seen.update(cfg=cfg) or CompileResult(False, None, "no")))
    from dcore.core import plan

    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("container")
    net.claim(agent, slug, "score_update")
    out = net.native.probe(agent, slug, "score_update", "int score_update() { return 0; }", "-O2")
    assert "doesn't compile" in out
    cfg = seen["cfg"]
    assert cfg.sandbox == "docker" and cfg.image == "gcc:8.1.0"
    assert cfg.cmd == ["gcc", "-O2", "-c", "-I{include}", "{src}", "-o", "{obj}"]


def test_a_wrong_arch_object_is_refused(tmp_path, elf_bytes, monkeypatch):
    """An arm64 container image on an arm Mac emits aarch64 objects for an x86_64 project: the
    compile path must refuse them with the fix instead of judging nonsense."""
    from dcore.core.compiler import CompileResult
    from dcore.core import native as nativeengine_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    arm = bytearray(64)
    arm[0:4] = b"\x7fELF"
    arm[18:20] = (0xB7).to_bytes(2, "little")  # EM_AARCH64
    monkeypatch.setattr(nativeengine_mod, "compile_source", lambda *a, **kw: CompileResult(True, bytes(arm), ""))
    fn = net.store.one("SELECT * FROM functions WHERE name='score_update'")
    res = net.native.compile_fn(fn, net._project(slug), "", "int score_update(int v) { return v; }")
    assert not res.ok and "aarch64" in res.log and "x86_64" in res.log


def test_functions_resolve_by_address_whatever_its_length(tmp_path, elf_bytes):
    """Agents read addresses in disassembly and ask for functions by them: the ROM-era bare eight
    digits still work, and 0x-prefixed addresses of any length resolve too (native ones are short)."""
    from dcore.core.network import NetworkError
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    ea = net.store.one("SELECT vram FROM functions WHERE name='score_update'")["vram"]
    assert net._function(f"0x{ea:X}", slug)["name"] == "score_update"
    assert net._function(f"0X{ea:X}", slug)["name"] == "score_update"
    assert net._function(f"{ea:08X}", slug)["name"] == "score_update"
    with pytest.raises(NetworkError, match="no function"):
        net._function("0x2", slug)  # missing addresses still say so plainly


def test_a_self_addressed_function_gets_its_reference_back():
    """ASAN code loads its own address; the assembler resolves that same-section reference WITHOUT a
    relocation, while the shipped side reconstructs one. Without the candidate's twin, the position
    sets differ and a 99%-identical function can never match — libtoolsd's DoubleLink::push was
    exactly this row."""
    from dcore.targets.plat.elf.object import Reloc, _self_reference_relocs

    # lea rax, [rip - 7] -> insn ends at 7, target = 0: its own start
    assert _self_reference_relocs(bytes.fromhex("488d05f9ffffff"), "f", []) == [Reloc(3, 2, "f", -4)]
    # lea rax, [rip + 0x100] -> lands outside: not a self-reference
    assert _self_reference_relocs(bytes.fromhex("488d0500010000"), "f", []) == []
    # an existing reloc at that field is left alone
    assert _self_reference_relocs(bytes.fromhex("488d05f9ffffff"), "f", [Reloc(3, 2, "x", 0)]) == [Reloc(3, 2, "x", 0)]


def test_dwarf_class_layouts_are_collected(tmp_path):
    """DWARF knows every struct's real member names, offsets and size — what the context header can
    hand the agents instead of them re-deriving layouts from [rdi+8] per function."""
    clang = shutil.which("clang++") or shutil.which("clang")
    if not clang:
        pytest.skip("needs clang")
    from dcore.targets.plat.elf import dwarf

    src = tmp_path / "layout.cpp"
    src.write_text("struct Node { Node *next; unsigned long v; char buf[32]; };\n"
                   "unsigned long f(Node *n) { return n->v; }\n")
    out = tmp_path / "layout.o"
    try:
        subprocess.run([clang, "--target=x86_64-unknown-linux-gnu", "-g", "-c", str(src), "-o", str(out)],
                       check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pytest.skip("clang can't cross-compile for x86_64-unknown-linux-gnu")
    d = dwarf.analyze(out)
    node = next(t for t in d["types"] if t["name"] == "Node")
    assert node["size"] == 48
    assert [(m["name"], m["off"]) for m in node["members"]] == [("next", 0), ("v", 8), ("buf", 16)]


def test_context_headers_carry_class_layouts():
    """The unit header gains the layouts of the classes its code names, with the original's member
    names, offsets and size — the fix for agents re-creating classes by hand."""
    from dcore.core import interfaces

    analysis = {
        "functions": [
            {"ea": 0x1000, "size": 8, "name": "f", "display": "ACME::Aurora::Core::DoubleLink::push",
             "file": "src/x.cpp", "provenance": "dwarf", "language": "c++",
             "linkage": "_ZN6common5tools10DoubleLink4pushEPNS0_14DoubleLinkNodeE", "lib": False, "inline": []},
            {"ea": 0x2000, "size": 8, "name": "g", "display": "other_fn", "file": "src/x.cpp",
             "provenance": "dwarf", "language": "c++", "linkage": "_Z1gv",
             "signature": "void other(DoubleLinkNode *)", "lib": False, "inline": []},
        ],
        "edges": [{"ea": 0x1000, "to": [0x2000]}],
        "graph": {"files": {"src/x.cpp": {"functions": [0x1000], "bytes": 8, "language": "c++"}}},
        "types": [
            {"name": "DoubleLinkNode", "ns": ["common", "tools"], "size": 32, "kind": "struct",
             "members": [{"name": "_vptr.DoubleLinkNode", "off": 0, "type": "void *"},
                         {"name": "owner_ptr", "off": 8, "type": "DoubleLink *"},
                         {"name": "next_ptr", "off": 16, "type": "DoubleLinkNode *"},
                         {"name": "prev_ptr", "off": 24, "type": "DoubleLinkNode *"}]},
        ],
    }
    header = interfaces.unit_header(analysis, "src/x.cpp", language="c++")
    assert "struct DoubleLinkNode" in header and "/* size 0x20 */" in header
    assert "DoubleLinkNode * next_ptr;" in header and "void * _vptr;" in header
    assert "ACME::Aurora::Core::DoubleLink::push" in header  # the own-signature comment still rides along
    assert "owner_ptr" in header and "count_" not in header  # only types the code names


def test_removing_a_project_closes_its_ida_database(tmp_path, elf_bytes):
    """Deleting a project used to leave the IDA worker holding its .i64 (and stale caches around);
    removal releases the database before the folder goes."""
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    net.overview(slug)  # warm the per-slug caches the removal must drop

    class FakeSession:
        def __init__(self):
            self.calls = []

        def call(self, name, args, **kw):
            self.calls.append(name)
            return {}

        def close(self):
            self.calls.append("close")

    fake = FakeSession()
    net.native._ida = ((slug, str(binary)), fake)
    net.remove_project(slug)
    assert fake.calls == ["close_database", "close"]  # released first, then the worker let go
    assert net.native._ida is None and slug not in net.native._analysis
    with pytest.raises(NetworkError):
        net._project(slug)


needs_ida = pytest.mark.skipif(not os.environ.get("DECOMPNET_TEST_IDA"),
                               reason="this test spawns IDA; set DECOMPNET_TEST_IDA=1 to run it")


def _fixture_compiler() -> tuple[str, list[str]] | None:
    """The driver + flags the ELF fixture was built with (mirrors _build_elf)."""
    if (zig := shutil.which("zig")):
        return f"{zig} cc -target x86_64-linux-gnu", ["-g", "-O2"]
    if sys.platform.startswith("linux") and (cc := shutil.which("cc") or shutil.which("gcc")):
        return cc, ["-g", "-O2"]
    return None


def test_native_compilers_resolution(tmp_path, elf_bytes):
    from dcore.core import compilers

    net, slug, _ = _native_project(tmp_path, elf_bytes)
    detected = compilers.resolve(net, slug, "c")
    assert detected.command and shutil.which(detected.command[0])
    assert detected.source_name == "func.c"
    cxx = compilers.resolve(net, slug, "c++")
    assert cxx.source_name == "func.cpp"
    # user-defined driver and flags always win; known pairs follow the language
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update(
        {"command": "zig cc -target x86_64-linux-gnu", "flags": ["-O2", "-g"]}))
    user_c = compilers.resolve(net, slug, "c")
    assert user_c.command[:2] == ["zig", "cc"] and user_c.flags == ["-O2", "-g"]
    if shutil.which("zig"):
        assert compilers.resolve(net, slug, "c++").command[:2] == ["zig", "c++"]
    with pytest.raises(Exception):
        net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": "no-such-cc-xyz"}))
        compilers.resolve(net, slug, "c")


def test_interfaces_qualify_cross_namespace_types():
    """DWARF records google::protobuf::Message; the class lives in proto. A bare `Message` inside
    namespace proto is not found, and poisons the whole unit header even for an empty function."""
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "Message", "ns": ["google", "protobuf"], "kind": "class", "size": 8,
         "members": [], "methods": []},
        {"name": "Thing", "ns": ["proto"], "kind": "class", "size": 16,
         "members": [{"name": "msg", "off": 0, "type": "Message *"}],
         "methods": [{"name": "CopyFrom", "ret": "void", "params": ["const Message &"],
                      "virtual": False}]},
    ]}
    block = interfaces.type_block(analysis, "Thing *t;")
    assert "::google::protobuf::Message * msg;" in block
    assert "void CopyFrom(const ::google::protobuf::Message &);" in block
    assert "    Message * msg;" not in block  # never the unqualified spelling


def test_interfaces_a_class_keeps_its_own_name_unqualified():
    """A copy constructor's `const Record &` names the class being defined. The bare-name map may
    hold an unrelated same-leaf type with more members; qualifying the self-reference as
    `::ACME::Obsidian::Base::Record` made the class body name a type it never declared."""
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "Record", "ns": ["ACME", "Aurora", "Core"], "kind": "struct", "size": 56,
         "members": [{"name": "weight", "off": 0, "type": "unsigned int"}],
         "methods": [{"name": "Record", "params": ["const Record &"]}]},
        {"name": "Record", "ns": ["ACME", "Obsidian", "Base"], "kind": "struct", "size": 48,
         "members": [{"name": "a", "off": 0, "type": "int"},
                     {"name": "b", "off": 4, "type": "int"},
                     {"name": "c", "off": 8, "type": "int"}],
         "methods": []},
        {"name": "Holder", "ns": ["ACME", "Aurora", "Core"], "kind": "struct", "size": 56,
         "members": [{"name": "record", "off": 0,
                      "type": "ACME::Aurora::Core::Record"}], "methods": []},
    ]}
    block = interfaces.type_block(analysis, "ACME::Aurora::Core::Holder h;")
    assert "Record(const Record &);" in block
    assert "::ACME::Obsidian::Base::Record &" not in block


def test_interfaces_a_qualified_signature_gets_its_forward_declaration():
    """`usable()` and `_qualify_types()` must resolve a bare name the same way. They disagreed on
    `Row` (two namespaces), so the method was rendered as `::ACME::Obsidian::Row *` while the
    forward declaration named the other class — an undeclared namespace in the header."""
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "Row", "ns": ["ACME", "Aurora"], "kind": "struct", "size": 32,
         "members": [{"name": "a", "off": 0, "type": "int"},
                     {"name": "b", "off": 4, "type": "int"}], "methods": []},
        {"name": "Row", "ns": ["ACME", "Obsidian"], "kind": "class", "size": 64,
         "members": [{"name": "a", "off": 0, "type": "int"},
                     {"name": "b", "off": 4, "type": "int"},
                     {"name": "c", "off": 8, "type": "int"}], "methods": []},
        {"name": "Counter", "ns": ["ACME", "Aurora"], "kind": "struct", "size": 16,
         "members": [], "methods": [{"name": "init", "ret": "int32_t",
                                      "params": ["const Row *"]}]},
    ]}
    block = interfaces.type_block(analysis, "ACME::Aurora::Counter *c;")
    assert "int32_t init(const ::ACME::Obsidian::Row *);" in block
    assert "namespace ACME { namespace Obsidian { class Row; }}" in block


def test_interfaces_an_alias_from_the_header_is_spellable():
    """A third-party type can be named by a unit-header alias (`using yield_context = …;`) even when
    it has no registry entry. Without the alias, a virtual method whose parameter is that type is
    silently dropped and the class cannot match the original definition."""
    from dcore.core import interfaces

    analysis = {"types": [{"name": "HttpSession", "ns": [], "kind": "class", "size": 8,
                           "members": [], "statics": [],
                           "methods": [{"name": "onConnect", "ret": "int32_t", "params": ["yield_context"],
                                        "virtual": True}]}]}
    block = interfaces.type_block(analysis, "HttpSession *session;", aliases={"yield_context"})
    assert "int32_t onConnect(yield_context);" in block


def test_header_for_renders_the_opaque_prelude_before_the_class():
    """The prelude carries the third-party stub and alias. It must precede the type block, because a
    class method may name the alias; a declaration after use does not compile."""
    from dcore.core import registry

    analysis = {"types": [{"name": "Session", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
                           "members": [], "statics": [],
                           "methods": [{"name": "onConnect", "ret": "int32_t", "params": ["yield_context"],
                                        "virtual": True}]}]}
    prelude = ("namespace acme { namespace thirdparty {\n"
               "template<class T> class yield_context { alignas(8) unsigned char opaque_[8]; };\n"
               "}}\nusing yield_context = acme::thirdparty::yield_context<void>;")
    out = registry.header_for(analysis, "/* ctx */\n", "int f(Session *session) { return 0; }",
                              {"version": 1, "types": {}}, prelude=prelude)
    assert out.index("namespace acme") < out.index("class Session")
    assert "int32_t onConnect(yield_context);" in out


def test_header_for_counts_inline_definitions_as_usage():
    """The class declaration and the inline definitions are emitted into the same header. A method
    only the definition mentions must still be declared (with its `const`), or the appended
    definition names a member the class does not have."""
    from dcore.core import registry

    analysis = {"types": [{"name": "Settings", "ns": ["ACME", "Aurora", "Core"], "kind": "class",
                           "size": 40,
                           "members": [{"name": "region", "off": 8,
                                        "type": "unsigned char[32]"}],
                           "statics": [],
                           "methods": [{"name": "regionName", "ret": "std::string const *",
                                        "params": [], "const": True}]}]}
    inline = ("inline std::string const *ACME::Aurora::Core::Settings::regionName() const\n"
              "{\n    return reinterpret_cast<std::string const *>(&region);\n}")
    out = registry.header_for(
        analysis, "/* ctx */\n", "int serviceType() { return 7; }",
        {"version": 1, "types": {}},
        inline_defs=[(("ACME::Aurora::Core::Settings", "regionName"), inline)])
    assert "std::string const * regionName() const;" in out
    assert inline in out


def test_interfaces_do_not_redeclare_platform_runtime():
    """pthread/cxxabi/unwind prototypes belong to the platform headers. Re-declaring them after
    <cstdint> is a C++ redeclaration error even when the unit never calls them."""
    from dcore.core import interfaces

    analysis = {"functions": [
        {"ea": 0x10, "name": "caller", "display": "caller", "provenance": "dwarf", "language": "c++",
         "signature": "void(int)", "lib": False},
        {"ea": 0x20, "name": "pthread_mutex_lock", "display": "pthread_mutex_lock",
         "provenance": "dwarf", "language": "c", "signature": "int(pthread_mutex_t *mutex)", "lib": False},
        {"ea": 0x30, "name": "_ZN2ns4funcEPv", "display": "ns::func(void *)", "provenance": "dwarf",
         "language": "c++", "linkage": "_ZN2ns4funcEPv", "signature": "void(ns::Foo *const this)", "lib": False},
    ], "edges": [{"ea": 0x10, "to": [0x20, 0x30]}],
        "graph": {"files": {"a.cpp": {"functions": [0x10]}}},
        "types": [{"name": "Foo", "ns": ["ns"], "kind": "class", "size": 8, "members": [], "methods": []}]}
    header = interfaces.unit_header(analysis, "a.cpp", language="c++")
    assert "#include <pthread.h>" in header
    assert "int pthread_mutex_lock(" not in header
    assert "ns::Foo *const self" in header and "ns::Foo *const this" not in header


def test_interfaces_leave_system_layouts_to_the_platform():
    """DWARF also contains libc layouts (timeval); redefining them collides with the system header
    that <pthread.h>/<memory> already pulled in."""
    from dcore.core import interfaces

    types = [
        {"name": "timeval", "ns": [], "kind": "struct", "size": 16,
         "members": [{"name": "tv_sec", "off": 0, "type": "long"},
                     {"name": "tv_usec", "off": 8, "type": "long"}], "methods": []},
        {"name": "Thing", "ns": ["ns"], "kind": "struct", "size": 8,
         "members": [{"name": "v", "off": 0, "type": "long"}], "methods": []},
    ]
    block = interfaces.type_block({"types": types}, "Thing *t; timeval *tv;")
    assert "struct Thing" in block
    assert "struct timeval" not in block


def test_interfaces_generate_unit_headers():
    from dcore.core import interfaces

    analysis = {"functions": [
        {"ea": 0x10, "name": "caller", "display": "caller", "provenance": "dwarf", "language": "c",
         "signature": "int(int x)", "lib": False},
        {"ea": 0x20, "name": "helper", "display": "helper", "provenance": "dwarf", "language": "c",
         "signature": "int __fastcall(int x, int y)", "lib": False},
        {"ea": 0x30, "name": "_ZN4game7free_fnEi", "display": "game::free_fn(int)", "provenance": "dwarf",
         "language": "c++", "linkage": "_ZN4game7free_fnEi", "signature": "long(int)", "lib": False},
        # IDA's spelling of a PLT thunk: it must be declared under its plain name WITH the variadic
        # signature — otherwise calls compile non-variadic and miss the `xor eax, eax` (AL = 0)
        {"ea": 0x40, "name": ".printf", "display": ".printf", "provenance": "auto", "language": "c",
         "signature": "int(const char *format, ...)", "lib": False},
    ], "edges": [{"ea": 0x10, "to": [0x20, 0x30, 0x40]}],
        "graph": {"files": {"a.c": {"functions": [0x10]}, "b.c": {"functions": [0x20]},
                            "game.cpp": {"functions": [0x30]}, "libc.so": {"functions": [0x40]}}}}
    header = interfaces.unit_header(analysis, "a.c", language="c")
    assert "int helper(int x, int y);" in header  # __fastcall stripped
    assert "int printf(const char *format, ...);" in header  # the thunk, under its import name, variadic
    assert 'extern "C"' not in header
    cpp = interfaces.unit_header(analysis, "a.c", language="c++")
    assert 'extern "C" {' in cpp
    assert "namespace game { long free_fn(int); }" in cpp
    assert "int printf(const char *format, ...);" in cpp
    assert "/* int caller(int x); */" in cpp  # its own signature, as a comment
    assert interfaces.sanitize("__int64 __fastcall(int x)") == "long long (int x)"


def test_c_headers_get_c_structs_and_prototypes():
    """C units get C: struct tags/typedefs and prototypes, no classes, methods or extern "C"."""
    from dcore.core import interfaces

    analysis = {"format": "elf", "arch": "x86_64", "functions": [
        {"ea": 0x10, "name": "caller", "display": "caller", "provenance": "dwarf", "language": "c",
         "signature": "int(struct Node *n)", "lib": False},
        {"ea": 0x20, "name": "helper", "display": "helper", "provenance": "dwarf", "language": "c",
         "signature": "int(struct Node *n, int x)", "lib": False},
    ], "edges": [{"ea": 0x10, "to": [0x20]}],
        "graph": {"files": {"a.c": {"functions": [0x10]}}},
        "types": [{"name": "Node", "ns": [], "kind": "struct", "size": 16,
                   "members": [{"name": "next", "off": 0, "type": "Node *"},
                               {"name": "value", "off": 8, "type": "long"}]}]}
    header = interfaces.unit_header(analysis, "a.c", language="c")
    assert "#include <stdint.h>" in header and "#include <stddef.h>" in header
    assert "typedef struct Node Node;" in header
    assert "struct Node {" in header and "Node * next;" in header
    assert "int helper(struct Node *n, int x);" in header
    assert "class " not in header and 'extern "C"' not in header
    # the same unit built as C++ keeps the C++ class spelling
    cpp = interfaces.unit_header(analysis, "a.c", language="c++")
    assert "class Node" in cpp or "struct Node" in cpp


def test_windows_context_uses_the_sdk_not_posix():
    from dcore.core import interfaces

    analysis = {"format": "pe", "arch": "x86_64", "functions": [
        {"ea": 0x10, "name": "caller", "display": "caller", "provenance": "pdb", "language": "c++",
         "signature": "void(int)", "lib": False},
        {"ea": 0x20, "name": "CreateFileW", "display": "CreateFileW", "provenance": "pdb",
         "language": "c", "signature": "void *(const wchar_t *, unsigned int, unsigned int, "
                                        "void *, unsigned int, unsigned int, void *)", "lib": False},
    ], "edges": [{"ea": 0x10, "to": [0x20]}],
        "graph": {"files": {"a.cpp": {"functions": [0x10]}}}, "types": []}
    header = interfaces.unit_header(analysis, "a.cpp", language="c++")
    assert "#include <windows.h>" in header
    assert "#include <pthread.h>" not in header


def test_plan_view_and_compiler_view(tmp_path, elf_bytes):
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    view = net.native.plan_view(slug)
    assert view["slug"] == slug and view["confirmed"] is False
    nodes = {n["path"]: n for n in view["nodes"]}
    assert set(nodes) == {"src/hello.c", "src/main.c"}
    assert nodes["src/hello.c"]["treatment"] == "decompile"
    # the invented edge: hello calls main, so main's dependents list hello (and the UI shows it)
    assert nodes["src/main.c"]["dependents"] == ["src/hello.c"]
    assert nodes["src/hello.c"]["deps"] == ["src/main.c"]
    assert view["totals"]["files"] == 2 and view["totals"]["treatments"]["decompile"] == 2
    assert view["compiler"]["error"] is None and view["compiler"]["driver"]
    plan.set_treatment(net, slug, "src/main.c", "interface")
    refreshed = {n["path"]: n for n in net.native.plan_view(slug)["nodes"]}
    assert refreshed["src/main.c"]["treatment"] == "interface"
    assert refreshed["src/hello.c"]["treatment"] == "decompile"


def test_bulk_treatments_preview_and_apply(tmp_path, elf_bytes):
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    treatments = plan.treatments_of(plan.load(net, slug), list(analysis["graph"]["files"]))
    assert plan.preview_many(analysis["graph"], treatments, ["src/main.c"], "exclude") == ["src/hello.c"]
    res = plan.set_many(net, slug, ["src/main.c"], "exclude")
    assert res["forced"] == ["src/hello.c"]
    nodes = {n["path"]: n["treatment"] for n in net.native.plan_view(slug)["nodes"]}
    assert nodes == {"src/main.c": "exclude", "src/hello.c": "exclude"}
    res2 = plan.set_many(net, slug, ["src/main.c", "src/hello.c"], "interface")  # interface never cascades
    assert res2["forced"] == []
    nodes = {n["path"]: n["treatment"] for n in net.native.plan_view(slug)["nodes"]}
    assert nodes == {"src/main.c": "interface", "src/hello.c": "interface"}


def test_auto_detected_compiler_matches_the_projects_format(tmp_path, elf_bytes):
    """The DeepSeek crash: auto-detect must never hand back a driver that emits the wrong object format."""
    from dcore.core.compiler import CompilerConfig, compile_source
    from dcore.core import compilers

    net, slug, _ = _native_project(tmp_path, elf_bytes)
    c = compilers.resolve(net, slug, "c")
    res = compile_source(CompilerConfig(cmd=c.template(), timeout=60),
                         "int marker(void);\n", "int marker(void) { return 1; }\n", source_name=c.source_name)
    assert res.ok, f"{c.command}: {res.log}"
    assert res.obj[:4] == b"\x7fELF", f"{c.command} emitted the wrong object format"


def test_wrong_driver_object_gets_a_clear_error(tmp_path, elf_bytes, monkeypatch):
    from dcore.core import native as nativeengine
    from dcore.core.compiler import CompileResult
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    monkeypatch.setattr(nativeengine, "compile_source",
                        lambda *a, **k: CompileResult(True, b"\xcf\xfa\xed\xfe" + bytes(60), ""))
    agent, _ = net.local_agent("fmtcheck")
    net.claim(agent, slug, "score_update")
    res = net.attempt(agent, "score_update", "int score_update(int *s, int d, int m) { return 0; }\n", slug)
    assert res["matched"] is False
    assert "Mach-O" in res["text"] and "ELF" in res["text"], res["text"]


def test_confirm_applies_suggestions(tmp_path, elf_bytes):
    import json as _json

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    for f in analysis["functions"]:  # one unit now looks like borrowed code: its suggestion is interface
        if f["file"] == "src/main.c":
            f["lib"] = True
    (Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json").write_text(_json.dumps(analysis))
    eff = plan.effective(analysis, plan.load(net, slug))
    assert eff["src/main.c"] == "interface" and eff["src/hello.c"] == "decompile"
    counts = plan.confirm(net, slug, log=lambda *_: None)
    assert counts == {"open": 1, "interface": 1, "missing": 0, "removed": 0}


def test_reconfirm_updates_prunes_and_never_duplicates(tmp_path, elf_bytes):
    import json as _json

    from dcore.core import analyze as analyze_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    assert plan.confirm(net, slug, log=lambda *_: None) == {"open": 2, "missing": 0, "removed": 0}

    # an address-duplicate (the bug: re-confirming used to re-add rows under suffixed names), with a claim
    with net.store.tx() as db:
        r = db.execute("SELECT * FROM functions WHERE name='main'").fetchone()
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,status,meta) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (r["project_id"], "main@dup", r["size"], r["n_insns"], r["target"], r["relocs"], r["asm"], None,
                    r["unit"], r["vram"], r["status"], r["meta"]))
        dup_id = db.execute("SELECT id FROM functions WHERE name='main@dup'").fetchone()["id"]
        db.execute("INSERT INTO claims VALUES(?,?,?,?)", (dup_id, 1, 0, 9e9))

    plan.set_treatment(net, slug, "src/main.c", "interface")
    res = plan.confirm(net, slug, log=lambda *_: None)
    assert res == {"open": 1, "interface": 1, "missing": 0, "removed": 1}
    assert sorted(r["name"] for r in net.store.all("SELECT name FROM functions")) == ["main", "score_update"]
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0  # the duplicate's claim went with it

    # a function that disappears from the analysis is pruned on the next re-confirm
    analysis = analyze_mod.load(net, slug)
    analysis["functions"] = [f for f in analysis["functions"] if f["name"] != "main"]
    analysis["graph"]["files"]["src/main.c"]["functions"] = []
    (Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json").write_text(_json.dumps(analysis))
    assert plan.confirm(net, slug, log=lambda *_: None) == {"open": 1, "missing": 0, "removed": 1}
    assert [r["name"] for r in net.store.all("SELECT name FROM functions")] == ["score_update"]


def test_registry_commit_writes_types_into_the_database():
    """With a backend, a committed type batch lands in the IDA database (parse_declarations +
    one forced save); unchanged batches and backend-less projects write nothing."""
    from types import SimpleNamespace

    from dcore.core import registry

    applied = {}

    class FakeNative:
        def ida_ready(self):
            return True

        def ida_apply_decls(self, slug, decls):
            applied["decls"] = decls
            return {"ok": True, "rc": 0}

        def ida_save(self, slug, force=False):
            applied["saved"] = (slug, force)
            return True

    t = {"name": "Cfg", "ns": [], "kind": "struct", "size": 8,
         "members": [{"name": "x", "off": 0, "type": "int"}]}
    analysis = {"functions": [], "types": [t], "graph": {"files": {}}}
    net = SimpleNamespace(native=FakeNative())
    note = registry._write_through(net, "slug", analysis, {}, {"Cfg": t})
    assert "1 type" in note and "struct Cfg" in applied["decls"]
    assert applied["saved"] == ("slug", True)
    applied.clear()
    assert registry._write_through(net, "slug", analysis, {"Cfg": t}, {"Cfg": t}) == ""
    assert not applied  # nothing changed: nothing written
    assert registry._write_through(SimpleNamespace(native=None), "slug", analysis, {}, {"Cfg": t}) == ""


def test_headers_materialize_on_use_and_survive_reconfirm(tmp_path, elf_bytes):
    """Header laziness: confirm writes none, the first touch generates one, and no confirm ever
    clobbers a stored header (generated or edited)."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    pid = net._project(slug)["id"]
    unit = "src/hello.c"

    def latest():
        return net.store.one("SELECT version, header, agent_id FROM context_versions "
                             "WHERE project_id=? AND unit=? ORDER BY version DESC LIMIT 1", pid, unit)

    # nothing stored at confirm: baking every unit's header was 13+ minutes of eager work on a
    # binary like ORION, so headers now materialize the first time a unit is touched
    assert latest() is None
    ctx = net._context(pid, unit)
    assert "context.h for" in ctx["header"]
    orig = latest()
    assert orig["agent_id"] is None
    assert net.store.one("SELECT COUNT(*) AS n FROM context_versions WHERE project_id=? AND unit!=''",
                         pid)["n"] == 1
    plan.confirm(net, slug, log=lambda *_: None)  # a re-confirm leaves stored headers alone
    assert latest()["version"] == orig["version"]

    agent, _ = net.local_agent("edit")
    net.edit_context(agent, slug, "", "/* mine */", "note", function="score_update")
    from dcore.core import entries as entries_mod

    live = entries_mod.list_for(net, slug, unit)
    assert [e["body"] for e in live] == ["/* mine */"]  # appends land as declaration entries now
    kept = latest()  # entries never rewrite the stored header: it is the frozen legacy layer
    assert kept["version"] == orig["version"]
    plan.confirm(net, slug, log=lambda *_: None)  # and a re-confirm leaves both layers alone
    assert latest()["version"] == orig["version"] and entries_mod.list_for(net, slug, unit)


def test_cpp_elf_project_matches_a_virtual_method(tmp_path):
    """A second, non-MSVC project: DWARF C++ class, function-scoped header, virtual method."""
    from dcore.core.engine import Engine
    from dcore.core import plan

    data = _build_cpp_elf(tmp_path)
    compiler = _cpp_fixture_compiler()
    if data is None or compiler is None:
        pytest.skip("needs zig or a Linux C++ compiler matching the fixture")
    net = Engine(tmp_path / "app.db", tmp_path / "work")
    slug = net.import_rom(data, confirmed=True, name="game-native", log=lambda *_: None)
    binary = Path(net.project_row(slug)["root"]) / "game-native"
    _write_dwarf_analysis(net, slug, binary, tmp_path, "game.cpp", types=True)
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update(
        {"command": command, "flags": flags}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("cpp")
    net.claim(agent, slug, "update")
    header = net.get_context(slug, function="update")
    source = (
        "int game::Player::update(int delta) {\n"
        "    hp += delta;\n"
        "    if (hp < 0) hp = 0;\n"
        "    return hp;\n"
        "}\n")
    fn = net.store.one("SELECT * FROM functions WHERE name='update'")
    compiled_header = net.native._render_header(fn, net.project_row(slug), header, source)
    assert "struct Player" in compiled_header and "virtual int update(int);" in compiled_header
    result = net.attempt(agent, "update", source, slug)
    assert result["matched"] is True, result["text"]


def test_build_flags_probe_and_gated_change(tmp_path, elf_bytes):
    """The -O0 trap: the project builds at the compiler default, the target at -O2. Agents can probe
    flags on one function (nothing recorded) and then adopt them — regression-tested against matches."""
    from dcore.core import plan
    from dcore.core.network import NetworkError as _NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": ["-O0"]}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("flags")
    brief = net.claim(agent, slug, "score_update")
    assert "compiling with:" in brief  # agents can see the build they are judged under
    source = (  # one function, first line to closing brace — the static helper is inlined by hand
        "int score_update(int *score, int delta, int max) {\n"
        "    int v = *score + delta;\n"
        "    if (v < 0) { *score = 0; return 0; }\n"
        "    if (v > max) { *score = max; return max; }\n"
        "    *score = v;\n"
        "    return v;\n"
        "}\n")
    # the project is at -O0: the correct source cannot match ...
    assert net.attempt(agent, "score_update", source, slug)["matched"] is False
    # ... but a probe with the original flags says exactly what to do, and records nothing
    probe = net.compile_and_diff(agent, "score_update", source, slug, flags=" ".join(flags))
    assert "BYTE-IDENTICAL" in probe and "set_build_flags" in probe
    row = net.store.one("SELECT status, attempts FROM functions WHERE name='score_update'")
    assert row["status"] == "open" and row["attempts"] == 1  # only the failed attempt; the probe never lands
    # adopting the flags is allowed (nothing matched to protect yet) ...
    assert net.native.set_flags(agent, slug, " ".join(flags)).startswith("✅")
    assert net.attempt(agent, "score_update", source, slug)["matched"] is True
    # ... and afterwards a change that would break the match is refused, leaving the flags alone
    rejected = net.native.set_flags(agent, slug, "-O0")
    assert rejected.startswith("❌") and "-O0" in rejected
    assert [str(f) for f in net.cfg(net._project(slug))["compiler"]["flags"]] == [str(f) for f in flags]
    with pytest.raises(_NetworkError):
        net.compile_and_diff(agent, "score_update", source, slug, flags="-O0")  # matched functions can't be probed


def test_per_file_flags_are_scoped_and_stick(tmp_path, elf_bytes):
    """Real builds compiled modules differently: flags adopted for one file don't touch the others,
    its own matches protect it, and the project default can still move for the un-pinned files."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": ["-O0"]}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("unitflags")
    net.claim(agent, slug, "score_update")
    source = (
        "static int clamp_i(int v, int lo, int hi) {\n"
        "    if (v < lo) return lo;\n"
        "    if (v > hi) return hi;\n"
        "    return v;\n"
        "}\n"
        "int score_update(int *score, int delta, int max) {\n"
        "    *score = clamp_i(*score + delta, 0, max);\n"
        "    return *score;\n"
        "}\n")
    # adopt -O2 for score_update's file only; the project default stays -O0
    ok = net.native.set_flags(agent, slug, " ".join(flags), function="score_update", scope="file")
    assert ok.startswith("✅") and "hello.c" in ok, ok
    ccfg = net.cfg(net._project(slug))["compiler"]
    assert ccfg["flags"] == ["-O0"]
    assert ccfg["units"]["src/hello.c"]["flags"] == list(flags)
    assert net.attempt(agent, "score_update", source, slug)["matched"] is True
    # the project default can move: the pinned file isn't re-tested, and the message says so
    moved = net.native.set_flags(agent, slug, "-O1")
    assert moved.startswith("✅") and "keep their per-file flags" in moved
    # but the file's own flags are protected by its matches
    rejected = net.native.set_flags(agent, slug, "-O0", function="score_update", scope="file")
    assert rejected.startswith("❌") and "hello.c" in rejected
    assert net.cfg(net._project(slug))["compiler"]["units"]["src/hello.c"]["flags"] == list(flags)


def test_per_function_flags_override_only_that_function(tmp_path, elf_bytes):
    """Two functions in one file can genuinely need different optimisation levels. The flag override
    is saved on the function (not the file), survives in meta, and the judge compiles that function
    with it while the file/project stay put."""
    import json as _json

    from dcore.core import compilers as compilers_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": ["-O0"]}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("fnflags")
    net.claim(agent, slug, "score_update")
    source = (
        "static int clamp_i(int v, int lo, int hi) {\n"
        "    if (v < lo) return lo;\n"
        "    if (v > hi) return hi;\n"
        "    return v;\n"
        "}\n"
        "int score_update(int *score, int delta, int max) {\n"
        "    *score = clamp_i(*score + delta, 0, max);\n"
        "    return *score;\n"
        "}\n")
    ok = net.native.set_flags(agent, slug, " ".join(flags), function="score_update")
    assert ok.startswith("✅") and "saved on the function" in ok, ok
    row = net.store.one("SELECT meta FROM functions WHERE name='score_update'")
    assert _json.loads(row["meta"])["build_flags"] == list(flags)
    ccfg = net.cfg(net._project(slug))["compiler"]
    assert ccfg["flags"] == ["-O0"] and not (ccfg.get("units") or {})
    resolved = compilers_mod.resolve(net, slug, "c", unit="src/hello.c", fn_flags=list(flags))
    assert resolved.flags == list(flags)
    assert net.attempt(agent, "score_update", source, slug)["matched"] is True
    # the match protects the override: falling back to -O0 would stop matching
    rejected = net.native.set_flags(agent, slug, "-O0", function="score_update")
    assert rejected.startswith("❌"), rejected
    assert _json.loads(net.store.one("SELECT meta FROM functions WHERE name='score_update'")["meta"])[
        "build_flags"] == list(flags)


def test_declare_opaque_is_project_global_and_removable(tmp_path, elf_bytes):
    """An opaque third-party declaration is stored once in the project registry and rendered before
    the type block, so every unit that includes it can name the alias. decl="" removes it."""
    import json as _json

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    agent, _ = net.local_agent("opaque")
    decl = ("namespace acme { namespace thirdparty {\n"
            "template<class T> class yield_context { alignas(8) unsigned char opaque_[8]; };\n"
            "}}\nusing yield_context = acme::thirdparty::yield_context<void>;")
    ok = net.native.declare_opaque(agent, slug, "acme::thirdparty::yield_context", decl,
                                   size="8", align="8", trivial="true", note="third-party")
    assert ok.startswith("✅"), ok
    data = _json.loads((Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native"
                        / "registry.json").read_text())
    entry = data["opaque"]["acme::thirdparty::yield_context"]
    assert entry["size"] == 8 and entry["align"] == 8 and entry["trivial"] is True
    from dcore.core import registry

    header = registry.header_for({"types": []}, "/* ctx */\n", "int f() { return 0; }", data,
                                 prelude=registry.opaque_text(data))
    assert "namespace acme" in header
    removed = net.native.declare_opaque(agent, slug, "acme::thirdparty::yield_context", "")
    assert removed.startswith("✅"), removed
    data = _json.loads((Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native"
                        / "registry.json").read_text())
    assert "acme::thirdparty::yield_context" not in (data.get("opaque") or {})


def test_function_modes_hide_from_the_queue_but_keep_the_header(tmp_path, elf_bytes):
    """header/skip are not body targets: no claim, no compile, no open-list entry. The class/signature
    stays in the project header, so callers still compile. A matched function cannot be hidden."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, _ = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("modes")
    ok = net.set_mode(agent, "score_update", "header", "third-party", slug)
    assert ok.startswith("✅") and "header" in ok
    with pytest.raises(NetworkError, match="header-only"):
        net.claim(agent, slug, "score_update")
    assert net.list_functions(slug, "open", 40, "score_update").startswith("No open functions")
    stats = next(p for p in net.status_json()["projects"] if p["slug"] == slug)
    assert stats["header_functions"] >= 1
    assert all(f["mode"] == "header" for f in stats["funcs"] if f["name"] == "score_update")
    # matched functions are not hidden by a mode switch
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched' WHERE name='score_update'")
    refused = net.set_mode(agent, "score_update", "skip", "", slug)
    assert refused.startswith("❌")
    assert net.set_mode(agent, "score_update", "decompile", "", slug).startswith("✅")


def test_ida_busy_cooldown_does_not_reopen_for_every_edit():
    from dcore.core.registry import _ida_recently_busy

    state = {"last_error": "the IDA database can't be opened right now: open in another IDA instance",
             "last_try_at": 1000.0}
    assert _ida_recently_busy(state, now=1050.0) is True
    assert _ida_recently_busy(state, now=1201.0) is False
    assert _ida_recently_busy({"last_error": "parse failed", "last_try_at": 1000.0}, now=1050.0) is False


def test_set_signature_replaces_a_free_function_prototype(tmp_path, elf_bytes):
    """set_signature is the no-body path: a header-only function still gets a declaration, and a
    second edit replaces the old prototype instead of stacking two conflicting ones."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, _ = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("signature")
    assert net.set_mode(agent, "score_update", "header", "", slug).startswith("✅")
    bad = net.native.set_signature(agent, slug, "score_update", "booll",
                                   "int *score", note="typo")
    assert bad.startswith("❌") and "compile" in bad, bad
    first = net.native.set_signature(agent, slug, "score_update", "int",
                                     "int *score, int delta, int max", note="header-only")
    assert first.startswith("✅"), first
    bodies = [r["body"] for r in net.store.all(
        "SELECT body FROM context_entries WHERE project_id=(SELECT id FROM projects WHERE slug=?) "
        "AND removed_at IS NULL", slug)]
    assert any("int score_update(int *score, int delta, int max);" in b for b in bodies)
    second = net.native.set_signature(agent, slug, "score_update", "long",
                                      "int *score, int delta", note="fix the return")
    assert second.startswith("✅"), second
    live = [r["body"] for r in net.store.all(
        "SELECT body FROM context_entries WHERE project_id=(SELECT id FROM projects WHERE slug=?) "
        "AND removed_at IS NULL", slug)]
    assert any("long score_update(int *score, int delta);" in b for b in live)
    assert not any("int score_update(int *score, int delta, int max);" in b for b in live)


def test_interfaces_platform_typedefs_are_spellable_in_methods():
    """ino_t/dev_t/... come from <sys/stat.h>, which the header includes. If they are not in the
    fixed typedef set, `_method_decl` drops the method (a virtual/normal member silently disappears)
    and the source gets "no declaration matches"."""
    from dcore.core import interfaces

    analysis = {"types": [{"name": "LogFile", "ns": ["ACME", "Aurora", "Core"], "kind": "class",
                           "size": 544, "members": [], "statics": [],
                           "methods": [{"name": "fileIno", "ret": "ino_t", "params": []}]}]}
    block = interfaces.type_block(analysis, "ACME::Aurora::Core::LogFile *p; p->fileIno();")
    assert "ino_t fileIno();" in block


def test_interfaces_shared_ptr_accepts_a_forward_declared_type():
    """A shared_ptr member is valid with an incomplete pointee. Requiring a complete by-value type
    turned `shared_ptr<AServerBase>` into an opaque byte array, so `ptr->isRun()` could not compile."""
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "Server", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
         "members": [], "statics": [], "methods": [{"name": "isRun", "ret": "bool", "virtual": True}]},
        {"name": "Manager", "ns": ["ACME", "Aurora"], "kind": "class", "size": 40,
         "members": [{"name": "server", "off": 8,
                      "type": "shared_ptr<ACME::Aurora::Server>"}], "statics": [], "methods": []},
    ]}
    block = interfaces.type_block(analysis, "ACME::Aurora::Manager *m;")
    assert "std::shared_ptr<" in block and "server" in block
    assert "unsigned char server" not in block


def test_interfaces_vtable_anchor_only_when_no_virtual_method_renders():
    """A real virtual method already occupies vtable slot 0. Adding the synthetic anchor as well
    shifts every call by one slot (isRun +0x38 instead of +0x30). Anchor only when all virtual
    signatures are unspellable and would otherwise be dropped."""
    from dcore.core import interfaces

    good = {"types": [{"name": "Server", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
                       "members": [{"name": "_vptr", "off": 0, "type": "void *"}], "statics": [],
                       "methods": [{"name": "isRun", "ret": "bool", "virtual": True}]}]}
    block = interfaces.type_block(good, "ACME::Aurora::Server *s;")
    assert "virtual bool isRun();" in block
    assert "_dcore_vtable_anchor" not in block

    bad = {"types": [{"name": "Opaque", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
                      "members": [{"name": "_vptr", "off": 0, "type": "void *"}], "statics": [],
                      "methods": [{"name": "run", "ret": "void", "params": ["Unknown<T>"],
                                   "virtual": True}]}]}
    block = interfaces.type_block(bad, "ACME::Aurora::Opaque *o;")
    assert "virtual void _dcore_vtable_anchor();" in block


def test_guess_language_detects_cxx_headers():
    """Header-only edit gates compile the header without a function. A C++ header that only looks
    like C prototypes (extern "C", <cstdint>, std::) must not be validated as `func.c`; that hides
    the real bad declaration behind a C++ include error."""
    from dcore.core.compilers import guess_language

    assert guess_language('#include <cstdint>\nextern "C" { int f(); }\n') == "c++"
    assert guess_language("namespace acme { class Widget; }\nvoid Widget::run();\n") == "c++"
    assert guess_language("std::string name;\n") == "c++"
    assert guess_language("#include <stdint.h>\nint f(void);\n") == "c"
    assert guess_language("int rename(const char *old, const char *new);\n") == "c"


def test_analyze_compiler_groups_rank_by_functions_not_units():
    """A vendored MySQL tree can contribute more C units than the game has merged C++ units. The
    project default must follow the code the user decompiles (function count), not unit count."""
    from dcore.core.analyze import compiler_groups

    units = [{"compiler": "GNU C 4.8.5", "flags": ["-O2"], "path": f"mysql/{i}.c"} for i in range(5)]
    units.append({"compiler": "GNU C++17 9.1.0", "flags": ["-Og", "-std=c++2a"], "path": "src/game.cpp"})
    funcs = [{"cu": "src/game.cpp"}] * 10 + [{"cu": f"mysql/{i}.c"} for i in range(5)]
    groups = compiler_groups(units, funcs)
    assert groups[0]["compiler"] == "GNU C++17 9.1.0"
    assert groups[0]["functions"] == 10 and groups[0]["units"] == 1
    assert groups[1]["compiler"] == "GNU C 4.8.5"
    assert groups[1]["functions"] == 5 and groups[1]["units"] == 5


def test_resolve_prefers_the_compile_units_producer_and_flags(tmp_path, elf_bytes):
    """One binary can vendor MySQL C 4.8.5 and game C++17 9.1.0. A function's line file may be a
    header, so the CU is the key: its flags beat the project's; an explicit unit override and a
    per-function probe still win, in that order."""
    from dcore.core import compilers

    net, slug, _binary = _native_project(tmp_path, elf_bytes)
    net._update_cfg(slug, lambda cfg: cfg.update({
        "compiler": {"guess": "GNU C 4.8.5", "flags": ["-O2"], "image": "gcc:9.1.0",
                     "cu": {"src/game.cpp": {"compiler": "GNU C++17 9.1.0", "flags": ["-Og"]}}},
        "analysis": {"compilers": [{"compiler": "GNU C 4.8.5", "flags": ["-O2"], "functions": 10,
                                    "units": 81}]},
    }))
    c = compilers.resolve(net, slug, "c++", cu="src/game.cpp")
    assert c.flags == ["-Og"] and c.command == ["g++"] and c.image == "gcc:9.1.0"
    net._update_cfg(slug, lambda cfg: cfg["compiler"].setdefault("units", {}).update(
        {"src/game.cpp": {"flags": ["-O1"]}}))
    assert compilers.resolve(net, slug, "c++", unit="src/game.cpp", cu="src/game.cpp").flags == ["-O1"]
    assert compilers.resolve(net, slug, "c++", cu="src/game.cpp", fn_flags=["-O3"]).flags == ["-O3"]


def test_analyze_compile_unit_map_keys_by_cu_path():
    from dcore.core.analyze import compile_unit_map

    units = [{"path": "src/game.cpp", "compiler": "GNU C++17 9.1.0", "flags": ["-Og"]},
             {"path": "mysql/a.c", "compiler": "GNU C 4.8.5", "flags": ["-O2"]},
             {"path": "", "compiler": "GNU C 4.8.5", "flags": []}]
    m = compile_unit_map(units)
    assert m["src/game.cpp"]["flags"] == ["-Og"]
    assert m["mysql/a.c"]["compiler"] == "GNU C 4.8.5"
    assert "" not in m


def test_signature_info_reads_class_fields_for_the_header_editor(tmp_path, elf_bytes):
    import json as _json

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    path = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    data = _json.loads(path.read_text())
    data["types"] = [{"name": "Widget", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
                      "members": [], "statics": [],
                      "methods": [{"name": "run", "ret": "bool", "params": ["int"], "const": True}]}]
    path.write_text(_json.dumps(data))
    net.native._analysis.pop(slug, None)
    info = net.native.signature_info({"name": "ACME::Aurora::Widget::run(int)"}, net._project(slug))
    assert info == {"ret": "bool", "params": "int", "const": True, "static": False, "virtual": False}


def test_drawer_diff_compiles_with_the_files_own_flags(tmp_path, elf_bytes):
    """The drawer drew a stale 41% next to a function marked 100%: function_diff compiled the matched
    source without the function, so the file's adopted flags were skipped and -O0 output was compared
    against the -O2 target. The matched source must score 0 under the same flags the judge used."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": ["-O0"]}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("drawer")
    net.claim(agent, slug, "score_update")
    source = (
        "static int clamp_i(int v, int lo, int hi) {\n"
        "    if (v < lo) return lo;\n"
        "    if (v > hi) return hi;\n"
        "    return v;\n"
        "}\n"
        "int score_update(int *score, int delta, int max) {\n"
        "    *score = clamp_i(*score + delta, 0, max);\n"
        "    return *score;\n"
        "}\n")
    assert net.native.set_flags(agent, slug, " ".join(flags), function="score_update", scope="file").startswith("✅")
    assert net.attempt(agent, "score_update", source, slug)["matched"] is True
    # the project default is still -O0, but the drawer must build like the match did
    assert net.cfg(net._project(slug))["compiler"]["flags"] == ["-O0"]
    d = net.function_diff(slug, "score_update")
    assert d["score"] == 0 and d["percent"] == 100.0, d.get("problems")


def test_a_class_name_asked_as_a_function_answers_with_its_layout(tmp_path, elf_bytes):
    """Agents dereference class and static-member names through get_function (the log is full of
    "no function 'ACME::Aurora::Core::DoubleLinkNode'"). The answer should be the layout, not a refusal."""
    import json as _json

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    path = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    data = _json.loads(path.read_text())
    data["types"] = [
        {"name": "Node", "ns": ["ACME", "Aurora", "Core"], "size": 32, "kind": "struct",
         "members": [{"name": "_vptr", "off": 0, "type": "void *"},
                     {"name": "owner_ptr", "off": 8, "type": "void *"},
                     {"name": "next_ptr", "off": 16, "type": "Node *"},
                     {"name": "prev_ptr", "off": 24, "type": "Node *"}],
         "statics": []},
        {"name": "Defaults", "ns": ["ACME", "Aurora", "Core"], "size": 8, "kind": "struct",
         "members": [{"name": "log_", "off": 0, "type": "int"}],
         "statics": ["legacy_name_", {"name": "default_log_obj_", "type": "Defaults *"}]},
    ]
    path.write_text(_json.dumps(data))
    out = net.get_function("ACME::Aurora::Core::Node", slug)
    assert "is a class, not a function" in out and "struct Node {" in out and "Node * next_ptr;" in out
    out = net.get_function("default_log_obj_", slug)
    assert "static data member" in out and "Defaults" in out
    assert "static Defaults * default_log_obj_;  /* defined elsewhere */" in out
    out = net.get_function("legacy_name_", slug)  # older analyses registered statics as plain names
    assert "static data member" in out and "Defaults" in out
    # a genuinely missing function still says so
    from dcore.core.network import NetworkError

    with pytest.raises(NetworkError, match="no function"):
        net.get_function("definitely_not_there", slug)


def test_native_loop_compiles_judges_and_protects_the_header(tmp_path, elf_bytes):
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    compiler = _fixture_compiler()
    if compiler is None:
        pytest.skip("needs zig or a Linux C compiler matching the fixture")
    command, flags = compiler
    net._update_cfg(slug, lambda cfg: cfg.setdefault("compiler", {}).update({"command": command, "flags": flags}))
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("loop")
    brief = net.claim(agent, slug, "score_update")
    assert "Target assembly" in brief and "score_update" in brief and "Where it lives" in brief
    context = net.get_context(slug, function="score_update")
    assert "context.h for" in context
    source = (
        "static int clamp_i(int v, int lo, int hi) {\n"
        "    if (v < lo) return lo;\n"
        "    if (v > hi) return hi;\n"
        "    return v;\n"
        "}\n"
        "int score_update(int *score, int delta, int max) {\n"
        "    *score = clamp_i(*score + delta, 0, max);\n"
        "    return *score;\n"
        "}\n")
    res = net.attempt(agent, "score_update", source, slug)
    assert res["matched"], res["text"][:800]
    audit = net.native.strict_rejudge(net.project_row(slug))
    assert "1 matched, 0 failed" in audit, audit
    # the header now has a match to protect: a note is fine, an error is rejected
    good = net.edit_context(agent, slug, "", "/* tuned */", "note", function="score_update")
    assert good.startswith("✅"), good
    bad = net.edit_context(agent, slug, "", "#error broken", "break it", function="score_update")
    assert bad.startswith("❌") and "score_update" in bad, bad
    # a wrong constant is still just a diff (scratch attempt on the matched function)
    res2 = net.attempt(agent, "score_update", source.replace("0, max", "1, max"), slug)
    assert res2["matched"] is False and res2["score"] is not None


@needs_ida
def test_full_analysis_with_ida(tmp_path, elf_bytes):
    from dcore.core import analyze as analyze_mod

    net, slug, _ = _native_project(tmp_path, elf_bytes)
    data = analyze_mod.analyze(net, slug, log=lambda *_: None)
    by_name = {f["display"]: f for f in data["functions"]}
    assert "score_update" in by_name and "main" in by_name
    score = by_name["score_update"]
    assert score["provenance"] == "dwarf" and score["file"].endswith("hello.c") and score["line"]
    assert data["graph"]["files"], "file graph expected"
    assert any(e["ea"] == by_name["main"]["ea"] for e in data["edges"]), "main calls printf"
    again = analyze_mod.analyze(net, slug, log=lambda *_: None)
    assert again["generated_at"] == data["generated_at"]  # cached: no second IDA run
    # confirm the plan, then a claim fetches that function's Hex-Rays seed through the same IDA
    from dcore.core import plan as plan_mod

    plan_mod.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("seeded")
    brief = net.claim(agent, slug, "score_update")
    assert "Hex-Rays" in brief and "score_update" in brief


# ------------------------------------------------------------------ the judge


def _build_elf_object(tmp_path, source: str, name: str = "hello") -> bytes | None:
    src = tmp_path / f"{name}.c"
    src.write_text(source)
    out = tmp_path / f"{name}.o"
    if (zig := shutil.which("zig")):
        cmd = [zig, "cc", "-target", "x86_64-linux-gnu", "-g", "-O2", "-c", str(src), "-o", str(out)]
    elif sys.platform.startswith("linux") and (cc := shutil.which("cc") or shutil.which("gcc")):
        cmd = [cc, "-g", "-O2", "-c", str(src), "-o", str(out)]
    else:
        return None
    try:
        _run(cmd)
    except subprocess.CalledProcessError:
        return None
    return out.read_bytes()


def test_judge_matches_reference_and_rejects_perturbation(tmp_path, elf_bytes):
    from io import BytesIO

    from elftools.elf.elffile import ELFFile

    from dcore.targets.plat.elf.object import extract_function
    from dcore.core import judge, scoring
    from dcore.targets.plat.elf import dwarf
    from dcore.targets import formats
    from dcore.core.target import Reconstructor

    binary = tmp_path / "hello"
    binary.write_bytes(elf_bytes)
    image = formats.identify(elf_bytes)
    assert image is not None
    d = dwarf.analyze(binary)
    funcs = {f["low"]: {"name": f.get("name"), "display": f.get("name")}
             for f in d["functions"] if f.get("kind") == "function"}
    symtab = ELFFile(BytesIO(elf_bytes)).get_section_by_name(".symtab")
    if symtab:  # thunks like `.printf` have no DWARF; the linker's names cover them
        for s in symtab.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
                funcs.setdefault(s["st_value"], {"name": s.name, "display": s.name})
    rc = Reconstructor(elf_bytes, image, funcs)
    obj = _build_elf_object(tmp_path, SRC)
    assert obj, "the candidate object couldn't be built"

    score_fn = next(f for f in d["functions"] if f.get("kind") == "function" and f.get("name") == "score_update")
    score_rec = {"ea": score_fn["low"], "size": score_fn["end"] - score_fn["low"], "name": "score_update"}
    target = rc.view(score_rec)
    candidate = extract_function(obj, "score_update")
    assert target is not None and candidate is not None
    verdict = judge.compare(target, candidate)
    assert verdict.match, verdict.diff.render() + "\n" + "\n".join(verdict.problems)
    assert verdict.diff.gist and verdict.diff.gist["ok"], verdict.diff.gist
    assert "calls" in scoring.gist_text(verdict.diff.gist)

    # the same function with a changed constant must be rejected, with a diff to look at
    bad_src = SRC.replace("clamp_i(*score + delta, 0, max)", "clamp_i(*score + delta, 1, max)")
    assert bad_src != SRC
    bad = _build_elf_object(tmp_path, bad_src, name="bad")
    assert bad
    verdict_bad = judge.compare(target, extract_function(bad, "score_update"))
    assert not verdict_bad.match and not verdict_bad.diff.bytes_match
    assert verdict_bad.diff.rows
    assert verdict_bad.diff.gist and not verdict_bad.diff.gist["ok"]
    assert verdict_bad.diff.gist["constants"]["missing"] or verdict_bad.diff.gist["constants"]["extra"]

    # main calls printf through the linked binary's thunk: the thunk is an explicit import
    # alias, and the local string label is a section-relative spelling.  Both are link
    # equivalence, not fuzzy matching.
    from dcore.core.symbols import SymbolTable

    main_fn = next(f for f in d["functions"] if f.get("kind") == "function" and f.get("name") == "main")
    target_main = rc.view({"ea": main_fn["low"], "size": main_fn["end"] - main_fn["low"], "name": "main"})
    aliases = SymbolTable.from_analysis(
        {"imports": [{"ea": 0, "name": "printf"}]},
        import_aliases={"sub_1001560": "printf"})
    verdict_main = judge.compare(target_main, extract_function(obj, "main"), symbols=aliases)
    assert verdict_main.match, verdict_main.diff.render() + "\n" + "\n".join(verdict_main.problems)
    assert all(m == " " for m, _, _ in verdict_main.diff.rows)  # normalized, not raw spelling


# ---------------------------------------------------------------- reconstruction / export

def test_a_recursive_call_relocation_is_link_equivalent_only_to_the_same_function():
    """The linked target has no reloc for a recursive call; viewed at base 0 it reads `call 0`.
    The object carries a reloc to its own symbol. Adopt it only for that same function."""
    from dcore.core import judge
    from dcore.targets.objects import FunctionObj, Reloc

    name = "?ExtractMatch@String@Base@Obsidian@ACME@@SA_NAEAV?$DynamicArray@VString@Base@Obsidian@ACME@@$01$0BA@@Std@34@PEBD11@Z"
    target = FunctionObj(name, "x86_64", False, bytes.fromhex("e8 fb ff ff ff c3"))
    candidate = FunctionObj(name, "x86_64", False, bytes.fromhex("e8 00 00 00 00 c3"),
                            [Reloc(1, 4, name, 0)])
    verdict = judge.compare(target, candidate)
    assert verdict.match and verdict.diff.score == 0
    assert any("self-call" in x for x in verdict.link_layer)
    other = FunctionObj(name, "x86_64", False, bytes.fromhex("e8 00 00 00 00 c3"),
                        [Reloc(1, 4, "?SomeOtherFunction@@YAXXZ", 0)])
    assert judge.compare(target, other).match is False
    # a call to the next instruction (target 5) is not a self-call, even with the right symbol
    not_self = FunctionObj(name, "x86_64", False, bytes.fromhex("e8 00 00 00 00 c3"))
    assert judge.compare(not_self, candidate).match is False


def test_a_self_call_is_recognized_with_a_demangled_target_name():
    """The stored name can be the demangled signature while the object carries the mangled
    symbol.  The target's own call is at +0xA1 (rel32 -0xA6 -> 0); the object's reloc is at
    the displacement field.  This used to fail because symbol_leaf() split on a `::` inside
    the parameter list, reporting one extra reference (score 10)."""
    from dcore.core import judge
    from dcore.targets.objects import FunctionObj, Reloc

    mangled = "?ExtractMatch@String@Base@Obsidian@ACME@@SA_NAEAV?$DynamicArray@VString@Base@Obsidian@ACME@@$01$0BA@@Std@34@PEBD11@Z"
    demangled = ("ACME::Obsidian::Base::String::ExtractMatch("
                 "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> &,"
                 "char const *,char const *,char const *)")
    # 0xA1 NOPs, then `e8 5a ff ff ff` (the report's self-call), then ret
    code = b"\x90" * 0xA1 + bytes.fromhex("e8 5a ff ff ff c3")
    target = FunctionObj(demangled, "x86_64", False, code)
    candidate = FunctionObj(mangled, "x86_64", False, code, [Reloc(0xA2, 4, mangled, 0)])
    verdict = judge.compare(target, candidate)
    assert verdict.match and verdict.diff.score == 0
    assert any("self-call" in x for x in verdict.link_layer)
    other = FunctionObj(mangled, "x86_64", False, code,
                        [Reloc(0xA2, 4, "?SomeOtherFunction@@YAXXZ", 0)])
    assert judge.compare(target, other).match is False


def test_a_self_call_is_recognized_by_resolved_address_even_with_unrelated_names():
    """The Name-based fallback is a stopgap.  When the shared SymbolTable maps the object's
    symbol to the diffed function's address, the self-call is link-equivalent regardless of
    the stored target/candidate spelling."""
    from dcore.core import judge
    from dcore.core.symbols import SymbolTable
    from dcore.targets.objects import FunctionObj, Reloc

    mangled = "?ExtractMatch@String@Base@Obsidian@ACME@@SA_NAEAV?$DynamicArray@VString@Base@Obsidian@ACME@@$01$0BA@@Std@34@PEBD11@Z"
    base = 0x140000000
    table = SymbolTable.from_analysis({
        "functions": [{"ea": base, "name": mangled, "display": "target", "linkage": mangled}],
    })
    code = b"\x90" * 0xA1 + bytes.fromhex("e8 5a ff ff ff c3")
    target = FunctionObj("target", "x86_64", False, code, base_ea=base)
    candidate = FunctionObj("candidate", "x86_64", False, code,
                            [Reloc(0xA2, 4, mangled, 0)])
    verdict = judge.compare(target, candidate, symbols=table)
    assert verdict.match and verdict.diff.score == 0
    assert any("self-call" in x for x in verdict.link_layer)

    # a symbol resolving to a different address is still a real extra reference
    other = SymbolTable.from_analysis({
        "functions": [{"ea": base + 0x1000, "name": mangled, "display": "other", "linkage": mangled}],
    })
    assert judge.compare(target, candidate, symbols=other).match is False


def test_local_branches_are_equivalent_even_when_the_object_has_a_local_reloc():
    """The linked target has no reloc for `je .L20`; a COFF object can spell it
    `.text+0x20`.  Both sides must normalise to the same relative destination before
    the offset sets are compared."""
    from dcore.core import judge
    from dcore.targets.objects import FunctionObj, Reloc

    # je +0x1a at 0 (6-byte near jump), NOPs, ret at +0x20
    code = bytes.fromhex("0f 84 1a 00 00 00") + b"\x90" * 0x1A + b"\xc3"
    target = FunctionObj("target", "x86_64", False, code, base_ea=0x140000000)
    # candidate has no reloc: both sides still decode +0x20 and match
    assert judge.compare(target, FunctionObj("candidate", "x86_64", False, code)).match

    local = FunctionObj("candidate", "x86_64", False, code,
                        [Reloc(2, 4, ".text+0x20", 0)])
    verdict = judge.compare(target, local)
    assert verdict.match and verdict.diff.score == 0

    wrong = FunctionObj("candidate", "x86_64", False, code,
                        [Reloc(2, 4, ".text+0x10", 0)])
    assert judge.compare(target, wrong).match is False

    unresolved = FunctionObj("candidate", "x86_64", False, code,
                             [Reloc(2, 4, "?SomeOtherFunction@@YAXXZ", 0)])
    assert judge.compare(target, unresolved).match is False


def test_a_jump_thunk_reads_as_its_target():
    from dcore.core.target import Reconstructor
    from dcore.targets.image import NativeImage, Section

    image = NativeImage("pe", "x86_64", 64, "exe", 0x1000, 0x1000,
                        [Section(".text", 0x1000, 0x200, 0x100, "code")],
                        False, "", None, "", [])
    data = bytearray(0x300)
    # thunk at 0x1000: jmp 0x1100 (next instruction 0x1005, displacement 0xfb)
    data[0x100:0x105] = b"\xe9\xfb\x00\x00\x00"
    data[0x200] = 0xC3  # ret at 0x1100
    rc = Reconstructor(bytes(data), image, {0x1100: {"name": "?foo@@YAXXZ", "display": "foo"}})
    assert rc.function_name(0x1000) == "foo"
    assert rc.function_name(0x1001) is None


def test_external_branches_compare_resolved_addresses_not_spellings():
    from dcore.core import judge
    from dcore.core.symbols import SymbolTable
    from dcore.targets.objects import FunctionObj, Reloc

    code = bytes.fromhex("e8 00 00 00 00 c3")
    table = SymbolTable.from_analysis({
        "functions": [
            {"ea": 0x140001000, "name": "bar", "display": "bar", "linkage": "bar"},
            {"ea": 0x140002000, "name": "baz", "display": "baz", "linkage": "baz"},
        ],
    })
    target = FunctionObj("target", "x86_64", False, code,
                         [Reloc(1, 2, "foo", -4, target_ea=0x140001000)],
                         base_ea=0x140000000)
    same = FunctionObj("candidate", "x86_64", False, code, [Reloc(1, 4, "bar", -4)])
    other = FunctionObj("candidate", "x86_64", False, code, [Reloc(1, 4, "baz", -4)])
    assert judge.compare(target, same, symbols=table).match
    assert judge.compare(target, other, symbols=table).match is False

    # Same spelling, different resolved address: the name fallback must not mask it.
    moved = SymbolTable.from_analysis({
        "functions": [{"ea": 0x140002000, "name": "foo", "display": "foo", "linkage": "foo"}],
    })
    same_name = FunctionObj("candidate", "x86_64", False, code, [Reloc(1, 4, "foo", -4)])
    assert judge.compare(target, same_name, symbols=moved).match is False


def test_data_references_compare_the_resolved_address_and_residual():
    from dcore.core import judge
    from dcore.core.symbols import SymbolTable
    from dcore.targets.objects import FunctionObj, Reloc

    code = bytes.fromhex("8b 05 00 00 00 00 c3")  # mov eax, [rip+disp32]
    table = SymbolTable.from_analysis({
        "data": [
            {"ea": 0x140003000, "name": "g"},
            {"ea": 0x140004000, "name": "h"},
            {"ea": 0x140005004, "name": "k"},
        ],
    })
    # target references g+8; candidate objects carry the PC-relative residual (4) and the
    # judge adds the x86 -4 instruction bias before comparing the final address.
    target = FunctionObj("target", "x86_64", False, code,
                         [Reloc(2, 2, "g", -4, target_ea=0x140003008)],
                         base_ea=0x140000000)
    same = FunctionObj("candidate", "x86_64", False, code, [Reloc(2, 4, "g", 4)])
    wrong_field = FunctionObj("candidate", "x86_64", False, code, [Reloc(2, 4, "g", 0)])
    wrong_global = FunctionObj("candidate", "x86_64", False, code, [Reloc(2, 4, "h", 4)])
    assert judge.compare(target, same, symbols=table).match
    assert judge.compare(target, wrong_field, symbols=table).match is False
    assert judge.compare(target, wrong_global, symbols=table).match is False

    # section-relative references compare the same section+offset, not the spelling.
    target_section = FunctionObj("target", "x86_64", False, code,
                                 [Reloc(2, 2, ".rdata+0x4", -4, target_ea=0x140005004)],
                                 base_ea=0x140000000)
    same_section = FunctionObj("candidate", "x86_64", False, code,
                               [Reloc(2, 4, ".rdata+0x4", 0)])
    other_section = FunctionObj("candidate", "x86_64", False, code,
                                [Reloc(2, 4, ".rdata+0x8", 0)])
    assert judge.compare(target_section, same_section).match
    assert judge.compare(target_section, other_section).match is False

    # A linked PE data reference has no target_ea and no name, only `.rdata+0x4`; the
    # rip-relative field still resolves it to h's address, so a named candidate matches.
    named = bytes.fromhex("8b 05 fe 4f 00 00 c3")  # dest = base + 6 + 0x4ffe = 0x140005004
    target_unnamed = FunctionObj("target", "x86_64", False, named,
                                 [Reloc(2, 2, ".rdata+0x4", -4)],
                                 base_ea=0x140000000)
    named_candidate = FunctionObj("candidate", "x86_64", False, named,
                                  [Reloc(2, 4, "k", -4)])
    wrong_candidate = FunctionObj("candidate", "x86_64", False, named,
                                  [Reloc(2, 4, "h", -4)])
    assert judge.compare(target_unnamed, named_candidate, symbols=table).match
    assert judge.compare(target_unnamed, wrong_candidate, symbols=table).match is False
    unknown = FunctionObj("candidate", "x86_64", False, named, [Reloc(2, 4, "zz", -4)])
    verdict = judge.compare(target_unnamed, unknown, symbols=table)
    assert verdict.match is False
    assert 'name_data("zz", "0x140005004")' in " ".join(verdict.problems)


def test_msvc_string_literals_compare_by_content_when_the_target_is_unnamed():
    """The target has only `aStringCpp`; the object names the literal by its mangled spelling.
    Decode the literal and read the target bytes: equal content is the same reference."""
    from dcore.core import judge
    from dcore.targets.objects import FunctionObj, Reloc

    symbol = "??_C@_0L@HJKDFAGD@String?4cpp?$AA@"
    assert judge._msvc_literal(symbol) == b"String.cpp\0"
    code = bytes.fromhex("48 8d 05 00 00 00 00 c3")
    target = FunctionObj("target", "x86_64", False, code,
                         [Reloc(3, 2, "aStringCpp", -4, target_ea=0x140006000)],
                         base_ea=0x140000000)
    candidate = FunctionObj("candidate", "x86_64", False, code,
                            [Reloc(3, 4, symbol, -4)])
    read = lambda ea, n: b"String.cpp\0" if ea == 0x140006000 else None
    assert judge.compare(target, candidate, read_bytes=read).match
    wrong = lambda ea, n: b"String.h\0" if ea == 0x140006000 else None
    assert judge.compare(target, candidate, read_bytes=wrong).match is False


def test_tls_relocations_are_link_equivalent_only_at_the_same_symbol_and_offset():
    """A compiled object spells a TLS access as SECREL + symbol; the binary has the linked offset.
    The judge adopts it only when the symbol's TLS offset equals the target's immediate."""
    from dcore.core import judge
    from dcore.targets.objects import FunctionObj, Reloc

    sym = "?s_pMemoryTagStack_@Memory@Core@Aurora@ACME@@3PEAV?$vector@PEBDV?$allocator@PEBD@std@@@std@@EA"
    target = FunctionObj("pop", "x86_64", False, bytes.fromhex("ba b0 00 00 00 c3"))
    candidate = FunctionObj("pop", "x86_64", False, bytes.fromhex("ba 00 00 00 00 c3"),
                            [Reloc(1, 11, sym, 0)])
    verdict = judge.compare(target, candidate, tls_offsets={"s_pMemoryTagStack_": 0xB0})
    assert verdict.match and verdict.diff.score == 0 and verdict.link_layer
    assert judge.compare(target, candidate, tls_offsets={"s_pMemoryTagStack_": 0xA0}).match is False
    assert judge.compare(target, candidate, tls_offsets={"other_tls": 0xB0}).match is False


def test_native_reconstruction_strips_the_scaffolding_from_a_matched_source():
    """Signature-anchored extraction: the definition survives, the hand-declared classes, the
    includes and the namespace wrappers around it do not."""
    from dcore.core import export as export_mod

    src = '''#include "somewhere.h"
namespace common { namespace tracekit {
struct TraceLogStream {
    TraceLogStream(TraceLog& log, unsigned int level, const char* file, const char* func, int line);
    char buf_[0x1a0];
};
}}

namespace common { namespace tools {
class DoubleLinkNode {
public:
    char data_[16];
    DoubleLinkNode *next_;
    DoubleLinkNode *prev_;
};
class DoubleLink {
public:
    static void remove(DoubleLinkNode *node_ptr);
    DoubleLinkNode *pop();
    DoubleLinkNode head_;
    DoubleLinkNode tail_;
};

DoubleLinkNode *DoubleLink::pop() {
    DoubleLinkNode *node_ptr = head_.next_;
    if (node_ptr == &tail_)
        return nullptr;
    remove(node_ptr);
    return node_ptr;
}
}}
'''
    cands = export_mod.extract_definitions(src, "ACME::Aurora::Core::DoubleLink::pop(void)")
    assert len(cands) == 1
    text = cands[0]["text"]
    assert text.startswith("DoubleLinkNode *DoubleLink::pop()")
    assert text.rstrip().endswith("}")
    for unwanted in ("TraceLogStream", "class DoubleLinkNode", "static void remove", "#include"):
        assert unwanted not in text


def test_native_reconstruction_place_qualifies_and_wraps():
    from dcore.core import export as export_mod

    types = [{"name": "DoubleLink", "ns": ["ACME", "Aurora", "Core"], "size": 72, "kind": "class",
              "members": [], "statics": [], "methods": []}]
    analysis = {"types": types}
    # written in-class style (unqualified): gets the class qualification
    cand = {"text": "DoubleLinkNode *pop() { return nullptr; }", "tail_at": 16}
    out = export_mod._place(cand, "ACME::Aurora::Core::DoubleLink::pop(void)", analysis)
    assert out.startswith("DoubleLinkNode *ACME::Aurora::Core::DoubleLink::pop()")
    # relative-qualified: stays itself, wrapped in its namespaces
    cand = {"text": "DoubleLinkNode *DoubleLink::pop() { return nullptr; }", "tail_at": 31}
    out = export_mod._place(cand, "ACME::Aurora::Core::DoubleLink::pop(void)", analysis)
    assert out.startswith("namespace ACME { namespace Aurora { namespace Core {\n") and "DoubleLink::pop()" in out


def test_native_reconstruction_renames_invented_members_onto_the_debug_info_layout():
    from dcore.core import export as export_mod

    analysis = {"types": [
        {"name": "DoubleLinkNode", "ns": ["common", "tools"], "size": 32, "kind": "struct",
         "members": [{"name": "_vptr.DoubleLinkNode", "off": 0, "type": "void *"},
                     {"name": "owner_ptr", "off": 8, "type": "DoubleLink *"},
                     {"name": "next_ptr", "off": 16, "type": "DoubleLinkNode *"},
                     {"name": "prev_ptr", "off": 24, "type": "DoubleLinkNode *"}],
         "statics": [], "methods": []},
        {"name": "DoubleLink", "ns": ["common", "tools"], "size": 72, "kind": "class",
         "members": [{"name": "head_", "off": 0, "type": "DoubleLinkNode"},
                     {"name": "tail_", "off": 32, "type": "DoubleLinkNode"}],
         "statics": [], "methods": []},
    ]}
    src = '''class DoubleLinkNode {
public:
    char data_[16];
    DoubleLinkNode *next_;
    DoubleLinkNode *prev_;
};
class DoubleLink {
public:
    DoubleLinkNode head_;
    DoubleLinkNode tail_;
};
'''
    text = "DoubleLinkNode *DoubleLink::pop() { return head_.next_; }"
    out = export_mod._renamed(text, src, analysis, 8)
    assert out and "head_.next_ptr" in out and "next_" not in out.replace("next_ptr", "")
    # nothing to rename: the same names already
    assert export_mod._renamed("return tail_.prev_ptr;", src, analysis, 8) is None


def test_native_reconstruction_salvages_pruned_classes_from_the_matched_sources():
    from dcore.core import export as export_mod

    out = export_mod._salvage_declarations(
        [],
        ["common::tracekit::TraceLogDefault::default_log_obj_, 4u"],
        ["""struct TraceLogDefault {
    static TraceLog default_log_obj_;
};"""])
    assert "namespace common { namespace tracekit {" in out
    assert "static TraceLog default_log_obj_;" in out
    # a class the debug info already describes is not salvaged
    assert export_mod._salvage_declarations(
        [{"name": "Known", "ns": [], "size": 4, "kind": "struct", "members": [],
          "statics": [], "methods": []}],
        ["Known::field"], []) == ""


def test_split_display_handles_operators_destructors_and_file_suffixes():
    from dcore.core.export import _split_display

    assert _split_display("ACME::Aurora::Core::DoubleLink::pushFront(ACME::Aurora::Core::DoubleLinkNode *)"
                          "@double_link.cpp") == ("ACME::Aurora::Core::DoubleLink", "pushFront")
    assert _split_display("ACME::Aurora::Core::X::operator()(int)") == ("ACME::Aurora::Core::X", "operator()")
    assert _split_display("ACME::Aurora::Core::DoubleLink::~DoubleLink(void)") == ("ACME::Aurora::Core::DoubleLink",
                                                                              "~DoubleLink")
    assert _split_display("plain_free_function(void)") == ("", "plain_free_function")


def test_native_layouts_declare_methods_variadics_and_forward_declarations():
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "TraceLog", "ns": ["common", "tracekit"], "size": 0x100000, "kind": "class",
         "members": [], "statics": [], "methods": []},
        {"name": "TraceLogStream", "ns": ["common", "tracekit"], "size": 32, "kind": "class",
         "members": [{"name": "log_", "off": 0, "type": "TraceLog &"}],
         "statics": [],
         "methods": [{"name": "TraceLogStream", "linkage": "c", "static": False, "const": False,
                      "virtual": False, "access": 1, "ret": "", "params": ["TraceLog &"], "variadic": False},
                     {"name": "operator()", "linkage": "v", "static": False, "const": False,
                      "virtual": False, "access": 1, "ret": "void", "params": ["const char *"],
                      "variadic": True}]},
        {"name": "Node", "ns": ["tools"], "size": 16, "kind": "struct",
         "members": [{"name": "_vptr.Node", "off": 0, "type": "void *"},
                     {"name": "next", "off": 8, "type": "Node *"}],
         "statics": [],
         "methods": [{"name": "~Node", "linkage": "d", "static": False, "const": False,
                      "virtual": True, "access": 1, "ret": "", "params": [], "variadic": False},
                     {"name": "remove", "linkage": "r", "static": True, "const": False,
                      "virtual": False, "access": 1, "ret": "void", "params": ["Node *"],
                      "variadic": False},
                     {"name": "empty", "linkage": "e", "static": False, "const": True,
                      "virtual": False, "access": 1, "ret": "bool", "params": [], "variadic": False},
                     {"name": "operator<< <unsigned int>", "linkage": "t", "static": False,
                      "const": False, "virtual": False, "access": 1, "ret": "Node &",
                      "params": [], "variadic": False}]},
    ]}
    block = interfaces.type_block(analysis, "TraceLogStream *s; Node *n;")
    assert "TraceLog & log_;" in block
    assert "class TraceLog;" in block  # a reference member to a class too big to define: forward-declared
    assert "TraceLogStream(TraceLog &);" in block
    assert "void operator()(const char *, ...);" in block  # variadic survives
    assert "virtual ~Node();" in block  # the vptr comes from this declaration…
    assert "void * _vptr;" not in block  # …so it must not also be a data member
    assert "static void remove(Node *);" in block
    assert "bool empty() const;" in block
    assert "operator<< <unsigned int>" not in block  # templates stay out of the declarations


# ---------------------------------------------------------------- the type registry

def test_native_registry_type_spellings():
    from dcore.core import registry

    for good in ("int", "unsigned long long", "char", "void *", "const char **", "DoubleLinkNode *",
                 "std::vector<int>", "std::map<std::string, Foo *>", "std::list<ACME::Aurora::Core::Node>",
                 "std::pair<int, std::vector<char>>", "Foo[32]", "const std::string &",
                 "std::unique_ptr<Foo>", "unsigned char[16]"):
        assert registry.check_type(good) is None, good
    for bad in ("", "int x", "foo bar;", "int;", "std::vector<int", "return 0;"):
        assert registry.check_type(bad) is not None, bad


def test_native_registry_view_layers_agent_entries_over_the_debug_info():
    from dcore.core import registry

    analysis = {"types": [{"name": "Node", "ns": ["a"], "size": 8, "kind": "struct",
                           "members": [{"name": "x", "off": 0, "type": "int"}],
                           "statics": [], "methods": []}]}
    overrides = {"version": 1, "types": {
        "a::Node": {"name": "Node", "ns": ["a"], "kind": "struct", "size": 16,
                    "members": [{"name": "x", "off": 0, "type": "int"},
                                {"name": "y", "off": 8, "type": "int"}],
                    "statics": [], "methods": []},
        "Bare": {"name": "Bare", "ns": [], "kind": "struct", "size": 4,
                 "members": [], "statics": [], "methods": []}}}
    v = registry.view(analysis, overrides)
    node = registry.find(v, "Node")
    assert node["origin"] == "agent" and node["size"] == 16 and len(node["members"]) == 2
    assert registry.find(v, "a::Node") is node
    assert registry.find(v, "Bare")["origin"] == "agent"
    # without overrides the debug info's copy is what you get
    assert registry.find(registry.view(analysis, None), "Node")["origin"] == "dwarf"


def test_native_registry_plan_change_operations():
    from dcore.core import registry

    analysis = {"types": []}
    step = registry.plan_change(analysis, {"version": 1, "types": {}}, "declare",
                                {"name": "ACME::Aurora::Core::Node", "kind": "struct", "size": 16, "note": "vptr+8"})
    assert "ACME::Aurora::Core::Node" in step["types"]
    step = registry.plan_change(analysis, step, "set_member",
                                {"name": "ACME::Aurora::Core::Node", "member": "next", "mtype": "Node *", "at": 8})
    assert step["types"]["ACME::Aurora::Core::Node"]["members"] == [{"name": "next", "type": "Node *", "off": 8}]
    step = registry.plan_change(analysis, step, "set_member",
                                {"name": "Node", "member": "arr", "mtype": "char", "at": 0, "count": 8})
    members = step["types"]["ACME::Aurora::Core::Node"]["members"]
    assert [m for m in members if m["off"] == 0][0]["type"] == "char[8]"
    step = registry.plan_change(analysis, step, "rename_member",
                                {"name": "Node", "member": "next", "new_name": "next_ptr"})
    assert [m for m in step["types"]["ACME::Aurora::Core::Node"]["members"] if m["off"] == 8][0]["name"] == "next_ptr"
    step = registry.plan_change(analysis, step, "move", {"name": "Node", "scope": "ACME::Obsidian"})
    assert "ACME::Obsidian::Node" in step["types"]
    bad = registry.plan_change(analysis, step, "declare", {"name": "Nope", "kind": "class"})
    with pytest.raises(registry.RegistryError):
        registry.plan_change(analysis, {"version": 1, "types": {}}, "declare",
                             {"name": "ACME::Aurora::Core::Node", "kind": "wat"})


def test_native_registry_set_method_keeps_templated_parameters_whole():
    """A parameter list is split on top-level commas only: a template argument or a function
    pointer carries its own commas, and splitting them produces a different (wrong) mangling."""
    from dcore.core import registry

    step = registry.plan_change({"types": []}, {"version": 1, "types": {}}, "declare",
                                {"name": "ACME::Aurora::Widget", "kind": "class", "size": 8})
    step = registry.plan_change(
        {"types": []}, step, "set_method",
        {"name": "Widget", "member": "take", "mtype": "int",
         "params": "std::pair<int, int> const &, void (*)(int, int), const boost::asio::yield_context &"})
    method = step["types"]["ACME::Aurora::Widget"]["methods"][0]
    assert method["params"] == ["std::pair<int, int> const &", "void (*)(int, int)",
                                "const boost::asio::yield_context &"]


def test_native_registry_set_method_preserves_existing_virtual_metadata():
    """Changing a return/parameter spelling must not drop `access`, `linkage` or `virtual`; vtable
    layout and mangling depend on them. Only flags explicitly passed are changed."""
    from dcore.core import registry

    analysis = {"types": [{"name": "Widget", "ns": ["ACME", "Aurora"], "kind": "class", "size": 8,
                           "members": [], "statics": [],
                           "methods": [{"name": "run", "ret": "void", "params": [], "virtual": True,
                                        "access": 1, "linkage": "_ZNK4ACME6Aurora6Widget3runEv"}]}]}
    step = registry.plan_change(analysis, {"version": 1, "types": {}}, "set_method",
                                {"name": "ACME::Aurora::Widget", "member": "run", "mtype": "bool",
                                 "params": "", "virtual": "true"})
    method = step["types"]["ACME::Aurora::Widget"]["methods"][0]
    assert method["ret"] == "bool" and method["virtual"] is True
    assert method["access"] == 1 and method["linkage"] == "_ZNK4ACME6Aurora6Widget3runEv"


def test_native_registry_remove_method_drops_one_overload_or_all():
    from dcore.core import registry

    analysis = {"types": []}
    step = registry.plan_change(analysis, {"version": 1, "types": {}}, "declare",
                                {"name": "ACME::Aurora::Widget", "kind": "class", "size": 8})
    step = registry.plan_change(analysis, step, "set_method",
                                {"name": "Widget", "member": "compute", "mtype": "int", "params": "int"})
    step = registry.plan_change(analysis, step, "set_method",
                                {"name": "Widget", "member": "compute", "mtype": "int",
                                 "params": "char const *"})
    step = registry.plan_change(analysis, step, "set_method",
                                {"name": "Widget", "member": "reset", "mtype": "void"})
    step = registry.plan_change(analysis, step, "remove_method",
                                {"name": "Widget", "member": "compute", "params": "int"})
    remaining = step["types"]["ACME::Aurora::Widget"]["methods"]
    assert [m["params"] for m in remaining if m["name"] == "compute"] == [["char const *"]]
    step = registry.plan_change(analysis, step, "remove_method",
                                {"name": "Widget", "member": "compute"})
    assert [m["name"] for m in step["types"]["ACME::Aurora::Widget"]["methods"]] == ["reset"]
    with pytest.raises(registry.RegistryError):
        registry.plan_change(analysis, step, "remove_method",
                             {"name": "Widget", "member": "compute"})


def test_native_registry_declared_names_and_header_shadowing():
    from dcore.core import interfaces, registry

    assert registry.declared_names("class DoubleLinkNode { public: int next; };") == {"DoubleLinkNode"}
    assert registry.declared_names("struct A {}; enum B { X }; union C {};") == {"A", "B", "C"}
    analysis = {"types": [{"name": "Node", "ns": ["a"], "size": 8, "kind": "struct",
                           "members": [{"name": "n", "off": 0, "type": "int"}],
                           "statics": [], "methods": []}]}
    hdr = registry.header_for(analysis, "/* ctx */\n", "void f(a::Node *p) { p->n = 1; }",
                              {"version": 1, "types": {}})
    assert "struct Node {" in hdr and "namespace a {" in hdr
    # the source declares its own Node: the projection steps aside, no redefinition fight
    hdr2 = registry.header_for(analysis, "/* ctx */\n", "struct Node { int n; };\nvoid f(Node *p) {}",
                               {"version": 1, "types": {}})
    assert interfaces._TYPE_MARK_BEGIN not in hdr2


def test_type_blocks_names_what_a_submission_defines_itself():
    from dcore.core import registry

    src = "\n".join([
        "struct Mentioned *p;",                        # a mention, not a definition
        "class Forward;",                              # forward declaration
        "// struct Commented { int x; };",
        'const char *s = "struct InString { int y; };";',
        "static const int kTable[] = { 1, 2 };",       # a constant table is the function's business
        "void f() { struct Local { int z; }; }",       # inside the function: its own business
        "namespace common {",                          # scaffolding wraps it in the project's namespace
        "struct TxtFile { struct Row { int n; }; };",  # flagged once, the outer struct
        "typedef unsigned int u32;",
        "}",
        'extern "C" {',
        "struct CLayout { int a; };",
        "}",
        "struct City { int pop; char *name; };",
        "enum class Mode : int { A, B };",
        "using Handle = void *;",
        "typedef void (*Callback)(int code);",
        "template <class T> struct Vec { T v; };",
        "template <> struct Vec<int> { int x; };",     # a specialization names itself, braces and all
        "typedef struct { int a; } Pair;",             # one report, as the typedef
        'static const struct { int id; const char *n; } kNames[] = { { 1, "a" } };',
    ])
    assert registry.type_blocks(src) == [
        "struct TxtFile", "typedef u32", "struct CLayout", "struct City", "enum class Mode",
        "using Handle =", "typedef Callback", "struct Vec", "struct Vec<int>", "typedef Pair",
        "an unnamed struct"]


def test_namespaced_scaffolding_is_still_refused():
    """The shape agents actually reach for: the project's own namespace, then the class chain inside —
    the namespace must not hide the definitions from the refusal."""
    from dcore.core import registry

    src = """
namespace common {
namespace tools {
struct TxtFile {
    struct Row {
        std::vector<std::string> data_vec;
    };
    Row row_;
};
}}
ACME::Aurora::Core::TxtFile::Row::~Row() {}
"""
    assert registry.type_blocks(src) == ["struct TxtFile"]


def test_extra_content_sees_what_rides_along_with_a_function():
    """A submission is exactly one definition: anything before its first line or after its closing
    brace is found — includes, tables, a second function, a namespace wrapper."""
    from dcore.core import registry

    assert registry.extra_content("int Score::value() const { return n_; } // done\n", "Score::value()") == []
    assert registry.extra_content("Foo::Foo() : head_{nullptr}, log_() { setup(); }", "a::Foo::Foo()") == []
    assert registry.extra_content("template <class T> void f(T v) { use(v); }", "f") == []
    assert registry.extra_content("bool DoubleLink::empty() const\n{ return head_ == nullptr; }",
                                  "DoubleLink::empty()") == []
    assert registry.extra_content("void f();", "f")                                     # not a definition
    assert registry.extra_content("#include <vector>\nvoid f() { }", "f")               # an include
    assert registry.extra_content("static const int k[] = { 1 };\nvoid f() { }", "f")   # a table
    assert registry.extra_content("void other() { }\nvoid f() { }", "f")                # a second function
    assert registry.extra_content("namespace n { void f() { } }", "f")                  # a namespace wrapper
    assert registry.extra_content("void f() { } static int t = 1;", "f")                # something after


def test_a_submission_is_exactly_the_function_or_it_is_refused():
    """compile_and_diff takes the function — first line to closing brace; type blocks go to the
    registry with the exact tools to call, and nothing else rides along."""
    from dcore.core.engine import Engine
    from dcore.core.native import NativeEngine
    from dcore.core.network import NetworkError

    engine = object.__new__(Engine)
    engine.native_slug = lambda project: "game"
    engine.native = object.__new__(NativeEngine)
    with pytest.raises(NetworkError) as e:
        Engine.compile_and_diff(engine, None, "f", "struct City { int pop; };\nvoid f() {}", "game")
    msg = str(e.value)
    assert "struct City" in msg and 'search_types("City")' in msg and "declare_type" in msg
    # everything else that rides along is refused too
    for source in ("#include <vector>\nvoid f() { }",
                   "static const int k[] = { 1 };\nvoid f() { }",
                   "void other() { }\nvoid f() { }",
                   "namespace n { void f() { } }",
                   "void f();"):
        with pytest.raises(NetworkError, match="exactly the function"):
            Engine.compile_and_diff(engine, None, "f", source, "game")
    # everything the function needs lives inside its body
    engine.native.refuse_extra_content("void f() { struct L { int z; }; static const int k[] = { 1, 2 }; }", "f")


def test_find_ida_database_next_to_the_binary(tmp_path):
    from dcore.core.native import find_ida_database

    binary = tmp_path / "libfoo.so"
    binary.write_bytes(b"\x7fELF")
    assert find_ida_database(binary) is None
    (tmp_path / "libfoo.so.idb").write_bytes(b"db")
    assert find_ida_database(binary).name == "libfoo.so.idb"
    (tmp_path / "libfoo.so.i64").write_bytes(b"db")
    assert find_ida_database(binary).name == "libfoo.so.i64"  # the .i64 spelling wins
    other = tmp_path / "libbar"
    other.write_bytes(b"x")
    (tmp_path / "libbar.i64").write_bytes(b"db")
    assert find_ida_database(other).name == "libbar.i64"


def test_ida_source_prefers_a_present_database(tmp_path):
    from dcore.core import analyze as analyze_mod

    (tmp_path / "game.bin").write_bytes(b"x")
    cfg = {"binary": {"file": "game.bin"}, "ida": {"database": str(tmp_path / "game.bin.i64")}}
    assert analyze_mod.ida_source(tmp_path, cfg).name == "game.bin"      # configured but gone: the binary
    (tmp_path / "game.bin.i64").write_bytes(b"db")
    assert analyze_mod.ida_source(tmp_path, cfg).name == "game.bin.i64"  # present: the database
    warned = []
    gone = {**cfg, "ida": {"database": str(tmp_path / "nope.i64")}}
    assert analyze_mod.ida_source(tmp_path, gone, log=warned.append).name == "game.bin"
    assert warned and "gone" in warned[0]


def test_the_sweep_opens_the_given_database_and_keys_the_cache_to_it(tmp_path, monkeypatch):
    import json as _json
    import re as _re

    from dcore.backends.ida import sweep as ida_export

    binary = tmp_path / "libfoo.so"
    binary.write_bytes(b"\x7fELF" + b"0" * 64)
    db = tmp_path / "libfoo.so.i64"
    db.write_bytes(b"IDA")
    cache_dir = tmp_path / "cache"
    seen = []

    class FakeSession:
        def __init__(self, log=print):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def call(self, tool, args, timeout=None):
            seen.append((tool, args))
            if tool == "open_database":
                return _json.dumps({"instance_id": "i1", "backend": "idalib"})
            if tool == "execute_python":
                out = _re.findall(r"'([^']+\.json)'", args["code"])[-1]
                Path(out).write_text(_json.dumps({"schema": ida_export.SCHEMA, "functions": []}))
                return _json.dumps({"stdout": "DECOMPNET_EXPORT " + _json.dumps(
                    {"functions": 3, "imports": 1, "exports": 0, "strings": 2, "processor": "metapc"}),
                    "stderr": "", "result": None})
            return "{}"

    monkeypatch.setattr(ida_export.ida, "IdaSession", FakeSession)
    monkeypatch.setattr(ida_export, "_SWEEP", "write __OUT__")
    data = ida_export.export_analysis(binary, cache_dir, db=db)
    assert [a["path"] for t, a in seen if t == "open_database"] == [str(db)]
    assert data["ida"]["counts"]["functions"] == 3
    name = next(cache_dir.glob("ida-*.json")).name
    assert "-db" in name and name.startswith("ida-" + ida_export.ida.sha256_file(binary)[:16])
    again = ida_export.export_analysis(binary, cache_dir, db=db)  # second run: the cache answers
    assert again["ida"]["counts"] == data["ida"]["counts"]
    assert len([1 for t, _ in seen if t == "open_database"]) == 1


def test_native_type_block_full_closure_std_includes_and_markers():
    from dcore.core import interfaces

    analysis = {"types": [
        {"name": "Holder", "ns": [], "size": 32, "kind": "struct",
         "members": [{"name": "items", "off": 0, "type": "std::vector<Item>"},
                     {"name": "log", "off": 24, "type": "Log &"}], "statics": [], "methods": []},
        {"name": "Item", "ns": [], "size": 8, "kind": "struct",
         "members": [{"name": "n", "off": 0, "type": "int"}], "statics": [], "methods": []},
        {"name": "Log", "ns": [], "size": 0x100000, "kind": "class", "members": [], "statics": [],
         "methods": []},
    ]}
    block = interfaces.type_block(analysis, "Holder *h;", full=True)
    assert "#include <vector>" in block
    assert "std::vector<Item> items;" in block
    assert "struct Item {" in block  # pulled recursively through vector<Item>
    assert "class Log;" in block and "struct Holder {" in block  # too big to define: forward-declared
    assert interfaces._TYPE_MARK_BEGIN in block and interfaces._TYPE_MARK_END in block
    excl = interfaces.type_block(analysis, "Holder *h;", exclude={"Holder"}, full=True)
    assert "struct Holder" not in excl
    stored = "/* ctx */\nint x;\n" + block + "\ntail\n"
    stripped = interfaces.strip_types(stored)
    assert "Holder" not in stripped and "tail" in stripped and "int x;" in stripped


def test_a_hidden_this_is_not_a_free_function_parameter():
    """IDA writes `Memory *__hidden this` even for a free function; emitting it asks for a
    type that is not a parameter and drops the declaration (`CheckHeap` was undeclared)."""
    from dcore.core import interfaces

    assert interfaces.prototype(
        "CheckHeap", "void __fastcall(ACME::Aurora::Core::Memory *__hidden this)",
        cpp=True) == "void CheckHeap();"
    assert interfaces._hidden_this(
        "int __fastcall(int *p, Engine *__hidden this, int n)") == "int __fastcall(int *p, int n)"


def test_a_legacy_prototype_yields_to_the_live_callee_signature():
    """The frozen header can say `void SetDebugFileName`, the analysis says `void *`; emitting
    both is C2373. The live callee context owns the prototype, unrelated legacy lines stay."""
    from dcore.core import registry

    legacy = ("void SetDebugFileName(void *p, const char *fileName, int lineNumber);\n"
              "extern int stale_global;\n"
              "void Keep(int);")
    base = ("namespace Memory { void * SetDebugFileName(void *p, const char *fileName, "
            "int lineNumber); }")
    out = registry._drop_shadowed_prototypes(legacy, base)
    assert "SetDebugFileName" not in out
    assert "stale_global" in out and "Keep(int)" in out


def test_native_registry_header_for_carries_salvaged_decls_and_skips_the_compiled_function():
    from dcore.core import registry

    analysis = {"types": []}
    sal = [{"name": "TraceLogDefault", "ns": ["common", "tracekit"], "kind": "struct", "origin": "salvage",
            "decl": "struct TraceLogDefault {\n    static TraceLog default_log_obj_;\n};"}]
    defs = [(("ACME::Aurora::Core::X", "f"), "inline void X::f() {}"),
            (("ACME::Aurora::Core::X", "g"), "inline void X::g() {}")]
    hdr = registry.header_for(
        analysis, "/* ctx */\n",
        "void h() { common::tracekit::TraceLogDefault::default_log_obj_; (void)&X::g; }",
        {"version": 1, "types": {}}, inline_defs=defs, skip=("ACME::Aurora::Core::X", "f"), salvaged=sal)
    assert "struct TraceLogDefault" in hdr and "namespace common { namespace tracekit {" in hdr
    assert "X::g()" in hdr and "X::f()" not in hdr  # the function being compiled is not re-defined


def test_native_registry_search_candidates_and_describe():
    from dcore.core import registry

    entries = [
        {"name": "DoubleLinkNode", "ns": ["ACME", "Aurora", "Core"], "kind": "struct", "size": 32, "origin": "dwarf",
         "members": [{"name": "owner_ptr", "off": 8, "type": "DoubleLink *"},
                     {"name": "next_ptr", "off": 16, "type": "DoubleLinkNode *"}], "statics": [], "methods": []},
        {"name": "Node", "ns": [], "kind": "struct", "size": 8, "origin": "agent",
         "members": [{"name": "v", "off": 0, "type": "int"}], "statics": [], "methods": []},
        {"name": "Node", "ns": ["x"], "kind": "struct", "size": 8, "origin": "agent",
         "members": [], "statics": [], "methods": []},
        {"name": "TraceLogStream", "ns": ["common", "tracekit"], "kind": "class", "size": 416, "origin": "dwarf",
         "members": [], "statics": [], "methods": []},
    ]
    keys = lambda hits: [registry.key_of(t) for t in hits]
    assert keys(registry.search(entries, "DoubleLink")) == ["ACME::Aurora::Core::DoubleLinkNode"]
    assert keys(registry.search(entries, "", ns="common::tracekit")) == ["common::tracekit::TraceLogStream"]
    assert keys(registry.search(entries, "", member="next_ptr")) == ["ACME::Aurora::Core::DoubleLinkNode"]
    assert keys(registry.search(entries, "", kind="struct")) == ["ACME::Aurora::Core::DoubleLinkNode", "Node", "x::Node"]
    assert registry.candidates(entries, "Node") == ["Node", "x::Node"]  # ambiguity is shown, not guessed
    text = registry.describe(entries[0], ["pushFront", "pop"])
    assert "+0x08" in text and "owner_ptr" in text and "used by 2 matched function(s)" in text


def test_native_find_functions_searches_names_and_addresses():
    from dcore.core import native as nativeengine

    class FakeNet:
        store = type("S", (), {"all": staticmethod(lambda *a, **k: [])})()

        def _project(self, slug):
            return {"id": 1, "slug": slug, "root": "."}

        def cfg(self, proj):
            return {}

    eng = nativeengine.NativeEngine.__new__(nativeengine.NativeEngine)
    eng.net = FakeNet()
    analysis = {
        "graph": {"files": {
            "/src/double_link.cpp": {"functions": [0x10, 0x20]},
            "/libs/libc.so": {"functions": [0x30]},
        }},
        "functions": [
            {"ea": 0x10, "name": "pushFront@double_link.cpp", "display": "ACME::Aurora::Core::DoubleLink::pushFront(ACME::Aurora::Core::DoubleLinkNode *)", "size": 100, "lib": False, "language": "c++"},
            {"ea": 0x20, "name": "pop@double_link.cpp", "display": "ACME::Aurora::Core::DoubleLink::pop(void)", "size": 50, "lib": False, "language": "c++"},
            {"ea": 0x30, "name": ".memcpy", "display": ".memcpy", "size": 20, "lib": True, "language": "asm",
             "glue": "plt"},
        ],
    }
    eng.analysis = lambda proj: analysis  # bypass the file-backed cache for the test

    by_name = eng.find_functions("x", "doublelink")
    assert by_name["total"] == 2
    assert {f["name"] for f in by_name["functions"]} == {"pushFront@double_link.cpp", "pop@double_link.cpp"}
    assert by_name["functions"][0]["treatment"] == "decompile"
    by_addr = eng.find_functions("x", "0x30")
    assert by_addr["total"] == 1 and by_addr["functions"][0]["glue"] == "plt"
    assert eng.find_functions("x", "")["total"] == 0  # an empty query is not a search


def test_native_registry_edit_racing_another_reapplies_on_top(tmp_path, monkeypatch):
    """Two agents editing the registry at once: the later commit re-applies its change on top of
    the other contribution (and re-verifies) instead of clobbering it — the same optimistic
    compare-and-swap edit_context uses on headers."""
    from dcore.core.engine import Engine
    from dcore.core import registry

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    net._project = lambda slug: {"id": 1, "slug": slug, "root": str(tmp_path)}
    net.native.analysis = lambda proj: {"types": [], "graph": {"files": {}}, "arch": "x86_64"}

    other = {"version": 1, "types": {"x::Other": {"name": "Other", "ns": ["x"], "kind": "struct",
                                                  "members": [], "statics": [], "methods": []}}}
    loads = {"n": 0}
    saves = []

    def fake_load(net_, slug):
        loads["n"] += 1
        # the lock check + the first attempt read the old state; the other agent commits mid-verify
        return {"version": 1, "types": {}} if loads["n"] <= 2 else other

    monkeypatch.setattr(registry, "load", fake_load)
    monkeypatch.setattr(registry, "save", lambda net_, slug, data: saves.append(data))

    res = registry.apply(net, "x", "declare", name="a::B", kind="struct")
    assert res["ok"] and loads["n"] == 6  # wait-check, read, collision, re-read, commit-check, refresh
    assert len(saves) == 1
    assert "x::Other" in saves[0]["types"] and "a::B" in saves[0]["types"]  # both contributions survive
    assert saves[0]["types"]["a::B"]["origin"] == "agent"


def test_native_registry_lock_session_stages_then_commits_once(tmp_path, monkeypatch):
    """lock_registry → stage edits (validated, not verified) → unlock_registry commits with one
    verification pass for the whole batch; a second agent's lock attempt reports who holds it."""
    import json as _json

    from dcore.core.engine import Engine
    from dcore.core import registry

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    net._project = lambda slug: {"id": 1, "slug": slug, "root": str(tmp_path)}
    net.native.analysis = lambda proj: {"types": [], "graph": {"files": {}}, "arch": "x86_64"}
    saved = {}
    monkeypatch.setattr(registry, "load",
                        lambda net_, slug: _json.loads(saved["data"]) if "data" in saved else {"version": 1, "types": {}})
    monkeypatch.setattr(registry, "save", lambda net_, slug, data: saved.update(data=_json.dumps(data)))

    agent = type("A", (), {"id": 7, "name": "test-agent"})()
    other = type("A", (), {"id": 8, "name": "other"})()
    res = registry.lock(net, "x", agent, wait=0)
    assert res["ok"] and res["token"]
    token = res["token"]
    busy = registry.lock(net, "x", other, wait=0)
    assert not busy["ok"] and busy["busy"] == "test-agent"
    assert registry.stage(net, "x", token, "declare",
                          {"name": "common::x::Node", "kind": "struct", "size": 16})["ok"]
    assert registry.stage(net, "x", token, "set_member",
                          {"name": "common::x::Node", "member": "next", "mtype": "Node *", "at": 8})["ok"]
    with pytest.raises(registry.RegistryError):
        registry.stage(net, "x", "wrong-token", "set_member",
                       {"name": "common::x::Node", "member": "n", "mtype": "int", "at": 0})
    out = registry.unlock(net, "x", token, commit=True)
    assert out["ok"] and out["failures"] == []
    data = _json.loads(saved["data"])
    assert "lock" not in data
    assert [m["name"] for m in data["types"]["common::x::Node"]["members"]] == ["next"]

    # abort throws a staged batch away and frees the lock
    res = registry.lock(net, "x", agent, wait=0)
    assert registry.stage(net, "x", res["token"], "set_size", {"name": "common::x::Node", "size": 64})["ok"]
    out = registry.unlock(net, "x", res["token"], commit=False)
    assert out["aborted"] and out["discarded"] == 1
    data = _json.loads(saved["data"])
    assert data["types"]["common::x::Node"]["size"] == 16  # untouched


def test_native_registry_lock_expires_and_is_taken_over(tmp_path, monkeypatch):
    import json as _json
    import time as _t

    from dcore.core.engine import Engine
    from dcore.core import registry

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    net._project = lambda slug: {"id": 1, "slug": slug, "root": str(tmp_path)}
    net.native.analysis = lambda proj: {"types": [], "graph": {"files": {}}, "arch": "x86_64"}
    stale = {"version": 1, "types": {},
             "lock": {"owner": 1, "name": "ghost", "token": "old", "since": 0,
                      "expires": _t.time() - 5, "staged": {}}}
    saved = {}
    monkeypatch.setattr(registry, "load", lambda net_, slug: stale if not saved else _json.loads(saved["data"]))
    monkeypatch.setattr(registry, "save", lambda net_, slug, data: saved.update(data=_json.dumps(data)))
    agent = type("A", (), {"id": 7, "name": "fresh"})()
    res = registry.lock(net, "x", agent, wait=0)
    assert res["ok"] and res["took_over"]  # an expired lease never wedges the registry


def test_native_registry_single_edit_waits_for_a_held_session(tmp_path, monkeypatch):
    import time as _t

    from dcore.core.engine import Engine
    from dcore.core import registry

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    net._project = lambda slug: {"id": 1, "slug": slug, "root": str(tmp_path)}
    net.native.analysis = lambda proj: {"types": [], "graph": {"files": {}}, "arch": "x86_64"}
    held = {"version": 1, "types": {},
            "lock": {"owner": 1, "name": "holder", "token": "t", "since": _t.time(),
                     "expires": _t.time() + 300, "staged": {}}}
    monkeypatch.setattr(registry, "load", lambda net_, slug: held)
    monkeypatch.setattr(registry, "save", lambda net_, slug, data: None)
    with pytest.raises(registry.RegistryError, match="holder is editing the registry right now"):
        registry.apply(net, "x", "declare", wait=0.3, name="a::B", kind="struct")


def test_native_registry_change_note_names_replaced_members():
    """An offset-anchored edit never shifts silently: 'b at +0x8' *replaces* what sat there, and
    the note says so up front — the agent sees the casualty before/with the gate's verdict."""
    from dcore.core import registry

    before = {"version": 1, "types": {"a::T": {
        "name": "T", "ns": ["a"], "kind": "struct", "size": 16,
        "members": [{"name": "a", "type": "int", "off": 8}], "statics": [], "methods": []}}}
    after = {"version": 1, "types": {"a::T": {
        "name": "T", "ns": ["a"], "kind": "struct", "size": 16,
        "members": [{"name": "b", "type": "int", "off": 8}], "statics": [], "methods": []}}}
    assert "replaced a (int) with b (int) at +0x8" in registry.change_note(before, after)
    assert "a::T: declared (struct)" in registry.change_note({"version": 1, "types": {}}, after)
    grown = {"version": 1, "types": {"a::T": {
        "name": "T", "ns": ["a"], "kind": "struct", "size": 24,
        "members": after["types"]["a::T"]["members"] + [{"name": "c", "type": "int", "off": 16}],
        "statics": [], "methods": []}}}
    note = registry.change_note(after, grown)
    assert "added c (int) at +0x10" in note and "size 0x10 -> 0x18" in note


def test_helpers_spread_across_units_before_sharing_one(tmp_path, elf_bytes):
    """Two agents in one unit edit the same declaration header and invalidate each other (the
    OSMemory/String raw-class churn). The second auto-claim prefers a unit nobody else holds."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    first, _ = net.local_agent("spread-a")
    second, _ = net.local_agent("spread-b")
    a = net.claim_row(first, slug)
    b = net.claim_row(second, slug)
    assert a is not None and b is not None
    assert a["unit"] != b["unit"]


def test_an_explicit_claim_cannot_enter_another_agents_unit(tmp_path, elf_bytes):
    """Strategy claims spread across units, but an explicit claim(function=…) could still put two
    agents in one unit (the OSMemory war). The explicit path now refuses the second owner."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    with net.store.tx() as db:  # put main in score_update's unit for this policy test
        db.execute("UPDATE functions SET unit=(SELECT unit FROM functions WHERE name='score_update') "
                   "WHERE name='main'")
    first, _ = net.local_agent("unit-owner")
    second, _ = net.local_agent("unit-intruder")
    net.claim(first, slug, "score_update")
    with pytest.raises(NetworkError, match="one agent per unit"):
        net.claim(second, slug, "main")
    # the auto strategy still spreads when another unit is free; explicit is the guarded path


def test_a_helper_with_everything_claimed_waits_instead_of_failing(tmp_path, elf_bytes):
    """opencode's "nothing left to claim" sessions were each counted as a failure and stopped it with a
    sign-in hint, while another helper simply held the last function. A helper with nothing claimable
    now waits quietly (and picks work up when a claim frees), and giving up on a function is not
    re-offered to the same helper."""
    import threading
    import time

    from dcore.app import agents as agents_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    holder_a, _ = net.local_agent("holder-a")
    holder_b, _ = net.local_agent("holder-b")
    waiter, _ = net.local_agent("waiter")
    net.claim(holder_a, slug, "score_update")
    net.claim(holder_b, slug, "main")
    manager = agents_mod.Manager(net, tmp_path, "http://127.0.0.1:9/mcp")
    assert manager._left(slug) == 2
    assert manager._claimable(slug, waiter.id) == 0  # both open functions are someone else's
    s = agents_mod.Session("native-wait", "api", "Waiter", slug, "waiter", {})
    thread = threading.Thread(target=manager._run, args=(s,), daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and not any("none claimable" in f["text"] for f in s.feed):
        time.sleep(0.05)
    s.stop.set()
    thread.join(timeout=2)
    assert any("none claimable" in f["text"] for f in s.feed)
    assert not any(f["type"] == "error" for f in s.feed)  # idle is not a strike
    # a claim coming free is what the waiter is waiting for ...
    assert manager._claimable(slug, waiter.id) == 0
    net.release(holder_b, "main", "gave it back", slug)
    assert manager._claimable(slug, waiter.id) == 1
    # ... and a function the helper itself gave up on stays unclaimable to it
    net.claim(waiter, slug, "main")
    net.release(waiter, "main", "not mine to finish", slug)
    assert manager._claimable(slug, waiter.id) == 0
    # (holder_a never released anything: its own claim plus the released main are both on its plate)
    assert manager._claimable(slug, holder_a.id) == 2


def test_native_tools_read_the_binary_and_the_dropped_ones_are_gone(tmp_path, elf_bytes):
    """read_data reads the imported binary (it once crashed with KeyError: 'rom'), and the ROM-only tools
    that only ever refused (split_function, find_similar, rename_symbol) are not part of this build at all."""
    from dcore.app import agents as agents_mod
    from dcore.app import tools as tools_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("tools")
    analysis = net.native.analysis(net._project(slug))
    score = next(f for f in analysis["functions"] if f["name"] == "score_update")
    by_addr = net.read_data(slug, f"0x{score['ea']:X}", 16)  # this used to raise KeyError: 'rom'
    assert by_addr.startswith(f"0x{score['ea']:08X}") and ":" in by_addr
    by_name = net.read_data(slug, "score_update", 8)
    assert by_name.startswith(f"0x{score['ea']:08X}")
    assert "not in a loaded section" in net.read_data(slug, "0xDEADBEEF", 8)
    assert not hasattr(net, "split_function") and not hasattr(net, "find_similar")
    native_tools = set(tools_mod.tool_names(native=True))
    assert "read_data" in native_tools
    assert {"declare", "undeclare", "list_decls"} <= native_tools  # the generated-header surface
    assert not ({"split_function", "find_similar", "rename_symbol"} & native_tools)
    names = {d["function"]["name"] for d in agents_mod.api_tool_schemas(native=True)}
    assert "set_build_flags" in names
    assert {"declare", "undeclare", "list_decls"} <= names
    assert not ({"split_function", "find_similar", "rename_symbol"} & names)


def test_named_globals_ride_from_sweep_to_read_data_and_the_reconstructor(tmp_path, elf_bytes):
    """The data sweep carries named globals/statics (schema 5 → merged 13): read_data resolves them by
    name, and the judge's data-ref labels prefer the name over the §section fallback."""
    import json as _json

    from dcore.core.network import NetworkError
    from dcore.core import target as target_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    image = formats.identify(binary.read_bytes())
    sec = next(s for s in image.sections if s.kind in ("rodata", "data") and s.size >= 16)
    ea = sec.vaddr + 4
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    on_disk = _json.loads(cache.read_text())
    on_disk["data"] = [{"ea": ea, "name": "s_lockMutexBuffer", "type": "ACME::Threading::Mutex"},
                       {"ea": ea + 0x10, "type": "",
                        "name": "ACME::Aurora::Core::Memory::s_memoryTagStack$initializer$"}]
    for f in on_disk["functions"]:
        if f["name"] == "score_update":
            f["linkage"] = "?score_update@fixture@@YAXXZ"  # the disassembly's spelling resolves
    cache.write_text(_json.dumps(on_disk))
    net.native._analysis.pop(slug, None)  # the file changed on disk: drop the cached copy
    from dcore.core import plan

    plan.confirm(net, slug, log=lambda *_: None)  # the store's rows carry vram/size for both lookups

    head = net.read_data(slug, "s_lockMutexBuffer").splitlines()[0]
    assert head.startswith(f"0x{ea:08X} s_lockMutexBuffer: ACME::Threading::Mutex"), head
    assert head.endswith(f"({sec.name})"), head
    assert net.read_data(slug, "S_LOCKMUTEXBUFFER", 16).splitlines()[0].startswith(f"0x{ea:08X}")
    score_ea = next(f["ea"] for f in on_disk["functions"] if f["name"] == "score_update")
    assert net.read_data(slug, "?score_update@fixture@@YAXXZ", 8).startswith(f"0x{score_ea:08X}")
    with pytest.raises(NetworkError, match="named global") as miss:
        net.read_data(slug, "s_not_there")
    assert "close names" not in str(miss.value)
    with pytest.raises(NetworkError, match="named global") as hint:
        net.read_data(slug, "s_memoryTagStack")  # the bare name the disassembly implies
    assert "s_memoryTagStack$initializer$" in str(hint.value)  # ...gets a close-name hint
    with pytest.raises(NetworkError, match="named global") as leaf:
        net.read_data(slug, "ACME::Aurora::Core::Memory::s_memoryTagStack")
    assert "s_memoryTagStack$initializer$" in str(leaf.value)  # a qualified spelling hints via its leaf
    assert net.read_data(slug, f"dword_{ea:X}", 8).splitlines()[0].startswith(f"0x{ea:08X}")
    fn_row = net.store.one("SELECT * FROM functions WHERE name='score_update'")
    with pytest.raises(NetworkError, match="sits inside"):
        net._function(f"0x{fn_row['vram'] + 1:X}", slug)
    rc = target_mod.Reconstructor(binary.read_bytes(), image, {}, data_names={ea: "s_lockMutexBuffer"})
    assert rc.data_name(ea) == "s_lockMutexBuffer"


def test_registry_tools_are_scoped_to_native_projects():
    from dcore.app import tools as tools_mod

    registry = {"search_types", "get_type", "declare_type", "edit_type", "add_method", "promote_type",
                "lock_registry", "unlock_registry"}
    native_tools = set(tools_mod.tool_names(native=True))
    plain_tools = set(tools_mod.tool_names())  # native=False: the calls that predate the plan
    assert registry <= native_tools
    assert not (registry & plain_tools)


def test_mcp_tools_taking_a_name_argument_dispatch(tmp_path):
    """Regression: the MCP dispatch helper's own parameter was called `name`, so tools whose arguments
    include `name` (get_type / declare_type / edit_type) died with a TypeError before ever running."""
    import asyncio

    import pytest as _pytest
    from mcp.server.mcpserver.exceptions import ToolError

    from dcore.app import tools as tools_mod
    from dcore.core.engine import Engine

    net = Engine(tmp_path / "app.db", tmp_path / "work")
    mcp = tools_mod.build_mcp(net, lambda ctx: (None, ""))
    with _pytest.raises(ToolError, match="get_type is for native programs"):
        # the friendly refusal proves the dispatcher reached the handler with name= intact
        asyncio.run(mcp._tool_manager.call_tool("get_type", {"name": "Node"}, None, convert_result=False))
    # declare_type/edit_type take a `name` too: same dispatch, same refusal (not a TypeError)
    with _pytest.raises(ToolError, match="declare_type is for native programs"):
        asyncio.run(mcp._tool_manager.call_tool("declare_type", {"name": "common::x::Node"}, None,
                                                convert_result=False))


def test_analyze_resweeps_when_the_database_changed(tmp_path, elf_bytes, monkeypatch):
    """Reverse sync, the detection half: the merged analysis records the database's identity and
    is reused only while it still matches — a database edited since (an agent's write-through or
    a human in IDA) re-runs the export instead of silently serving stale names and types, and the
    plan screen says so (one stat) before the user re-analyzes."""
    import os as _os

    from dcore.backends.ida import sweep as ida_export
    from dcore.core import analyze as analyze_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    db_file = tmp_path / "fake.i64"
    db_file.write_bytes(b"not really an ida database" * 64)
    net._update_cfg(slug, lambda cfg: cfg.setdefault("ida", {}).update({"database": str(db_file)}))

    calls = []

    def fake_export(binary, cache_dir, *, db=None, force=False, log=print):
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        calls.append(str(db))
        source = Path(db) if db else Path(binary)
        return {"functions": [{"ea": 0x1000, "end": 0x1020, "name": "score_update", "demangled": "",
                               "lib": False, "signature": "", "file": "src/hello.c", "line": 3}],
                "edges": [], "imports": [], "exports": [], "strings": [],
                "types": [{"name": "Player", "ns": [], "kind": "struct", "size": 8,
                           "members": [{"name": "hp", "off": 0, "type": "int"}]}],
                "ida": {"source": str(source), "source_key": ida_export.db_key(source)}}

    monkeypatch.setattr(ida_export, "export_analysis", fake_export)
    analyze_mod.analyze(net, slug, log=lambda *_: None)
    assert calls == [str(db_file)]  # the configured database reached the sweep
    assert net.cfg(net.project_row(slug))["analysis"]["source_key"] == ida_export.db_key(db_file)
    assert net.native.plan_view(slug)["analysis_stale"] is None

    stat = db_file.stat()
    _os.utime(db_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10_000_000_000))  # edited since
    assert "database changed" in (net.native.plan_view(slug)["analysis_stale"] or "")
    analyze_mod.analyze(net, slug, log=lambda *_: None)
    assert len(calls) == 2  # stale: the export ran again
    assert net.native.plan_view(slug)["analysis_stale"] is None  # ... and caught up with the stamp
    analyze_mod.analyze(net, slug, log=lambda *_: None)
    assert len(calls) == 2  # unchanged since: the merged result is reused, no third sweep


def test_database_sync_adopts_renames_into_rows_headers_and_sources(tmp_path, elf_bytes):
    """Reverse sync, the adoption half: renames the database now carries flow into the rows'
    display names, the stored headers and the matched sources, and one event says what moved.
    Types here are unchanged, so nothing is recompiled (the gate's probe found no touched unit)."""
    import copy
    import json as _json

    from dcore.core import analyze as analyze_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    old = _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    pid = proj["id"]
    ctx = net._context(pid, "src/hello.c")  # materializes the stored unit header
    assert "score_update" in ctx["header"]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched', "
                   "matched_source='int score_update(int *s) { return *s; }' WHERE name='score_update'")

    new = copy.deepcopy(old)
    for f in new["functions"]:
        if f["name"] == "score_update":
            f["name"] = f["display"] = "score_state"

    stats = analyze_mod._adopt(net, proj, old, new, log=lambda *_: None)
    assert stats["names"] == 1 and stats["rows"] == 1 and not stats["reopened"]
    ea = next(f["ea"] for f in old["functions"] if f["name"] == "score_update")
    row = net.store.one("SELECT name, matched_source FROM functions WHERE vram=?", ea)
    assert row["name"] == "score_state" and "score_state" in row["matched_source"]
    latest = net.store.one("SELECT header, message FROM context_versions WHERE project_id=? "
                           "AND unit='src/hello.c' ORDER BY version DESC LIMIT 1", pid)
    assert "score_state" in latest["header"] and latest["message"] == "database sync"
    meta = _json.loads(net.store.one("SELECT meta FROM functions WHERE vram=?", ea)["meta"])
    assert meta["symbol"] == "score_update"  # the plan-time symbol stays the historical record
    kinds = [r["kind"] for r in net.store.all("SELECT kind FROM events WHERE project_id=?", pid)]
    assert "analysis" in kinds


def test_database_sync_rechecks_matches_the_new_types_can_break(tmp_path, elf_bytes, monkeypatch):
    """A type edited in the database can invalidate a match. The sync regenerates the stored
    headers whose projection changes, recompiles the matches there, and reopens the ones that no
    longer come out byte-identical — a match status must never lie."""
    import copy

    from dcore.core import analyze as analyze_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    old = _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    pid = proj["id"]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched', "
                   "matched_source='struct Player *p; return p;' WHERE name='score_update'")
    net._context(pid, "src/hello.c")  # the stored header as the old analysis renders it

    new = copy.deepcopy(old)
    for f in new["functions"]:
        if f["name"] == "main":
            f["signature"] = "Player *main(Player *p)"  # the unit's context now names Player
    ptype = {"name": "Player", "ns": [], "kind": "struct", "size": 16,
             "members": [{"name": "hp", "off": 0, "type": "int"},
                         {"name": "mp", "off": 4, "type": "int"},
                         {"name": "coins", "off": 8, "type": "int"}]}
    old["types"] = [{**ptype, "size": 8, "members": ptype["members"][:1]}]
    new["types"] = [ptype]

    seen = {}

    def fake_regression(proj_, header, sources=None, only=None, header_for=None):
        seen["only"] = [r["name"] for r in only or []]
        seen["header"] = header_for(only[0]) if header_for else header
        return [("score_update", "compiles but no longer matches")]

    monkeypatch.setattr(net, "regression_test", fake_regression)
    stats = analyze_mod._adopt(net, proj, old, new, log=lambda *_: None)

    assert seen["only"] == ["score_update"]  # only the unit whose projection changed re-checks
    assert "mp" in seen["header"]  # judged against the regenerated header, not the stale one
    assert stats["reopened"] == ["score_update"]
    assert net.store.one("SELECT status FROM functions WHERE name='score_update'")["status"] == "open"
    latest = net.store.one("SELECT header, message FROM context_versions WHERE project_id=? "
                           "AND unit='src/hello.c' ORDER BY version DESC LIMIT 1", pid)
    assert latest["message"] == "regenerated (types: database sync)"
    assert "mp" in latest["header"]


def test_database_sync_drops_overrides_the_database_now_carries(tmp_path, elf_bytes):
    """An override whose content the refreshed base carries in full is dropped — the database is
    the authority. Without this, a human's edit to a type agents had written through (agent edit
    -> .i64, human extends it there, sync) would stay invisible under the redundant override.
    An override with a note is never dropped: the note lives nowhere else."""
    import copy
    import json as _json

    from dcore.core import analyze as analyze_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    old = _write_fake_analysis(net, slug, binary, tmp_path)
    proj = net.project_row(slug)
    player8 = {"name": "Player", "ns": [], "kind": "struct", "size": 8,
               "members": [{"name": "hp", "off": 0, "type": "int"}], "statics": [], "methods": []}
    noted = {"name": "Noted", "ns": [], "kind": "struct", "size": 4,
             "members": [{"name": "id", "off": 0, "type": "int"}], "statics": [], "methods": [],
             "note": "an agent's reasoning lives here"}
    cache = Path(proj["root"]) / ".decomp-wtf" / "native"
    overrides = {"version": 1, "types": {
        "Player": {**copy.deepcopy(player8), "origin": "agent", "updated": 0.0},
        "Noted": {**copy.deepcopy(noted), "origin": "agent", "updated": 0.0}}}
    (cache / "registry.json").write_text(_json.dumps(overrides))
    old["types"] = [copy.deepcopy(player8), {k: v for k, v in noted.items() if k != "note"}]
    new = copy.deepcopy(old)
    new["types"] = [{**copy.deepcopy(player8), "size": 16,
                     "members": [*player8["members"], {"name": "mp", "off": 4, "type": "int"}]},
                    {k: v for k, v in noted.items() if k != "note"}]

    stats = analyze_mod._adopt(net, proj, old, new, log=lambda *_: None)
    assert stats["pruned"] == 2  # Player dropped outright; Noted survives as a note carrier
    overrides = _json.loads((cache / "registry.json").read_text())
    assert "Player" not in overrides["types"]  # the base now carries it (with the human's member)
    carrier = overrides["types"]["Noted"]
    assert not carrier.get("members") and carrier.get("note") == "an agent's reasoning lives here"
    from dcore.core import registry

    layered = {t["name"]: t for t in registry.view(new, overrides)}
    assert layered["Noted"]["members"] == [{"name": "id", "off": 0, "type": "int"}]  # content: base
    assert layered["Noted"]["note"] == "an agent's reasoning lives here"  # the note rides on top


def test_regeneration_swaps_only_the_generated_block(tmp_path, elf_bytes):
    """A type edit refreshes stored headers - it must replace the generated block and nothing
    else. A whole-header rewrite silently dropped an agent's hand-written decls (live, the
    OSMemory header lost its declarations and the agent rebuilt it by hand)."""
    import json as _json

    from dcore.core import plan
    from dcore.core import registry as registry_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": [], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    for f in analysis["functions"]:
        if f["name"] == "score_update":
            f["signature"] = "Player *(int *)"  # the unit's context now names Player
    proj = net.project_row(slug)
    cache = Path(proj["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    pid = proj["id"]
    unit = "src/hello.c"
    ctx = net._context(pid, unit)  # materialize the stored unit header
    agent, _ = net.local_agent("hdr")
    # a LEGACY stored header (the pre-entries world): hand-written decls live outside the generated
    # block, and regeneration must keep them exactly where the strip/refill compile path expects them
    head, _, rest = ctx["header"].partition("/* >>> decomp.wtf types")
    legacy = head + "int my_handwritten_decl(void);\n\n/* >>> decomp.wtf types" + rest
    import time as _time

    with net.store.tx() as db:
        version = net._next_version(db, pid)
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?,?)", (pid, version, legacy, agent.id, "legacy header", _time.time(), unit))

    registry_mod._refresh(net, slug, proj, analysis, [unit], {}, "test")

    after = net.store.one("SELECT version, header FROM context_versions WHERE project_id=? AND unit=? "
                          "ORDER BY version DESC LIMIT 1", pid, unit)
    assert "my_handwritten_decl" in after["header"]  # the agent's decl survived the refresh
    assert ">>> decomp.wtf types" in after["header"]  # ...and a fresh generated block rode in
    assert "struct Player" in after["header"]
    registry_mod._refresh(net, slug, proj, analysis, [unit], {}, "test again")
    again = net.store.one("SELECT version FROM context_versions WHERE project_id=? AND unit=? "
                          "ORDER BY version DESC LIMIT 1", pid, unit)
    assert again["version"] == after["version"]  # same view: the second refresh is a no-op


def test_registry_saves_survive_a_concurrent_writer(tmp_path, elf_bytes, monkeypatch):
    """Two agents staging types at once shared one registry.json.tmp: the first os.replace
    consumed it and the second raised FileNotFoundError (an agent's edit_type crashed live).
    Saves now write per-writer tmp names; a save landing mid-replace must not hurt."""
    import os as _os

    from dcore.core import plan
    from dcore.core import registry as registry_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    fake = {"name": "X", "ns": [], "kind": "struct", "size": 4,
            "members": [{"name": "v", "off": 0, "type": "int"}]}
    real_replace = _os.replace
    state = {"nested": False}

    def replace_with_visitor(src, dst):
        if not state["nested"]:  # another writer lands while this save is mid-replace
            state["nested"] = True
            registry_mod.save(net, slug, {"version": 1, "types": {"X": fake}})
        return real_replace(src, dst)

    monkeypatch.setattr(registry_mod.os, "replace", replace_with_visitor)
    registry_mod.save(net, slug, {"version": 1, "types": {"Y": fake}})
    data = registry_mod.load(net, slug)
    assert "Y" in data["types"]  # the outer save's replace survived and landed last
    assert not list((Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native").glob("*.tmp"))


def test_donated_submit_uses_the_native_compile_and_judge():
    """A worker's improvement is a final submission: same fence, pinned compile and judge."""
    from dcore.core import jobs

    seen = {}

    class Res:
        ok = True
        obj = b"obj"

    class Verdict:
        match = True
        score = 0

    class Native:
        def refuse_extra_content(self, source, function):
            seen["fenced"] = (source, function)

        def compile_fn(self, fn, proj, header, source):
            seen["compiled"] = (fn["name"], header, source)
            return Res()

        def judge(self, fn, proj, obj):
            seen["judged"] = (fn["name"], obj)
            return object(), Verdict(), []

    class Store:
        def one(self, sql, *args):
            return None if "claims" in sql else {"id": 1, "slug": "p"}

    class Net:
        store = Store()
        native = Native()

        def native_slug(self, slug):
            return slug

        def _require_budget(self, agent):
            pass

        def _function(self, function, project):
            return {"id": 1, "status": "open", "name": "f", "unit": "u",
                    "project_id": 1, "best_score": 50}

        def _hash_only(self, fn):
            return False

        def _context(self, project_id, unit):
            return {"header": "h", "version": 3}

        def _record(self, fn, agent, score, source, version, matched=False, via=""):
            seen["record"] = (score, matched, via)

        def add_note(self, *args, **kw):
            seen["noted"] = True

    result = jobs.submit(Net(), type("A", (), {"id": 9})(), "p", "f", "int f() {}")
    assert result["accepted"] and result["matched"] and result["score"] == 0
    assert seen["fenced"] == ("int f() {}", "f")
    assert seen["compiled"] == ("f", "h", "int f() {}")
    assert seen["record"] == (0, True, "permuter") and seen["noted"]


def test_registry_save_is_deterministic(tmp_path):
    """The registry file is a reviewable artifact: equal mappings must serialize identically
    regardless of insertion order, or concurrent edits look like churn."""
    from dcore.core import registry

    class Net:
        def _project(self, slug):
            return {"root": str(tmp_path)}

    net = Net()
    registry.save(net, "x", {"version": 1, "types": {"b": {"name": "B"}, "a": {"name": "A"}}})
    first = (tmp_path / ".decomp-wtf" / "native" / "registry.json").read_text()
    registry.save(net, "x", {"version": 1, "types": {"a": {"name": "A"}, "b": {"name": "B"}}})
    second = (tmp_path / ".decomp-wtf" / "native" / "registry.json").read_text()
    assert first == second


def test_a_stalled_agent_stream_is_restarted(tmp_path, elf_bytes, monkeypatch):
    """The provider can die mid-stream: the model emits one sentence and the socket goes quiet
    forever. Nothing noticed - the session sat "working" indefinitely while the user watched.
    The stall watchdog terminates the run so the retry loop starts a fresh session."""
    import time as _time

    from dcore.app import agents as agents_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    monkeypatch.setattr(agents_mod, "STALL_SECONDS", 1)
    mgr = agents_mod.Manager(net, tmp_path / "agents-home", "http://127.0.0.1:1/mcp")

    def fake_command(self, s, token, workdir):
        return (["sleep", "30"], {}, "prompt")  # alive and connected, producing nothing

    monkeypatch.setattr(agents_mod.Manager, "_command", fake_command)
    s = agents_mod.Session("t-1", "opencode", "test", slug, "t-1", {})
    t0 = _time.time()
    ok = mgr._run_cli(s, "token", tmp_path)
    assert ok is False and _time.time() - t0 < 20
    assert any("stalled" in f["text"] for f in s.feed)


def test_a_down_model_server_gets_patience_not_three_strikes(tmp_path, elf_bytes, monkeypatch):
    """A local model server goes quiet for minutes while it loads or swaps a model. The api session
    used to die after ~a minute of quick failures ('the model server stopped answering'). Server-down
    failures now walk their own ladder (15s, 30s, 60s steady) for up to half an hour and never count
    toward the three-strike stop."""
    import time as _time

    from dcore.app import agents as agents_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    mgr = agents_mod.Manager(net, tmp_path / "agents-home", "http://127.0.0.1:1/mcp")
    s = agents_mod.Session("t-3", "api", "test", slug, "t-3", {})
    s.server_down = True
    waits = [mgr._server_down_wait(s) for _ in range(4)]
    assert waits == [15.0, 30.0, 60.0, 60.0]  # the ladder climbs, then holds
    assert any("isn't answering" in f["text"] for f in s.feed)
    monkeypatch.setattr(agents_mod, "SERVER_DOWN_GRACE", 0.0)
    s.server_since = _time.time() - 1  # the grace clock has run out
    assert mgr._server_down_wait(s) is None and s.state == "error"
    assert any("stopping" in f["text"] for f in s.feed)


def test_the_api_run_marks_the_server_down_on_exhausted_retries(tmp_path, elf_bytes, monkeypatch):
    """`_run_api`'s transport retries (~2s+4s) ending with nothing on the wire must mark the session
    server_down, so the loop switches to patience instead of counting a strike."""
    from dcore.app import agents as agents_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    agent, _ = net.local_agent("api-down")
    mgr = agents_mod.Manager(net, tmp_path / "agents-home", "http://127.0.0.1:1/mcp")
    monkeypatch.setattr(agents_mod.time, "sleep", lambda *_: None)  # no real backoff in the test
    s = agents_mod.Session("t-5", "api", "test", slug, "t-5",
                           {"base_url": "http://127.0.0.1:1/v1", "model": "m", "context_tokens": 4096})
    ok = mgr._run_api(s, agent)
    assert ok is False and s.server_down is True
    assert "stopped answering" in s.error


def test_ida_queries_build_marked_snippets_and_parse_their_answers():
    """Every curated IDA lookup is one IDAPython snippet printing one DECOMP_QUERY marker; the app
    parses that marker and renders compact text for the agent (read-only by contract)."""
    import json as _json

    from dcore.backends.ida import queries

    for action in queries.ACTIONS:
        code = queries.build(action, "OSMemory", 5)
        assert queries.MARKER in code and "dq_emit" in code
    assert "end_ea" in queries.build("disasm", "some_function", 5)  # a name walks the whole body
    with pytest.raises(ValueError, match="unknown IDA lookup"):
        queries.build("wat", "x")

    xrefs = {"target": {"ea": 0x1000, "name": "target"}, "to": [{"ea": 0x2000, "kind": "call_near",
                                                                 "from": {"ea": 0x1F00, "name": "caller"}}],
             "from": [{"ea": 0x3000, "kind": "read", "at": 0x1010, "to": {"ea": 0x3000, "name": "s_thing"}}]}
    out = queries.render("xrefs", xrefs)
    assert "0x00002000" in out and "caller" in out and "s_thing" in out
    dec = queries.render("decompile", {"function": {"ea": 0x1000, "name": "f"}, "pseudocode": "int f() { return 7; }"})
    assert "Hex-Rays" in dec and "return 7" in dec
    assert "no type matching" in queries.render("types", {"query": "X", "matches": []})
    typed = queries.render("types", {"query": "H", "matches": [
        {"name": "Handle", "members": [{"name": "ptr", "offset": 0, "type": "void *"},
                                       {"name": "size", "offset": 8, "type": "unsigned int"}]}]})
    assert "Handle" in typed and "+0x00" in typed and "ptr" in typed and "unsigned int" in typed
    segs = queries.render("segments", {"segments": [{"start": 0x1000, "end": 0x2000, "name": ".text",
                                                     "class": "CODE", "perm": "r-x"}]})
    assert "0x00001000-0x00002000" in segs and "r-x" in segs
    payload = {"items": [1]}
    assert queries.result("chatter\nDECOMP_QUERY " + _json.dumps(payload) + "\n") == payload
    assert queries.result("no marker here") is None


def test_ida_lookup_caches_by_database_identity(tmp_path, elf_bytes, monkeypatch):
    """A lookup is one snippet through the long-lived session, cached per database identity: the
    Hex-Rays/Names() cost is paid once per query per database state."""
    from dcore.core import analyze as analyze_mod
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    root = Path(net.project_row(slug)["root"])
    fake = root / "game.i64"
    fake.write_bytes(b"\0")
    monkeypatch.setattr(analyze_mod, "ida_source", lambda root_, cfg: fake)
    calls = []

    def fake_read(slug_, code, timeout=0):
        calls.append(code)
        return {"stdout": 'DECOMP_QUERY {"segments": [{"start": 4096, "end": 8192, "name": ".text", '
                          '"class": "CODE", "perm": "r-x"}]}', "stderr": ""}

    monkeypatch.setattr(net.native, "ida_read", fake_read)
    first = net.native.ida_lookup(slug, "segments")
    second = net.native.ida_lookup(slug, "segments")
    assert len(calls) == 1 and first == second  # the second answer came from the cache
    assert "0x00001000-0x00002000" in first
    assert list((root / ".decomp-wtf" / "ida-cache").rglob("segments-*.json"))

    monkeypatch.setattr(net.native, "ida_read",
                        lambda slug_, code, timeout=0: {"stdout": 'DECOMP_QUERY {"error": "no function at 0x1"}',
                                                        "stderr": ""})
    with pytest.raises(NetworkError, match="no function"):
        net.native.ida_lookup(slug, "decompile", "0x1")


def test_context_entries_journal_and_fence(tmp_path, elf_bytes):
    """Headers are generated; entries are the editable facts behind them. Adding validates through
    the same fence as header edits, removal is a tombstone, and listing returns live entries in
    insertion order."""
    from dcore.core import entries as entries_mod
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("entries")
    unit = "src/hello.c"
    first = entries_mod.add(net, slug, unit, "prototype", "int my_helper(int value)", agent=agent)
    assert first["name"] == "my_helper" and first["body"].endswith(";")
    assert entries_mod.add(net, slug, unit, "include", "cstdarg")["body"] == "cstdarg"
    assert entries_mod.add(net, slug, unit, "note", "allocator assumes 16-byte alignment")["name"] == ""
    define = entries_mod.add(net, slug, unit, "raw", "#define _VCRT_NEW_", agent=agent)
    assert define["body"] == "#define _VCRT_NEW_"  # a directive is a line, not a declaration
    live = entries_mod.list_for(net, slug, unit)
    assert [e["kind"] for e in live] == ["prototype", "include", "note", "raw"]
    removed = entries_mod.remove(net, slug, unit, name="my_helper", agent=agent)
    assert removed["id"] == first["id"]
    assert [e["kind"] for e in entries_mod.list_for(net, slug, unit)] == ["include", "note", "raw"]
    with pytest.raises(NetworkError, match="entry kind"):
        entries_mod.add(net, slug, unit, "wat", "x")
    with pytest.raises(NetworkError, match="freestanding"):
        entries_mod.add(net, slug, unit, "include", "windows.h")
    with pytest.raises(NetworkError, match="pragmas"):
        entries_mod.add(net, slug, unit, "raw", "#pragma once")
    with pytest.raises(NetworkError, match="no live entry"):
        entries_mod.remove(net, slug, unit, name="missing")
    lines = entries_mod.render(entries_mod.list_for(net, slug, unit))
    assert lines[0] == "#include <cstdarg>"
    assert lines[1].startswith("/* allocator assumes")
    assert lines[2] == "#define _VCRT_NEW_"


def test_declare_undeclare_gate_roundtrip(tmp_path, elf_bytes):
    """The agent-facing declaration entries: declare adds a gated entry, list shows it, undeclare
    removes it, and bad kinds are refused with actionable messages."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("decl")
    out = net.declare_entry(agent, slug, "int entry_marker(int value)", "prototype", "score_update")
    assert out.startswith("✅") and "entry_marker" in out
    assert "get_context(function=" in out  # the message points at the rendered compile view
    assert "entry_marker" in net.list_entries(agent, slug, "score_update")
    out = net.undeclare_entry(agent, slug, name="entry_marker", function="score_update")
    assert out.startswith("✅") and "removed" in out
    assert "get_context(function=" in out
    assert "entry_marker" not in net.list_entries(agent, slug, "score_update")
    with pytest.raises(NetworkError, match="entry kind"):
        net.declare_entry(agent, slug, "x", "wat", "score_update")


def test_rejected_entry_edits_keep_their_position(tmp_path, elf_bytes, monkeypatch):
    """Entry order is semantic. A rejected undeclare/edit must restore the entry where it was — the
    append-on-restore bug is what wedged String.obj: a "rejected" edit still moved its namespace
    prelude behind the declarations that needed it."""
    from dcore.core import entries as entries_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("ord")
    unit = net._unit_of(net.project_row(slug), "score_update")
    first = entries_mod.add(net, slug, unit, "prototype", "int first_marker(void)")
    entries_mod.add(net, slug, unit, "prototype", "int second_marker(void)")
    monkeypatch.setattr(net, "regression_test", lambda *a, **k: [("score_update", "no longer compiles")])
    out = net.undeclare_entry(agent, slug, entry=first["id"], function="score_update")
    assert out.startswith("❌") and "restored as #" in out, out
    live = entries_mod.list_for(net, slug, unit)
    assert [e["name"] for e in live] == ["first_marker", "second_marker"]
    assert live[0]["id"] == first["id"]  # the same row, not a new id, in its old place

    # a rejected text edit is also a true no-op (same row/id)
    out = net.edit_context(agent, slug, "int first_marker(void)", "int first_marker(char)",
                           "reject this edit", function="score_update")
    assert out.startswith("❌"), out
    live = entries_mod.list_for(net, slug, unit)
    assert [e["id"] for e in live] == [first["id"], live[1]["id"]]
    assert live[0]["body"] == "int first_marker(void);"

    # an accepted edit also keeps its place (edit_context tombstones + re-adds the entry)
    monkeypatch.setattr(net, "regression_test", lambda *a, **k: [])
    out = net.edit_context(agent, slug, "int first_marker(void)", "int first_marker(long)",
                           "edit in place", function="score_update")
    assert out.startswith("✅"), out
    live = entries_mod.list_for(net, slug, unit)
    assert [e["body"] for e in live] == ["int first_marker(long);", "int second_marker(void);"]


def test_edit_decls_applies_removals_atomically(tmp_path, elf_bytes):
    """Two entries that each break the header on their own (the String.obj shape): removing either
    leaves the other breaking every compile, so single edits are refused. The atomic edit removes
    both and the startup unit check flags the wedge before an agent has to find it."""
    import time as _time

    from dcore.core import entries as entries_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    agent, _ = net.local_agent("batch")
    unit = net._unit_of(proj, "score_update")
    # entries admitted under an older render order: each is broken where it now renders (the writer
    # bypasses the gate on purpose - this reproduces an existing unit, it does not create one)
    with net.store.tx() as db:
        for name in ("probe_a", "probe_b"):
            db.execute("INSERT INTO context_entries(project_id, unit, kind, name, body, agent_id, created_at) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (proj["id"], unit, "prototype", name, f"static Missing_{name} *{name}(void);",
                        None, _time.time()))
    broken = net.validate_units(slug)
    assert any(b["unit"] == unit for b in broken), broken
    assert net.store.one("SELECT id FROM reports WHERE title LIKE '%declaration entries do not compile'")

    live = entries_mod.list_for(net, slug, unit)
    ids = [e["id"] for e in live]
    single = net.undeclare_entry(agent, slug, entry=ids[0], function="score_update")
    assert single.startswith("❌"), single
    assert [e["id"] for e in entries_mod.list_for(net, slug, unit)] == ids  # the same rows, un-tombstoned
    assert [e["body"] for e in entries_mod.list_for(net, slug, unit)] == [e["body"] for e in live]

    ids = [e["id"] for e in entries_mod.list_for(net, slug, unit)]
    before = [e["body"] for e in entries_mod.list_for(net, slug, unit)]
    bad = net.edit_entries(agent, slug, remove=[ids[0]],
                           add=[{"kind": "prototype", "body": "static Missing_probe_c *probe_c(void);"}],
                           function="score_update")
    assert bad.startswith("❌"), bad
    assert [e["id"] for e in entries_mod.list_for(net, slug, unit)] == ids  # rollback restores the same ids
    assert [e["body"] for e in entries_mod.list_for(net, slug, unit)] == before  # nothing added

    ids = [e["id"] for e in entries_mod.list_for(net, slug, unit)]
    out = net.edit_entries(agent, slug, remove=ids, function="score_update")
    assert out.startswith("✅") and "removed" in out, out
    assert not entries_mod.list_for(net, slug, unit)
    assert not net.validate_units(slug)


def test_declare_refuses_file_scope_members_and_points_at_the_real_tool(tmp_path, elf_bytes):
    """The mistake that poisoned String.obj: a class member written as a file-scope prototype. It is
    refused up front, with the two working paths named (add_method, or promote_type for a frozen seed)."""
    import json as _json

    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": ["game"], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("fence")
    with pytest.raises(NetworkError, match="add_method") as member:
        net.declare_entry(agent, slug, "static Player *Player::clone(int hp);", "prototype", "score_update")
    assert "promote_type" in str(member.value)  # the frozen-seed escape is named too
    with pytest.raises(NetworkError, match="namespace") as ns:
        net.declare_entry(agent, slug, "void nowhere_ns::f(void);", "prototype", "score_update")
    assert "add_method" in str(ns.value)
    assert not net.store.all("SELECT id FROM context_entries WHERE name='clone'")


def test_promote_type_hands_a_frozen_definition_to_the_registry(tmp_path, elf_bytes):
    """The second agent report: the seed's class definition shadows the registry, so edit_type/
    add_method changes never render. promote_type removes the frozen definition (gated), the
    projection renders the registry's version, and a method added afterwards is visible in
    get_context — the whole 'declare a member' path, end to end."""
    import json as _json
    import time as _time

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": ["game"], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    cache = Path(net.project_row(slug)["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    unit = net._unit_of(proj, "score_update")
    with net.store.tx() as db:
        version = net._next_version(db, proj["id"])
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (proj["id"], version, "namespace game { struct Player { int hp; }; }\n",
                    None, "test seed", _time.time(), unit))
        db.execute("UPDATE functions SET best_source=?, meta=? WHERE name='score_update'",
                   ("game::Player *score_update(game::Player *p) { return p; }", '{"language": "c++"}'))
    agent, _ = net.local_agent("promote-type")
    out = net.promote_type(agent, slug, "game::Player", function="score_update")
    assert out.startswith("✅"), out
    latest = net.store.one("SELECT header FROM context_versions WHERE project_id=? AND unit=? "
                           "ORDER BY version DESC LIMIT 1", proj["id"], unit)
    assert "struct Player" not in latest["header"]  # the frozen definition is gone
    view = net.get_context(slug, function="score_update")
    assert "struct Player" in view and "int hp;" in view  # ... the projection renders it now

    edited = net.native.edit_type(agent, slug, "set_method", name="game::Player", member="clone",
                                  mtype="Player *", params="", static="true")
    assert edited.startswith("✅"), edited
    view = net.get_context(slug, function="score_update")
    assert "static Player * clone();" in view  # a registry member now reaches the compile

    kinded = net.native.edit_type(agent, slug, "set_kind", name="game::Player", kind="class")
    assert kinded.startswith("✅"), kinded
    assert "class Player {" in net.get_context(slug, function="score_update")  # PEAV, not PEAU


def test_compiles_render_unit_entries(tmp_path, elf_bytes):
    """The generated-header model at runtime: an entry is a declaration every compile of its unit
    sees (context + legacy text + entries + projection). The fixture's C compiler rejects unknown
    types outright, so the source only compiles because the entry declared the typedef."""
    from dcore.core import entries as entries_mod
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    pid = proj["id"]
    units = net._unit_contexts(pid)
    fn = dict(net.store.one("SELECT * FROM functions WHERE project_id=? AND name='score_update'", pid))
    unit = net._effective_unit(fn, units)
    header = net._context(pid, unit)["header"]
    src = "my_u64 score_update(int *s) { return (my_u64)*s; }\n"
    before = net.native.compile_fn(fn, proj, header, src)
    assert not before.ok  # unknown type name: nothing declared it
    entries_mod.add(net, slug, unit, "alias", "typedef unsigned long long my_u64")
    after = net.native.compile_fn(fn, proj, header, src)
    assert after.ok, after.log
    view = net.get_context(slug, function="score_update")
    assert "rendered exactly as this function's next compile will see it" in view
    assert "typedef unsigned long long my_u64" in view  # the entry is in the view the compile gets
    entries_mod.remove(net, slug, unit, name="my_u64")
    again = net.native.compile_fn(fn, proj, header, src)
    assert not again.ok  # tombstoned: the declaration is gone from the compile again
    assert "typedef unsigned long long my_u64" not in net.get_context(slug, function="score_update")


def test_get_context_shows_the_fresh_projection_the_compile_uses(tmp_path, elf_bytes):
    """`get_context` used to show the stored header + entries — not the registry projection the
    compiler actually receives, so an agent couldn't see what its edits produced. The view is now
    rendered by compile_fn's own pipeline: a type only the function's source names (absent from
    the stored header) appears, with the layout the compile will use."""
    import json as _json

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [{"name": "Player", "ns": [], "kind": "struct", "size": 8,
                          "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    proj = net.project_row(slug)
    cache = Path(proj["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched', matched_source=?, meta=? WHERE name='score_update'",
                   ("Player *score_update(int *s) { return (Player *)s; }", '{"language": "c++"}'))
    fn = net.store.one("SELECT * FROM functions WHERE name='score_update'")
    stored = net._context(proj["id"], net._effective_unit(fn, net._unit_contexts(proj["id"])))["header"]
    assert "struct Player" not in stored  # the projection is not stored text
    view = net.get_context(slug, function="score_update")
    assert "rendered exactly as this function's next compile will see it" in view
    assert "struct Player {" in view and "int hp;" in view  # ... it is in the view the compile gets


def test_a_running_tool_is_not_a_stall(tmp_path, elf_bytes, monkeypatch):
    """A compile or the first IDA draft fetch can keep the app busy for minutes with no agent
    stdout at all; the watchdog must not kill a healthy session just because its tool runs long."""
    from dcore.app import agents as agents_mod
    from dcore.app import tools as tools_mod

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    monkeypatch.setattr(agents_mod, "STALL_SECONDS", 1)
    monkeypatch.setattr(tools_mod, "tool_active", lambda name: True)  # a tool of this agent's is running
    mgr = agents_mod.Manager(net, tmp_path / "agents-home", "http://127.0.0.1:1/mcp")

    def fake_command(self, s, token, workdir):
        return (["sleep", "3"], {}, "prompt")

    monkeypatch.setattr(agents_mod.Manager, "_command", fake_command)
    s = agents_mod.Session("t-2", "opencode", "test", slug, "t-2", {})
    ok = mgr._run_cli(s, "token", tmp_path)
    assert ok is False  # used no tools, so the run still counts as failed...
    assert not any("stalled" in f["text"] for f in s.feed)  # ...but it was never called a stall


def test_set_flags_materializes_headers_lazily(tmp_path, elf_bytes, monkeypatch):
    """Adopting flags built *every* unit's context before any regression ran: on ORION that is
    thousands of ~1s renders (a live rescue sat 15 minutes and stored 467 unit headers before
    it was killed). header_for must materialize only the units of affected matches - none here."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("flagster")

    calls = []
    real = net._context
    monkeypatch.setattr(net, "_context", lambda pid, unit="": (calls.append(unit), real(pid, unit))[1])
    out = net.native.set_flags(agent, slug, "/O2")
    assert "/O2" in out
    assert calls == [], f"nothing matched: no unit header may be materialized, got {calls}"


def test_type_renders_arrays_with_brackets_on_the_name():
    """IDA prints array member types postfix ("unsigned int[1]"); emitting them verbatim produced
    invalid C (`unsigned int[1] reserved1_;`) that broke context.h - an agent had to patch the
    registry to work around it. The brackets belong on the member name (count= forms too)."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    types = [{"name": "Block", "ns": [], "kind": "struct", "size": 12,
              "members": [{"name": "reserved1_", "type": "unsigned int[1]", "off": 0},
                          {"name": "flag", "type": "unsigned int", "off": 4},
                          {"name": "buf", "type": "unsigned char", "count": 4, "off": 8}],
              "statics": [], "methods": []}]
    out = interfaces.type_block(analysis, "Block b;", types=types)
    assert "unsigned int reserved1_[1];" in out
    assert "unsigned int[1] reserved1_" not in out
    assert "unsigned char buf[4];" in out


def test_type_renders_a_class_base_and_bitfields():
    """The PDB layout of ACME::Obsidian::Base::String: an empty base plus three bitfields.
    Rendering the members as ordinary 4-byte fields produced a 24-byte class instead of
    16, and dropping the base changed the C++ layout."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    alloc = {"name": "Allocatable", "ns": ["ACME", "Obsidian", "Base"], "kind": "class",
             "size": 1, "align": 1, "members": [], "statics": [], "methods": []}
    string = {"name": "String", "ns": ["ACME", "Obsidian", "Base"], "kind": "class",
              "size": 16, "align": 8,
              "bases": [{"name": "ACME::Obsidian::Base::Allocatable", "type": "ACME::Obsidian::Base::Allocatable",
                         "off": 0}],
              "members": [
                  {"name": "data_", "type": "char *", "off": 0, "size": 8},
                  {"name": "memorySize_", "type": "unsigned int", "off": 8, "size": 4},
                  {"name": "length_", "type": "unsigned int", "off": 12, "size": 4,
                   "is_bitfield": True, "bit_start": 96, "bit_size": 24},
                  {"name": "allocated_", "type": "unsigned int", "off": 15, "size": 1,
                   "is_bitfield": True, "bit_start": 120, "bit_size": 1},
                  {"name": "readOnly_", "type": "unsigned int", "off": 15, "size": 1,
                   "is_bitfield": True, "bit_start": 121, "bit_size": 1},
              ],
              "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "ACME::Obsidian::Base::String s;", types=[string, alloc])
    assert "class String : public ACME::Obsidian::Base::Allocatable" in out
    assert "char * data_;" in out
    assert "unsigned int memorySize_;" in out
    assert "unsigned int length_ : 24;" in out
    assert "unsigned int allocated_ : 1;" in out
    assert "unsigned int readOnly_ : 1;" in out
    assert "_pad" not in out
    assert "class Allocatable" in out


def test_type_renders_template_specialisations_after_a_primary():
    """IB/PDB gives the concrete DynamicArray<String,2,16> layout, but C++ needs a primary
    template declaration before `template <> class DynamicArray<...>`. The member
    SmallPointer<...> pulls in its own primary as well."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    alloc = {"name": "Allocatable", "ns": ["ACME", "Obsidian", "Base"], "kind": "class",
             "size": 1, "align": 1, "members": [], "statics": [], "methods": []}
    string = {"name": "String", "ns": ["ACME", "Obsidian", "Base"], "kind": "class",
              "size": 16, "align": 8, "bases": [], "statics": [],
              "methods": [{"name": "ExtractMatch", "ret": "bool", "static": True,
                           "params": ["ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> &",
                                      "char const *", "char const *", "char const *"]}],
              "members": [{"name": "data_", "type": "char *", "off": 0, "size": 8}]}
    small = {"name": "SmallPointer<ACME::Obsidian::Base::String,0,unsigned int,32>",
             "ns": ["ACME", "Obsidian", "Std"], "kind": "struct", "size": 8, "align": 8,
             "members": [{"name": "data", "type": "ACME::Obsidian::Base::String *", "off": 0, "size": 8}],
             "statics": [], "methods": []}
    dynamic = {"name": "DynamicArray<ACME::Obsidian::Base::String,2,16>",
               "ns": ["ACME", "Obsidian", "Std"], "kind": "class", "size": 16, "align": 8,
               "members": [
                   {"name": "data_", "type": "ACME::Obsidian::Std::SmallPointer<ACME::Obsidian::Base::String,0,unsigned int,32>",
                    "off": 0, "size": 8},
                   {"name": "size_", "type": "unsigned int", "off": 8, "size": 4},
                   {"name": "reservedSize_", "type": "unsigned int", "off": 12, "size": 4},
               ], "statics": [],
               "methods": [{"name": "Clear", "ret": "void", "params": []},
                           {"name": "Add", "ret": "void",
                            "params": ["ACME::Obsidian::Base::String const &"]}]}
    out = interfaces.type_block(
        analysis, "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> d;",
        types=[dynamic, small, string, alloc])
    assert "template <typename T0, int N0, int N1> class DynamicArray;" in out
    assert "template <> class DynamicArray<ACME::Obsidian::Base::String,2,16>" in out
    assert "template <typename T0, int N0, typename T1, int N1> struct SmallPointer;" in out
    assert "template <> struct SmallPointer<ACME::Obsidian::Base::String,0,unsigned int,32>" in out
    assert "ACME::Obsidian::Std::SmallPointer<ACME::Obsidian::Base::String,0,unsigned int,32> data_;" in out
    assert "ACME::Obsidian::Base::String * data;" in out
    assert "unsigned int reservedSize_;" in out
    assert "void Clear();" in out
    assert "void Add(ACME::Obsidian::Base::String const &);" in out
    assert ("static bool ExtractMatch(ACME::Obsidian::Std::DynamicArray<"
            "ACME::Obsidian::Base::String,2,16> &, char const *, char const *, char const *);") in out
    # a by-value template member must be defined before its owner
    assert out.index("template <> struct SmallPointer") < out.index("template <> class DynamicArray")


def test_type_block_follows_only_methods_the_source_uses():
    """Schema 17 carries every observed method. A function-scoped header must not pull the
    parameter types of methods this function never calls (that is how unrelated engine and std
    types entered ExtractMatch's header), but a method with locally resolvable types still
    renders, so registry edits remain visible."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    a = {"name": "A", "ns": ["game"], "kind": "struct", "size": 4, "align": 4,
         "members": [{"name": "x", "type": "int", "off": 0, "size": 4}], "statics": [],
         "methods": [{"name": "Unused", "ret": "void", "params": ["game::Bad *"]},
                     {"name": "Clone", "ret": "game::A *", "params": []}]}
    bad = {"name": "Bad", "ns": ["game"], "kind": "struct", "size": 4, "align": 4,
           "members": [{"name": "y", "type": "int", "off": 0, "size": 4}],
           "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "game::A a;", types=[a, bad],
                                usage="game::A a;")
    assert "game::A * Clone();" in out  # locally spellable: always part of the type
    assert "struct Bad {" not in out and "int y;" not in out  # only a forward declaration
    used = interfaces.type_block(analysis, "game::A a;", types=[a, bad],
                                 usage="game::A a; a.Unused(b);")
    assert "void Unused(game::Bad *);" in used
    assert "struct Bad {" in used and "int y;" in used


def test_pe_system_includes_are_demand_driven():
    """A PE target no longer gets windows.h merely because it is PE.  The SDK is pulled only
    when a declaration actually names a Windows type/API; a pure C++ class header stays portable."""
    from dcore.core import interfaces

    pe = {"format": "pe"}
    assert interfaces.system_includes("class String { int x; };", "c++", pe) == []
    assert "#include <windows.h>" in interfaces.system_includes("HANDLE h;", "c++", pe)
    assert "#include <windows.h>" in interfaces.system_includes(
        "void *CreateFileW(const wchar_t *, unsigned int, unsigned int, void *, unsigned int, "
        "unsigned int, void *);", "c++", pe)


def test_a_parameter_named_type_is_not_a_global_type():
    """`OSMemory::Type type` names a parameter, not a global struct `type`. Seeding that generic
    local-type entry dragged Object/protobuf into an allocation function's header; a real
    lowercase type used as `value *p` must still come along."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    heavy = {"name": "Heavy", "ns": ["engine"], "kind": "struct", "size": 8, "align": 8,
             "members": [{"name": "ptr", "type": "void *", "off": 0, "size": 8}],
             "statics": [], "methods": []}
    generic = {"name": "type", "ns": [], "kind": "struct", "size": 8, "align": 8,
               "members": [{"name": "ptr_", "type": "engine::Heavy *", "off": 0, "size": 8}],
               "statics": [], "methods": []}
    value = {"name": "value", "ns": ["game"], "kind": "struct", "size": 4, "align": 4,
             "members": [{"name": "i", "type": "int", "off": 0, "size": 4}],
             "statics": [], "methods": []}
    out = interfaces.type_block(
        analysis, "void f(game::value *p, int type) {}", types=[heavy, generic, value],
        usage="void f(game::value *p, int type) {}")
    assert "struct value {" in out and "int i;" in out
    assert "struct type {" not in out and "struct Heavy {" not in out


def test_a_polymorphic_class_keeps_its_vptr_slot():
    """A virtual class's vptr is compiler-generated, but only if a virtual method actually
    renders. If all virtual signatures are skipped, anchor the vtable or every field shifts by 8."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    poly = {"name": "Poly", "ns": [], "kind": "class", "size": 16, "align": 8,
            "members": [{"name": "_vptr.Poly", "type": "void ***", "off": 0},
                        {"name": "x_", "type": "int", "off": 8, "size": 4}],
            "statics": [],
            "methods": [{"name": "run", "ret": "void", "params": [], "virtual": True}]}
    out = interfaces.type_block(analysis, "Poly p;", types=[poly])
    assert "virtual void run();" in out and "_dcore_vtable_anchor" not in out
    assert "int x_;" in out

    # If every virtual signature is unspellable, keep a synthetic anchor so the vptr still
    # occupies slot 0 and the first real field stays at +8.
    poly["methods"] = [{"name": "run", "ret": "void", "params": ["Unknown<T>"], "virtual": True}]
    out = interfaces.type_block(analysis, "Poly p;", types=[poly])
    assert "virtual void _dcore_vtable_anchor();" in out
    assert "int x_;" in out


def test_an_opaque_member_keeps_its_alignment():
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    holder = {"name": "Holder", "ns": ["g"], "kind": "struct", "size": 40, "align": 8,
              "members": [{"name": "m_", "type": "g::Mystery", "off": 0, "size": 40}],
              "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "g::Holder h;", types=[holder])
    assert "alignas(8) unsigned char m_[40];" in out


def test_time_t_is_a_known_typedef_for_static_members():
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    timer = {"name": "Timer", "ns": ["game"], "kind": "struct", "size": 1, "align": 1,
             "members": [], "statics": [{"name": "offset_", "type": "time_t"}], "methods": []}
    out = interfaces.type_block(analysis, "game::Timer t;", types=[timer])
    assert "static time_t offset_;" in out


def test_a_hidden_static_member_keeps_its_visibility():
    """ELF globals built with `-fvisibility=hidden` need the attribute on the static member;
    without it GCC emits a GOT load instead of the target's direct `lea` + load."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": [],
                "format": "elf"}
    timer = {"name": "Timer", "ns": ["game"], "kind": "struct", "size": 1, "align": 1,
             "members": [], "statics": [{"name": "offset_", "type": "time_t",
                                         "visibility": "hidden"}], "methods": []}
    out = interfaces.type_block(analysis, "game::Timer t;", types=[timer])
    assert 'static __attribute__((visibility("hidden"))) time_t offset_;' in out


def test_a_frozen_elf_header_drops_libc_redeclarations():
    from dcore.core import registry

    out = registry._drop_libc_prototypes(
        "extern \"C\" {\n"
        "    long long strtol(const char *, char **, int);\n"
        "    __sighandler_t signal(int, __sighandler_t);\n"
        "}\n")
    assert "strtol" not in out and "signal" not in out


def test_a_namespace_component_is_not_a_type():
    """`namespace ACME { namespace Obsidian { namespace Base {` mentions a namespace, not the
    unrelated `ExitGames::Common::Base` class of the same leaf. Seeding that class pulled its
    ToString/JString graph into every String function's header."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    other = {"name": "Base", "ns": ["ExitGames", "Common"], "kind": "class", "size": 8,
             "align": 8, "members": [{"name": "n", "type": "engine::Heavy *",
                                       "off": 0, "size": 8}],
             "statics": [], "methods": []}
    heavy = {"name": "Heavy", "ns": ["engine"], "kind": "struct", "size": 8, "align": 8,
             "members": [{"name": "x", "type": "int", "off": 0, "size": 4}],
             "statics": [], "methods": []}
    string = {"name": "String", "ns": ["ACME", "Obsidian", "Base"], "kind": "struct",
              "size": 4, "align": 4,
              "members": [{"name": "length_", "type": "int", "off": 0, "size": 4}],
              "statics": [], "methods": []}
    text = ("namespace ACME { namespace Obsidian { namespace Base {\n"
            "struct String { int length_; };\n}}}}")
    out = interfaces.type_block(analysis, text, types=[other, heavy, string],
                                usage="ACME::Obsidian::Base::String s;")
    assert "struct String {" in out and "int length_;" in out
    assert "ExitGames" not in out and "struct Heavy {" not in out


def test_std_templates_are_forward_declared_before_legacy_uses():
    """A legacy header may use `std::vector` before its own minimal definition. The generated
    header must declare the template first; an earlier declaration needs no duplicate."""
    from dcore.core import interfaces

    fwd = interfaces.std_forwards("extern std::vector<int> *p;")
    assert fwd and fwd[0].startswith("namespace std {") and "class vector;" in fwd[0]
    assert interfaces.std_forwards(
        "namespace std { template <class T, class A> class vector; }\nstd::vector<int> *p;") == []
    assert interfaces.std_forwards("int x;") == []


def test_exported_headers_get_the_same_std_providers_as_compile_headers():
    from dcore.core import export

    out = export._with_providers("extern std::vector<int> *p;")
    assert "#include <vector>" in out and "class vector;" in out
    minimal = export._with_providers(
        "namespace std { template <class T, class A> class vector { }; }\n"
        "std::vector<int> *p;")
    assert "#include <vector>" not in minimal


def test_a_header_only_unit_drops_prototypes_without_a_type_block():
    """`aserver_mgr.hpp` has no analysis type block, so a legacy `boost::…` prototype cannot be
    completed. It must become a line comment, not an unparsable declaration or nested comment."""
    from dcore.core import registry

    text = ("namespace boost { void do_throw_error(const boost::system::error_code *e); }\n"
            "int keep(void);\n"
            "ACME::lm::vector<void (*)(void)> callbacks_;")
    out = registry._drop_unresolved_prototypes(text)
    assert "skipped prototype without a type block" in out
    assert "do_throw_error" not in out and "int keep(void);" in out
    assert "callbacks_" in out  # a template argument with `(` is not a top-level call


def test_a_legacy_library_template_specialization_is_commented_not_wrapped():
    from dcore.core import registry

    line = "namespace boost { void throw_exception<boost::lock_error>(const boost::lock_error *e); }"
    out = registry._fix_legacy_template_prototypes(line)
    assert out.startswith("// skipped library template specialization")
    assert "/*" not in out


def test_an_unknown_by_value_member_is_opaque_with_its_size():
    """A stripped binary has no type definition for a member, but the layout still has an
    offset and size. Opaque storage keeps the offsets; dropping or shrinking the member does not."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    holder = {"name": "Holder", "ns": ["game"], "kind": "struct", "size": 16, "align": 8,
              "members": [{"name": "mystery_", "type": "game::Mystery", "off": 0, "size": 12},
                          {"name": "tail", "type": "int", "off": 12, "size": 4}],
              "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "game::Holder h;", types=[holder])
    assert "unsigned char mystery_[12];" in out and "int tail;" in out


def test_an_unknown_member_without_a_size_still_gets_opaque_storage():
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    holder = {"name": "Holder", "ns": ["game"], "kind": "struct", "size": 4, "align": 4,
              "members": [{"name": "mystery_", "type": "game::Mystery", "off": 0}],
              "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "game::Holder h;", types=[holder])
    assert "unsigned char mystery_[4];" in out


def test_cross_namespace_by_value_types_are_ordered_before_their_owner():
    """`google::protobuf::Message` holds `internal::HasBits<1>` by value. Namespace blocks
    used to be alphabetical, so the holder was emitted before the helper and GCC saw an
    incomplete member; the helper's group must come first."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    bits = {"name": "HasBits<1>", "ns": ["g", "i"], "kind": "class", "size": 4, "align": 4,
            "members": [{"name": "v", "type": "int", "off": 0, "size": 4}],
            "statics": [], "methods": []}
    holder = {"name": "Holder", "ns": ["g"], "kind": "class", "size": 8, "align": 8,
              "members": [{"name": "bits_", "type": "g::i::HasBits<1>", "off": 0, "size": 4}],
              "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "g::Holder h;", types=[holder, bits])
    assert out.index("class HasBits<1> {") < out.index("class Holder {")


def test_a_minimal_std_declaration_suppresses_the_real_include():
    from dcore.core import registry

    text = ("namespace std { template <class T, class A> class vector { }; }\n"
            "std::vector<int> *p;")
    assert "#include <vector>" not in registry.std_includes(text)
    assert "#include <vector>" in registry.std_includes("std::vector<int> *p;")


def test_std_layouts_come_from_the_toolchain_not_the_binary():
    """A member `std::atomic<int>` must use the STL's declaration. Emitting the binary's
    `std::_Atomic_int` and `template <> struct atomic<int>` next to <atomic> is C2766."""
    from dcore.core import interfaces

    analysis = {"types": [], "functions": [], "graph": {"files": {}}, "edges": []}
    holder = {"name": "Holder", "ns": ["game"], "kind": "struct", "size": 4, "align": 4,
              "members": [{"name": "referenceCount_", "type": "std::atomic<int>",
                           "off": 0, "size": 4}], "statics": [], "methods": []}
    atomic = {"name": "atomic<int>", "ns": ["std"], "kind": "struct", "size": 4, "align": 4,
              "members": [], "statics": [], "methods": []}
    storage = {"name": "_Atomic_int", "ns": ["std"], "kind": "struct", "size": 4, "align": 4,
               "members": [{"name": "_Value", "type": "int", "off": 0, "size": 4}],
               "statics": [], "methods": []}
    out = interfaces.type_block(analysis, "game::Holder h;", types=[holder, atomic, storage])
    assert "#include <atomic>" in out
    assert "std::atomic<int> referenceCount_;" in out
    assert "_Atomic_int" not in out
    assert "template <> struct atomic" not in out


def test_type_block_sanitizes_msvc_spellings_for_gcc():
    """The same generated class must compile under g++: IDA's __int64/__int32 spellings become
    long long/unsigned int, and class allocation operators use size_t, not unsigned __int64."""
    from dcore.core import interfaces

    thing = {"name": "Thing", "ns": ["game"], "kind": "class", "size": 16, "align": 8,
             "members": [
                 {"name": "data", "type": "unsigned __int64", "off": 0, "size": 8},
                 {"name": "length", "type": "unsigned __int32", "off": 8, "size": 4,
                  "is_bitfield": True, "bit_start": 64, "bit_size": 24},
                 {"name": "flag", "type": "unsigned __int32", "off": 11, "size": 1,
                  "is_bitfield": True, "bit_start": 88, "bit_size": 1},
             ],
             "methods": [
                 {"name": "Add", "ret": "void", "params": ["unsigned __int64"]},
                 {"name": "operator new", "ret": "void *", "static": True,
                  "params": ["unsigned __int64"]},
                 {"name": "operator delete", "ret": "void", "static": True,
                  "params": ["void *", "unsigned __int64"]},
             ], "statics": []}
    out = interfaces.type_block({"types": []}, "game::Thing t;", types=[thing])
    assert "unsigned long long data;" in out
    assert "unsigned int length : 24;" in out
    assert "void Add(unsigned long long);" in out
    assert "static void * operator new(size_t);" in out
    assert "static void operator delete(void *, size_t);" in out
    assert "__int" not in out


def test_context_block_can_be_scoped_to_one_function():
    """A unit header used to declare every callee of every function in the unit; the compile header
    now seeds from one function's edges so unrelated classes cannot enter the type closure."""
    from dcore.core import interfaces

    analysis = {
        "functions": [
            {"ea": 0x10, "name": "caller", "display": "caller", "provenance": "dwarf",
             "language": "c++", "signature": "void(void)", "file": "a.cpp"},
            {"ea": 0x20, "name": "?helper@game@@YAXXZ", "display": "game::helper(int)",
             "provenance": "dwarf", "language": "c++", "linkage": "?helper@game@@YAXXZ",
             "signature": "void __fastcall(int)", "file": "b.cpp"},
            {"ea": 0x30, "name": "other", "display": "other", "provenance": "dwarf",
             "language": "c++", "signature": "void(void)", "file": "a.cpp"},
            {"ea": 0x40, "name": "?unrelated@game@@YAXXZ", "display": "game::unrelated(int)",
             "provenance": "dwarf", "language": "c++", "linkage": "?unrelated@game@@YAXXZ",
             "signature": "void __fastcall(int)", "file": "a.cpp"},
        ],
        "edges": [{"ea": 0x10, "to": [0x20]}, {"ea": 0x30, "to": [0x40]}],
        "graph": {"files": {"a.cpp": {"functions": [0x10, 0x30]},
                            "b.cpp": {"functions": [0x20, 0x40]}}},
        "types": [],
    }
    text = "\n".join(interfaces.context_block(analysis, ["a.cpp"], language="c++",
                                               only_eas={0x10}))
    assert "namespace game { void helper(int); }" in text
    assert "unrelated" not in text


def test_member_signatures_attach_to_the_type_methods():
    """The PDB type may carry only data members. The function table still names
    `Class::Method(...)` and its signature; attach those declarations to the class so the
    generated header can call them without a manual add_method per function."""
    from dcore.core import analyze

    types = [
        {"name": "String", "ns": ["ACME", "Obsidian", "Base"], "kind": "class", "size": 16,
         "members": [], "methods": []},
        {"name": "DynamicArray", "ns": ["ACME", "Obsidian", "Std"], "kind": "class", "size": 16,
         "members": [], "methods": []},
        {"name": "DynamicArray<ACME::Obsidian::Base::String,2,16>", "ns": ["ACME", "Obsidian", "Std"],
         "kind": "class", "size": 16, "members": [], "methods": []},
    ]
    functions = [
        {"language": "c++",
         "display": "ACME::Obsidian::Std::DynamicArray::Clear(void)",
         "signature": "void __fastcall(ACME::Obsidian::Std::DynamicArray *const this)"},
        {"language": "c++",
         "display": "ACME::Obsidian::Base::String::ExtractMatch(char const *,char const *)",
         "signature": "bool __fastcall(const char *text, const char *pattern)"},
        {"language": "c++",
         "display": "ACME::Obsidian::Base::String::String(char const *)",
         "signature": "ACME::Obsidian::Base::String *__fastcall("
                      "ACME::Obsidian::Base::String *const this, char const *text)"},
        {"language": "c++",
         "display": "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16>"
                    "::DynamicArray<ACME::Obsidian::Base::String,2,16>(int)",
         "signature": "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> *__fastcall("
                      "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> *const this, int)"},
        {"language": "c++",
         "display": "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16>"
                    "::~DynamicArray<ACME::Obsidian::Base::String,2,16>(void)",
         "signature": "void __fastcall(ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> *const this)"},
        # IDA sometimes mislabels a method's class in the demangled display; the explicit `this`
        # type in the signature is the authority.
        {"language": "c++",
         "display": "ACME::Obsidian::Base::String::data(void)",
         "signature": "ACME::Aurora::PlatformService::Trophy::WinTrophyContext *__fastcall("
                      "ACME::Aurora::PlatformService::Trophy::TrophyContextHandle *this)"},
    ]
    analyze._attach_methods(types, functions)
    clear = next(m for m in types[1]["methods"] if m["name"] == "Clear")
    assert clear["ret"] == "void" and clear["static"] is False and clear["params"] == []
    match = next(m for m in types[0]["methods"] if m["name"] == "ExtractMatch")
    assert match["ret"] == "bool" and match["static"] is True
    ctor = next(m for m in types[0]["methods"] if m["name"] == "String")
    assert ctor["ret"] == "" and ctor["static"] is False and ctor["params"] == ["char const *"]
    assert not any(m["name"] == "data" for m in types[0]["methods"])
    template_names = {m["name"] for m in types[2]["methods"]}
    assert "DynamicArray" in template_names and "~DynamicArray" in template_names
    from dcore.core import interfaces
    ctor_decl = interfaces._method_decl(types[2], next(m for m in types[2]["methods"]
                                                       if m["name"] == "DynamicArray"),
                                        lambda _: True)
    assert ctor_decl is not None and ctor_decl.startswith("DynamicArray(")


def test_set_method_and_move_tombstones(tmp_path, elf_bytes):
    """Two gaps an agent hit reconstructing a static-member call honestly: edit_type could not
    declare member functions at all (the C++ mangling needs the declaration inside the class),
    and `move` left the analysis's old base entry rendering (C2011). set_method plus move/hide
    tombstones close both - no linker aliases needed."""
    import json as _json

    from dcore.core import interfaces, registry as reg

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    agent, _ = net.local_agent("typesmith")

    reg.apply(net, slug, "declare", name="OSMemory", kind="struct", size=1)
    reg.apply(net, slug, "set_method", name="OSMemory", member="GetSystemTotalSize",
              mtype="unsigned __int64", static="true")
    reg.apply(net, slug, "set_static", name="OSMemory", member="enable_", mtype="bool")
    proj = net._project(slug)
    analysis = net.native.analysis(proj)
    entry = reg.find(reg.view(analysis, reg.load(net, slug)), "OSMemory")
    assert entry["methods"] == [{"name": "GetSystemTotalSize", "params": [],
                                 "ret": "unsigned __int64", "static": True}]
    assert entry["statics"] == [{"name": "enable_", "type": "bool"}]
    block = interfaces.type_block(analysis, "OSMemory o;", types=[entry])
    assert "static unsigned long long GetSystemTotalSize();" in block
    assert "static bool enable_;" in block

    # a base stub the debug info carries, then move: the old base must stop rendering
    apath = Path(proj["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    data = _json.loads(apath.read_text())
    data["types"] = [{"name": "Gadget", "ns": [], "kind": "struct", "size": 1, "members": [],
                      "statics": [], "methods": [], "origin": "ida"}]
    apath.write_text(_json.dumps(data))
    reg.apply(net, slug, "move", name="Gadget", scope="Detail")
    keys = [t["key"] for t in reg.view(net.native.analysis(proj), reg.load(net, slug))]
    assert "Gadget" not in keys and "Detail::Gadget" in keys

    reg.apply(net, slug, "hide", name="Detail::Gadget")
    keys = [t["key"] for t in reg.view(net.native.analysis(proj), reg.load(net, slug))]
    assert "Detail::Gadget" not in keys
    reg.apply(net, slug, "unhide", name="Detail::Gadget")
    keys = [t["key"] for t in reg.view(net.native.analysis(proj), reg.load(net, slug))]
    assert "Detail::Gadget" in keys


def test_the_header_fence_refuses_pragmas(tmp_path, elf_bytes):
    """A matched function had been pushed through with a linker directive riding in its context.h
    (edit_context was fenced by nothing, while submissions ban pragmas/asm). Headers now carry the
    same fence - the generated types block is exempt, it is replaced at compile time anyway."""
    import pytest as _pytest

    from dcore.core import plan
    from dcore.core.compiler import SourceRejected, check_header

    check_header("int x;\n")  # plain declarations stay fine
    with _pytest.raises(SourceRejected, match="pragmas"):
        check_header('#pragma comment(linker, "/alternatename:a=b")\n')

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("hdr")
    out = net.edit_context(agent, slug, "", '#pragma comment(linker, "x")\n', "poke",
                           function="score_update")
    assert out.startswith("❌ REJECTED") and "pragma" in out


def test_freestanding_includes_pass_the_fence():
    """The fence bans system includes so context.h stays the ground truth - but it rejected the
    freestanding ones too, including the <cstdint> the generated header itself ships, so a
    variadic reconstruction could not use the real <cstdarg> and hand-rolled a va_start shim
    instead (it drifts from the compiler's own codegen). The freestanding set passes now."""
    import pytest as _pytest

    from dcore.core.compiler import SourceRejected, check_header, check_source

    check_header('#include <cstdarg>\n#include <cstdint>\nint x;\n')
    check_header('#include <stdarg.h>\n#include <stddef.h>\n')
    check_header('#include <intrin.h>\n#include <immintrin.h>\n#include <x86intrin.h>\n')
    check_source('#include <cstddef>\nint f(void) { return 0; }\n')
    for bad in ("#include <windows.h>\n", '#include <vector>\n', "#include <cstdintfoo>\n",
                "#include <intrinsics_world.h>\n"):
        with _pytest.raises(SourceRejected, match="freestanding"):
            check_header(bad)
        with _pytest.raises(SourceRejected, match="freestanding"):
            check_source(bad)


def test_the_projection_never_spells_template_garbage_as_a_namespace():
    """A qualified template spelling some producer split on '::' used to render in the forward
    section as `namespace ACME { … namespace DynamicArray<ACME { … struct String,2,16>; }}}` -
    stored headers with that line don't parse, so every edit_context on the unit bounced and the
    agents went reading the app's own source over it. Non-identifier entries are never spelled."""
    from dcore.core import interfaces

    holder = {"name": "Holder", "ns": [], "kind": "struct", "size": 8,
              "members": [{"name": "p", "off": 0, "type": "Polluted *"}]}
    polluted = {"name": "Polluted", "ns": ["ACME", "DynamicArray<ACME", "Base"], "kind": "struct"}
    block = interfaces.type_block({"types": []}, "Holder", types=[holder, polluted])
    # the unspellable type degrades to an opaque member (it must not dangle undeclared)...
    assert "unsigned char p[8];  /* Polluted * */" in block
    assert "DynamicArray<ACME" not in block and "namespace DynamicArray" not in block


def test_nested_types_of_a_class_are_never_spelled_as_namespaces():
    """A class with nested types (Black::Motion::DmAnimation::DmResourceInfo) used to render as
    `namespace DmAnimation {` right next to the `struct DmAnimation;` forward the same block
    emits - a C2757 'redefinition as different kind' cascade that ICE'd cl during an agent's
    compile and dead-ended the function (it released it with a note). Nested paths under a type
    are skipped; only exact path prefixes count, so real namespaces stay."""

    from dcore.core import interfaces

    outer = {"name": "DmAnimation", "ns": ["Black", "Motion"], "kind": "class", "size": 8,
             "members": []}
    nested = {"name": "DmResourceInfo", "ns": ["Black", "Motion", "DmAnimation"], "kind": "struct",
              "size": 16, "members": [{"name": "id", "off": 0, "type": "int"}]}
    holder = {"name": "Holder", "ns": [], "kind": "struct", "size": 8,
              "members": [{"name": "res", "off": 0, "type": "DmResourceInfo *"}]}
    block = interfaces.type_block({"types": []}, "Holder DmAnimation", types=[outer, nested, holder])
    assert "namespace DmAnimation" not in block  # the C2757 pair can never form
    assert "class DmAnimation;" in block  # the class itself still forwards (it's mentioned)
    assert "unsigned char res[8];  /* DmResourceInfo * */" in block  # the use degrades, honestly
    # a namespace that merely shares a leaf name with a class elsewhere is NOT nested: its path
    # prefix is not a type, so its contents keep rendering
    seq_ns = {"name": "SequenceGroup", "ns": ["ACME", "Obsidian", "Framework", "Sequence"],
              "kind": "struct", "size": 4, "members": [{"name": "n", "off": 0, "type": "int"}]}
    seq_cls = {"name": "Sequence", "ns": ["ACME", "Aurora", "Core"], "kind": "class", "size": 8,
               "members": []}
    block2 = interfaces.type_block({"types": []}, "SequenceGroup", types=[seq_ns, seq_cls])
    assert "namespace Sequence {" in block2 and "struct SequenceGroup" in block2


def test_edits_judge_the_visible_header_not_the_stale_block(tmp_path, elf_bytes):
    """The stored generated block is always stripped and replaced at compile time, so the
    nothing-matched parse check must judge the stripped text: a stale block with unparseable
    leftovers used to reject every edit on the unit - with a message claiming matched functions
    broke when none existed. The message tells the truth now."""
    from dcore.core import interfaces
    from dcore.core import plan

    mark_begin, mark_end = interfaces._TYPE_MARK_BEGIN, interfaces._TYPE_MARK_END
    garbage = "namespace Broken<X { struct Y,2,16>; }}}}\n"
    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)

    assert net.regression_test(proj, f"int ok;\n{mark_begin}\n{garbage}{mark_end}\n") == []
    broken = net.regression_test(proj, garbage)
    assert broken and broken[0][0] == "<header>"  # garbage in the visible part is still an error

    agent, _ = net.local_agent("hdr")
    out = net.edit_context(agent, slug, "", garbage, "probe", function="score_update")
    assert out.startswith("❌ REJECTED") and "doesn't compile on its own" in out
    assert "already-matched" not in out


def test_edit_context_maps_onto_entries_now(tmp_path, elf_bytes, monkeypatch):
    """edit_context is a compat shim over the generated-header world: an append becomes a raw
    declaration entry (gated against the unit's matched functions — the old mention narrowing is
    gone with the text editor), a replacement edits a live entry's own text, and text outside every
    entry is refused with the migration hint."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched', "
                   "matched_source='int score_update(int *s) { return helper_used_by_match(*s); }' "
                   "WHERE name='score_update'")
    agent, _ = net.local_agent("hdr")
    seen = {}

    def spy(proj_, header, sources=None, only=None, header_for=None):
        seen["only"] = [r["name"] for r in only or []]
        return []

    monkeypatch.setattr(net, "regression_test", spy)
    out = net.edit_context(agent, slug, "", "int my_fresh_helper(void);", "add", function="score_update")
    assert seen["only"] == ["score_update"] and out.startswith("✅ entry"), (seen, out)
    out = net.edit_context(agent, slug, "int my_fresh_helper(void);",
                           "int my_fresh_helper(long);", "edit", function="score_update")
    assert seen["only"] == ["score_update"] and "entry (edited)" in out, (seen, out)
    with pytest.raises(NetworkError, match="matches no live declaration entry"):
        net.edit_context(agent, slug, "int not_in_any_entry(void);", "x;", "nope", function="score_update")


def test_type_edits_verify_only_the_functions_whose_header_changed(tmp_path, elf_bytes, monkeypatch):
    """The dependency proof at the registry gate: a matched function whose rendered compile header is
    byte-identical under the candidate (same defs, same salvage) cannot be affected — it is not
    recompiled at all. Only the function whose header actually changed pays for a compile."""
    import json as _json

    from dcore.core import plan
    from dcore.core import registry as reg

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    analysis["types"] = [
        {"name": "Player", "ns": [], "kind": "struct", "size": 8,
         "members": [{"name": "hp", "off": 0, "type": "int"}]},
        {"name": "Monster", "ns": [], "kind": "struct", "size": 8,
         "members": [{"name": "hp", "off": 0, "type": "int"}]}]
    for f in analysis["functions"]:
        f["file"] = "src/hello.c"  # one unit: the gate's per-function render is what we measure
        if f["name"] == "main":
            f["signature"] = "int (void)"  # the fixture compiler warns on `long main();` (-Werror)
    proj = net.project_row(slug)
    cache = Path(proj["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    plan.confirm(net, slug, log=lambda *_: None)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched', "
                   "matched_source='Player *score_update(int *s) { return (Player *)s; }' "
                   "WHERE name='score_update'")
        db.execute("UPDATE functions SET status='matched', unit='src/hello.c', "
                   "matched_source='int main(Monster *m) { return m->hp; }' WHERE name='main'")
    seen = []
    monkeypatch.setattr(reg, "_verify_one",
                        lambda engine, proj_, fn, header, form: (seen.append(fn["name"]), (True, "ok"))[1])
    out = reg.apply(net, slug, "set_size", name="Player", size=16)
    assert out["ok"], out
    assert out["skipped"] == 1  # the proof is counted, and the tool messages report it
    assert seen == ["score_update"], seen  # main's compiled header didn't change: proven, not compiled


def test_the_ida_database_held_elsewhere_explains_itself():
    """The 1228-class open failure is the app colliding with the user's own IDA instance; the message
    says so instead of an internal error id."""
    from dcore.core import native as native_mod

    msg = native_mod.friendly_ida_error("Oops! internal error 1228 ( 0x4CC )")
    assert msg and "open in another IDA instance" in msg and "unaffected" in msg
    assert native_mod.friendly_ida_error("disk full") is None


def test_write_through_queues_and_retries_while_ida_is_held(tmp_path, elf_bytes, monkeypatch):
    """A write-through that can't reach the database (open in IDA Professional) queues the pending
    type keys in settings; the next write retries and clears them — edits are never lost, only the
    visibility is delayed."""
    import time

    from dcore.core import plan
    from dcore.core import registry as reg

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    t = {"name": "B", "ns": ["A"], "kind": "struct", "size": 4,
         "members": [{"name": "v", "off": 0, "type": "int"}]}
    monkeypatch.setattr(net.native, "ida_ready", lambda: True)
    monkeypatch.setattr(net.native, "ida_apply_decls",
                        lambda slug_, decls: {"ok": False, "error": "Oops! internal error 1228"})
    out = reg._write_through(net, slug, analysis, {}, {("A", "B"): t})
    assert "queued" in out and "IDA Professional" in out
    state = reg._sync_state(net, slug)
    assert state["pending"] == ["A::B"] and "1228" in state["last_error"]
    monkeypatch.setattr(net.native, "ida_apply_decls", lambda slug_, decls: {"ok": True})
    monkeypatch.setattr(net.native, "ida_save", lambda slug_, force=False: True)
    state = reg._sync_state(net, slug)
    state["last_try_at"] = time.time() - 121  # the busy cooldown has passed
    reg._sync_save(net, slug, state)
    out = reg._write_through(net, slug, analysis, {("A", "B"): t}, {("A", "B"): t})
    assert "written to the IDA database" in out  # an unchanged edit still retries the queue
    assert reg._sync_state(net, slug)["pending"] == []


def test_promote_legacy_moves_frozen_text_into_entries(tmp_path, elf_bytes, monkeypatch):
    """The frozen legacy layer has a sanctioned escape: the exact text leaves the stored header (a new
    version keeps the rest) and becomes a gated entry — the only way to fix a seed's wrong type tag."""
    import time as _time

    from dcore.core import entries as entries_mod
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    pid = proj["id"]
    unit = "src/hello.c"
    ctx = net._context(pid, unit)
    head, _, rest = ctx["header"].partition("/* >>> decomp.wtf types")
    with net.store.tx() as db:
        version = net._next_version(db, pid)
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (pid, version, head + "typedef unsigned long long my_u64;\n/* >>> decomp.wtf types" + rest,
                    None, "legacy", _time.time(), unit))
    agent, _ = net.local_agent("promoter")
    seen = {}

    def spy(proj_, header, sources=None, only=None, header_for=None):
        seen["only"] = [r["name"] for r in only or []]
        seen["composite_has_text"] = "typedef unsigned long long my_u64" in (header or "")
        return []

    monkeypatch.setattr(net, "regression_test", spy)
    out = net.promote_legacy(agent, slug, "typedef unsigned long long my_u64;", "", "alias", "score_update")
    assert out.startswith("✅"), out
    assert "get_context(function=" in out  # and the promoted entry is inspectable as rendered
    assert seen["only"] == [] and seen["composite_has_text"]  # the entry now carries it for the parse check
    latest = net.store.one("SELECT header FROM context_versions WHERE project_id=? AND unit=? "
                           "ORDER BY version DESC LIMIT 1", pid, unit)
    assert "typedef unsigned long long my_u64;" not in latest["header"]  # left the frozen layer
    live = entries_mod.list_for(net, slug, unit)
    assert live and live[0]["body"].startswith("typedef unsigned long long my_u64")
    with pytest.raises(NetworkError, match="exactly once"):
        net.promote_legacy(agent, slug, "not in the header", "", "alias", "score_update")


def test_reports_are_the_deduped_todo_list(tmp_path, elf_bytes):
    """The stack's walls, filed by agents: kind bug/need, one line each, identical titles merge into a
    hit-counted todo item (so the recurring gaps sort to the top instead of drowning in notes)."""
    from dcore.app import agents as agents_mod
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("reporter")
    out = net.report_issue(agent, slug, "need", "no way to express a variadic method",
                           "set_method refuses the ellipsis", "score_update")
    assert out.startswith("✅") and "#" in out
    again = net.report_issue(agent, slug, "need", "no way to express a variadic method", "second hit")
    assert "seen 2 times" in again
    live = net.reports(slug)
    assert len(live) == 1 and live[0]["hits"] == 2 and live[0]["kind"] == "need"
    assert live[0]["function"] == "score_update"  # the blocker keeps its first context
    net.report_issue(agent, slug, "bug", "declare eats trailing semicolons", "")
    assert len(net.reports(slug)) == 2
    with pytest.raises(NetworkError, match="kind"):
        net.report_issue(agent, slug, "rant", "x")
    with pytest.raises(NetworkError, match="title"):
        net.report_issue(agent, slug, "bug", "   ")
    names = {d["function"]["name"] for d in agents_mod.api_tool_schemas(native=True)}
    assert "report" in names


def test_switching_functions_spells_out_the_release_and_claim(tmp_path, elf_bytes):
    """With several agents per project the claim churn is constant; the errors must name the held
    claim and the calls that switch, so a switch costs one turn instead of two failed ones."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("switch")
    net.claim(agent, slug, "score_update")
    with pytest.raises(NetworkError) as e:
        net.attempt(agent, "main", "int main(void) { return 0; }")
    msg = str(e.value)
    assert "score_update" in msg and "release_function" in msg and "claim_function" in msg, msg
    with pytest.raises(NetworkError) as e2:
        net.claim(agent, slug, "main")
    msg = str(e2.value)
    assert "score_update" in msg and "release_function" in msg and "claim again" in msg, msg


def test_the_resolver_speaks_the_mangled_spelling(tmp_path, elf_bytes):
    """The disassembly hands agents mangled names, and they copy them into the tools; the resolver
    matched only stored names (whose meta predates the linkage field), so a mangled compile_and_diff
    said 'no function'. The analysis's spellings resolve now, keyed to their ea."""
    import json as _json

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    for f in analysis["functions"]:
        if f["name"] == "score_update":
            f["linkage"] = "?score_update@fixture@@YAXXZ"
    proj = net.project_row(slug)
    cache = Path(proj["root"]) / ".decomp-wtf" / "native" / "analysis.json"
    cache.write_text(_json.dumps(analysis))
    net.native._analysis.pop(slug, None)
    row = net._function("?score_update@fixture@@YAXXZ", slug)
    assert row["name"] == "score_update"


def test_compile_failures_name_the_binarys_signature(tmp_path, elf_bytes, monkeypatch):
    """The C2556/C2372-class laps: definition and header disagree with the binary's signature (which
    we know exactly). The failure now carries it - one authoritative line instead of the agent
    re-spelling the prototype for three more compiles."""
    from dcore.core import plan
    from dcore.core.compiler import CompileResult

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET meta=? WHERE name='score_update'",
                   ('{"demangled": "Score::update(int *, int)", "signature": "int __fastcall(int *, int)",'
                    ' "language": "c++"}',))
    agent, _ = net.local_agent("hdr")
    monkeypatch.setattr(net, "_compile",
                        lambda proj_, header, source, **kw: CompileResult(
                            False, None, "func.cpp(1): error C2556: 'update': overloaded function differs"))
    out = net.attempt(agent, "score_update", "int *update(int *, int) { return 0; }")
    assert "this is the binary's function" in out["text"] and "Score::update(int *, int)" in out["text"]
    assert "int __fastcall(int *, int)" in out["text"]
    monkeypatch.setattr(net, "_compile",
                        lambda proj_, header, source, **kw: CompileResult(
                            False, None, "func.cpp(1): error C2143: syntax error"))
    out = net.attempt(agent, "score_update", "int *update(int *, int) { return 0; }")
    assert "this is the binary's function" not in out["text"]


def test_compile_prepends_the_functions_own_declaration(tmp_path, elf_bytes):
    """MSVC refuses a qualified definition (`Ret Ns::f(...) { }`) without a prior declaration
    (C2039) - a function its unit never declared as a callee could not compile at all. Every
    compile gets the function's own prototype prepended, from the debug info's signature."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    fn = dict(net.store.one("SELECT * FROM functions WHERE name='score_update'"))
    fn["meta"] = ('{"demangled": "score_update(int *s, int d, int m)",'
                  ' "signature": "int __fastcall(int *, int, int)"}')
    out = net.native._self_declared(fn, "int score_update(int *s, int d, int m) { return 0; }")
    assert out.startswith("int __fastcall score_update(int *s, int d, int m);\n")
    # a namespaced function: the declaration must sit INSIDE the namespaces (cl refuses qualified
    # declarations from outside them, C2039)
    fn["meta"] = ('{"demangled": "ACME::Aurora::Core::Memory::GetTotalHeapSize(void)",'
                  ' "signature": "unsigned __int64 __fastcall()"}')
    out = net.native._self_declared(fn, "X")
    assert out.startswith("namespace ACME { namespace Aurora { namespace Core { namespace Memory { "
                          "unsigned __int64 __fastcall GetTotalHeapSize(void);}}}}\n")
    fn["meta"] = '{"demangled": "", "signature": ""}'
    src = "int f(void) { return 0; }"
    assert net.native._self_declared(fn, src) == src  # nothing known: untouched


def test_a_header_written_class_shadows_the_registry_definition(tmp_path, elf_bytes):
    """A class an agent wrote into context.h must not get a second definition from the projection
    (C2011) - the base is the compile unit's ground truth. This is what lets a hand-written class
    and a registry entry hand over to each other across two edits, instead of needing a size-0
    suppression trick or an atomic header+registry batch."""
    from dcore.core import registry as reg

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    analysis = _write_fake_analysis(net, slug, binary, tmp_path)
    entry = {"name": "Widget", "ns": [], "kind": "struct", "size": 4, "origin": "agent",
             "members": [{"name": "x", "off": 0, "type": "int"}], "statics": [], "methods": []}
    overrides = {"types": {"Widget": entry}}
    base = "/* context */\nstruct Widget {\n    int x;\n};\n"
    out = reg.header_for(analysis, base, "Widget w;", overrides)
    assert out.count("struct Widget {") == 1  # only the base's; the projection stays quiet
    out2 = reg.header_for(analysis, "/* context */\n", "Widget w;", overrides)
    assert out2.count("struct Widget {") == 1  # no base declaration: the projection defines it


def test_a_trailing_tail_jump_survives_the_coff_slice():
    """A thunk that ends in `jmp rel32` has its rel32 field zeroed in the unlinked COFF (the
    relocation carries the target). The trailing-zero trim used to eat it as alignment padding -
    the function came out four bytes short, capstone rendered the leftover opcode as `.byte 0xe9`
    and a byte-perfect tail call scored as a mismatch. Fields a relocation covers are never
    padding. The fixture is the real object cl 19.00.24210 produced for DmDebugMalloc."""
    import base64

    from dcore.core import scoring
    from dcore.targets.plat.pe.object import extract_function

    obj = base64.b64decode(
        "ZIYDAHwD0mo1AQAACgAAAAAAAAAuZHJlY3R2ZQAAAAAAAAAALwAAAIwAAAAAAAAAAAAAAAAAAAAAChAA"
        "DmRlYnVnJFMAAAAAAAAAAGAAAAC7AAAAAAAAAAAAAAAAAAAAQAAQQi50ZXh0JG1uAAAAAAAAAAAQAAAA"
        "GwEAACsBAAAAAAAAAQAAACAQUGAgICAvREVGQVVMVExJQjoiTElCQ01UIiAvREVGQVVMVExJQjoiT0xE"
        "TkFNRVMiIAQAAADxAAAAUwAAABUAAREAAAAAWjpcd29ya1xmdW5jLm8AOgA8EQFiAADQABMAAACSXgAA"
        "EwAAAJJeAABNaWNyb3NvZnQgKFIpIE9wdGltaXppbmcgQ29tcGlsZXIAAEUzyUGNURBFjUFC6QAAAAAM"
        "AAAACAAAAAQAQGNvbXAuaSSSXgUB//8AAAMAQGZlYXQuMDCQAQCA//8AAAMALmRyZWN0dmUAAAAAAQAA"
        "AAMBLwAAAAAAAAAAAAAAAAAAAAAALmRlYnVnJFMAAAAAAgAAAAMBYAAAAAAAAAAAAAAAAAAAAAAALnRl"
        "eHQkbW4AAAAAAwAAAAMBEAAAAAEAAAB8BJ88AAABAAAAAAAAAAQAAAAAAAAAAAAgAAIAAAAAADgAAAAA"
        "AAAAAwAgAAIAZgAAAD9NYWxsb2NATWVtb3J5QENvcmVAQXVyb3JhQ29AQUNNRUBAWUFQRUFYX0swSFBF"
        "QlhAWgA/RG1EZWJ1Z01hbGxvY0BDb3JlQEF1cm9yYUNvQEFDTUVAQFlBUEVBWF9LQFoA")
    got = extract_function(obj, "?DmDebugMalloc@Core@AuroraCo@ACME@@YAPEAX_K@Z")
    assert got is not None
    assert len(got.code) == 16  # through the jmp's field; the trim stops at the relocation
    assert got.code[-5] == 0xE9 and got.code[-4:] == b"\0\0\0\0"
    assert any(r.symbol.startswith("?Malloc@") for r in got.relocs)
    last = scoring.disassemble(got)[-1]
    assert last.mnemonic == "jmp" and not last.text.startswith(".byte")


def test_resolution_accepts_signatures_and_qualified_forms(tmp_path, elf_bytes):
    """Three ways agents name functions that used to dead-end: a signature with commas (the name
    splitter cut it into phantom names like 'int)'), a bare symbol behind a qualified demangled
    form (the loose lookup only anchored at the start, and the fallback suggestions drowned in
    thousands of %Malloc% rows), and a bare hex address from the disassembly view."""
    import json as _json

    from dcore.app.tools import _split_names
    from dcore.core import plan
    from dcore.core import engine as engine_mod

    assert _split_names("ACME::Memory::Malloc(unsigned __int64, int), second") == \
        ["ACME::Memory::Malloc(unsigned __int64, int)", "second"]
    assert _split_names("f(a<b, c>), g") == ["f(a<b, c>)", "g"]
    assert engine_mod._ADDRESS.match("142FDD240")  # the disassembly view prints bare, any length

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("resolver")
    row = dict(net.store.one("SELECT * FROM functions WHERE name='score_update'"))
    with net.store.tx() as db:
        db.execute("UPDATE functions SET meta=? WHERE id=?",
                   (_json.dumps({**_json.loads(row["meta"] or "{}"),
                                 "demangled": "ACME::Deep::scored_thing(int)",
                                 "symbol": "?scored_thing@ACME@@YAXH@Z"}), row["id"]))
    assert net.resolve_function(agent, slug, "scored_thing") == "score_update"
    assert net.resolve_function(agent, slug, f"0x{row['vram']:X}") == "score_update"


def test_claim_leases_renew_while_the_agent_is_working(tmp_path, elf_bytes):
    """A local model can think for many minutes without calling a tool; the claim must not expire
    under it. The runner beats the lease, and any tool call renews it too."""
    import time as _time

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("lease")
    net.claim(agent, slug, "score_update")
    with net.store.tx() as db:
        db.execute("UPDATE claims SET expires_at=? WHERE agent_id=?", (_time.time() + 60, agent.id))
    assert net.renew_claims(agent, slug) == 1
    left = net.store.one("SELECT expires_at FROM claims WHERE agent_id=?", agent.id)["expires_at"] - _time.time()
    assert left > 20 * 60  # a fresh 30-minute lease, not the one-minute one


def test_release_claims_frees_a_stopped_helpers_functions(tmp_path, elf_bytes):
    """Claims outlive the process that made them unless something releases them: the quit path
    exits ~0.5s after setting the stop flag, so a dying agent's reader thread may never reach the
    _run tail. Manager.stop must release synchronously - and an identity whose session is already
    gone (the "connected agent" ghost card) must be releasable through the same engine call."""
    from dcore.app.agents import Manager, Session
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("opencode-9")
    net.claim(agent, slug, "score_update")
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 1

    mgr = Manager(net, tmp_path / "agents-home", "http://127.0.0.1:1/mcp")
    s = Session("opencode-9", "opencode", "opencode #9", slug, "opencode-9", {"per_session": 1}, state="working")
    mgr.sessions[s.id] = s
    mgr.stop(s.id)
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0
    assert any("released" in f["text"] for f in s.feed)

    # the ghost card's escape hatch: no session anywhere, claim still there
    ghost, _ = net.local_agent("ghost-9")
    net.claim(ghost, slug, "main")
    assert net.release_claims("ghost-9", slug) == ["main"]
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0


def test_a_handoff_needs_effort_or_a_filed_blocker(tmp_path, elf_bytes):
    """Agents were releasing after a handful of compiles (one at 11 tries / 50%). A handoff now
    needs ~20 compiles or an open report for that function that documents the blocker."""
    from dcore.core import plan
    from dcore.core.network import NetworkError

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("handoff")
    net.claim(agent, slug, "score_update")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET attempts=2 WHERE name='score_update'")
    with pytest.raises(NetworkError, match="only 2 compile"):
        net.release(agent, "score_update", "not yet", slug)
    net.report_issue(agent, slug, "bug", "blocked by the header", "repro", function="score_update")
    assert net.release(agent, "score_update", "blocked; see the report", slug).startswith("Released")

    net.claim(agent, slug, "main")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET attempts=20 WHERE name='main'")
    assert net.release(agent, "main", "twenty real tries", slug).startswith("Released")


def test_function_detail_serves_a_clicked_function(tmp_path, elf_bytes):
    """Clicking a function on the map 500ed with AttributeError ('Engine' has no attribute
    'fork_slug' — another pruned decomp.wtf concept). Nothing outside the browser ever called
    function_detail(); this pins the payload a click renders."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    with net.store.tx() as db:  # a source on file: no IDA draft to fetch in the test
        db.execute("UPDATE functions SET best_source='int score_update(void){return 0;}' WHERE name='score_update'")
    detail = net.function_detail(slug, "score_update")
    assert detail["name"] == "score_update" and detail["vram"]
    assert detail["source_kind"] == "best" and "score_update" in detail["source"]
    assert isinstance(detail["calls"], list) and isinstance(detail["called_by"], list)
    assert detail["asm"]


def test_live_feed_serves_the_project(tmp_path, elf_bytes):
    """The live view's poll endpoint raised AttributeError ('Engine' has no attribute 'links' — a
    pruned decomp.wtf concept) on every call, so the first real UI run flooded the console with
    500s. Nothing had ever called live(); this pins the feed's shape and the claims it carries."""
    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    agent, _ = net.local_agent("liver")
    net.claim(agent, slug, "score_update")
    feed = net.live(slug)
    assert set(feed) == {"events", "attempts", "claims", "overview"}
    assert feed["overview"]["functions"] >= 1
    assert any(c["name"] == "score_update" and c["agent"] == "liver" for c in feed["claims"])


def test_rename_symbol_updates_the_row_name_and_texts(tmp_path, elf_bytes):
    """The rename's local half used to lag: headers, sources and the .i64 got the new name while
    the row (what the claim title shows) kept the old one until some later re-analysis."""
    import json as _json

    from dcore.core import plan

    net, slug, binary = _native_project(tmp_path, elf_bytes)
    _write_fake_analysis(net, slug, binary, tmp_path)
    plan.confirm(net, slug, log=lambda *_: None)
    proj = net.project_row(slug)
    pid = proj["id"]
    assert "score_update" in net._context(pid, "src/hello.c")["header"]

    agent, _ = net.local_agent("renamer")
    out = net.rename_symbol(agent, slug, "score_update", "score_state")
    assert "renamed `score_update` -> `score_state`" in out
    row = net.store.one("SELECT name, meta FROM functions WHERE unit='src/hello.c'")
    assert row["name"] == "score_state"
    assert _json.loads(row["meta"])["symbol"] == "score_update"  # provenance is not rewritten
    latest = net.store.one("SELECT header, message FROM context_versions WHERE project_id=? "
                           "AND unit='src/hello.c' ORDER BY version DESC LIMIT 1", pid)
    assert "score_state" in latest["header"] and latest["message"] == "rename score_update -> score_state"
