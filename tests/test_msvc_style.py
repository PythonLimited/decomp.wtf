"""The MSVC compile style: a PE project's driver spells flags the way cl does.

Probes are how agents find the original build's flags, and on Windows those are `/O2 /GS /EHsc`,
not `-O2 -fstack-protector`. Resolution therefore prefers a driver that speaks cl's language —
real cl, clang-cl, or clang in `--driver-mode=cl` — and the command template follows.
"""

from __future__ import annotations

import shutil

import pytest

from dcore.core.compiler import CompilerConfig, compile_source
from dcore.core.compilers import Compiler, _detect, _style_of, _swap_cxx
from dcore.targets import plat_pack

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="needs clang")


def test_the_msvc_template_spells_c_i_and_fo():
    c = Compiler(command=["cl"], flags=["/O2", "/GS"], language="c", source_name="func.c", style="msvc")
    assert c.template() == ["cl", "/nologo", "/O2", "/GS", "/c", "/I{include}", "/Fo{obj}", "{src}"]
    gcc = Compiler(command=["gcc"], flags=["-O2"], language="c", source_name="func.c")
    assert gcc.template() == ["gcc", "-O2", "-c", "-I{include}", "{src}", "-o", "{obj}"]


def test_style_is_read_from_the_driver_spelling():
    assert _style_of(["cl"]) == "msvc" and _style_of(["/usr/bin/cl.exe"]) == "msvc"
    assert _style_of(["clang-cl"]) == "msvc"
    assert _style_of(["clang", "--target=x86_64-pc-windows-msvc", "--driver-mode=cl"]) == "msvc"
    assert _style_of(["clang"]) == "gcc" and _style_of(["zig", "cc"]) == "gcc"


def test_the_cxx_swap_leaves_cl_mode_drivers_alone():
    """clang-cl starts with "clang-", which the gcc-family swap would mangle into `clang++-cl`."""
    assert _swap_cxx(["clang-cl"]) == ["clang-cl"]
    assert _swap_cxx(["cl"]) == ["cl"]
    assert _swap_cxx(["clang", "--driver-mode=cl"]) == ["clang", "--driver-mode=cl"]
    assert _swap_cxx(["clang"]) == ["clang++"]  # plain clang still swaps
    assert _swap_cxx(["gcc"]) == ["g++"]        # C++ units use the C++ driver
    assert _swap_cxx(["gcc-12"]) == ["g++-12"]


def test_a_pe_project_resolves_to_an_msvc_style_driver():
    command, note = _detect("MSVC 19.00 (VS2015 U3)", "c", "pe", "x86_64")
    assert command and _style_of(command) == "msvc"
    assert "msvc" in note.lower() or "windows" in note.lower()


def test_pe_targets_get_the_linux_platform_and_cl_in_image():
    from dcore.core.compilers import _image_driver, docker_platform, suggested_image

    # docker platform is per target: an msvc-wine image is an amd64 linux container for x86/x64
    assert docker_platform("pe", "x86_64") == "linux/amd64"
    assert docker_platform("pe", "x86") == "linux/amd64"
    assert docker_platform("pe", "aarch64") == "linux/arm64"
    assert docker_platform("elf", "x86_64") == "linux/amd64" and docker_platform("elf", "x86") is None
    assert docker_platform("macho", "x86_64") is None

    # inside an image the driver is the family's plain binary — an msvc-wine image carries cl
    assert _image_driver("MSVC 19.00 (VS2015 U3)") == ["cl"]
    assert _image_driver("Microsoft Visual C++ 19.16") == ["cl"]
    assert _image_driver("GNU C 8.1.0") == ["gcc"] and _image_driver("clang version 15.0.0") == ["clang"]
    assert _image_driver("") == ["cc"]

    # and the compiler card suggests the wine image for a VS2015 U3 binary
    assert suggested_image("MSVC 19.00 (VS2015 U3)") == "dcore-msvc-wine:2015u3"
    assert suggested_image("GNU C 8.1.0") == "gcc:8.1.0"
    assert suggested_image("MSVC 19.00 (VS2015)") == ""  # pre-U3: no image for it


def test_an_image_platform_override_beats_the_target_platform():
    """A Hangover image carries the x86-64 toolset natively on arm64: the target stays x86_64 but
    the container is linux/arm64. `native`/`host` omits --platform entirely."""
    from dcore.core.compilers import image_platform

    cfg = {"format": "pe", "arch": "x86_64"}
    assert image_platform(cfg, {}) == "linux/amd64"
    assert image_platform(cfg, {"platform": "linux/arm64"}) == "linux/arm64"
    assert image_platform(cfg, {"platform": "native"}) is None


def test_compile_and_read_back_through_the_msvc_style(tmp_path):
    """The whole arc, for real: resolve a PE driver, compile through the msvc template, read the
    object back with the COFF reader. This is how a Windows candidate is judged."""
    command, _ = _detect("MSVC 19.00 (VS2015 U3)", "c", "pe", "x86_64")
    compiler = Compiler(command=command, flags=["/O2"], language="c", source_name="func.c",
                        style=_style_of(command))
    cfg = CompilerConfig(cmd=compiler.template())
    source = "int add(int a, int b) { return a * 3 + b; }\n"
    res = compile_source(cfg, "typedef int s32;\n", source)
    assert res.ok, res.log
    fn = plat_pack("pe").object_reader().extract_function(res.obj, "add")
    assert fn is not None and fn.arch == "x86_64" and len(fn.code) >= 4 and fn.relocs == []
    again = compile_source(cfg, "typedef int s32;\n", source)
    assert again.ok
    assert plat_pack("pe").object_reader().extract_function(again.obj, "add").fingerprint() == fn.fingerprint()
