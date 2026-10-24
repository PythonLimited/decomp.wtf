from __future__ import annotations

import pytest

from dcore.model import (
    Environment,
    Toolchain,
    canonical_toolchain_id,
    function_key,
    function_unit,
    normalize_target,
    parse_producer,
    resolve_analysis,
)


def _gcc91() -> Toolchain:
    return Toolchain(
        id="gcc-9.1.0-x86_64-linux-gnu",
        family="gcc",
        version="9.1.0",
        target="x86_64-linux-gnu",
        abi="sysv",
        object_format="elf",
        driver=("g++-9",),
        image="gcc:9.1.0@sha256:abc",
        stdlib="libstdc++ 3.4.28",
        crt="glibc 2.31",
        probe_hash="probe-gcc91",
        tier="validated",
    )


def _msvc1900() -> Toolchain:
    return Toolchain(
        id="msvc-19.00.24215.1-x86_64-pc-windows-msvc",
        family="msvc",
        version="19.00.24215.1",
        target="x86_64-pc-windows-msvc",
        abi="ms",
        object_format="pe",
        driver=("cl",),
        image="dcore-msvc-wine:2015u3@sha256:abc",
        stdlib="msvcp140",
        crt="vcruntime140",
        probe_hash="probe-msvc1900",
        tier="validated",
    )


def _analysis() -> dict:
    return {
        "format": "elf",
        "arch": "x86_64",
        "unit_compilers": {
            "src/acme.cpp": {
                "compiler": "GNU C++17 9.1.0 -O2 -fPIC",
                "flags": ["-O2", "-fPIC"],
            },
            "vendor/third.c": {
                "compiler": "GNU C11 4.8.5 -O3",
                "flags": ["-O3"],
            },
        },
        "functions": [
            {"ea": 0x1000, "name": "ACME::Aurora::run", "cu": "src/acme.cpp", "language": "c++"},
            {"ea": 0x2000, "name": "vendor_add", "cu": "vendor/third.c", "language": "c"},
            {"ea": 0x3000, "name": "no_compile_unit", "language": "c++"},
        ],
        "compilers": [
            {"compiler": "GNU C++17 9.1.0", "flags": ["-O2"], "functions": 10, "units": 1},
        ],
    }


def test_parse_gcc_producer_keeps_language_version_and_flags():
    producer = parse_producer("GNU C++17 9.1.0 -O2 -fPIC -std=c++17")
    assert producer is not None
    assert producer.family == "gcc"
    assert producer.version == "9.1.0"
    assert producer.language == "c++"
    assert producer.flags == ("-O2", "-fPIC", "-std=c++17")


def test_parse_c_producer_is_not_mistaken_for_cpp():
    producer = parse_producer("GNU C11 4.8.5 -O2")
    assert producer is not None
    assert producer.language == "c"
    assert producer.version == "4.8.5"


def test_parse_clang_and_apple_clang_are_distinct_families():
    upstream = parse_producer("clang version 12.0.0 (https://github.com/llvm/llvm-project)")
    apple = parse_producer("Apple clang version 15.0.0 (clang-1500.0.40.1)")
    assert upstream is not None and upstream.family == "clang"
    assert upstream.version == "12.0.0"
    assert apple is not None and apple.family == "apple-clang"
    assert apple.version == "15.0.0"


def test_parse_msvc_producer_keeps_the_toolset_version():
    producer = parse_producer(
        "Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24215.1 for x64")
    assert producer is not None
    assert producer.family == "msvc"
    assert producer.version == "19.00.24215.1"


def test_unknown_producer_is_explicitly_unknown():
    assert parse_producer("a homegrown compiler") is None
    assert parse_producer("") is None


def test_targets_are_canonical_per_object_format():
    assert normalize_target("elf", "amd64") == "x86_64-unknown-linux-gnu"
    assert normalize_target("pe", "x64") == "x86_64-pc-windows-msvc"
    assert normalize_target("macho", "arm64") == "aarch64-apple-darwin"


def test_toolchain_ids_normalize_the_unknown_component():
    producer = parse_producer("GNU C++17 9.1.0")
    assert producer is not None
    assert canonical_toolchain_id(producer, "x86_64-unknown-linux-gnu") == \
        "gcc-9.1.0-x86_64-linux-gnu"


def test_resolver_keeps_environments_per_compile_unit_and_maps_functions():
    report = resolve_analysis(_analysis(), catalog={"gcc-9.1.0-x86_64-linux-gnu": _gcc91()})

    acme = report.units["src/acme.cpp"]
    vendor = report.units["vendor/third.c"]
    fallback = report.units[""]

    assert acme.language == "c++"
    assert acme.selected is not None
    assert acme.selected.toolchain == "gcc-9.1.0-x86_64-linux-gnu"
    assert acme.selected.flags == ("-O2", "-fPIC")
    assert acme.missing_toolchain is False
    assert acme.functions == (str(0x1000),)

    assert vendor.language == "c"
    assert vendor.selected is not None
    assert vendor.selected.toolchain == "gcc-4.8.5-x86_64-linux-gnu"
    assert vendor.selected.flags == ("-O3",)
    assert vendor.missing_toolchain is True

    assert fallback.selected is not None
    assert fallback.selected.flags == ("-O2",)
    assert "project default" in " ".join(fallback.notes)

    assert report.functions[str(0x1000)] == acme.selected.id
    assert report.functions[str(0x2000)] == vendor.selected.id
    assert report.functions[str(0x3000)] == fallback.selected.id
    assert report.unresolved_units == ()


def test_resolver_marks_missing_catalog_toolchains_but_still_exposes_the_environment():
    analysis = _analysis()
    no_catalog = resolve_analysis(analysis)
    with_catalog = resolve_analysis(analysis, catalog={"gcc-9.1.0-x86_64-linux-gnu": _gcc91()})

    assert no_catalog.units["src/acme.cpp"].missing_toolchain is True
    assert no_catalog.units["src/acme.cpp"].selected is not None
    assert no_catalog.units["src/acme.cpp"].selected.confidence < \
        with_catalog.units["src/acme.cpp"].selected.confidence
    assert "not in the catalog" in " ".join(no_catalog.units["src/acme.cpp"].notes)


def test_resolver_uses_the_msvc_toolchain_for_a_pe_unit():
    analysis = {
        "format": "pe",
        "arch": "x86_64",
        "unit_compilers": {
            "src/acme.cpp": {
                "compiler": "Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24215.1 for x64",
                "flags": ["/O2", "/EHsc"],
            },
        },
        "functions": [
            {"ea": 0x140001000, "name": "ACME::Aurora::run", "cu": "src/acme.cpp", "language": "c++"},
        ],
        "compilers": [],
    }
    report = resolve_analysis(analysis, catalog={"msvc-19.00.24215.1-x86_64-pc-windows-msvc": _msvc1900()})
    unit = report.units["src/acme.cpp"]
    assert unit.selected is not None
    assert unit.selected.toolchain == "msvc-19.00.24215.1-x86_64-pc-windows-msvc"
    assert unit.selected.flags == ("/O2", "/EHsc")
    assert unit.selected.language == "c++"


def test_resolver_uses_the_apple_clang_family_for_macho():
    analysis = {
        "format": "macho",
        "arch": "arm64",
        "unit_compilers": {
            "src/acme.cpp": {"compiler": "Apple clang version 15.0.0 (clang-1500.0.40.1)",
                             "flags": ["-O2"]},
        },
        "functions": [{"ea": 0x1000, "name": "ACME::Aurora::run", "cu": "src/acme.cpp",
                       "language": "c++"}],
        "compilers": [],
    }
    report = resolve_analysis(analysis)
    unit = report.units["src/acme.cpp"]
    assert unit.selected is not None
    assert unit.selected.toolchain == "apple-clang-15.0.0-aarch64-apple-darwin"


def test_mixed_languages_within_one_unit_are_reported():
    analysis = {
        "format": "elf",
        "arch": "x86_64",
        "unit_compilers": {"src/acme.cpp": {"compiler": "GNU C++17 9.1.0", "flags": ["-O2"]}},
        "functions": [
            {"ea": 1, "name": "a", "cu": "src/acme.cpp", "language": "c++"},
            {"ea": 2, "name": "b", "cu": "src/acme.cpp", "language": "c"},
        ],
        "compilers": [],
    }
    unit = resolve_analysis(analysis).units["src/acme.cpp"]
    assert any("mixed function languages" in note for note in unit.notes)


def test_a_unit_with_no_facts_and_no_project_default_is_unresolved():
    analysis = {
        "format": "elf",
        "arch": "x86_64",
        "unit_compilers": {},
        "functions": [{"ea": 1, "name": "a", "cu": "src/acme.cpp", "language": "c++"}],
        "compilers": [],
    }
    report = resolve_analysis(analysis)
    assert report.units["src/acme.cpp"].selected is None
    assert report.functions["1"] is None
    assert report.unresolved_units == ("src/acme.cpp",)


def test_function_unit_prefers_cu_and_falls_back_for_flattened_rows():
    assert function_unit({"cu": "src/acme.cpp", "unit": "header.h"}) == "src/acme.cpp"
    assert function_unit({"unit": "src/acme.cpp"}) == "src/acme.cpp"


def test_function_key_prefers_stable_identity_over_name():
    assert function_key({"id": 7, "ea": 0x1000, "name": "run"}) == "7"
    assert function_key({"ea": 0x1000, "name": "run"}) == str(0x1000)
    assert function_key({"name": "run"}) == "run"


def test_report_can_look_up_an_environment_by_function_key():
    report = resolve_analysis(_analysis(), catalog={"gcc-9.1.0-x86_64-linux-gnu": _gcc91()})
    env = report.environment_for(str(0x1000))
    assert env is not None
    assert env.toolchain == "gcc-9.1.0-x86_64-linux-gnu"
    assert report.environment_for("missing") is None


def test_environment_can_be_supplied_as_a_project_default():
    default = Environment.create("gcc-9.1.0-x86_64-linux-gnu", "c++", ("-Og",), confidence=0.3)
    analysis = {
        "format": "elf",
        "arch": "x86_64",
        "unit_compilers": {},
        "functions": [{"ea": 1, "name": "a", "cu": "src/acme.cpp", "language": "c++"}],
        "compilers": [],
    }
    unit = resolve_analysis(analysis, project_default=default).units["src/acme.cpp"]
    assert unit.selected is not None
    assert unit.selected.flags == ("-Og",)
    assert "project default" in " ".join(unit.notes)
