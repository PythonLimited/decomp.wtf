from __future__ import annotations

import json

import pytest

from dcore.model import (
    Builtin,
    Environment,
    Evidence,
    Fact,
    FunctionDecl,
    FunctionType,
    Layout,
    Match,
    Member,
    Named,
    Opaque,
    Pointer,
    Qualified,
    Reference,
    Toolchain,
    TypeDecl,
    dump_toolchain,
    load_catalog,
    load_toolchain,
)


def _toolchain(**overrides) -> Toolchain:
    data = dict(
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
        macros={"__GNUC__": "9", "__GLIBCXX__": "20190503"},
        probe_hash="probe-abc",
        license="GPL-3.0-or-later WITH GCC-exception-3.1",
        tier="validated",
    )
    data.update(overrides)
    return Toolchain(**data)


def test_type_algebra_keeps_qualifiers_and_pointee_separate():
    int_type = Builtin("int", 4, 4, "int")
    const_int = Qualified(int_type, const=True)
    pointer = Pointer(const_int, const=True)

    assert pointer.to.const is True
    assert pointer.const is True
    assert pointer != Pointer(int_type, const=True)
    assert Opaque(4, 4) != Opaque(8, 8)


def test_type_decl_layouts_are_per_environment():
    int_type = Builtin("int", 4, 4, "int")
    decl = TypeDecl(
        id="t:ACME::Aurora::Widget",
        kind="struct",
        name="Widget",
        members=(Member("value", int_type, offset=0),),
        layout={
            "env-gcc91": Layout(size=4, align=4),
            "env-msvc": Layout(size=8, align=8),
        },
    )

    assert decl.layout["env-gcc91"].size == 4
    assert decl.layout["env-msvc"].align == 8
    assert decl.members[0].offset == 0


def test_function_decl_keeps_linkage_and_signature():
    void = Builtin("void", 0, 1, "void")
    int_type = Builtin("int", 4, 4, "int")
    fn = FunctionDecl(
        id="f:ACME::Aurora::run",
        name="ACME::Aurora::run",
        linkage="_ZN4ACME6Aurora3runEi",
        signature=FunctionType(ret=void, params=(int_type,), cc="sysv64"),
        storage="extern",
        flags=frozenset({"noexcept"}),
    )

    assert fn.signature.params == (int_type,)
    assert fn.linkage.startswith("_Z")


def test_environment_id_is_content_addressed_and_flag_order_sensitive():
    first = Environment.create("tc-gcc91", "c++", ("-O2", "-fPIC"))
    same = Environment.create("tc-gcc91", "c++", ("-O2", "-fPIC"))
    reordered = Environment.create("tc-gcc91", "c++", ("-fPIC", "-O2"))

    assert first.id == same.id
    assert first.id != reordered.id
    assert first.id.startswith("env-")


def test_environment_defines_are_order_insensitive_but_includes_are_not():
    first = Environment.create("tc", "c", defines={"B": "2", "A": "1"})
    same = Environment.create("tc", "c", defines={"A": "1", "B": "2"})
    other_include = Environment.create("tc", "c", includes=("third_party",))

    assert first.id == same.id
    assert first.id != other_include.id


def test_environment_rejects_unknown_language_and_bad_confidence():
    with pytest.raises(ValueError, match="language"):
        Environment.create("tc", "rust")
    with pytest.raises(ValueError, match="confidence"):
        Environment.create("tc", "c", confidence=1.5)


def test_toolchain_validation_surfaces_descriptor_problems():
    assert _toolchain().validate() == ()
    assert "tier" in " ".join(_toolchain(tier="maybe").validate())
    assert "object_format" in " ".join(_toolchain(object_format="wasm").validate())
    assert "pinned image" in " ".join(_toolchain(image=None).validate())


def test_toolchain_descriptor_round_trip(tmp_path):
    original = _toolchain()
    path = tmp_path / "gcc.json"
    path.write_text(json.dumps(dump_toolchain(original)), encoding="utf-8")

    loaded = load_toolchain(path)
    assert loaded == original
    assert loaded.driver == ("g++-9",)
    assert loaded.macros["__GNUC__"] == "9"


def test_toolchain_catalog_rejects_duplicate_ids(tmp_path):
    data = json.dumps(dump_toolchain(_toolchain()))
    (tmp_path / "a.json").write_text(data, encoding="utf-8")
    (tmp_path / "b.json").write_text(data, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate toolchain id"):
        load_catalog(tmp_path)


def test_toolchain_descriptor_rejects_unknown_keys(tmp_path):
    data = dump_toolchain(_toolchain())
    data["compiler"] = "gcc"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown keys"):
        load_toolchain(path)


def test_match_requires_the_environment_and_hashes():
    match = Match(
        function="f:ACME::Aurora::run",
        source_hash="src-1",
        environment="env-1",
        header_hash="hdr-1",
        compiler="gcc 9.1.0",
        flags=("-O2", "-fPIC"),
    )
    assert match.environment == "env-1"

    with pytest.raises(ValueError, match="environment"):
        Match(function="f", source_hash="s", environment="", header_hash="h")


def test_reference_kinds_are_typed_dependencies_not_raw_xrefs():
    edge = Reference("f:caller", "t:ACME::Aurora::Widget", "member", "src/acme.cpp:42")
    assert edge.kind == "member"

    with pytest.raises(ValueError, match="reference kind"):
        Reference("a", "b", "probably")


def test_fact_keeps_provenance_and_confidence():
    fact = Fact(
        entity=Named("t:ACME::Aurora::Widget"),
        origin="dwarf",
        confidence=0.9,
        evidence=(Evidence("dwarf", "DW_TAG_structure_type"),),
    )
    assert fact.origin == "dwarf"
    assert fact.evidence[0].source == "dwarf"

    with pytest.raises(ValueError, match="confidence"):
        Fact(entity=Named("t:x"), origin="ida", confidence=-0.1)
