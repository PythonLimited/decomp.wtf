from __future__ import annotations

import pytest

from dcore.model import (
    Base,
    Builtin,
    Fact,
    FunctionDecl,
    FunctionType,
    GlobalDecl,
    Member,
    Method,
    Named,
    Pointer,
    Reference,
    RenderError,
    Scope,
    TypeDecl,
    render_header,
    render_prelude,
)

INT = Builtin("int", 4, 4, "int")
UINT = Builtin("unsigned int", 4, 4, "int")
VOID = Builtin("void", 0, 1, "void")


def _facts():
    acme = Scope("s:ACME", "namespace", "ACME", None)
    aurora = Scope("s:ACME::Aurora", "namespace", "Aurora", "s:ACME")
    base = TypeDecl(
        id="t:ACME::Aurora::Base", kind="struct", name="Base",
        scope="s:ACME::Aurora", members=(Member("id", INT, offset=0),),
    )
    widget = TypeDecl(
        id="t:ACME::Aurora::Widget", kind="class", name="Widget",
        scope="s:ACME::Aurora", bases=(Base(Named("t:ACME::Aurora::Base")),),
        members=(Member("value", INT, offset=0),
                 Member("next", Pointer(Named("t:ACME::Aurora::Widget")), offset=8)),
        methods=(Method("get", FunctionType(INT, ()), const=True),),
    )
    flags = TypeDecl(
        id="t:ACME::Aurora::Flags", kind="struct", name="Flags",
        scope="s:ACME::Aurora",
        members=(Member("low", UINT, offset=0, bit_width=3),),
    )
    functions = (
        FunctionDecl("f:add", "ACME::Aurora::add", FunctionType(INT, (INT, INT))),
        FunctionDecl("f:get", "ACME::Aurora::Widget::get", FunctionType(INT, ()),
                     owner="t:ACME::Aurora::Widget"),
        FunctionDecl("f:flags", "ACME::Aurora::flags",
                     FunctionType(UINT, (Pointer(Named("t:ACME::Aurora::Flags")),))),
        FunctionDecl("f:body", "ACME::Aurora::body", FunctionType(VOID, ())),
        FunctionDecl("f:caller", "ACME::Aurora::caller", FunctionType(VOID, ())),
    )
    return [Fact(acme, "analysis"), Fact(aurora, "analysis"),
            Fact(base, "dwarf"), Fact(widget, "dwarf"), Fact(flags, "dwarf"),
            *[Fact(fn, "dwarf") for fn in functions]]


def test_header_for_leaf_function_does_not_pull_types():
    text = render_header(_facts(), "f:add")
    assert "int add(int, int);" in text
    assert "Widget" not in text
    assert "Flags" not in text


def test_header_for_method_includes_owner_and_base_but_not_unrelated_types():
    text = render_header(_facts(), "f:get")
    assert "class Widget : public ACME::Aurora::Base" in text
    assert "struct Base {" in text
    assert "int get() const;" in text
    assert "Flags" not in text


def test_header_for_parameter_type_includes_that_type_only():
    text = render_header(_facts(), "f:flags")
    assert "struct Flags {" in text
    assert "unsigned int low : 3;" in text
    assert "class Widget" not in text


def test_body_only_dependency_can_be_supplied_explicitly():
    text = render_header(_facts(), "f:body",
                         required=("t:ACME::Aurora::Widget",))
    assert "class Widget" in text
    assert "struct Base {" in text


def test_call_reference_pulls_callee_prototype():
    refs = (Reference("f:caller", "f:add", "call"),)
    text = render_header(_facts(), "f:caller", references=refs)
    assert "int add(int, int);" in text
    assert "class Widget" not in text


def test_header_is_a_subset_of_the_prelude():
    facts = _facts()
    full = render_prelude(facts, include_functions=False)
    header = render_header(facts, "f:flags", include_functions=False)
    assert len(header) < len(full)
    assert "struct Flags" in header
    assert "class Widget" not in header


def test_unknown_function_is_rejected():
    with pytest.raises(RenderError, match="unknown function"):
        render_header(_facts(), "f:missing")
