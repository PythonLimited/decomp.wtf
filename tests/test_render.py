from __future__ import annotations

import pytest

from dcore.model import (
    Base,
    Builtin,
    Fact,
    FunctionDecl,
    FunctionType,
    GlobalDecl,
    Layout,
    Member,
    Method,
    Named,
    Opaque,
    Pointer,
    Qualified,
    ReferenceType,
    RenderError,
    Scope,
    TypeDecl,
    render_layout_probes,
    render_prelude,
)

INT = Builtin("int", 4, 4, "int")
VOID = Builtin("void", 0, 1, "void")


def _facts():
    scope = Scope("s:ACME::Aurora", "namespace", "Aurora", "s:ACME")
    scope_acme = Scope("s:ACME", "namespace", "ACME", None)
    base = TypeDecl(
        id="t:ACME::Aurora::Base", kind="struct", name="Base",
        scope="s:ACME::Aurora",
        members=(Member("id", INT, offset=0),),
        layout={"@binary": Layout(8, 8)},
        origin="dwarf",
    )
    widget = TypeDecl(
        id="t:ACME::Aurora::Widget", kind="class", name="Widget",
        scope="s:ACME::Aurora",
        bases=(Base(Named("t:ACME::Aurora::Base")),),
        members=(
            Member("value", INT, offset=0),
            Member("next", Pointer(Named("t:ACME::Aurora::Widget")), offset=8),
        ),
        methods=(
            Method("get", FunctionType(INT, ()), const=True),
        ),
        layout={"@binary": Layout(16, 8)},
        origin="dwarf",
    )
    add = FunctionDecl(
        id="f:add", name="ACME::Aurora::add",
        signature=FunctionType(INT, (INT, INT)),
        linkage="_ZN4ACME6Aurora3addEii",
    )
    counter = GlobalDecl(id="g:counter", name="g_counter", type=INT)
    return [
        Fact(scope_acme, "analysis"), Fact(scope, "analysis"),
        Fact(base, "dwarf"), Fact(widget, "dwarf"),
        Fact(add, "dwarf"), Fact(counter, "dwarf"),
    ]


def test_prelude_has_one_definition_per_type_in_dependency_order():
    text = render_prelude(_facts(), include_functions=False)
    assert "namespace ACME {" in text
    assert "namespace Aurora {" in text
    assert "struct Base;" in text
    assert "class Widget;" in text
    assert text.index("struct Base {") < text.index("class Widget :")
    assert "class Widget : public ACME::Aurora::Base {" in text
    assert "int value;" in text
    assert "ACME::Aurora::Widget *next;" in text
    assert "int get() const;" in text
    assert "int ACME::Aurora::add" not in text


def test_prelude_renders_function_prototypes_in_their_namespace_when_requested():
    text = render_prelude(_facts())
    assert "int add(int, int);" in text
    assert "extern int g_counter;" in text
    assert "int ACME::Aurora::add" not in text


def test_layout_probes_use_the_observed_binary_layout():
    text = render_layout_probes(_facts(), environment="@binary")
    assert 'static_assert(sizeof(::ACME::Aurora::Base) == 8, "Base size");' in text
    assert 'static_assert(offsetof(::ACME::Aurora::Widget, value) == 0, "Widget::value");' in text
    assert 'static_assert(offsetof(::ACME::Aurora::Widget, next) == 8, "Widget::next");' in text


def test_unresolved_opaque_type_is_a_render_error_not_a_guess():
    decl = TypeDecl(id="t:Unknown", kind="struct", name="Unknown",
                    members=(Member("raw", Opaque(0, 1), offset=0),))
    with pytest.raises(RenderError, match="opaque"):
        render_prelude([Fact(decl, "ida")])


def test_qualified_pointer_and_reference_declarators():
    assert render_prelude([Fact(TypeDecl(
        id="t:ACME::Aurora::Holder", kind="struct", name="Holder",
        members=(
            Member("text", Pointer(Qualified(Builtin("char", 1, 1, "int"), const=True), const=True), offset=0),
            Member("ref", ReferenceType(Named("t:ACME::Aurora::Base")), offset=8),
        ),
    ), "dwarf")], include_functions=False).count("const char * const text;") == 1
