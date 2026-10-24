from __future__ import annotations

from dcore.model import (
    Array,
    Builtin,
    FunctionDecl,
    GlobalDecl,
    Named,
    Pointer,
    Qualified,
    ReferenceType,
    Scope,
    TemplateInstance,
    TypeDecl,
)
from dcore.providers import BINARY_LAYOUT, from_analysis, parse_type, sizes_for


def test_provider_type_parser_keeps_declarator_precedence():
    char = parse_type("char")
    assert parse_type("const char *") == Pointer(Qualified(char, const=True))
    assert parse_type("char * const") == Pointer(char, const=True)
    assert parse_type("char **") == Pointer(Pointer(char))
    assert parse_type("int[4]") == Array(Builtin("int", 4, 4, "int"), 4)
    assert parse_type("int *[4]") == Array(Pointer(Builtin("int", 4, 4, "int")), 4)
    assert parse_type("ACME::Aurora::Widget &") == ReferenceType(Named("t:ACME::Aurora::Widget"))


def test_provider_type_parser_supports_templates_and_function_pointers():
    vector = parse_type("std::vector<int>")
    assert isinstance(vector, TemplateInstance)
    assert vector.template == "t:std::vector"
    assert vector.args == (Builtin("int", 4, 4, "int"),)

    fp = parse_type("void (*)(int, int)")
    assert isinstance(fp, Pointer)
    assert fp.to.params == (Builtin("int", 4, 4, "int"), Builtin("int", 4, 4, "int"))


def test_provider_type_sizes_follow_the_target_abi():
    assert parse_type("long", sizes_for("elf", "x86_64")).size == 8
    assert parse_type("long", sizes_for("pe", "x86_64")).size == 4
    assert parse_type("size_t", sizes_for("pe", "x86_64")).size == 8
    assert parse_type("wchar_t", sizes_for("pe", "x86_64")).size == 2


def _analysis() -> dict:
    return {
        "format": "elf",
        "arch": "x86_64",
        "dwarf_units": 1,
        "types": [
            {
                "name": "Base", "ns": ["ACME", "Aurora"], "size": 8, "align": 8,
                "kind": "struct", "members": [{"name": "id", "off": 0, "type": "int"}],
                "statics": [], "methods": [],
            },
            {
                "name": "Widget", "ns": ["ACME", "Aurora"], "size": 16, "align": 8,
                "kind": "class",
                "bases": [{"name": "Base", "type": "ACME::Aurora::Base", "virtual": False}],
                "members": [
                    {"name": "value", "off": 0, "type": "int"},
                    {"name": "next", "off": 8, "type": "ACME::Aurora::Widget *"},
                    {"name": "base", "off": 12, "type": "ACME::Aurora::Base *"},
                ],
                "statics": [{"name": "count", "type": "int"}],
                "methods": [
                    {"name": "get", "ret": "int", "params": [], "const": True,
                     "static": False, "virtual": False},
                    {"name": "set", "ret": "void", "params": ["int"], "const": False,
                     "static": False, "virtual": False},
                ],
            },
        ],
        "functions": [
            {
                "ea": 0x1000, "name": "ACME::Aurora::Widget::get",
                "display": "ACME::Aurora::Widget::get()",
                "signature": "int ()",
                "linkage": "_ZNK4ACME6Aurora6Widget3getEv",
                "cu": "src/acme.cpp", "language": "c++", "provenance": "dwarf",
            },
            {
                "ea": 0x2000, "name": "ACME::Aurora::free",
                "display": "ACME::Aurora::free(ACME::Aurora::Widget &)",
                "signature": "void (ACME::Aurora::Widget &)",
                "linkage": "_ZN4ACME6Aurora4freeERNS0_6WidgetE",
                "cu": "src/acme.cpp", "language": "c++", "provenance": "dwarf",
            },
        ],
        "data": [{"ea": 0x3000, "name": "g_counter", "type": "int"}],
        "edges": [{"ea": 0x2000, "to": [0x1000]}],
    }


def test_analysis_adapter_builds_typed_entities_not_provider_text():
    facts = from_analysis(_analysis())
    by_id = {f.entity.id: f.entity for f in facts.facts}

    widget = by_id["t:ACME::Aurora::Widget"]
    assert isinstance(widget, TypeDecl)
    assert widget.kind == "class"
    assert widget.scope == "s:ACME::Aurora"
    assert widget.layout[BINARY_LAYOUT].size == 16
    assert widget.layout[BINARY_LAYOUT].align == 8
    assert widget.members[1].type == Pointer(Named("t:ACME::Aurora::Widget"))
    assert widget.members[2].offset == 12
    assert widget.bases[0].type == Named("t:ACME::Aurora::Base")
    assert widget.methods[0].name == "get" and widget.methods[0].const is True
    assert widget.methods[0].signature.ret == Builtin("int", 4, 4, "int")
    assert widget.methods[1].signature.params == (Builtin("int", 4, 4, "int"),)
    assert any(m.static for m in widget.members if m.name == "count")

    get = by_id["f:0x1000"]
    assert isinstance(get, FunctionDecl)
    assert get.owner == "t:ACME::Aurora::Widget"
    assert get.signature.ret == Builtin("int", 4, 4, "int")
    assert get.linkage == "_ZNK4ACME6Aurora6Widget3getEv"

    free = by_id["f:0x2000"]
    assert isinstance(free, FunctionDecl)
    assert free.signature.params == (ReferenceType(Named("t:ACME::Aurora::Widget")),)
    assert free.owner is None

    counter = by_id["g:0x3000"]
    assert isinstance(counter, GlobalDecl)
    assert counter.type == Builtin("int", 4, 4, "int")

    assert isinstance(by_id["s:ACME::Aurora"], Scope)
    assert facts.function_ids[0x1000] == "f:0x1000"
    assert facts.type_ids["ACME::Aurora::Widget"] == "t:ACME::Aurora::Widget"
    assert facts.global_ids[0x3000] == "g:0x3000"


def test_analysis_adapter_emits_typed_reference_edges():
    facts = from_analysis(_analysis())
    edges = {(e.src, e.dst, e.kind) for e in facts.references}

    assert ("f:0x2000", "f:0x1000", "call") in edges
    assert ("t:ACME::Aurora::Widget", "t:ACME::Aurora::Base", "base") in edges
    assert ("t:ACME::Aurora::Widget", "t:ACME::Aurora::Widget", "member") not in edges
    assert ("t:ACME::Aurora::Widget", "t:ACME::Aurora::Base", "member") in edges
    assert ("f:0x2000", "t:ACME::Aurora::Widget", "type_use") in edges


def test_analysis_adapter_keeps_provenance_and_unknown_globals_visible():
    analysis = _analysis()
    analysis["data"].append({"ea": 0x3004, "name": "g_unknown", "type": ""})
    facts = from_analysis(analysis)
    by_id = {f.entity.id: (f, f.entity) for f in facts.facts}

    widget_fact, _ = by_id["t:ACME::Aurora::Widget"]
    get_fact, _ = by_id["f:0x1000"]
    counter_fact, counter = by_id["g:0x3000"]
    unknown_fact, unknown = by_id["g:0x3004"]

    assert widget_fact.origin == "dwarf"
    assert get_fact.origin == "dwarf"
    assert counter_fact.origin == "ida"
    assert counter.type == Builtin("int", 4, 4, "int")
    assert unknown_fact.confidence < 1.0
    assert unknown.type.size == 0  # Opaque(0, 1): unresolved, not guessed
