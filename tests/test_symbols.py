from dcore.core.symbols import Reference, SymbolTable


MANGLED = "?ExtractMatch@String@Base@Obsidian@ACME@@SA_NAEAV?$DynamicArray@VString@Base@Obsidian@ACME@@$01$0BA@@Std@34@PEBD11@Z"
DISPLAY = ("ACME::Obsidian::Base::String::ExtractMatch("
           "ACME::Obsidian::Std::DynamicArray<ACME::Obsidian::Base::String,2,16> &,"
           "char const *,char const *,char const *)")


def _analysis():
    return {
        "functions": [
            {"ea": 0x140001000, "name": MANGLED, "display": DISPLAY, "linkage": MANGLED},
            {"ea": 0x140002000, "name": "sub_140002000", "display": "sub_140002000"},
        ],
        "data": [{"ea": 0x140003000, "name": "i_pString"}],
        "imports": [{"ea": 0x140004000, "name": ".printf"}],
    }


def test_symbols_resolve_mangled_demangled_and_synthetic_names():
    table = SymbolTable.from_analysis(_analysis())
    assert table.resolve_code(MANGLED) == 0x140001000
    assert table.resolve_code(DISPLAY) == 0x140001000
    assert table.resolve_code("sub_140002000") == 0x140002000
    assert table.resolve_code("sub_140009999") is None
    assert table.resolve_data("i_pString") == 0x140003000
    assert table.resolve_data("data_140003000") == 0x140003000
    assert table.resolve_data("?i_pString@@3QBDB") == 0x140003000


def test_symbols_canonicalise_import_spellings_and_sections():
    table = SymbolTable.from_analysis(_analysis())
    assert table.resolve_import(".printf") == "printf"
    assert table.resolve_import("__imp_printf") == "printf"
    assert table.resolve_import("printf@8") == "printf"
    assert table.reference("__imp_printf") == Reference("import", "printf")
    assert table.reference(".rdata+0x4") == Reference("section", ".rdata", 4)


def test_symbols_prefer_an_explicit_target_address_and_aliases():
    table = SymbolTable.from_analysis(_analysis(), aliases={"my_fn": 0x140002000})
    assert table.resolve_code("my_fn") == 0x140002000
    assert table.reference("i_pString", target_ea=0x140003010) == Reference("addr", 0x140003010)
    assert table.reference("my_fn").kind == "addr"
    assert table.reference("unknown_name") == Reference("symbol", "unknown_name", 0)


def test_symbols_know_the_msvc_stack_probe_aliases():
    """IDA/FLIRT calls the x64 stack probe `_alloca_probe`; MSVC emits `__chkstk`. The same
    routine must resolve to the analysis address, or identical prologues fail the judge."""
    analysis = {"functions": [{"ea": 0x143036F20, "name": "_alloca_probe",
                               "display": "_alloca_probe"}], "data": [], "imports": []}
    table = SymbolTable.from_analysis(analysis)
    assert table.resolve_code("__chkstk") == 0x143036F20
    assert table.resolve_code("___chkstk_ms") == 0x143036F20
    assert table.reference("__chkstk") == Reference("addr", 0x143036F20)


def test_msvc_member_access_does_not_change_identity():
    """The binary's STL says protected `IEAA`, the rebuilt header says public `QEAA`; the
    mangled names differ only in the access letter, and the code is the same function."""
    protected = "?_Reallocate@?$vector@PEBDV?$allocator@PEBD@std@@@std@@IEAAX_K@Z"
    public = "?_Reallocate@?$vector@PEBDV?$allocator@PEBD@std@@@std@@QEAAX_K@Z"
    other = "?_Reallocate@?$vector@PEBDV?$allocator@PEBD@std@@@std@@QEAAX_J@Z"
    table = SymbolTable.from_analysis({
        "functions": [{"ea": 0x1414C24C0, "name": protected, "linkage": protected,
                       "display": "std::vector<char const *>::_Reallocate(unsigned __int64)"}],
        "data": [], "imports": [],
    })
    assert table.resolve_code(public) == 0x1414C24C0
    assert table.resolve_code(other) is None


def test_a_data_global_is_its_qualified_name_not_its_pointer_type():
    """The analysis records `IMemoryAllocator *memoryAllocator_`; the rebuilt header spells
    `void *memoryAllocator_`. Both mangled names share the qualified global name."""
    target = "?memoryAllocator_@Memory@Core@Aurora@ACME@@3PEAVIMemoryAllocator@1234@EA"
    candidate = "?memoryAllocator_@Memory@Core@Aurora@ACME@@3PEAXEA"
    table = SymbolTable.from_analysis({
        "functions": [],
        "data": [{"ea": 0x1460A5AF8, "name": target}],
        "imports": [],
    })
    assert table.resolve_data(candidate) == 0x1460A5AF8


def test_a_data_alias_names_an_unnamed_address():
    table = SymbolTable.from_analysis({}, data_aliases={"counter": 0x145F85428})
    assert table.resolve_data("counter") == 0x145F85428
