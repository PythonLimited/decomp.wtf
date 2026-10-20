"""Pure-Python PE seed inventory: pdata/imports/TLS/load-config replacement."""

from __future__ import annotations

import struct


def _pe_with_tables() -> bytes:
    image_base, pe_off, size_opt = 0x140000000, 0x80, 0xF0
    opt = pe_off + 24
    raw = bytearray(0xB00)
    raw[0:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, pe_off)
    raw[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, pe_off + 4, 0x8664, 1, 0, 0, 0, size_opt, 0x22)
    struct.pack_into("<H", raw, opt, 0x20B)
    struct.pack_into("<I", raw, opt + 16, 0x1000)
    struct.pack_into("<Q", raw, opt + 24, image_base)
    struct.pack_into("<I", raw, opt + 32, 0x1000)
    struct.pack_into("<I", raw, opt + 36, 0x200)
    struct.pack_into("<I", raw, opt + 56, 0x2000)
    struct.pack_into("<I", raw, opt + 60, 0x200)
    struct.pack_into("<H", raw, opt + 68, 3)
    struct.pack_into("<I", raw, opt + 108, 16)
    dd = opt + 112
    dirs = {
        0: (0x14C0, 40),       # exports
        1: (0x1400, 40),       # imports
        3: (0x1000, 36),       # .pdata: 3 entries
        9: (0x1480, 40),       # TLS
        10: (0x14A0, 0x100),   # load config
    }
    for index, (rva, size) in dirs.items():
        struct.pack_into("<II", raw, dd + index * 8, rva, size)
    struct.pack_into("<8sIIII", raw, opt + size_opt, b".rdata", 0x1000, 0x1000, 0x900, 0x200)
    struct.pack_into("<I", raw, opt + size_opt + 36, 0x40000040)

    # .pdata at RVA 0x1000 / file 0x200
    for i, (begin, end) in enumerate(((0x1100, 0x1140), (0x1120, 0x1160), (0x1300, 0x1340))):
        struct.pack_into("<III", raw, 0x200 + 12 * i, begin, end, 0x1200)

    # import descriptor at RVA 0x1400 / file 0x600
    struct.pack_into("<IIIII", raw, 0x600, 0x1460, 0, 0, 0x1450, 0x1460)
    raw[0x650:0x650 + 13] = b"KERNEL32.dll\0"
    struct.pack_into("<QQQ", raw, 0x660, 0x1470, 0x1478, 0)

    # TLS at RVA 0x1480 / file 0x680; callbacks at RVA 0x1520 / file 0x720
    struct.pack_into("<QQQQ", raw, 0x680, 0, 0, 0, image_base + 0x1520)
    struct.pack_into("<QQQ", raw, 0x720, image_base + 0x1500, image_base + 0x1510, 0)

    # load config at RVA 0x14A0 / file 0x6A0
    struct.pack_into("<I", raw, 0x6A0, 0x100)
    struct.pack_into("<Q", raw, 0x6A0 + 88, image_base + 0x14B0)
    struct.pack_into("<Q", raw, 0x6A0 + 112, image_base + 0x14B8)

    # export directory at RVA 0x14C0 / file 0x6C0
    struct.pack_into("<I", raw, 0x6C0 + 20, 3)
    return bytes(raw)


def test_pe_seed_tables_are_parsed():
    from dcore.targets.plat.pe import seeds

    info = seeds.parse(_pe_with_tables())
    assert info is not None
    assert [p[:2] for p in info["pdata"]] == [
        (0x140001100, 0x140001140),
        (0x140001120, 0x140001160),
        (0x140001300, 0x140001340),
    ]
    assert info["import_dlls"] == 1 and info["imports"] == 2
    assert info["exports"] == 3
    assert info["tls_callbacks"] == [0x140001500, 0x140001510]
    assert info["cfg_check"] == 0x1400014B8
    assert info["security_cookie"] == 0x1400014B0


def test_analyze_classifies_pdata_coverage():
    from dcore.core import analyze
    from dcore.targets.plat.pe import seeds

    data = _pe_with_tables()
    assert seeds.parse(b"not a PE") is None
    assert analyze.seeds({"format": "elf"}, [], data) is None

    info = analyze.seeds(
        {"format": "pe"},
        [{"ea": 0x140001100, "end": 0x140001150}],
        data,
    )
    assert info is not None
    assert info["pdata_count"] == 3
    assert info["pdata_covered"] == 1
    assert info["pdata_inside"] == 1  # 0x140001120 is inside the first function
    assert info["pdata_missing"] == [0x140001300]
    assert info["imports"] == 2 and info["exports"] == 3
