"""The modular core: the target matrix, the packs that answer for a platform or an ISA,
and the import dispatcher that asks them instead of knowing formats itself."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from dcore import targets
from dcore.targets import arch_pack, formats, plat_pack, resolve


def test_the_matrix_declares_the_worlds_this_build_knows():
    assert targets.MATRIX["elf"] == ("x86", "x86_64", "aarch64")
    assert resolve("windows", "amd64").plat == "pe"          # aliases answer
    assert str(resolve("android", "arm64")) == "android × aarch64"
    with pytest.raises(LookupError, match="no platform pack"):
        resolve("switch", "aarch64")
    with pytest.raises(LookupError, match="no x86 variant"):
        resolve("macho", "x86")  # macOS never shipped 32-bit Mach-O in this build's matrix


def test_packs_answer_what_a_platform_and_an_isa_are():
    assert plat_pack("elf").key == "elf"
    android = plat_pack("android")
    assert android.key == "android" and android.family == "elf"   # a skin, not a fork
    assert isinstance(android, type(plat_pack("elf")))
    assert arch_pack("x86_64").ready is True
    assert arch_pack("x86").ready is False and arch_pack("aarch64").ready is False
    md = arch_pack("x86_64").disassembler()
    assert md is not None and md.detail


def test_the_dispatcher_asks_the_packs():
    elf_head = b"\x7fELF" + bytes(12) + struct.pack("<HH", 2, 0x3E) + bytes(200)
    assert formats.looks_native(elf_head) == ("elf", "x86_64")
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x84, 0x8664)
    assert formats.looks_native(bytes(pe)) == ("pe", "x86_64")
    assert formats.identify(bytes(pe)[:0x50]) is None  # magic alone isn't a whole image — and no crash
    assert formats.looks_native(b"RIFF....") is None


def test_the_elf_pack_spells_names_the_object_sides_way():
    elf = plat_pack("elf")
    assert elf.section_alias(".rodata.str1.1") == ".rodata"
    assert elf.section_alias(".text.unlikely") == "unlikely"
    assert elf.section_alias(".data") == ".data"
    assert elf.import_base("printf@@GLIBC_2.2.5") == "printf"
    assert elf.reloc_type("x86_64", "pc") == 2  # R_X86_64_PC32
    assert elf.reloc_type("x86", "pc") == 2  # R_386_PC32


def test_a_32_bit_pe_parses_too():
    """PE32 and PE32+ differ in the optional header's shape; a 32-bit Windows exe must import."""
    import struct

    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", pe, 0x84, 0x14C, 1)  # i386, one section
    struct.pack_into("<H", pe, 0x94, 96)  # size of the PE32 optional header
    struct.pack_into("<H", pe, 0x96, 0x0102)  # executable, 32-bit
    opt = 0x98
    struct.pack_into("<H", pe, opt, 0x10B)  # PE32 magic
    struct.pack_into("<I", pe, opt + 16, 0x1000)  # entry RVA
    struct.pack_into("<I", pe, opt + 28, 0x400000)  # u32 image base
    so = opt + 96
    pe[so:so + 8] = b".text".ljust(8, b"\0")
    struct.pack_into("<IIII", pe, so + 8, 0x200, 0x1000, 0x200, 0x200)  # vsize, vaddr, raw size, raw ptr
    struct.pack_into("<I", pe, so + 36, 0x60000020)  # code | execute | read
    image = formats.identify(bytes(pe))
    assert image is not None and image.format == "pe" and image.arch == "x86" and image.bits == 32
    assert image.image_base == 0x400000 and image.entry == 0x401000 and image.kind == "exe"
    assert [s.name for s in image.sections] == [".text"]


@pytest.mark.skipif(sys.platform != "darwin", reason="a real Mach-O to chew on needs macOS")
def test_a_real_macos_binary_parses_as_macho():
    image = formats.identify_path("/bin/ls")
    assert image.format == "macho" and image.arch in ("x86_64", "aarch64")
    assert image.kind in ("exe", "pie")
    assert any(s.kind == "code" for s in image.sections)
    assert image.image_base  # __TEXT vmaddr


@pytest.mark.skipif(sys.platform != "darwin", reason="wraps a real slice")
def test_a_universal_binary_picks_its_first_supported_slice():
    slice_bytes = Path("/bin/ls").read_bytes()
    fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, 28, len(slice_bytes), 0)
    image = formats.identify(fat + slice_bytes)
    assert image is not None and image.format == "macho"
    assert "universal" in " ".join(image.notes)
