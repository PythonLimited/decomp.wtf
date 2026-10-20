"""ELF parsing (executables, PIEs, shared libraries, relocatables) via pyelftools."""

from __future__ import annotations

from io import BytesIO

from elftools.elf.elffile import ELFFile

from ...image import NativeImage, Section, compiler_from_comment

ELF_MACHINES = {"EM_X86_64": "x86_64", "EM_AARCH64": "aarch64", "EM_386": "x86"}
ELF_MACHINE_IDS = {0x3E: "x86_64", 0xB7: "aarch64", 0x03: "x86"}


def sniff(head: bytes) -> str | None:
    """The arch this ELF header names, from the first bytes alone."""
    if head[:4] != b"\x7fELF" or len(head) < 20:
        return None
    return ELF_MACHINE_IDS.get(int.from_bytes(head[18:20], "little"))


def parse(data: bytes) -> NativeImage | None:
    return parse_python(data)


def parse_python(data: bytes) -> NativeImage | None:
    """The pyelftools parser."""
    if data[:4] != b"\x7fELF":
        return None
    try:
        elf = ELFFile(BytesIO(data))
    except Exception:
        return None
    machine = elf["e_machine"]
    if machine not in ELF_MACHINES:
        return None
    kind = {"ET_EXEC": "exe", "ET_DYN": "pie", "ET_REL": "object"}.get(elf["e_type"])
    if kind is None:
        return None
    base = None
    interp = False
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_INTERP":
            interp = True
        elif seg["p_type"] == "PT_LOAD":
            v = seg["p_vaddr"]
            base = v if base is None or v < base else base
    if kind == "pie" and not interp:
        kind = "shared"  # ET_DYN without an interpreter: a shared library
    if kind == "object":
        base = 0
    sections: list[Section] = []
    has_debug = False
    has_symtab = False
    comment = b""
    for sec in elf.iter_sections():
        name = sec.name
        flags = sec["sh_flags"]
        if name == ".symtab":
            has_symtab = True
        elif name == ".comment":
            comment = sec.data() or b""
        elif name in (".debug_info", ".zdebug_info"):
            has_debug = True
        if not flags & 0x2 or sec["sh_size"] == 0:  # SHF_ALLOC only: what exists at runtime
            continue
        if flags & 0x4:
            sk = "code"
        elif sec["sh_type"] == "SHT_NOBITS":
            sk = "bss"
        elif flags & 0x1:
            sk = "data"
        else:
            sk = "rodata"
        sections.append(Section(name, sec["sh_addr"], sec["sh_size"], sec["sh_offset"], sk))
    notes = []
    if kind in ("exe", "pie", "shared") and not has_symtab:
        notes.append("stripped (no .symtab)")
    return NativeImage("elf", ELF_MACHINES[machine], elf.elfclass, kind, base or 0,
                       elf["e_entry"] if kind != "object" else 0, sections, has_debug,
                       "dwarf" if has_debug else "", None, compiler_from_comment(comment), notes)
