"""Judging a native candidate: the shipped function vs a freshly compiled one, objdiff-style.

Both sides are elfobj.FunctionObj. Relocations are compared by *position*; when the two
sides name a reference differently that is reported, not fatal — the community's objdiff
uses the same rule (`functionRelocDiffs=none`) because compilers spell section labels their
own way. What is never done is silently masking a reference one side has and the other
doesn't: that is a real difference and is surfaced in `problems`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import scoring
from .symbols import Reference, SymbolTable
from ..targets.objects import FunctionObj, Reloc


_MSVC_LITERAL_CODES = {
    "0": ",", "2": "\\", "3": ":", "4": ".", "5": " ",
    "AA": "\0", "CI": "(", "CJ": ")", "CF": "%", "DM": "<", "DN": "=", "DP": "?", "CB": "!",
}


def _msvc_literal(symbol: str) -> bytes | None:
    """Decode an MSVC string-literal symbol (`??_C@_0BE@hash@Memory?2OSMemory?4cpp?$AA@`).

    Only the codes seen in real literals are decoded; an unknown escape returns None so the
    judge never adopts a guess."""
    m = re.match(r"^\?\?_C@", symbol or "")
    if not m:
        return None
    parts = (symbol or "").split("@")
    if len(parts) < 3:
        return None
    enc = parts[-2] if parts[-1] == "" else parts[-1]
    out, i = bytearray(), 0
    while i < len(enc):
        ch = enc[i]
        if ch != "?":
            out += ch.encode("latin-1")
            i += 1
            continue
        if i + 1 >= len(enc):
            return None
        if enc[i + 1] == "$":
            code, i = enc[i + 2:i + 4], i + 4
        else:
            code, i = enc[i + 1], i + 2
        value = _MSVC_LITERAL_CODES.get(code)
        if value is None:
            return None
        out += value.encode("latin-1")
    return bytes(out)


@dataclass
class Verdict:
    match: bool
    diff: scoring.DiffResult
    renamed: list[tuple[str, str]] = field(default_factory=list)  # (original, yours)
    problems: list[str] = field(default_factory=list)
    link_layer: list[str] = field(default_factory=list)  # adopted TLS/symbol references, reported, not failures

    @property
    def score(self) -> int:
        return 0 if self.match else max(1, self.diff.score)


def compare(target: FunctionObj, candidate: FunctionObj, *, report_all_names: bool = False,
            tls_offsets: dict[str, int] | None = None, signature: str | None = None,
            symbols: SymbolTable | None = None, read_bytes=None) -> Verdict:
    """Byte-normalized, position-strict comparison of a reconstructed target and a compiled candidate.

    Relocation spelling (PLT32 vs PC32, section-label names, addends) is normalized away by
    adopting the candidate's view at every shared offset; the offset sets themselves must
    be identical, and the masked bytes must be identical.  Function-local branch targets are
    the exception: both sides get a synthetic ``@local:<offset>`` reference and the field is
    masked, so an object's local relocation cannot hide a wrong local destination.

    A compiled object cannot contain the linked TLS offset the binary has (`mov edx, 0xb0`): it
    carries a SECREL relocation to the TLS symbol instead. When the caller provides the binary's
    `tls_offsets` (symbol leaf -> offset), such a candidate relocation is adopted only if its
    symbol's offset equals the target's immediate at that field. A wrong TLS variable or offset
    still fails; this is link equivalence, not a fuzzy match."""
    target, candidate = _normalise_local_branches(target, candidate, symbols)
    t_offsets = sorted(r.offset for r in target.relocs)
    c_offsets = sorted(r.offset for r in candidate.relocs)
    c_at = {r.offset: r for r in candidate.relocs}
    t_at = {r.offset: r for r in target.relocs}
    renamed: list[tuple[str, str]] = []
    bad_refs: list[tuple[str, str]] = []
    data_hints: list[tuple[str, int]] = []
    normalized: list[Reloc] = []
    link_layer: list[str] = []
    accepted: set[int] = set()
    branch_fields = {b.field for b in scoring.branches(target) if b.width == 4}
    t_ins = None
    for r in target.relocs:
        c = c_at.get(r.offset)
        if c is None:
            normalized.append(r)
            continue
        # Synthetic local references carry the destination in the symbol.  Adopting the
        # candidate's symbol here would erase a wrong local branch; preserve the target's.
        if r.symbol.startswith("@local:") or c.symbol.startswith("@local:"):
            normalized.append(r)
            continue
        branch = r.offset in branch_fields
        t_ref = _target_reference(r, symbols, branch)
        c_ref = _candidate_reference(c, target, symbols, branch)
        if t_ref.kind == "section" and c_ref.kind in ("addr", "symbol") and not branch:
            if r.target_ea is not None:
                t_ref = Reference("addr", int(r.target_ea))
            elif (target.arch == "x86_64" and target.base_ea is not None
                  and r.offset + 4 <= len(target.code)):
                # The linked PE has no relocation name for this data ref, only `.data+0x...`.
                # Its rip-relative field still encodes the final address; compare that address
                # with the candidate's named global instead of requiring the section spelling.
                disp = int.from_bytes(target.code[r.offset:r.offset + 4], "little", signed=True)
                t_ref = Reference("addr", target.base_ea + r.offset + 4 + disp)
        same = _same_reference(t_ref, c_ref, r, c, branch)
        if (not same and read_bytes is not None and t_ref.kind == "addr"
                and c_ref.kind == "symbol" and str(c_ref.value).startswith("??_C@")):
            literal = _msvc_literal(str(c_ref.value))
            if literal:
                got = read_bytes(int(t_ref.value) + t_ref.offset, len(literal))
                if got == literal:
                    same = True
                    link_layer.append(f"string literal {c.symbol} at 0x{int(t_ref.value):x}")
        if (not same and not branch and r.target_ea is not None
                and _section_reference(r.symbol) is not None
                and symbols is not None and not symbols.data_by_name
                and c_ref.kind == "symbol"):
            # Migration fallback: the analysis has no data names yet (schema-2 sweep), so a
            # section alias and the object's named global cannot be resolved.  A re-sweep
            # turns this into the strict address comparison above.
            same = True
            link_layer.append(f"unresolved data name {c.symbol!r} at +0x{r.offset:x} (data sweep pending)")
        if not same:
            bad_refs.append((r.symbol, c.symbol))
            if not branch and c_ref.kind == "symbol" and t_ref.kind == "addr":
                data_hints.append((c.symbol, int(t_ref.value) + t_ref.offset))
            normalized.append(r)
            continue
        if r.symbol != c.symbol and (report_all_names or _meaningful(r.symbol) or _meaningful(c.symbol)):
            renamed.append((r.symbol, c.symbol))
        normalized.append(Reloc(r.offset, c.type, c.symbol, c.addend))
    for c in candidate.relocs:
        if c.offset in t_at or not tls_offsets or c.type not in (11, 12):
            continue  # not an extra TLS/SECREL reference
        leaf = scoring.symbol_leaf(c.symbol)
        off = tls_offsets.get(leaf) or tls_offsets.get(c.symbol)
        if off is None:
            continue
        field = target.code[c.offset:c.offset + 4]
        if len(field) == 4 and int.from_bytes(field, "little") == off:
            # the object's TLS relocation and the binary's linked offset name the same variable at
            # the same offset; adopt it as a shared reference (masked/symbolized on both sides)
            normalized.append(Reloc(c.offset, c.type, c.symbol, c.addend))
            accepted.add(c.offset)
            link_layer.append(f"TLS relocation {leaf}=0x{off:x} at +0x{c.offset:x}")
    # A recursive call in a linked binary has no relocation: the target view is based at offset 0,
    # so the self-call reads `call 0`. The object necessarily carries a reloc to the function's own
    # symbol there. Adopt it only when the target instruction is a call whose target is 0 and the
    # candidate names this same function; a call to anything else remains a real difference.
    for c in candidate.relocs:
        if c.offset in t_at or c.offset in accepted:
            continue
        # Compare against both spellings: the binary's stored name can be the demangled
        # signature while the object carries the mangled symbol.  symbol_leaf(target.name)
        # alone lands inside a parameter type when the signature contains "::".
        own = [n for n in (target.name, candidate.name) if n]
        by_name = c.symbol in own or any(
            scoring.symbol_leaf(c.symbol) == _function_leaf(n) for n in own)
        by_addr = (symbols is not None and target.base_ea is not None
                   and symbols.resolve_code(c.symbol) == target.base_ea)
        if not by_name and not by_addr:
            continue
        if t_ins is None:
            t_ins = scoring.disassemble(target)
        ins = next((i for i in reversed(t_ins) if i.offset <= c.offset), None)
        if ins is not None and ins.mnemonic.startswith("call") and ins.operands.strip() in ("0", "0x0"):
            normalized.append(Reloc(c.offset, c.type, c.symbol, c.addend))
            accepted.add(c.offset)
            link_layer.append(f"self-call {scoring.symbol_leaf(c.symbol)} at +0x{c.offset:x}")
    t2 = FunctionObj(target.name, target.arch, target.big_endian, target.code, normalized,
                     masks=target.masks, base_ea=target.base_ea)
    result = scoring.diff(t2, candidate, signature=signature)

    problems: list[str] = []
    missing_offsets = set(t_offsets) - set(c_offsets)
    extra_offsets = set(c_offsets) - set(t_offsets) - accepted
    if missing_offsets or extra_offsets:
        problems.append(f"references to other code and data differ: {len(missing_offsets)} the original has that "
                        f"your code doesn't, {len(extra_offsets)} yours has that the original doesn't")
    if bad_refs:
        problems.append(f"{len(bad_refs)} reference(s) point at different destinations")
    seen_hints = set()
    for symbol, ea in data_hints:
        if (symbol, ea) in seen_hints:
            continue
        seen_hints.add((symbol, ea))
        problems.append(f'unnamed data at 0x{ea:x} is {symbol}; '
                        f'call name_data("{symbol}", "0x{ea:x}") to bind it')
        if len(seen_hints) >= 4:
            break
    match = result.bytes_match and not missing_offsets and not extra_offsets and not bad_refs
    return Verdict(match=match, diff=result, renamed=renamed, problems=problems, link_layer=link_layer)


_LOCAL_TYPE = 0x1000  # synthetic relocation type: masks the 4-byte displacement, no linker meaning
_CODE_SECTION = re.compile(r"(?i)(?:^|[.\\/])(?:text|code)(?:$|[.$])")
_SECTION_OFFSET = re.compile(r"^(?P<section>.+)\+0x(?P<off>[0-9a-fA-F]+)$")


def _looks_code(section: str) -> bool:
    return bool(_CODE_SECTION.search(section or ""))


def _looks_section(name: str) -> bool:
    s = (name or "").strip()
    return s.startswith((".rdata", ".data", ".text", ".rodata", ".bss", ".tls",
                         ".gfids", "_RDATA")) or s in ("CODE", "DATA", "TEXT")


def _section_reference(name: str, addend: int = 0) -> Reference | None:
    s = (name or "").strip()
    m = _SECTION_OFFSET.match(s)
    if m and _looks_section(m.group("section")):
        return Reference("section", m.group("section"), int(m.group("off"), 16) + addend)
    if _looks_section(s):
        return Reference("section", s, addend)
    return None


def _canonical_import(name: str) -> str:
    s = (name or "").strip()
    if s.startswith("."):
        s = s[1:]
    if s.startswith("__imp_"):
        s = s[len("__imp_"):]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s


def _target_reference(r: Reloc, symbols: SymbolTable | None, branch: bool) -> Reference:
    if not branch:
        sec = _section_reference(r.symbol)
        if sec is not None:
            return sec
    imp = _canonical_import(r.symbol)
    if symbols is not None:
        resolved = symbols.resolve_import(imp)
        if resolved is not None:
            return Reference("import", resolved)
    if (r.symbol or "").startswith(".") and not _looks_section(r.symbol):
        return Reference("import", imp)
    if r.target_ea is not None:
        return Reference("addr", int(r.target_ea))
    if symbols is not None:
        addr = (symbols.resolve_code(r.symbol) if branch
                else (symbols.resolve_data(r.symbol) or symbols.resolve_code(r.symbol)))
        if addr is not None:
            return Reference("addr", addr)
    return Reference("symbol", (r.symbol or "").strip(), 0 if branch else r.addend)


def _candidate_reference(c: Reloc, target: FunctionObj, symbols: SymbolTable | None,
                         branch: bool) -> Reference:
    if not branch:
        # The reader bakes a section offset into the symbol (`.rdata+0x13f8`); its addend is
        # the instruction's PC bias, not a second offset.
        sec = _section_reference(c.symbol)
        if sec is not None:
            return sec
    imp = _canonical_import(c.symbol)
    if symbols is not None:
        resolved = symbols.resolve_import(imp)
        if resolved is not None:
            return Reference("import", resolved)
    if symbols is not None:
        if branch:
            addr = symbols.resolve_code(c.symbol)
            if addr is not None:
                return Reference("addr", addr)
        else:
            base = symbols.resolve_data(c.symbol)
            if base is None:
                base = symbols.resolve_code(c.symbol)
            if base is not None:
                # x86 PC-relative data addends carry the -4 instruction bias in the object;
                # the target side records the final address.  Keep the bias here, not in the
                # symbol spelling.
                bias = 4 if target.arch in ("x86_64", "x86") else 0
                return Reference("addr", base + c.addend + bias)
    return Reference("symbol", (c.symbol or "").strip(), 0 if branch else c.addend)


def _local_label(name: str) -> bool:
    s = (name or "").strip()
    return s.startswith((".L", ".l", "..", "$"))


def _same_reference(t_ref: Reference, c_ref: Reference, r: Reloc, c: Reloc,
                    branch: bool) -> bool:
    if t_ref.kind == "section" or c_ref.kind == "section":
        if t_ref.key() == c_ref.key():
            return True
        # A compiler-local label is a section-relative spelling, not a semantic name;
        # the old normalisation treated it as link-equivalent to the section alias.
        if t_ref.kind == "section" and c_ref.kind == "symbol" and _local_label(str(c_ref.value)):
            return True
        if c_ref.kind == "section" and t_ref.kind == "symbol" and _local_label(str(t_ref.value)):
            return True
        return False
    # Resolved destinations are authoritative.  Exact spellings are a fallback only when at
    # least one side is unresolved; otherwise a copied addend/symbol would hide a different
    # address.  A branch's addend is encoding bias; a data reference's is semantic.
    if t_ref.key() == c_ref.key():
        return True
    if (t_ref.kind == "symbol" or c_ref.kind == "symbol") and r.symbol and r.symbol == c.symbol:
        return True if branch else (r.addend == c.addend)
    return False


def _local_symbol_dest(reloc: Reloc, target: FunctionObj, want: int,
                       symbols: SymbolTable | None) -> int | None:
    """Where a candidate's local-symbol relocation points, relative to the function start.

    A COFF section-relative reference is spelled `.text+0xNN` by the reader.  A named
    symbol is resolved through the shared table; only a destination equal to the target's
    own function start (self) or to the local target is equivalent.
    """
    sym = (reloc.symbol or "").strip()
    m = _SECTION_OFFSET.match(sym)
    if m and _looks_code(m.group("section")):
        return int(m.group("off"), 16)
    if symbols is not None:
        addr = symbols.resolve_code(sym)
        if addr is not None and target.base_ea is not None:
            if addr == target.base_ea + want:
                return want
            if addr == target.base_ea:
                return 0
    return None


def _normalise_local_branches(target: FunctionObj, candidate: FunctionObj,
                              symbols: SymbolTable | None) -> tuple[FunctionObj, FunctionObj]:
    """Make direct branches to function-local labels comparable on both sides.

    The linked target has no relocation for a label inside its own body; the object reader
    can still emit one (a section-relative `.text+off` or a named local symbol).  Without
    this, the offset sets differ and an otherwise byte-identical function fails with
    "1 reference yours has that the original doesn't".

    The two sides get the same synthetic `@local:<relative destination>` relocation and the
    displacement field is masked.  A candidate destination that differs still produces a
    different canonical symbol, so a wrong local branch is not accepted.
    """
    target_branches = scoring.branches(target)
    if not target_branches:
        return target, candidate
    candidate_by_offset = {b.offset: b for b in scoring.branches(candidate)}
    t_relocs = list(target.relocs)
    c_relocs = list(candidate.relocs)
    changed = False
    for b in target_branches:
        if b.width != 4:  # short jumps have no linker relocation; leave their bytes alone
            continue
        if any(r.offset == b.field for r in target.relocs):
            continue  # already an external/self relocation
        if not (0 <= b.dest < len(target.code)):
            continue  # external; the reconstructor owns that reference
        if b.dest == 0:
            continue  # self-call: handled by the self-reference path
        if (symbols is not None and target.base_ea is not None
                and (target.base_ea + b.dest) in symbols.code_by_ea):
            continue  # a known function start inside IDA's size is external
        cb = candidate_by_offset.get(b.offset)
        if cb is None or cb.width != 4:
            continue
        raw = [r for r in candidate.relocs if r.offset == cb.field]
        c_dest = cb.dest
        if raw:
            resolved = _local_symbol_dest(raw[0], target, b.dest, symbols)
            if resolved is None:
                continue  # leave the raw relocation: the offset sets will report it
            c_dest = resolved
            c_relocs = [r for r in c_relocs if r.offset != cb.field]
        t_relocs.append(Reloc(b.field, _LOCAL_TYPE, f"@local:{b.dest:x}", 0))
        c_relocs.append(Reloc(cb.field, _LOCAL_TYPE, f"@local:{c_dest:x}", 0))
        changed = True
    if not changed:
        return target, candidate
    return (
        FunctionObj(target.name, target.arch, target.big_endian, target.code, t_relocs,
                    masks=target.masks, base_ea=target.base_ea),
        FunctionObj(candidate.name, candidate.arch, candidate.big_endian, candidate.code,
                    c_relocs, masks=candidate.masks, base_ea=candidate.base_ea),
    )


def _function_leaf(name: str) -> str:
    """The function name's leaf, dropping a demangled signature's parameter list first.
    A signature like `Ns::String::ExtractMatch(DynamicArray<...> &, ...)` contains `::` in
    its parameters; taking the last `::` would land inside a parameter type, not the name."""
    s = (name or "").strip()
    if "(" in s:
        s = s.split("(", 1)[0].rstrip()
    return scoring.symbol_leaf(s) if s else ""


def _meaningful(name: str) -> bool:
    """Names worth showing when they change: not compiler-generated labels and not sections."""
    if not name:
        return False
    if name.startswith((".L", "@", "$", "..", ".rodata", ".data", ".text", "data_", "sub_")):
        return False
    return True
