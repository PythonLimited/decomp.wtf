"""The arch pack protocol: everything ISA-shaped, and nothing else.

An arch pack answers one question the judge cannot avoid — *which operands inside a
function's bytes are references, and to what* — because the target side of a match is a
loaded image whose relocations were resolved by the linker and must be rebuilt from the
instructions. It also declares how those relocations are spelled in each object format,
via :class:`RelocKind` values the platform pack maps onto its container's entries.

A pack that cannot rebuild relocations yet (``x86`` today) says so honestly instead of
guessing: ``reconstruct`` returns ``[]`` and :attr:`ArchPack.ready` is False, so the plan
can refuse the target up front rather than judging garbage.
"""

from __future__ import annotations

from dataclasses import dataclass

import capstone


@dataclass(frozen=True)
class RelocKind:
    """One kind of reference a compiler emits, in ISA terms — not container terms.

    ``rel_width`` is the size of the *field* the compiler rewrites (4 for a rip-relative
    disp32 or a call rel32, 8 for a movabs/ADRP pair's absolute part); ``pc_bias`` is what
    the linker adds relative to the field's own address (-4 for x86 call/jmp/rip forms).
    Platform packs translate these into R_X86_64_PC32 / IMAGE_REL_AMD64_REL32 / …
    """

    name: str
    rel_width: int
    pc_bias: int
    kind: str  # "pc" | "abs" | "branch"


class ArchPack:
    """Base class for ``targets/arch/<arch>.py`` modules (each exposes a module-level PACK)."""

    key = ""
    ready = False  # True once reconstruct() really produces relocations for this ISA

    def supports(self) -> bool:  # pragma: no cover - trivial
        return True

    def disassembler(self) -> capstone.Cs | None:
        """A configured capstone engine for this ISA, or None when capstone can't (yet)."""
        return None

    def reconstruct(self, reco, code: bytes, ea: int) -> list:
        """Relocations a compiler would have emitted for ``code`` at address ``ea``.

        ``reco`` is the core's :class:`dcore.core.target.Reconstructor`, which resolves an
        operand target to the name the *object side* would use (``function_name`` /
        ``data_name``); the pack only decides which operands count.
        """
        return []

    def reloc_kinds(self) -> dict[str, RelocKind]:
        """This ISA's reference kinds, by name — the platform pack maps them per container."""
        return {}
