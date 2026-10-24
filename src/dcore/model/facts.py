"""Facts, typed references and environment-pinned matches.

A provider emits facts; the resolver merges them; the registry consumes the
result. A reference is a *semantic* edge, not a raw xref: a non-inline call
depends on the callee's signature/ABI, while an inline call depends on its body
and everything that body uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias

from .environment import Evidence
from .types import Entity, TypeRef

FactEntity: TypeAlias = Entity | TypeRef


@dataclass(frozen=True, slots=True)
class Fact:
    """One provider's claim about an entity."""

    entity: FactEntity
    origin: str  # dwarf | pdb | ida | ghidra | clang | inferred | agent
    confidence: float = 1.0
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.origin:
            raise ValueError("fact origin is empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"fact confidence {self.confidence!r} is outside [0, 1]")


REFERENCE_KINDS = (
    "call",
    "read",
    "write",
    "address",
    "base",
    "member",
    "type_use",
    "instantiate",
    "vtable_slot",
    "include",
)


@dataclass(frozen=True, slots=True)
class Reference:
    """A typed dependency edge between entities."""

    src: str
    dst: str
    kind: str
    location: str | None = None

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise ValueError("reference needs a source and a destination")
        if self.kind not in REFERENCE_KINDS:
            raise ValueError(f"reference kind {self.kind!r} is not one of {REFERENCE_KINDS}")


@dataclass(frozen=True, slots=True)
class Match:
    """A byte-exact match under a pinned environment.

    Changing the registry does not rewrite this record. A newer revision may mark
    it stale, but the environment/source/header hashes remain the evidence of what
    was actually verified.
    """

    function: str
    source_hash: str
    environment: str
    header_hash: str
    deps_hash: str = ""
    compiler: str = ""
    flags: tuple[str, ...] = ()
    alternate_environments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("function", "source_hash", "environment", "header_hash"):
            if not getattr(self, name):
                raise ValueError(f"match {name} is empty")
