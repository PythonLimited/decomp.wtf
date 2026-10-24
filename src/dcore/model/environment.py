"""First-class toolchain and compile-environment records.

The key distinction:

* ``Toolchain`` is an exact compiler build. "gcc" is not a toolchain; a specific
  build/version/target/ABI/image is.
* ``Environment`` is a toolchain plus the effective compile inputs (language,
  flags, defines, includes). It is what a unit or function compiles under.

A match is valid for one environment, never for "the current compiler on PATH".
Changing a flag creates a new environment; it does not mutate an existing one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Mapping

TOOLCHAIN_TIERS = ("validated", "supported", "user-provided", "unavailable")
OBJECT_FORMATS = ("elf", "pe", "macho")
LANGUAGES = ("c", "c++")


@dataclass(frozen=True, slots=True)
class Evidence:
    """One reason to believe an environment fact."""

    source: str  # dwarf | pe-rich | pdb | elf-comment | import | fingerprint | match
    detail: str
    location: str | None = None


@dataclass(frozen=True, slots=True)
class Toolchain:
    """An exact compiler build, described as data rather than Python branches."""

    id: str
    family: str
    version: str
    target: str
    abi: str
    object_format: str
    driver: tuple[str, ...]
    image: str | None = None  # a pinned digest for validated containers
    platform: str | None = None  # docker platform for the image (e.g. linux/amd64)
    stdlib: str | None = None
    crt: str | None = None
    macros: Mapping[str, str] = field(default_factory=dict)
    probe_hash: str = ""
    license: str = ""
    tier: str = "supported"

    def validate(self) -> tuple[str, ...]:
        """Return descriptor problems; an empty tuple means usable.

        This is intentionally non-fatal: a partially known user-provided
        toolchain may still be useful. The loader decides whether an issue is a
        hard error.
        """

        issues: list[str] = []
        for name in ("id", "family", "version", "target", "abi", "object_format"):
            if not getattr(self, name):
                issues.append(f"{name} is empty")
        if not self.driver:
            issues.append("driver is empty")
        if self.object_format and self.object_format not in OBJECT_FORMATS:
            issues.append(f"object_format {self.object_format!r} is not one of {OBJECT_FORMATS}")
        if self.tier not in TOOLCHAIN_TIERS:
            issues.append(f"tier {self.tier!r} is not one of {TOOLCHAIN_TIERS}")
        if self.tier == "validated" and not self.image:
            issues.append("a validated toolchain needs a pinned image")
        return tuple(issues)


def _environment_digest(toolchain: str, language: str, flags: tuple[str, ...],
                        defines: Mapping[str, str], includes: tuple[str, ...]) -> str:
    payload = {
        "toolchain": toolchain,
        "language": language,
        "flags": list(flags),
        "defines": dict(sorted(defines.items())),
        "includes": list(includes),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "env-" + hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class Environment:
    id: str
    toolchain: str
    language: str
    flags: tuple[str, ...] = ()
    defines: Mapping[str, str] = field(default_factory=dict)
    includes: tuple[str, ...] = ()
    confidence: float = 0.0
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("environment id is empty")
        if not self.toolchain:
            raise ValueError("environment toolchain is empty")
        if self.language not in LANGUAGES:
            raise ValueError(f"language {self.language!r} is not one of {LANGUAGES}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence!r} is outside [0, 1]")

    @classmethod
    def create(cls, toolchain: str, language: str, flags: tuple[str, ...] = (),
               defines: Mapping[str, str] | None = None, includes: tuple[str, ...] = (),
               confidence: float = 0.0, evidence: tuple[Evidence, ...] = ()) -> "Environment":
        """Build an environment with a content-addressed id.

        Flag order is preserved because some drivers treat order as meaningful.
        Defines are sorted for identity; include order is preserved because it can
        affect header lookup.
        """

        defines = dict(defines or {})
        return cls(
            id=_environment_digest(toolchain, language, tuple(flags), defines, tuple(includes)),
            toolchain=toolchain,
            language=language,
            flags=tuple(flags),
            defines=defines,
            includes=tuple(includes),
            confidence=confidence,
            evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class EnvironmentCandidate:
    """A ranked guess. The resolver returns these instead of one silent fallback."""

    environment: Environment
    confidence: float
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"candidate confidence {self.confidence!r} is outside [0, 1]")
