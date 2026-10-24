"""JSON descriptors for toolchains.

A new compiler version is a new descriptor, not a new code path. The loader is
strict about the descriptor's shape so a typo cannot silently select the wrong
environment.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .environment import Toolchain


def _tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, (list, tuple)):
        raise ValueError("driver must be a list of strings")
    return tuple(str(v) for v in value)


def load_toolchain(path: str | Path) -> Toolchain:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read toolchain descriptor {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"toolchain descriptor {p} must be a JSON object")
    unknown = set(data) - {
        "id", "family", "version", "target", "abi", "object_format", "driver", "image",
        "platform", "stdlib", "crt", "macros", "probe_hash", "license", "tier",
    }
    if unknown:
        raise ValueError(f"toolchain descriptor {p} has unknown keys: {', '.join(sorted(unknown))}")
    try:
        toolchain = Toolchain(
            id=str(data["id"]),
            family=str(data["family"]),
            version=str(data["version"]),
            target=str(data["target"]),
            abi=str(data["abi"]),
            object_format=str(data["object_format"]),
            driver=_tuple(data.get("driver")),
            image=str(data["image"]) if data.get("image") else None,
            platform=str(data["platform"]) if data.get("platform") else None,
            stdlib=str(data["stdlib"]) if data.get("stdlib") else None,
            crt=str(data["crt"]) if data.get("crt") else None,
            macros={str(k): str(v) for k, v in (data.get("macros") or {}).items()},
            probe_hash=str(data.get("probe_hash") or ""),
            license=str(data.get("license") or ""),
            tier=str(data.get("tier") or "supported"),
        )
    except KeyError as exc:
        raise ValueError(f"toolchain descriptor {p} is missing {exc.args[0]!r}") from exc
    issues = toolchain.validate()
    if issues:
        raise ValueError(f"invalid toolchain descriptor {p}: " + "; ".join(issues))
    return toolchain


def load_catalog(directory: str | Path) -> dict[str, Toolchain]:
    """Load every ``*.json`` descriptor in a directory, keyed by toolchain id."""

    root = Path(directory)
    out: dict[str, Toolchain] = {}
    if not root.is_dir():
        return out
    for path in sorted(root.glob("*.json")):
        toolchain = load_toolchain(path)
        if toolchain.id in out:
            raise ValueError(f"duplicate toolchain id {toolchain.id!r} in {root}")
        out[toolchain.id] = toolchain
    return out


def dump_toolchain(toolchain: Toolchain) -> dict:
    """The JSON shape of a descriptor (driver becomes a list, tuples become lists)."""

    data = asdict(toolchain)
    data["driver"] = list(toolchain.driver)
    return data
