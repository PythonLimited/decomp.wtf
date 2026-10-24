"""Bundled toolchain descriptors.

The exact compiler build is data; adding a version is adding a JSON descriptor,
not a new code path. ``catalog`` is intentionally small for now: the two first
targets, GCC 9.1.0 and VS2015 U3.
"""

from __future__ import annotations

from pathlib import Path

from ..model import Toolchain, load_catalog


def catalog() -> dict[str, Toolchain]:
    """Load the descriptors shipped with this package."""

    return load_catalog(Path(__file__).parent)


__all__ = ["catalog"]
