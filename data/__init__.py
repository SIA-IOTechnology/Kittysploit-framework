"""Bundled framework data files (wordlists, syscall DB, vendors, sounds)."""

from __future__ import annotations

from importlib import resources


def resource(*parts: str):
    """Return an importlib Traversable for a path under this package."""
    return resources.files(__package__).joinpath(*parts)
