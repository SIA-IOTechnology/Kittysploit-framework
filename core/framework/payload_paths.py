"""Shared helpers for framework payload path conventions."""

from __future__ import annotations

NOPAYLOAD_PATHS = frozenset({"nopayload", "none"})


def is_nopayload_path(path: str) -> bool:
    """True when path selects built-in exploit delivery (no framework payload module)."""
    return str(path or "").strip().lower() in NOPAYLOAD_PATHS


def normalize_nopayload_path(path: str) -> str:
    """Return canonical nopayload token, or the stripped path unchanged."""
    text = str(path or "").strip().lower()
    if text in NOPAYLOAD_PATHS:
        return text
    return str(path or "").strip()
