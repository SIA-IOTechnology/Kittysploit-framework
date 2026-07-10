#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DBMS fingerprinting from SQL error responses."""

from __future__ import annotations

from typing import Optional

from .constants import DBMS_ERROR_HINTS, SQLI_ERROR_TOKENS


def match_sqli_error(text: str) -> Optional[str]:
    """Return the first matched error token or None."""
    lowered = (text or "").lower()
    for token in SQLI_ERROR_TOKENS:
        if token in lowered:
            return token
    return None


def contains_sqli_error(text: str) -> bool:
    return match_sqli_error(text) is not None


def fingerprint_dbms(text: str) -> Optional[str]:
    """Guess DBMS from response body after an error-based probe."""
    lowered = (text or "").lower()
    for token, dbms in DBMS_ERROR_HINTS:
        if token in lowered:
            return dbms
    return None


def evidence_snippet(text: str, matched_token: str, *, radius: int = 140) -> str:
    """Short excerpt around the first DB error match."""
    if not text:
        return ""
    low = text.lower()
    needle = (matched_token or "").lower()
    if needle and needle in low:
        i = low.index(needle)
        a = max(0, i - radius)
        b = min(len(text), i + len(needle) + radius)
        return text[a:b].replace("\n", " ").replace("\r", " ").strip()[:900]
    return text.replace("\n", " ")[:400].strip()
