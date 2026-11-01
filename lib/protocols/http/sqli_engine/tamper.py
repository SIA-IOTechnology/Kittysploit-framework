#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lightweight WAF evasion transforms (native, no sqlmap dependency)."""

from __future__ import annotations

from typing import Iterable, List


def tamper_variants(payload: str) -> List[str]:
    """Return *payload* plus a small set of encoded variants."""
    base = str(payload or "")
    if not base:
        return []
    seen = {base}
    out: List[str] = [base]

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            out.append(value)

    if " " in base:
        add(base.replace(" ", "/**/"))
        add(base.replace(" ", "%09"))
    if "UNION" in base.upper():
        add(replace_ci(base, "UNION", "UN/**/ION"))
        add(replace_ci(base, "SELECT", "SeLeCt"))
    if " AND " in base.upper():
        add(replace_ci(base, " AND ", "%09AND%09"))
    if "--" in base:
        add(base.replace("--", "--%20"))
    if "'" in base:
        add(base.replace("'", "%27"))
    return out


def replace_ci(text: str, needle: str, repl: str) -> str:
    low = text.lower()
    n = needle.lower()
    idx = low.find(n)
    if idx < 0:
        return text
    return text[:idx] + repl + text[idx + len(needle) :]


def expand_probe_list(payloads: Iterable[str], *, waf: bool) -> List[str]:
    if not waf:
        return list(dict.fromkeys(str(p) for p in payloads if str(p)))
    expanded: List[str] = []
    seen = set()
    for payload in payloads:
        for variant in tamper_variants(str(payload)):
            if variant not in seen:
                seen.add(variant)
                expanded.append(variant)
    return expanded
