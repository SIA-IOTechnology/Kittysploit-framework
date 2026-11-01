#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Injection point typing (numeric vs quoted string, quote character, boundary)."""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import match_sqli_error
from .oracle import HttpParameterOracle


@dataclass
class InjectionContext:
    original: str = "1"
    numeric: bool = False
    quote: str = "'"  # ', ", or empty when numeric
    paren_close: str = ""  # e.g. ")" when value is wrapped in SQL parentheses
    comment: str = "-- "

    def close_quote(self) -> str:
        if self.numeric:
            return ""
        return self.quote

    def append_sql(self, fragment: str) -> str:
        """Build the full parameter value: original + close + optional paren + SQL fragment."""
        base = self.original if self.original else "1"
        frag = str(fragment or "").strip()
        if self.numeric:
            return f"{base} {frag}".strip()
        q = self.quote or "'"
        if frag.startswith(q) and frag.startswith(base + q):
            return frag
        return f"{base}{q}{self.paren_close}{frag}"

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "numeric": self.numeric,
            "quote": self.quote,
            "paren_close": self.paren_close,
            "comment": self.comment,
        }


def infer_context_from_value(original: str) -> InjectionContext:
    s = str(original or "1").strip()
    numeric = s.isdigit() or (s.startswith("-") and s[1:].isdigit())
    # HTTP id/search params are often quoted in SQL even when digits-only (DVWA, etc.).
    if numeric and len(s) <= 12:
        return InjectionContext(original=s or "1", numeric=False, quote="'")
    return InjectionContext(original=s or "1", numeric=numeric, quote="" if numeric else "'")


def refine_context_with_oracle(
    oracle: HttpParameterOracle,
    ctx: InjectionContext,
    *,
    max_probes: int = 2,
) -> InjectionContext:
    """Use at most *max_probes* requests to pick quote style when not numeric."""
    if ctx.numeric:
        return ctx
    probes = 0
    for quote in ("'", '"'):
        if probes >= max_probes:
            break
        resp = oracle.send(f"{ctx.original}{quote}{ctx.paren_close}")
        probes += 1
        if match_sqli_error(resp.text):
            return InjectionContext(
                original=ctx.original,
                numeric=False,
                quote=quote,
                paren_close=ctx.paren_close,
                comment=ctx.comment,
            )
    return ctx
