#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Post-detection extraction helpers (blind + scalar)."""

from __future__ import annotations

from typing import Callable, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from lib.protocols.http.sqli import sqli_blind_extract_string as _extract_fn
    from lib.protocols.http.sqli import sqli_blind_search_int as _search_fn

__all__ = [
    "sqli_blind_search_int",
    "sqli_blind_extract_string",
    "BlindOracle",
    "extract_scalar_blind",
    "make_blind_oracle",
]


def _blind_fns():
    from lib.protocols.http.sqli import sqli_blind_extract_string, sqli_blind_search_int

    return sqli_blind_search_int, sqli_blind_extract_string


def sqli_blind_search_int(*args, **kwargs):
    fn, _ = _blind_fns()
    return fn(*args, **kwargs)


def sqli_blind_extract_string(*args, **kwargs):
    _, fn = _blind_fns()
    return fn(*args, **kwargs)


class BlindOracle(Protocol):
    def true(self, cond: str) -> bool: ...
    def gt(self, expr: str) -> bool: ...
    def errors(self, subquery: str) -> bool: ...


def extract_scalar_blind(
    oracle: BlindOracle,
    subquery: str,
    *,
    threads: int = 8,
    max_length: int = 1024,
) -> Optional[str]:
    """Extract a scalar string via boolean blind SQLi using an oracle."""
    return sqli_blind_extract_string(
        oracle.true,
        oracle.gt,
        oracle.errors,
        subquery,
        threads=threads,
        max_length=max_length,
    )


def make_blind_oracle(
    true_fn: Callable[[str], bool],
    gt_fn: Optional[Callable[[str], bool]] = None,
    errors_fn: Optional[Callable[[str], bool]] = None,
) -> BlindOracle:
    """Build a minimal blind oracle from callables."""

    class _Oracle:
        def true(self, cond: str) -> bool:
            return true_fn(cond)

        def gt(self, expr: str) -> bool:
            fn = gt_fn or true_fn
            return fn(f"({expr})")

        def errors(self, subquery: str) -> bool:
            if errors_fn:
                return errors_fn(subquery)
            return False

    return _Oracle()
