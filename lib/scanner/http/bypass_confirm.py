#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Confirmation helpers for HTTP 403/404 bypass scanners (reduce homepage FPs)."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Set

# Statuses that can indicate a meaningful access change.
_ACCESS_STATUSES: Set[int] = {200, 201, 204, 301, 302, 307, 308, 401, 403}
# Hard error / non-bypass outcomes.
_ERROR_STATUSES: Set[int] = {400, 405, 408, 413, 414, 421, 429, 500, 501, 502, 503, 504}


def signatures_similar(
    left: Optional[Mapping[str, Any]],
    right: Optional[Mapping[str, Any]],
    *,
    length_ratio: float = 0.08,
    min_abs: int = 64,
) -> bool:
    """True when two response signatures look like the same page."""
    if not left or not right:
        return False
    try:
        left_status = int(left.get("status") or 0)
        right_status = int(right.get("status") or 0)
        left_len = int(left.get("length") or 0)
        right_len = int(right.get("length") or 0)
    except (TypeError, ValueError):
        return False
    if left_status != right_status:
        return False
    delta = abs(left_len - right_len)
    threshold = max(min_abs, int(max(left_len, right_len) * length_ratio))
    return delta <= threshold


def looks_like_path_escape(name: str, path: str, target_path: str) -> bool:
    """True for variants that typically leave the protected path (e.g. /admin/../)."""
    low_name = str(name or "").lower()
    low_path = str(path or "")
    target = str(target_path or "").rstrip("/") or "/"
    if "/../" in low_path or low_path.endswith("/.."):
        return True
    if "/..;/" in low_path:
        return True
    # Header tricks that issue GET / are confirmed via homepage compare, not here.
    if low_name.startswith(("x-original-url", "x-rewrite-url", "x-original-forwarded")):
        if low_path in {"/", ""}:
            return False
    # Encoded traversal that collapses to parent of target.
    if target != "/" and low_path.rstrip("/").endswith("/.."):
        return True
    return False


def is_confirmed_bypass(
    sig: Optional[Mapping[str, Any]],
    *,
    blocked_sig: Optional[Mapping[str, Any]],
    home_sig: Optional[Mapping[str, Any]] = None,
    name: str = "",
    path: str = "",
    target_path: str = "",
    blocked_status: int = 404,
) -> bool:
    """
    Return True only when the candidate looks like real access to the target
    resource, not a homepage collapse or protocol error.
    """
    if not sig:
        return False
    try:
        status = int(sig.get("status") or 0)
    except (TypeError, ValueError):
        return False

    if status in _ERROR_STATUSES:
        return False
    if status == int(blocked_status):
        return False
    if status not in _ACCESS_STATUSES and status != int(blocked_status):
        # Allow uncommon 2xx/3xx already covered; reject plain oddities.
        if status < 200 or status >= 500:
            return False

    # Empty redirect bodies (len=0) are almost always generic slash-normalization,
    # not a successful unlock of the protected resource.
    try:
        length = int(sig.get("length") or 0)
    except (TypeError, ValueError):
        length = 0
    if status in {301, 302, 303, 307, 308} and length <= 0:
        return False

    # Still the same blocked page (soft-404 / soft-403).
    if blocked_sig and signatures_similar(sig, blocked_sig):
        return False

    # Classic false positive: /admin/../ or ignored X-Original-URL → homepage.
    if home_sig and signatures_similar(sig, home_sig):
        return False

    if looks_like_path_escape(name, path, target_path):
        # Escape variants are only kept when they clearly do NOT match home
        # (already checked) AND still differ from blocked — but /../ almost
        # always is home; reject them to avoid noisy "yes" rows.
        return False

    # For 404-bypass, reaching 403/401 can still be useful (resource exists).
    if int(blocked_status) == 404 and status in {401, 403}:
        return True

    # For 403-bypass, only treat as success when we leave 403 toward access/auth.
    if int(blocked_status) == 403:
        return status in {200, 201, 204, 301, 302, 307, 308, 401}

    return status in _ACCESS_STATUSES
