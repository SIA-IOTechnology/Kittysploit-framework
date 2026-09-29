#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve stage_cache prestage options from payload context and module options."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_stage_cache_context(
    module=None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ctx = dict(context or {})
    cache_dir = str(
        ctx.get("cache_dir")
        or ctx.get("prestage_cache_dir")
        or _opt_value(module, "cache_dir", "")
        or ""
    ).strip()
    default_url = str(
        ctx.get("stage_url")
        or ctx.get("prestage_stage_url")
        or _opt_value(module, "stage_url", "")
        or ""
    ).strip()
    ttl_raw = ctx.get("cache_ttl")
    if ttl_raw is None:
        ttl_raw = ctx.get("prestage_cache_ttl")
    if ttl_raw is None:
        ttl_raw = _opt_value(module, "cache_ttl", 86400)
    try:
        cache_ttl = int(ttl_raw)
    except (TypeError, ValueError):
        cache_ttl = 86400
    if cache_ttl <= 0:
        cache_ttl = 86400
    return {
        "cache_dir": cache_dir,
        "cache_ttl": cache_ttl,
        "stage_url": default_url,
    }
