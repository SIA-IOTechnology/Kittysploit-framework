#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve agent_store prestage options from payload context and module options."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_agent_store_context(
    module=None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    ctx = dict(context or {})
    store_path = str(ctx.get("store_path") or _opt_value(module, "store_path", "") or "").strip()
    store_secret = str(ctx.get("store_secret") or _opt_value(module, "store_secret", "") or "").strip()
    if not store_secret:
        store_secret = "kitty-agent-store"
    return {"store_path": store_path, "store_secret": store_secret}
