#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve telemetry_buffer prestage options from payload context and module options."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_telemetry_context(
    module=None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    ctx = dict(context or {})
    buffer_path = str(ctx.get("telemetry_path") or _opt_value(module, "buffer_path", "") or "").strip()
    return {"buffer_path": buffer_path}
