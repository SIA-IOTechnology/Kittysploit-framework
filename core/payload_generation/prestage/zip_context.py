#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve ZIP prestage options from payload context and module options."""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_zip_prestage_context(
    module=None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build normalized ZIP prestage fields for Python or Zig emitters."""
    ctx = dict(context or {})
    zip_b64 = str(ctx.get("zip_b64") or "").strip()

    if not zip_b64:
        archive_path = str(_opt_value(module, "zip_file", "") or "").strip()
        if archive_path and os.path.isfile(archive_path):
            with open(archive_path, "rb") as fh:
                zip_b64 = base64.b64encode(fh.read()).decode("ascii")

    extract_to = str(ctx.get("extract_to") or _opt_value(module, "extract_to", "") or "").strip()

    cleanup = ctx.get("cleanup_zip")
    if cleanup is None:
        cleanup = bool(_opt_value(module, "cleanup_zip", True))

    chmod_exec = ctx.get("chmod_exec")
    if chmod_exec is None:
        chmod_exec = bool(_opt_value(module, "chmod_exec", True))

    return {
        "zip_b64": zip_b64,
        "extract_to": extract_to,
        "cleanup_zip": bool(cleanup),
        "chmod_exec": bool(chmod_exec),
    }
