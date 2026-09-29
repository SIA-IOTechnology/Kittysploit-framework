#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve payload-side values shared by multiple prestage modules."""

from __future__ import annotations

from typing import Any, Dict


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_payload_prestage_context(module=None) -> Dict[str, Any]:
    """Collect callback host/port and scope hints from the active payload module."""
    ctx: Dict[str, Any] = {}
    lhost = str(_opt_value(module, "lhost", "") or _opt_value(module, "LHOST", "") or "").strip()
    lport = _opt_value(module, "lport", None)
    if lport is None:
        lport = _opt_value(module, "LPORT", None)
    comms_host = str(_opt_value(module, "payload_comms_host", "") or "").strip()
    if comms_host:
        ctx["c2_host"] = comms_host
    elif lhost:
        ctx["c2_host"] = lhost
    if lport not in (None, ""):
        try:
            ctx["c2_port"] = int(lport)
        except (TypeError, ValueError):
            pass

    scope = str(_opt_value(module, "prestage_scope", "") or "").strip()
    if scope:
        ctx["prestage_scope"] = scope

    stage_sha = str(_opt_value(module, "prestage_stage_sha256", "") or "").strip()
    if stage_sha:
        ctx["prestage_stage_sha256"] = stage_sha

    return ctx
