#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Chain metadata parsing — no framework imports (safe for isolated tests)."""

from __future__ import annotations

from typing import Any, Dict, List


def normalize_chain_block(raw: Any) -> Dict[str, Any]:
    """Parse ``agent.chain`` metadata from module ``__info__``."""
    if not isinstance(raw, dict):
        return {
            "produces_capabilities": [],
            "consumes_capabilities": [],
            "option_bindings": {},
            "suggested_followups": [],
        }
    produces: List[Dict[str, str]] = []
    seen_produces = set()
    for item in raw.get("produces_capabilities") or []:
        if isinstance(item, str) and item.strip():
            spec = {"capability": item.strip().lower(), "from_detail": ""}
        elif isinstance(item, dict):
            cap = str(item.get("capability") or "").strip().lower()
            if cap:
                spec = {
                    "capability": cap,
                    "from_detail": str(item.get("from_detail") or item.get("from") or "").strip(),
                }
            else:
                continue
        else:
            continue
        key = (spec["capability"], spec["from_detail"])
        if key in seen_produces:
            continue
        produces.append(spec)
        seen_produces.add(key)

    consumes: List[str] = []
    seen_consumes = set()
    for x in raw.get("consumes_capabilities") or raw.get("consumes") or []:
        cap = str(x).strip().lower()
        if not cap or cap in seen_consumes:
            continue
        consumes.append(cap)
        seen_consumes.add(cap)
    bindings: Dict[str, str] = {}
    raw_bindings = raw.get("option_bindings") or {}
    if isinstance(raw_bindings, dict):
        for opt, cap in raw_bindings.items():
            opt_s = str(opt).strip()
            cap_s = str(cap).strip().lower()
            if opt_s and cap_s:
                bindings[opt_s] = cap_s
    followups: List[str] = []
    seen_followups = set()
    for x in raw.get("suggested_followups") or raw.get("followups") or []:
        path = str(x).strip()
        if not path or path in seen_followups:
            continue
        followups.append(path)
        seen_followups.add(path)
    return {
        "produces_capabilities": produces,
        "consumes_capabilities": consumes,
        "option_bindings": bindings,
        "suggested_followups": followups,
    }
