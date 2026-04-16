#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Optional ``agent`` block inside module ``__info__`` for planner-aware metadata.

Example::

    __info__ = {
        "name": "...",
        "agent": {
            "requires": {
                "min_endpoints": 0,
                "tech_hints_any": [],
                "risk_signals_any": [],
                "auth_session": false,
            },
            "incompatible_when": {"tech_hints_any": []},
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": "medium",
            "noise": "low",
            "value": "high",
        },
    }
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional

# Controlled vocabulary for ``produces`` (extensible).
KNOWN_PRODUCES: tuple[str, ...] = (
    "endpoints",
    "params",
    "tech_hints",
    "specializations",
    "risk_signals",
    "login_paths",
    "credentials",
    "exploit_paths",
)

LEVELS: Mapping[str, float] = {
    "low": 0.35,
    "medium": 1.0,
    "high": 2.2,
}


def _level_or_float(value: Any, default: float = 1.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in LEVELS:
            return float(LEVELS[low])
        try:
            return float(low)
        except ValueError:
            return default
    return default


def normalize_requires(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "min_endpoints": 0,
            "min_params": 0,
            "tech_hints_any": [],
            "tech_hints_all": [],
            "specializations_any": [],
            "risk_signals_any": [],
            "auth_session": False,
        }
    return {
        "min_endpoints": int(raw.get("min_endpoints", 0) or 0),
        "min_params": int(raw.get("min_params", 0) or 0),
        "tech_hints_any": [str(x).lower() for x in (raw.get("tech_hints_any") or []) if str(x).strip()],
        "tech_hints_all": [str(x).lower() for x in (raw.get("tech_hints_all") or []) if str(x).strip()],
        "specializations_any": [str(x).lower() for x in (raw.get("specializations_any") or []) if str(x).strip()],
        "risk_signals_any": [str(x).lower() for x in (raw.get("risk_signals_any") or []) if str(x).strip()],
        "auth_session": bool(raw.get("auth_session", False)),
    }


def normalize_incompatible(raw: Any) -> Dict[str, List[str]]:
    if not isinstance(raw, dict):
        return {"tech_hints_any": [], "risk_signals_any": []}
    return {
        "tech_hints_any": [str(x).lower() for x in (raw.get("tech_hints_any") or []) if str(x).strip()],
        "risk_signals_any": [str(x).lower() for x in (raw.get("risk_signals_any") or []) if str(x).strip()],
    }


def normalize_produces(raw: Any) -> List[str]:
    if not isinstance(raw, (list, tuple)):
        return []
    out = []
    for x in raw:
        s = str(x).strip().lower()
        if s:
            out.append(s)
    return out


def normalize_agent_block(raw: Any) -> Optional[Dict[str, Any]]:
    """Parse ``__info__['agent']``. Returns ``None`` if the key is absent or invalid."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return None
    requires = normalize_requires(raw.get("requires"))
    incompatible = normalize_incompatible(raw.get("incompatible_when"))
    produces = normalize_produces(raw.get("produces"))
    return {
        "requires": requires,
        "incompatible_when": incompatible,
        "produces": produces,
        "cost": _level_or_float(raw.get("cost"), 1.0),
        "noise": _level_or_float(raw.get("noise"), 0.5),
        "value": _level_or_float(raw.get("value"), 1.0),
    }


def has_agent_planner_meta(agent: Optional[Mapping[str, Any]]) -> bool:
    return agent is not None


def merge_produces_into_kb(
    kb: MutableMapping[str, Any],
    module_path: str,
    produces: List[str],
    *,
    max_semantic: int = 120,
    max_per_module: int = 24,
) -> None:
    """Record declared ``produces`` tokens on the knowledge base (step 7)."""
    if not isinstance(kb, MutableMapping) or not produces:
        return
    by_mod = kb.setdefault("produces_by_module", {})
    if isinstance(by_mod, dict) and module_path:
        by_mod[str(module_path)[:300]] = produces[:max_per_module]
    sem = kb.setdefault("semantic_produces", [])
    if not isinstance(sem, list):
        sem = []
        kb["semantic_produces"] = sem
    seen = set(str(x).lower() for x in sem)
    for p in produces:
        pl = str(p).lower().strip()
        if pl and pl not in seen:
            sem.append(pl)
            seen.add(pl)
            if len(sem) > max_semantic:
                kb["semantic_produces"] = sem[-max_semantic:]
