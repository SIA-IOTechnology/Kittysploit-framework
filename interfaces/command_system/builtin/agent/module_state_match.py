#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic prerequisite matching and composite scoring for agent-planner module metadata.

See :mod:`interfaces.command_system.builtin.agent.agent_module_meta`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set

from interfaces.command_system.builtin.agent.agent_module_meta import has_agent_planner_meta
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost, module_path_lower


def module_matches_state(agent: Optional[Dict[str, Any]], kb: Dict[str, Any]) -> bool:
    """
    Return False if ``incompatible_when`` matches or ``requires`` are not satisfied.
    Missing/empty ``agent`` → True (no extra gating).
    """
    if not agent or not isinstance(kb, dict):
        return True

    inc = agent.get("incompatible_when") or {}
    hints = {str(x).lower() for x in kb.get("tech_hints", []) or []}
    signals = {str(x).lower() for x in kb.get("risk_signals", []) or []}
    for t in inc.get("tech_hints_any") or []:
        if t.lower() in hints:
            return False
    for t in inc.get("risk_signals_any") or []:
        if t.lower() in signals:
            return False

    req = agent.get("requires") or {}
    if int(req.get("min_endpoints", 0) or 0) > len(kb.get("discovered_endpoints", []) or []):
        return False
    if int(req.get("min_params", 0) or 0) > len(kb.get("discovered_params", []) or []):
        return False

    need_any = [str(x).lower() for x in (req.get("tech_hints_any") or []) if str(x).strip()]
    if need_any and not any(x in hints for x in need_any):
        return False
    need_all = [str(x).lower() for x in (req.get("tech_hints_all") or []) if str(x).strip()]
    if need_all and not all(x in hints for x in need_all):
        return False

    spec_need = [str(x).lower() for x in (req.get("specializations_any") or []) if str(x).strip()]
    specs = {str(x).lower() for x in kb.get("specializations", []) or []}
    if spec_need and not any(x in specs for x in spec_need):
        return False

    rs_any = [str(x).lower() for x in (req.get("risk_signals_any") or []) if str(x).strip()]
    if rs_any and not any(x in signals for x in rs_any):
        return False

    if bool(req.get("auth_session", False)) and "authenticated_session" not in signals:
        return False

    return True


def compute_generic_module_score(
    module: Dict[str, Any],
    kb: Dict[str, Any],
    tech_hints: Set[str],
    executed_paths: Set[str],
    performance_memory: Any = None,
    context_memory: Any = None,
) -> Optional[float]:
    """
    Composite score: prerequisite fit, declared value/cost/noise, path cost, history.

    Returns:
        ``None`` → caller should fall back to legacy :func:`campaign_utility.module_utility`.
        ``-1.0`` → hard skip (prereqs failed).
        ``>= 0`` → higher is better.
    """
    agent = module.get("agent")
    if not has_agent_planner_meta(agent):
        return None
    if not module_matches_state(agent, kb):
        return -1.0

    path = module_path_lower(module)
    cost_meta = float(agent.get("cost", 1.0))
    noise = float(agent.get("noise", 0.5))
    value = float(agent.get("value", 1.0))

    cost_path = float(estimate_network_cost(path))
    cost_eff = max(0.35, (cost_meta + cost_path) * 0.5)
    noise_eff = max(0.15, 1.0 + noise)

    # Hint overlap bonus with declared scanner role
    hint_bonus = 0.0
    blob = " ".join([
        path,
        str(module.get("name", "")).lower(),
        str(module.get("description", "")).lower(),
    ])
    for h in tech_hints:
        if h and h in blob:
            hint_bonus += 0.15
    hint_bonus = min(0.6, hint_bonus)

    hist = 1.0
    if performance_memory is not None and path:
        try:
            hist = float(performance_memory.utility_multiplier(path, kb))
        except Exception:
            hist = 1.0

    ctxm = 1.0
    if context_memory is not None and path:
        try:
            ctxm = float(context_memory.context_multiplier(path, kb))
        except Exception:
            ctxm = 1.0

    # Redundancy: same module path already executed this campaign
    red = 0.2 if path in executed_paths else 0.0

    score = (value + hint_bonus) * hist * ctxm * (1.0 - red) / (cost_eff * noise_eff)
    return float(score)
