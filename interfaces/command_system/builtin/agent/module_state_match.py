#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic prerequisite matching and composite scoring for agent-planner module metadata.

See :mod:`interfaces.command_system.builtin.agent.agent_module_meta`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set

from interfaces.command_system.builtin.agent.agent_module_meta import has_agent_planner_meta
from interfaces.command_system.builtin.agent.attack_chain_memory import (
    capabilities_satisfied,
    chain_observation_penalty,
)
from interfaces.command_system.builtin.agent.goal_planner import kb_api_surface_ready
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost, module_path_lower


def _kb_tech_confidence(kb: Dict[str, Any], tech: str) -> float:
    conf = kb.get("tech_confidence", {}) or {}
    try:
        return float(conf.get(str(tech).lower(), 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _spa_incompatibility_blocks(agent: Optional[Dict[str, Any]], kb: Dict[str, Any], hint: str, module_path: str = "") -> bool:
    """True if this incompatible hint should block, accounting for CMS/SPA override."""
    from interfaces.command_system.builtin.agent.module_stack_gate import (
        SPA_STACK_HINTS_SET,
        cms_key_for_module_path,
        spa_incompatibility_applies,
    )
    tl = str(hint or "").lower()
    if tl not in SPA_STACK_HINTS_SET:
        return True
    if module_path:
        cms = cms_key_for_module_path(module_path) or ""
        if cms and not spa_incompatibility_applies(kb, cms):
            return False
    return True


def module_mismatch_reason(agent: Optional[Dict[str, Any]], kb: Dict[str, Any], *, module_path: str = "") -> str:
    """Human-readable reason when :func:`module_matches_state` would return False."""
    if not agent or not isinstance(kb, dict):
        return ""

    inc = agent.get("incompatible_when") or {}
    hints = {str(x).lower() for x in kb.get("tech_hints", []) or []}
    signals = {str(x).lower() for x in kb.get("risk_signals", []) or []}
    for t in inc.get("tech_hints_any") or []:
        if t.lower() in hints and _spa_incompatibility_blocks(agent, kb, t, module_path):
            return f"incompatible: tech hint `{t}` present"
    for t in inc.get("risk_signals_any") or []:
        if t.lower() in signals:
            return f"incompatible: risk signal `{t}` present"

    req = agent.get("requires") or {}
    if int(req.get("min_endpoints", 0) or 0) > len(kb.get("discovered_endpoints", []) or []):
        return f"requires at least {req.get('min_endpoints')} discovered endpoint(s)"
    if int(req.get("min_params", 0) or 0) > len(kb.get("discovered_params", []) or []):
        return f"requires at least {req.get('min_params')} discovered param(s)"

    need_any = [str(x).lower() for x in (req.get("tech_hints_any") or []) if str(x).strip()]
    if need_any and not any(x in hints for x in need_any):
        return f"requires tech hint(s): {', '.join(need_any)}"

    need_all = [str(x).lower() for x in (req.get("tech_hints_all") or []) if str(x).strip()]
    if need_all and not all(x in hints for x in need_all):
        return f"requires all tech hints: {', '.join(need_all)}"

    conf_min = req.get("confidence_min") or {}
    if isinstance(conf_min, dict):
        for tech, min_val in conf_min.items():
            try:
                floor = float(min_val)
            except (TypeError, ValueError):
                continue
            if _kb_tech_confidence(kb, str(tech)) < floor:
                return f"requires `{tech}` confidence >= {floor:.2f}"

    conf_min_any = req.get("confidence_min_any") or {}
    if isinstance(conf_min_any, dict) and conf_min_any:
        if not any(
            _kb_tech_confidence(kb, str(tech)) >= float(min_val)
            for tech, min_val in conf_min_any.items()
            if str(tech).strip()
        ):
            parts = [f"{t}>={v}" for t, v in conf_min_any.items()]
            return f"requires any stack confidence: {', '.join(parts)}"

    endpoint_patterns = [str(x).lower() for x in (req.get("endpoint_pattern_any") or []) if str(x).strip()]
    if endpoint_patterns:
        endpoints = [str(e).lower() for e in (kb.get("discovered_endpoints", []) or [])]
        if not any(pat in ep for ep in endpoints for pat in endpoint_patterns):
            return f"requires endpoint matching: {', '.join(endpoint_patterns)}"

    param_need = [str(x).lower() for x in (req.get("param_any") or []) if str(x).strip()]
    if param_need:
        params = {str(p).lower() for p in (kb.get("discovered_params", []) or [])}
        if not any(p in params for p in param_need):
            return f"requires param(s): {', '.join(param_need)}"

    if bool(req.get("api_surface_ready", False)) and not kb_api_surface_ready(kb):
        return "requires API surface ready before generic API probing"

    if bool(req.get("auth_session", False)) and "authenticated_session" not in signals:
        return "requires authenticated session"

    spec_need = [str(x).lower() for x in (req.get("specializations_any") or []) if str(x).strip()]
    specs = {str(x).lower() for x in kb.get("specializations", []) or []}
    if spec_need and not any(x in specs for x in spec_need):
        return f"requires specialization(s): {', '.join(spec_need)}"

    rs_any = [str(x).lower() for x in (req.get("risk_signals_any") or []) if str(x).strip()]
    if rs_any and not any(x in signals for x in rs_any):
        return f"requires risk signal(s): {', '.join(rs_any)}"

    if not capabilities_satisfied(
        kb,
        req.get("capabilities_any") or [],
        req.get("capabilities_all") or [],
    ):
        return "required attack-chain capabilities not satisfied"

    return ""


def module_matches_state(
    agent: Optional[Dict[str, Any]],
    kb: Dict[str, Any],
    *,
    module_path: str = "",
) -> bool:
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
        if t.lower() in hints and _spa_incompatibility_blocks(agent, kb, t, module_path):
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

    if bool(req.get("api_surface_ready", False)) and not kb_api_surface_ready(kb):
        return False

    conf_min = req.get("confidence_min") or {}
    if isinstance(conf_min, dict):
        for tech, min_val in conf_min.items():
            try:
                floor = float(min_val)
            except (TypeError, ValueError):
                continue
            if _kb_tech_confidence(kb, str(tech)) < floor:
                return False

    conf_min_any = req.get("confidence_min_any") or {}
    if isinstance(conf_min_any, dict) and conf_min_any:
        if not any(
            _kb_tech_confidence(kb, str(tech)) >= float(min_val)
            for tech, min_val in conf_min_any.items()
            if str(tech).strip()
        ):
            return False

    endpoint_patterns = [str(x).lower() for x in (req.get("endpoint_pattern_any") or []) if str(x).strip()]
    if endpoint_patterns:
        endpoints = [str(e).lower() for e in (kb.get("discovered_endpoints", []) or [])]
        if not any(pat in ep for ep in endpoints for pat in endpoint_patterns):
            return False

    param_need = [str(x).lower() for x in (req.get("param_any") or []) if str(x).strip()]
    if param_need:
        params = {str(p).lower() for p in (kb.get("discovered_params", []) or [])}
        if not any(p in params for p in param_need):
            return False

    if not capabilities_satisfied(
        kb,
        req.get("capabilities_any") or [],
        req.get("capabilities_all") or [],
    ):
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
    path = module_path_lower(module)
    if not module_matches_state(agent, kb, module_path=path):
        return -1.0
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
    try:
        score -= 0.45 * chain_observation_penalty(module, kb)
    except Exception:
        pass
    return float(score)
