#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Opportunistic scan selection: utility ≈ expected information gain / estimated network cost.

Used to rank modules within a phase instead of relying only on static list order.
Heuristics are intentionally simple and tunable in one place.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from interfaces.command_system.builtin.agent.module_scoring import (
    estimate_network_cost,
    information_score_kb,
    module_blob_lower,
    module_path_lower,
    score_tech_hints_in_blob,
)
from interfaces.command_system.builtin.agent.module_state_match import compute_generic_module_score
from interfaces.command_system.builtin.agent.action_planner import planner_alignment_bonus


def _scanner_basename(path_lower: str) -> str:
    parts = path_lower.rstrip("/").split("/")
    return parts[-1] if parts else path_lower


def redundancy_penalty(path_lower: str, executed_paths: Set[str]) -> float:
    """Penalty when the same scanner family was already run (reduces duplicate work)."""
    if not path_lower or not executed_paths:
        return 0.0
    fam = _scanner_basename(path_lower)
    same = sum(1 for p in executed_paths if p and _scanner_basename(p.lower()) == fam)
    return min(0.75, same * 0.18)


def exploit_proximity_bonus(path_lower: str, kb: Dict[str, Any]) -> float:
    """Boost modules likely to lead toward exploitation or chained impact."""
    bonus = 0.0
    if path_lower.startswith("exploits/"):
        bonus += 2.8
    if any(x in path_lower for x in ("rce", "cve_", "exploit", "sqli", "lfi", "ssrf")):
        bonus += 1.1
    post_paths = kb.get("post_auth_exploit_paths", []) or []
    for c in post_paths:
        if isinstance(c, str) and c and len(c) > 3 and c.lower() in path_lower:
            bonus += 1.2
            break
    return bonus


def expected_information_gain(
    blob: str,
    path_lower: str,
    tech_hints: Set[str],
    kb: Dict[str, Any],
) -> float:
    """Heuristic expected novelty / discovery value given current KB and hints."""
    gain = 1.0
    hints_list = list(tech_hints)
    gain += 0.42 * score_tech_hints_in_blob(blob, hints_list, weight=1)

    n_ep = len(kb.get("discovered_endpoints", []) or [])
    if n_ep < 4:
        if any(x in path_lower for x in ("_detect", "banner", "robots", "graphql_detect", "swagger_detect")):
            gain += 1.85
        if "crawler" in path_lower:
            gain += 1.15
    elif n_ep >= 12:
        if any(x in path_lower for x in ("fuzzer", "injection", "sqli", "xss", "lfi", "ssrf")):
            gain += 1.05

    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({
        "login_form_detected",
        "login_surface_detected",
        "login_redirect_detected",
        "credentials_obtained",
    }):
        if any(x in path_lower for x in ("login", "bruteforce", "auth", "admin_login")):
            gain += 1.45

    if "authenticated_session" in signals:
        if "exploit" in path_lower or "auxiliary/scanner" in path_lower:
            gain += 0.75
    return gain


def module_utility(
    module: Dict[str, Any],
    kb: Dict[str, Any],
    tech_hints: Set[str],
    executed_paths: Set[str],
    performance_memory: Any = None,
    context_memory: Any = None,
) -> float:
    """
    utility = (gain * redundancy_discount + exploit_bonus) / network_cost

    Optional ``performance_memory`` (:class:`~.module_performance_memory.ModulePerformanceMemory`)
    scales utility by historical reward for this module + target profile.

    Optional ``context_memory`` (:class:`~.module_context_memory.ModuleContextMemory`)
    scales by learned usefulness in the current operational context (login vs auth vs CMS vs cold).
    """
    blob = module_blob_lower(module)
    path = module_path_lower(module)
    gain = expected_information_gain(blob, path, tech_hints, kb if isinstance(kb, dict) else {})
    gain += exploit_proximity_bonus(path, kb if isinstance(kb, dict) else {})
    red = redundancy_penalty(path, executed_paths)
    effective = gain * (1.0 - 0.55 * red)
    cost = estimate_network_cost(path)
    u = effective / max(0.4, cost)
    if performance_memory is not None and path:
        try:
            u *= float(performance_memory.utility_multiplier(path, kb if isinstance(kb, dict) else {}))
        except Exception:
            pass
    if context_memory is not None and path:
        try:
            u *= float(context_memory.context_multiplier(path, kb if isinstance(kb, dict) else {}))
        except Exception:
            pass
    try:
        u += planner_alignment_bonus(module, kb if isinstance(kb, dict) else {})
    except Exception:
        pass
    return u


def unified_module_score(
    module: Dict[str, Any],
    kb: Dict[str, Any],
    tech_hints: Set[str],
    executed_paths: Set[str],
    performance_memory: Optional[Any] = None,
    context_memory: Optional[Any] = None,
) -> Optional[float]:
    """
    Prefer :func:`compute_generic_module_score` when ``module`` carries planner ``agent`` metadata;
    otherwise fall back to :func:`module_utility`. Returns ``None`` only if skipped (should not happen).
    """
    g = compute_generic_module_score(
        module, kb, tech_hints, executed_paths, performance_memory, context_memory,
    )
    if g is not None:
        return g
    return module_utility(module, kb, tech_hints, executed_paths, performance_memory, context_memory)


def select_opportunistic_batch(
    candidates: List[Dict[str, Any]],
    kb: Dict[str, Any],
    tech_hints: Set[str],
    executed_paths: Set[str],
    limit: int,
    performance_memory: Optional[Any] = None,
    context_memory: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Pick up to ``limit`` unseen modules with highest unified score (generic ``agent`` or legacy utility)."""
    if limit <= 0:
        return []
    kb = kb if isinstance(kb, dict) else {}
    unseen = [
        m for m in (candidates or [])
        if isinstance(m, dict) and m.get("path") and m.get("path") not in executed_paths
    ]
    if not unseen:
        return []
    scored = []
    for m in unseen:
        g = compute_generic_module_score(
            m, kb, tech_hints, executed_paths, performance_memory, context_memory,
        )
        if g is not None and g < 0:
            continue
        if g is not None:
            scored.append((g, m))
        else:
            scored.append((
                module_utility(m, kb, tech_hints, executed_paths, performance_memory, context_memory),
                m,
            ))
    scored.sort(key=lambda item: (item[0], str(item[1].get("path", ""))), reverse=True)
    return [m for _, m in scored[:limit]]
