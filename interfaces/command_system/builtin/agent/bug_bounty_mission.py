#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bug bounty mission — OWASP parallel specialists + compound validation under bug-bounty-safe policy.

Profile: ``bug-bounty`` (see mission_profiles.py). Keeps programs rules: no brute force,
post-exploit, payloads, or destructive actions; maximizes validated, reportable findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.owasp_mission import (
    apply_owasp_web_parallel_to_kb,
    apply_owasp_web_parallel_to_state,
    normalize_owasp_classes,
)

MISSION_PROFILE_NAME = "bug-bounty"
KB_MISSION_KEY = "bug_bounty_mission"
DEFAULT_FAN_OUT = 5


def build_bug_bounty_mission(
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = DEFAULT_FAN_OUT,
) -> Dict[str, Any]:
    selected = normalize_owasp_classes(classes)
    return {
        "schema_version": "1.0",
        "enabled": True,
        "profile": MISSION_PROFILE_NAME,
        "classes": selected,
        "fan_out": max(1, min(int(fan_out or DEFAULT_FAN_OUT), 8)),
        "parallel_specialists": True,
        "compound_validation": True,
        "compound_specialist_fanout": True,
        "framework_expert": True,
        "discovery_hypotheses": True,
        "catalog_policy": "bug-bounty-safe",
        "exploit_chains_poc_only": True,
    }


def apply_bug_bounty_to_kb(
    kb: MutableMapping[str, Any],
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = DEFAULT_FAN_OUT,
) -> Dict[str, Any]:
    apply_owasp_web_parallel_to_kb(kb, classes=classes, fan_out=fan_out, exploit=False)
    mission = build_bug_bounty_mission(classes=classes, fan_out=fan_out)
    kb[KB_MISSION_KEY] = mission
    kb["mission_profile_intent"] = MISSION_PROFILE_NAME
    kb["compound_validation_preferred"] = True
    planner = dict(kb.get("planner_intelligence") or {})
    planner.update({
        "bug_bounty": True,
        "framework_expert": True,
        "compound_validation": True,
        "domain_orchestrator": True,
        "specialist_llm": True,
        "specialists": "parallel",
    })
    kb["planner_intelligence"] = planner
    playbooks = dict(kb.get("playbook_planner") or {})
    playbooks["prefer_source"] = "bug-bounty"
    playbooks["enabled"] = True
    kb["playbook_planner"] = playbooks
    signals = list(kb.get("risk_signals") or [])
    for token in ("bug_bounty_mission", "owasp_web_parallel"):
        if token not in {str(s).lower() for s in signals}:
            signals.append(token)
    kb["risk_signals"] = signals
    return mission


def apply_bug_bounty_to_state(
    state: Any,
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = DEFAULT_FAN_OUT,
) -> Dict[str, Any]:
    apply_owasp_web_parallel_to_state(state, classes=classes)
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    mission = apply_bug_bounty_to_kb(kb, classes=classes, fan_out=fan_out)
    state.domain_orchestrator_enabled = True
    state.specialist_llm_enabled = True
    state.hierarchical_planner_enabled = True
    state.specialist_parallel_enabled = True
    state.specialist_sequential_enabled = False
    state.discovery_enabled = True
    if not getattr(state, "campaign_goal", None) or str(state.campaign_goal) == "recon":
        state.campaign_goal = "validate"
    return mission


def is_bug_bounty_mission(
    kb: Optional[Mapping[str, Any]] = None,
    *,
    mission_profile: str = "",
) -> bool:
    profile = str(mission_profile or "").strip().lower().replace("_", "-")
    if profile in {MISSION_PROFILE_NAME, "bug_bounty", "bugbounty"}:
        return True
    if profile == "bug-bounty-safe" and isinstance(kb, Mapping):
        mission = kb.get(KB_MISSION_KEY)
        if isinstance(mission, dict) and mission.get("enabled"):
            return True
    if not isinstance(kb, Mapping):
        return False
    mission = kb.get(KB_MISSION_KEY)
    return isinstance(mission, dict) and bool(mission.get("enabled"))


def filter_paths_for_bug_bounty(state: Any, paths: Sequence[str]) -> List[str]:
    """Drop module paths blocked under bug-bounty-safe catalog policy."""
    if not paths:
        return []
    kb = getattr(state, "knowledge_base", None)
    policy = getattr(state, "runtime_policy", None)
    profile = ""
    if policy is not None:
        profile = str(getattr(policy, "mission_profile", "") or "")
    if not is_bug_bounty_mission(kb if isinstance(kb, dict) else None, mission_profile=profile):
        if str(profile) != "bug-bounty-safe":
            return list(paths)
    if policy is None:
        return list(paths)
    try:
        from interfaces.command_system.builtin.agent.runtime_policy import (
            _mission_catalog_block_reason,
            assess_module_risk,
            normalize_mission_profile,
        )
    except Exception:
        return list(paths)
    mission = normalize_mission_profile(getattr(policy, "mission_profile", "") or "bug-bounty-safe")
    if mission not in {"bug-bounty-safe", "bug-bounty"}:
        return list(paths)
    allowed: List[str] = []
    for raw in paths:
        path = str(raw or "").strip()
        if not path:
            continue
        risk = assess_module_risk(None, path)
        if _mission_catalog_block_reason(policy, risk, module_path=path):
            continue
        if not policy.risk_approved(risk):
            continue
        allowed.append(path)
    return allowed


__all__ = [
    "apply_bug_bounty_to_kb",
    "apply_bug_bounty_to_state",
    "build_bug_bounty_mission",
    "filter_paths_for_bug_bounty",
    "is_bug_bounty_mission",
]
