#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attack-specialists mission — OWASP parallel fan-out plus framework expert intelligence.

Profile: ``attack-specialists`` (see mission_profiles.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.owasp_mission import (
    apply_owasp_web_parallel_to_kb,
    apply_owasp_web_parallel_to_state,
    normalize_owasp_classes,
)

MISSION_PROFILE_NAME = "attack-specialists"
KB_MISSION_KEY = "attack_specialists_mission"


def build_attack_specialists_mission(
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = 6,
    discovery: bool = False,
) -> Dict[str, Any]:
    selected = normalize_owasp_classes(classes)
    return {
        "schema_version": "1.0",
        "enabled": True,
        "profile": MISSION_PROFILE_NAME,
        "classes": selected,
        "fan_out": max(1, min(int(fan_out or 6), 12)),
        "parallel_specialists": True,
        "framework_expert": True,
        "specialist_attack_intel": True,
        "specialist_army": True,
        "domain_orchestrator": True,
        "discovery_hypotheses": bool(discovery),
    }


def apply_attack_specialists_to_kb(
    kb: MutableMapping[str, Any],
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = 6,
    discovery: bool = False,
) -> Dict[str, Any]:
    apply_owasp_web_parallel_to_kb(kb, classes=classes, fan_out=fan_out)
    mission = build_attack_specialists_mission(classes=classes, fan_out=fan_out, discovery=discovery)
    kb[KB_MISSION_KEY] = mission
    kb["specialist_army"] = True
    kb["attack_specialist_intel"] = True
    kb["reactive_surface"] = True
    planner = dict(kb.get("planner_intelligence") or {})
    planner.update({
        "attack_specialists": True,
        "domain_orchestrator": True,
        "specialist_llm": True,
        "specialist_army": True,
        "framework_expert": True,
    })
    kb["planner_intelligence"] = planner
    signals = list(kb.get("risk_signals") or [])
    if "attack_specialists" not in {str(s).lower() for s in signals}:
        signals.append("attack_specialists")
    kb["risk_signals"] = signals
    return mission


def apply_attack_specialists_to_state(
    state: Any,
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = 6,
    discovery: bool = False,
) -> Dict[str, Any]:
    """Enable full attack-specialist stack on AgentState."""
    apply_owasp_web_parallel_to_state(state, classes=classes)
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    mission = apply_attack_specialists_to_kb(
        kb,
        classes=classes,
        fan_out=fan_out,
        discovery=discovery,
    )
    state.domain_orchestrator_enabled = True
    state.specialist_llm_enabled = True
    state.specialist_army_enabled = True
    state.hierarchical_planner_enabled = True
    state.specialist_parallel_enabled = True
    state.specialist_sequential_enabled = False
    if discovery:
        state.discovery_enabled = True
    if not getattr(state, "campaign_goal", None):
        state.campaign_goal = "validate"
    return mission


def is_attack_specialists_mission(kb: Optional[Mapping[str, Any]] = None, *, mission_profile: str = "") -> bool:
    profile = str(mission_profile or "").strip().lower()
    if profile in {MISSION_PROFILE_NAME, "attack_specialist", "attack-specialist"}:
        return True
    if not isinstance(kb, Mapping):
        return False
    mission = kb.get(KB_MISSION_KEY)
    return isinstance(mission, dict) and bool(mission.get("enabled"))
