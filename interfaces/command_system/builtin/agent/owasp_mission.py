#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OWASP web-app parallel mission helpers.

Seeds specialist fan-out by vulnerability class (injection / xss / ssrf / auth / authz)
so analyze→exploit runs specialist proposals concurrently instead of a single free-form loop.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set

from interfaces.command_system.builtin.agent.exploit_queue import OWASP_CLASSES

SCHEMA_VERSION = "1.0"
KB_MISSION_KEY = "owasp_web_mission"
MISSION_PROFILE_NAME = "owasp-web-parallel"
DEFAULT_FAN_OUT = 5

# OWASP-oriented class set for the parallel web mission.
OWASP_WEB_CLASSES: tuple[str, ...] = ("injection", "xss", "ssrf", "auth", "authz")

# Map OWASP class → vuln specialist registry keys (see specialist_registry / vuln_specialists).
CLASS_SPECIALIST_KEYS: Dict[str, tuple[str, ...]] = {
    "injection": ("sqli", "lfi", "ssti"),
    "xss": ("xss",),
    "ssrf": ("ssrf",),
    "auth": ("auth",),
    "authz": ("authz",),
}

# Preferred scanner/auxiliary module path tokens per class (used for scan specialization hints).
CLASS_MODULE_HINTS: Dict[str, tuple[str, ...]] = {
    "injection": (
        "sqli_engine",
        "sql_injection",
        "php_injection",
        "ssti",
        "lfi",
        "xxe_scanner",
        "command_injection",
    ),
    "xss": ("xss_scanner", "dom_xss", "xss"),
    "ssrf": ("ssrf_scanner", "ssrf"),
    "auth": (
        "login_page_detector",
        "simple_login_scanner",
        "admin_login_bruteforce",
        "jwt",
        "oauth",
    ),
    "authz": (
        "api_bola_idor",
        "bola",
        "idor",
        "broken_access",
        "authz",
        "privilege",
    ),
}

# Risk signals seeded so SpecialistRegistry.match() picks the right vuln specialists.
CLASS_RISK_SIGNALS: Dict[str, tuple[str, ...]] = {
    "injection": ("sqli", "lfi", "ssti", "sql_signal"),
    "xss": ("xss",),
    "ssrf": ("ssrf",),
    "auth": ("auth", "login_surface_detected"),
    "authz": ("authz", "bola", "idor"),
}


def normalize_owasp_classes(values: Optional[Sequence[Any]] = None) -> List[str]:
    allowed = set(OWASP_WEB_CLASSES)
    out: List[str] = []
    seen: Set[str] = set()
    for raw in values or OWASP_WEB_CLASSES:
        key = str(raw or "").strip().lower()
        if key == "other":
            continue
        if key not in allowed or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out or list(OWASP_WEB_CLASSES)


def specialist_keys_for_classes(classes: Optional[Sequence[str]] = None) -> List[str]:
    keys: List[str] = []
    seen: Set[str] = set()
    for owasp_class in normalize_owasp_classes(classes):
        for key in CLASS_SPECIALIST_KEYS.get(owasp_class, ()):
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def module_hints_for_classes(classes: Optional[Sequence[str]] = None) -> List[str]:
    hints: List[str] = []
    seen: Set[str] = set()
    for owasp_class in normalize_owasp_classes(classes):
        for hint in CLASS_MODULE_HINTS.get(owasp_class, ()):
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)
    return hints


def risk_signals_for_classes(classes: Optional[Sequence[str]] = None) -> List[str]:
    signals: List[str] = []
    seen: Set[str] = set()
    for owasp_class in normalize_owasp_classes(classes):
        for signal in CLASS_RISK_SIGNALS.get(owasp_class, ()):
            if signal not in seen:
                seen.add(signal)
                signals.append(signal)
    return signals


def is_owasp_web_parallel_mission(kb: Optional[Mapping[str, Any]] = None, *, mission_profile: str = "") -> bool:
    profile = str(mission_profile or "").strip().lower()
    if profile in {MISSION_PROFILE_NAME, "owasp-web", "owasp_parallel"}:
        return True
    if not isinstance(kb, Mapping):
        return False
    mission = kb.get(KB_MISSION_KEY)
    if isinstance(mission, dict) and mission.get("enabled"):
        return True
    return False


def mission_fan_out(kb: Optional[Mapping[str, Any]] = None, default: int = 3) -> int:
    if not isinstance(kb, Mapping):
        return int(default)
    mission = kb.get(KB_MISSION_KEY)
    if isinstance(mission, dict):
        try:
            value = int(mission.get("fan_out") or default)
            return max(1, min(value, 8))
        except (TypeError, ValueError):
            return int(default)
    return int(default)


def build_owasp_web_mission(
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = DEFAULT_FAN_OUT,
    exploit: bool = True,
) -> Dict[str, Any]:
    selected = normalize_owasp_classes(classes)
    return {
        "schema_version": SCHEMA_VERSION,
        "enabled": True,
        "profile": MISSION_PROFILE_NAME,
        "classes": selected,
        "specialist_keys": specialist_keys_for_classes(selected),
        "module_hints": module_hints_for_classes(selected),
        "fan_out": max(1, min(int(fan_out or DEFAULT_FAN_OUT), 8)),
        "parallel_specialists": True,
        "exploit": bool(exploit),
    }


def apply_owasp_web_parallel_to_kb(
    kb: MutableMapping[str, Any],
    *,
    classes: Optional[Sequence[str]] = None,
    fan_out: int = DEFAULT_FAN_OUT,
    exploit: bool = True,
) -> Dict[str, Any]:
    """Seed knowledge_base for parallel OWASP-class specialist fan-out.

    Does **not** inject module tokens into ``tech_hints`` or pre-claim vuln
    ``risk_signals`` — those drive scan module selection and would burn budget
    on false stack hits before any real surface evidence exists.
    """
    mission = build_owasp_web_mission(classes=classes, fan_out=fan_out, exploit=exploit)
    kb[KB_MISSION_KEY] = mission

    signals = list(kb.get("risk_signals") or [])
    signal_set = {str(s).lower() for s in signals}
    # Mission marker only — specialist registry expands classes from owasp_web_mission.
    if "owasp_web_parallel" not in signal_set:
        signals.append("owasp_web_parallel")
    kb["risk_signals"] = signals

    kb["mission_module_hints"] = list(mission["module_hints"])
    kb["mission_owasp_classes"] = list(mission["classes"])
    kb["planner_intelligence"] = dict(kb.get("planner_intelligence") or {})
    kb["planner_intelligence"]["specialists"] = "parallel"
    kb["planner_intelligence"]["owasp_web_parallel"] = True
    return mission


def apply_owasp_web_parallel_to_state(state: Any, *, classes: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Enable parallel specialists + seed KB on a live AgentState."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    mission = apply_owasp_web_parallel_to_kb(kb, classes=classes)
    state.specialist_parallel_enabled = True
    state.specialist_sequential_enabled = False
    # Prefer hierarchical commander so parallel specialist proposals are authorized.
    if getattr(state, "hierarchical_planner_enabled", None) is None:
        state.hierarchical_planner_enabled = True
    # Keep scan_specializations empty at start; module hints stay in mission KB for
    # reason/act specialists. Pre-seeding burned request budget on speculative scanners.
    if not getattr(state, "campaign_goal", None):
        state.campaign_goal = "exploit"
    return mission


def filter_queue_by_mission_classes(
    items: Sequence[Mapping[str, Any]],
    kb: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Keep queue items whose owasp_class is in the active mission (or all if unset)."""
    classes: Set[str] = set()
    if isinstance(kb, Mapping):
        mission = kb.get(KB_MISSION_KEY)
        if isinstance(mission, dict):
            classes = set(normalize_owasp_classes(mission.get("classes")))
        elif kb.get("mission_owasp_classes"):
            classes = set(normalize_owasp_classes(kb.get("mission_owasp_classes")))
    if not classes:
        return [dict(row) for row in items if isinstance(row, Mapping)]
    # Always keep "other" blocked items for telemetry; filter approved/queued to mission classes.
    out: List[Dict[str, Any]] = []
    for row in items:
        if not isinstance(row, Mapping):
            continue
        owasp = str(row.get("owasp_class") or "other").lower()
        if owasp in classes or owasp == "other":
            out.append(dict(row))
    return out


# Re-export for callers that only import owasp_mission.
__all__ = [
    "OWASP_CLASSES",
    "OWASP_WEB_CLASSES",
    "CLASS_SPECIALIST_KEYS",
    "CLASS_MODULE_HINTS",
    "MISSION_PROFILE_NAME",
    "KB_MISSION_KEY",
    "DEFAULT_FAN_OUT",
    "normalize_owasp_classes",
    "specialist_keys_for_classes",
    "module_hints_for_classes",
    "risk_signals_for_classes",
    "is_owasp_web_parallel_mission",
    "mission_fan_out",
    "build_owasp_web_mission",
    "apply_owasp_web_parallel_to_kb",
    "apply_owasp_web_parallel_to_state",
    "filter_queue_by_mission_classes",
]
