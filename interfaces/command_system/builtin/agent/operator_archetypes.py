#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Operator archetypes for the autonomous agent kill chain.

Inspired by multi-operator offensive frameworks: each workflow phase maps to a
specialized operator persona with MITRE ATT&CK tactics, capabilities, and
module-family hints. Used for decision explanations, LLM context, and reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

# Agent workflow phases → operator archetype
PHASE_OPERATOR_MAP: Dict[str, str] = {
    "init": "coordinator",
    "scan": "recon",
    "analyze": "scanner",
    "reason": "coordinator",
    "exploit": "exploiter",
    "report": "analyst",
    "catalog": "coordinator",
    "plan": "coordinator",
}

# Campaign goals that shift the active operator during exploitation
GOAL_OPERATOR_OVERRIDE: Dict[str, str] = {
    "obtain-shell": "exploiter",
    "post-auth": "infiltrator",
    "obtain-auth": "exploiter",
    "recon": "recon",
    "validate": "scanner",
    "evidence-only": "analyst",
    "detection-validation": "scanner",
    "infra-discovery": "recon",
}


@dataclass(frozen=True)
class OperatorArchetype:
    key: str
    name: str
    description: str
    mitre_tactics: Sequence[str]
    kill_chain_phases: Sequence[str]
    capabilities: Sequence[str]
    module_families: Sequence[str]
    techniques: Sequence[str]
    maturity: str = "stable"  # stable | experimental | planned


ARCHETYPE_PROFILES: Dict[str, OperatorArchetype] = {
    "recon": OperatorArchetype(
        key="recon",
        name="Reconnaissance Operator",
        description="OSINT, surface discovery, and passive/active enumeration",
        mitre_tactics=("TA0043",),
        kill_chain_phases=("recon",),
        capabilities=("osint", "dns_enum", "subdomain_discovery", "port_scanning", "service_detection"),
        module_families=("scanner", "auxiliary/scanner", "osint"),
        techniques=("T1595", "T1592", "T1589", "T1590"),
        maturity="stable",
    ),
    "scanner": OperatorArchetype(
        key="scanner",
        name="Vulnerability Scanner",
        description="Identifies vulnerabilities and security misconfigurations",
        mitre_tactics=("TA0007",),
        kill_chain_phases=("weaponize",),
        capabilities=("vuln_scanning", "web_scanning", "config_audit"),
        module_families=("scanner", "auxiliary/scanner"),
        techniques=("T1046", "T1082", "T1083"),
        maturity="stable",
    ),
    "exploiter": OperatorArchetype(
        key="exploiter",
        name="Exploitation Specialist",
        description="Executes exploits and achieves initial access",
        mitre_tactics=("TA0001", "TA0002"),
        kill_chain_phases=("deliver", "exploit"),
        capabilities=("initial_access", "code_execution", "payload_delivery"),
        module_families=("exploits", "auxiliary"),
        techniques=("T1190", "T1133", "T1078", "T1059"),
        maturity="stable",
    ),
    "infiltrator": OperatorArchetype(
        key="infiltrator",
        name="Lateral Movement Specialist",
        description="Privilege escalation, credential reuse, and pivoting",
        mitre_tactics=("TA0008", "TA0004"),
        kill_chain_phases=("install",),
        capabilities=("priv_esc", "lateral_movement", "credential_access"),
        module_families=("post", "auxiliary", "exploits"),
        techniques=("T1021", "T1078", "T1068", "T1548"),
        maturity="experimental",
    ),
    "exfiltrator": OperatorArchetype(
        key="exfiltrator",
        name="Data Collection Specialist",
        description="Collects and stages sensitive data",
        mitre_tactics=("TA0009", "TA0010"),
        kill_chain_phases=("actions",),
        capabilities=("data_collection", "staging"),
        module_families=("post", "auxiliary"),
        techniques=("T1041", "T1048", "T1567"),
        maturity="experimental",
    ),
    "ghost": OperatorArchetype(
        key="ghost",
        name="Persistence Specialist",
        description="Persistence and evasion (policy-gated)",
        mitre_tactics=("TA0003", "TA0005"),
        kill_chain_phases=("install", "c2"),
        capabilities=("persistence", "evasion"),
        module_families=("post",),
        techniques=("T1547", "T1053", "T1070"),
        maturity="planned",
    ),
    "coordinator": OperatorArchetype(
        key="coordinator",
        name="Mission Coordinator",
        description="Orchestrates phases, plans next actions, enforces RoE",
        mitre_tactics=("TA0011",),
        kill_chain_phases=("c2",),
        capabilities=("orchestration", "task_management", "decision_making"),
        module_families=(),
        techniques=("T1071", "T1573"),
        maturity="stable",
    ),
    "analyst": OperatorArchetype(
        key="analyst",
        name="Security Analyst",
        description="Analyzes findings, evidence quality, and reporting",
        mitre_tactics=(),
        kill_chain_phases=("actions",),
        capabilities=("analysis", "reporting", "risk_assessment"),
        module_families=("analysis",),
        techniques=(),
        maturity="stable",
    ),
}


def resolve_operator_for_phase(
    phase: str,
    *,
    campaign_goal: str = "",
    module_path: str = "",
) -> OperatorArchetype:
    """Return the active operator archetype for a workflow phase."""
    goal_key = str(campaign_goal or "").strip().lower().replace("_", "-")
    phase_key = str(phase or "init").strip().lower()

    if phase_key == "exploit" and goal_key in GOAL_OPERATOR_OVERRIDE:
        archetype_key = GOAL_OPERATOR_OVERRIDE[goal_key]
    else:
        archetype_key = PHASE_OPERATOR_MAP.get(phase_key, "coordinator")

    low_path = str(module_path or "").lower()
    if low_path.startswith("post/"):
        archetype_key = "infiltrator"
    elif low_path.startswith("analysis/"):
        archetype_key = "analyst"
    elif low_path.startswith("exploits/") and phase_key in {"exploit", "reason"}:
        archetype_key = "exploiter"

    return ARCHETYPE_PROFILES.get(archetype_key, ARCHETYPE_PROFILES["coordinator"])


def operator_context_for_phase(
    phase: str,
    *,
    campaign_goal: str = "",
    module_path: str = "",
) -> Dict[str, Any]:
    """Serialize operator context for LLM payloads and timeline events."""
    op = resolve_operator_for_phase(phase, campaign_goal=campaign_goal, module_path=module_path)
    return {
        "archetype": op.key,
        "name": op.name,
        "phase": str(phase or ""),
        "campaign_goal": str(campaign_goal or ""),
        "mitre_tactics": list(op.mitre_tactics),
        "capabilities": list(op.capabilities),
        "module_families": list(op.module_families),
        "maturity": op.maturity,
        "description": op.description,
    }


def list_operator_profiles() -> List[Dict[str, Any]]:
    """Return all archetype profiles for doctor/status output."""
    rows: List[Dict[str, Any]] = []
    for key, profile in ARCHETYPE_PROFILES.items():
        rows.append({
            "archetype": key,
            "name": profile.name,
            "description": profile.description,
            "mitre_tactics": list(profile.mitre_tactics),
            "capabilities": list(profile.capabilities),
            "maturity": profile.maturity,
        })
    return rows


def mission_operator_summary(
    timeline: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    current_phase: str = "",
    campaign_goal: str = "",
) -> Dict[str, Any]:
    """Summarize which operators were active during a run."""
    phases_seen: List[str] = []
    if timeline:
        for row in timeline:
            if not isinstance(row, Mapping):
                continue
            phase = str(row.get("phase") or "").strip()
            if phase and phase not in phases_seen:
                phases_seen.append(phase)
    if current_phase and current_phase not in phases_seen:
        phases_seen.append(current_phase)

    operators = [
        operator_context_for_phase(p, campaign_goal=campaign_goal)
        for p in phases_seen
    ]
    active = resolve_operator_for_phase(
        current_phase or (phases_seen[-1] if phases_seen else "init"),
        campaign_goal=campaign_goal,
    )
    return {
        "active_operator": active.key,
        "active_name": active.name,
        "phases_covered": phases_seen,
        "operators_by_phase": operators,
        "campaign_goal": str(campaign_goal or ""),
    }
