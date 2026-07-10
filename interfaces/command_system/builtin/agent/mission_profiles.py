#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Predefined agent mission profiles."""

from __future__ import annotations

from typing import Any, Dict

MISSION_PROFILES: Dict[str, Dict[str, Any]] = {
    "passive": {
        "safety_profile": "safe",
        "approved_risks": ["read"],
        "request_budget": 8,
        "http_replay": "off",
        "description": "Read-only observation; no intrusive modules.",
    },
    "safe-web": {
        "safety_profile": "safe",
        "approved_risks": ["read", "active"],
        "request_budget": 20,
        "http_replay": "safe",
        "description": "Conservative web audit with declared-safe modules only.",
    },
    "authenticated-audit": {
        "safety_profile": "discreet",
        "approved_risks": ["read", "active"],
        "request_budget": 40,
        "http_replay": "safe",
        "reuse_proxy_auth": True,
        "description": "Authenticated review using approved proxy cookies.",
    },
    "api-review": {
        "safety_profile": "discreet",
        "approved_risks": ["read", "active"],
        "request_budget": 30,
        "http_replay": "safe",
        "description": "API surface validation without destructive actions.",
    },
    "internal-lab": {
        "safety_profile": "normal",
        "approved_risks": ["read", "active", "intrusive"],
        "request_budget": 80,
        "http_replay": "safe",
        "catalog_policy": "internal-lab",
        "description": "Lab environment with broader approvals.",
    },
    "bug-bounty-safe": {
        "safety_profile": "discreet",
        "approved_risks": ["read", "active"],
        "request_budget": 30,
        "http_replay": "safe",
        "catalog_policy": "bug-bounty-safe",
        "description": "Bug-bounty-safe validation; no post-exploit, payloads, DoS, persistence, or brute force.",
    },
    "detection-validation": {
        "safety_profile": "discreet",
        "approved_risks": ["read", "active"],
        "request_budget": 25,
        "campaign_goal": "detection-validation",
        "description": "Offensive signals paired with defensive validation artifacts.",
    },
    "training-lab": {
        "safety_profile": "safe",
        "approved_risks": ["read", "active"],
        "request_budget": 15,
        "plan_only": True,
        "description": "Training mode: plan without exploitation.",
    },
    "ot-safe-assessment": {
        "safety_profile": "safe",
        "approved_risks": ["read", "active"],
        "request_budget": 35,
        "campaign_goal": "recon",
        "catalog_policy": "ot-safe",
        "description": (
            "Read-only OT assessment — passive/active ICS recon, no DoS or PLC control."
        ),
    },
    "ot-safe": {
        "safety_profile": "safe",
        "approved_risks": ["read", "active"],
        "request_budget": 35,
        "campaign_goal": "recon",
        "catalog_policy": "ot-safe",
        "description": "Alias for ot-safe-assessment; strict OT recon/gather only.",
    },
    "europol-passive": {
        "safety_profile": "safe",
        "approved_risks": ["read"],
        "request_budget": 12,
        "http_replay": "off",
        "campaign_goal": "recon",
        "catalog_policy": "europol-passive",
        "plan_only": False,
        "osint_retention_days": 90,
        "osint_pseudonymize_exports": True,
        "osint_require_legal_basis": True,
        "description": (
            "Law-enforcement passive OSINT only — no active scanning, bruteforce, "
            "credential generation, or exploitation. GDPR retention defaults applied."
        ),
    },
    "infra-discovery": {
        "safety_profile": "discreet",
        "approved_risks": ["read", "active"],
        "request_budget": 70,
        "http_replay": "safe",
        "campaign_goal": "infra-discovery",
        "catalog_policy": "infra-discovery",
        "description": (
            "Network service and panel discovery with verification pass — scanner modules only. "
            "Recommended chain: network-services → devops-panels/saas-panels → verification."
        ),
    },
}


def apply_mission_profile(name: str) -> Dict[str, Any]:
    key = str(name or "").strip().lower()
    if key not in MISSION_PROFILES:
        raise ValueError(f"Unknown mission profile: {name}")
    return dict(MISSION_PROFILES[key])


def list_mission_profiles() -> Dict[str, str]:
    return {name: str(row.get("description", "")) for name, row in MISSION_PROFILES.items()}
