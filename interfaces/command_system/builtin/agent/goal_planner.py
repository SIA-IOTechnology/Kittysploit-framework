#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Goal-oriented planning defaults for agent campaigns."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

GOAL_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["dry_run_complete", "no_vulnerabilities"],
        "default_budget": 20,
        "skip_exploitation": True,
    },
    "validate": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["no_vulnerabilities"],
        "default_budget": 15,
        "skip_exploitation": True,
    },
    "obtain-auth": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 25,
        "skip_exploitation": False,
    },
    "obtain-shell": {
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 40,
        "skip_exploitation": False,
    },
    "post-auth": {
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 35,
        "skip_exploitation": False,
    },
    "evidence-only": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["dry_run_complete"],
        "default_budget": 12,
        "skip_exploitation": True,
    },
    "detection-validation": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["waf_or_blocking_detected"],
        "default_budget": 18,
        "skip_exploitation": True,
    },
    "retest": {
        "allowed_action_types": ["run_followup"],
        "terminal_conditions": ["no_vulnerabilities"],
        "default_budget": 8,
        "skip_exploitation": True,
    },
}


def normalize_goal(goal: Optional[str]) -> str:
    value = str(goal or "recon").strip().lower().replace("_", "-")
    aliases = {
        "obtain_auth": "obtain-auth",
        "obtain_shell": "obtain-shell",
        "post_auth": "post-auth",
        "evidence_only": "evidence-only",
        "detection_validation": "detection-validation",
    }
    return aliases.get(value, value)


def build_goal_plan(goal: Optional[str], *, request_budget: int = 0) -> Dict[str, Any]:
    key = normalize_goal(goal)
    if key not in GOAL_DEFINITIONS:
        raise ValueError(f"Unknown campaign goal: {goal}")
    definition = GOAL_DEFINITIONS[key]
    budget = int(request_budget or definition.get("default_budget", 20))
    return {
        "campaign_goal": key,
        "next_actions": [],
        "max_requests_next_phase": budget,
        "stop_conditions": list(definition.get("terminal_conditions", [])),
        "reasoning_confidence": 0.0,
        "skip_exploitation": bool(definition.get("skip_exploitation", False)),
        "allowed_action_types": list(definition.get("allowed_action_types", [])),
    }


def filter_actions_for_goal(
    actions: List[Dict[str, Any]],
    goal: Optional[str],
) -> List[Dict[str, Any]]:
    key = normalize_goal(goal)
    definition = GOAL_DEFINITIONS.get(key, {})
    allowed = set(definition.get("allowed_action_types", []))
    if not allowed:
        return actions
    return [
        row for row in actions
        if str(row.get("type", "")).lower() in allowed
    ]
