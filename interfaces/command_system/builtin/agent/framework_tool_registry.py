#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Framework tools exposed to the mission orchestrator LLM (validated, policy-bound)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.domain_agent_roles import DOMAIN_AGENT_KEYS, roster_for_llm
from interfaces.command_system.builtin.agent.redaction import sanitize_nested


@dataclass(frozen=True)
class FrameworkToolSpec:
    name: str
    description: str
    parameters: Mapping[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": dict(self.parameters),
        }


FRAMEWORK_TOOLS: Sequence[FrameworkToolSpec] = (
    FrameworkToolSpec(
        name="delegate_domain_agents",
        description=(
            "Activate one or more domain agents for this planning cycle. "
            "Each agent proposes read-only module/http actions from the admissible catalog."
        ),
        parameters={
            "domains": (
                "array of strings: web | sql | ad | network | post | cloud | cms | "
                "services | osint | identity | ot"
            ),
            "rationale": "string, max 500 chars",
        },
    ),
    FrameworkToolSpec(
        name="rank_catalog_action",
        description=(
            "Pick a single action_id from admissible_actions when no domain agent fits "
            "or a direct probe is faster."
        ),
        parameters={
            "action_id": "string, must exist in admissible_actions",
            "hypothesis": "string",
            "confidence": "number 0..1",
        },
    ),
    FrameworkToolSpec(
        name="http_request",
        description=(
            "Schedule one bounded in-scope HTTP request (GET/HEAD/OPTIONS) via catalog "
            "when routing/auth/version must be clarified before modules."
        ),
        parameters={
            "action_id": "string for an http_request catalog row",
            "method": "GET | HEAD | OPTIONS",
        },
    ),
    FrameworkToolSpec(
        name="run_module",
        description="Run a KittySploit module path already present in admissible_actions.",
        parameters={
            "action_id": "string",
            "options": "object, optional module options",
        },
    ),
    FrameworkToolSpec(
        name="search_modules",
        description="Semantic hint for module discovery (delegates to framework search, read-only).",
        parameters={
            "terms": "array of short search tokens",
            "families": "array of module family prefixes",
        },
    ),
    FrameworkToolSpec(
        name="shell_exec",
        description="Local allowlisted command (curl, nmap, openssl) when modules cannot express the step.",
        parameters={"command": "string", "timeout": "optional seconds"},
    ),
    FrameworkToolSpec(
        name="framework_command",
        description="Native KittySploit CLI (browser_server, sessions, use/run module).",
        parameters={"command": "string command line"},
    ),
    FrameworkToolSpec(
        name="browser_eval",
        description="Queue JS on an active browser_server hook session.",
        parameters={"session_id": "optional string", "code": "javascript"},
    ),
    FrameworkToolSpec(
        name="discover_modules",
        description="Off-catalog module search by keywords/CVE/tags.",
        parameters={"terms": "array of strings", "limit": "optional int"},
    ),
)


def tools_prompt_block() -> List[Dict[str, Any]]:
    return [tool.to_dict() for tool in FRAMEWORK_TOOLS]


def orchestrator_tooling_context(
    *,
    kb: Mapping[str, Any],
    admissible_count: int,
    phase: str,
    campaign_goal: str,
) -> Dict[str, Any]:
    return sanitize_nested({
        "phase": phase,
        "campaign_goal": campaign_goal,
        "admissible_action_count": admissible_count,
        "domain_agents": roster_for_llm(),
        "framework_tools": tools_prompt_block(),
        "knowledge_signals": {
            "risk_signals": list(kb.get("risk_signals") or [])[:24],
            "tech_hints": list(kb.get("tech_hints") or [])[:16],
            "protocol": kb.get("protocol"),
            "services": list(kb.get("identified_services") or kb.get("services") or [])[:12],
        },
    })


def parse_orchestrator_response(payload: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return None
    domains_raw = payload.get("delegate_domains") or payload.get("domains") or []
    if not isinstance(domains_raw, list):
        domains_raw = []
    domains: List[str] = []
    allowed = {k for k in DOMAIN_AGENT_KEYS if k != "orchestrator"}
    for item in domains_raw:
        token = str(item or "").strip().lower()
        if token in allowed and token not in domains:
            domains.append(token)
    rationale = str(payload.get("rationale") or "")[:500]
    try:
        confidence = float(payload.get("reasoning_confidence") or payload.get("confidence") or 0.6)
    except (TypeError, ValueError):
        confidence = 0.6
    confidence = max(0.0, min(1.0, confidence))
    tool = str(payload.get("tool") or payload.get("preferred_tool") or "delegate_domain_agents").strip().lower()
    action_id = str(payload.get("action_id") or "").strip()
    return {
        "domains": domains,
        "rationale": rationale,
        "confidence": confidence,
        "tool": tool,
        "action_id": action_id or None,
    }
