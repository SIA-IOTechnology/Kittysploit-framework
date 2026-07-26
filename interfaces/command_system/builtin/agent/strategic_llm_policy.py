#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adaptive LLM invocation policy for strategic agent decisions."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_constants import DISCREET_PROFILE_MAX_LLM_CALLS

DEFAULT_STRATEGIC_LLM_MODEL = "llama3.3:latest"
FALLBACK_LLM_MODEL = "llama3.1:8b"

_PROFILE_LLM_BUDGETS: Dict[str, int] = {
    "safe": 2,
    "discreet": 3,
    "normal": 5,
    "aggressive": 8,
}


def resolve_llm_model(state: Any) -> str:
    explicit = str(getattr(state, "llm_model", "") or "").strip()
    if explicit:
        return explicit
    if getattr(state, "llm_local", False):
        return DEFAULT_STRATEGIC_LLM_MODEL
    return FALLBACK_LLM_MODEL


def resolve_effective_llm_budget(state: Any) -> int:
    """Adaptive LLM call budget when a local/connected LLM is enabled."""
    if not getattr(state, "llm_local", False) and getattr(state, "local_llm", None) is None:
        return 0
    explicit = int(getattr(state, "llm_budget", 0) or 0)
    if explicit > 0:
        return explicit
    profile = str(getattr(state, "safety_profile", "normal") or "normal").strip().lower()
    base = _PROFILE_LLM_BUDGETS.get(profile, 5)
    if profile == "discreet":
        base = max(base, DISCREET_PROFILE_MAX_LLM_CALLS + 1)
    if getattr(state, "shell_hunter", False):
        base += 2
    # Extra tactical room when LLM is connected for situational recon.
    if getattr(state, "local_llm", None) is not None or getattr(state, "llm_local", False):
        base += 1
    return base


def _risk_signals(kb: Mapping[str, Any]) -> set:
    return {str(x).lower() for x in (kb.get("risk_signals") or [])}


def chain_is_blocked(kb: Mapping[str, Any]) -> bool:
    """Poisoned capabilities exist but no ready chain follow-up module."""
    try:
        from interfaces.command_system.builtin.agent.attack_chain_memory import (
            capabilities_present,
            suggest_chain_module_paths,
        )
    except Exception:
        return False
    present = capabilities_present(kb)
    if not present:
        return False
    ready = suggest_chain_module_paths(kb)
    return len(present) >= 2 and not ready


def waf_or_blocking_active(kb: Mapping[str, Any], state: Any) -> bool:
    signals = _risk_signals(kb)
    if any("waf" in sig or "blocking" in sig for sig in signals):
        return True
    reason = str(getattr(state, "campaign_stop_reason", "") or "").lower()
    return "waf" in reason or "blocking" in reason


def playbook_needs_guidance(kb: Mapping[str, Any], findings: Optional[Sequence[Any]] = None) -> bool:
    try:
        from core.playbooks.executor import pick_active_playbook, next_playbook_steps
    except Exception:
        return False
    playbook = pick_active_playbook(kb, findings)
    if not playbook:
        return False
    steps = next_playbook_steps(playbook, kb, max_steps=1)
    return bool(steps)


def api_surface_ambiguous(kb: Mapping[str, Any], state: Any = None) -> bool:
    try:
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            api_surface_ambiguous as _ambiguous,
        )

        return _ambiguous(kb, state)
    except Exception:
        return False


def http_recon_needed(kb: Mapping[str, Any], state: Any = None) -> bool:
    if api_surface_ambiguous(kb, state):
        return True
    try:
        from interfaces.command_system.builtin.agent.http_probe_actions import http_surface_observed

        if not http_surface_observed(kb, state):
            return False
    except Exception:
        return False
    endpoints = kb.get("discovered_endpoints") or []
    llm_reqs = kb.get("llm_http_requests") or []
    return len(endpoints) < 3 and len(llm_reqs) < 2


def should_force_strategic_llm(
    state: Any,
    kb: Mapping[str, Any],
    complexity: Mapping[str, Any],
    *,
    findings: Optional[Sequence[Any]] = None,
) -> bool:
    """
    Return True when the agent should invoke the LLM even for « simple » cases.
    """
    if not getattr(state, "llm_local", False) and getattr(state, "local_llm", None) is None:
        return False
    if waf_or_blocking_active(kb, state):
        return True
    if chain_is_blocked(kb):
        return True
    if playbook_needs_guidance(kb, findings):
        return True
    if api_surface_ambiguous(kb, state) or http_recon_needed(kb, state):
        return True
    if bool(complexity.get("is_complex")):
        return True
    if int(getattr(getattr(state, "metrics", None), "llm_fallback_count", 0) or 0) >= 1:
        return True
    return False


def llm_budget_remaining(state: Any) -> int:
    budget = resolve_effective_llm_budget(state)
    if budget <= 0:
        return 0
    used = int(getattr(getattr(state, "metrics", None), "llm_calls", 0) or 0)
    return max(0, budget - used)


def llm_budget_exhausted(state: Any) -> bool:
    budget = resolve_effective_llm_budget(state)
    if budget <= 0:
        return True
    return llm_budget_remaining(state) <= 0


def strategic_llm_context(
    state: Any,
    kb: Mapping[str, Any],
    complexity: Mapping[str, Any],
    *,
    findings: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Extra prompt context for strategic LLM calls."""
    triggers = []
    if waf_or_blocking_active(kb, state):
        triggers.append("waf_or_blocking")
    if chain_is_blocked(kb):
        triggers.append("chain_blocked")
    if playbook_needs_guidance(kb, findings):
        triggers.append("playbook_reachable")
    if api_surface_ambiguous(kb, state):
        triggers.append("api_surface_ambiguous")
    if http_recon_needed(kb, state):
        triggers.append("http_recon_needed")
    if complexity.get("is_complex"):
        triggers.extend(list(complexity.get("reasons") or []))

    playbook_hint = None
    try:
        from core.playbooks.executor import pick_active_playbook, next_playbook_steps

        playbook = pick_active_playbook(kb, findings)
        if playbook:
            steps = next_playbook_steps(playbook, kb, max_steps=3)
            playbook_hint = {
                "playbook_id": playbook.get("playbook_id"),
                "coverage": playbook.get("coverage"),
                "next_steps": [s.get("module") for s in steps],
                "blockers": playbook.get("blockers"),
            }
    except Exception:
        playbook_hint = None

    try:
        from interfaces.command_system.builtin.agent.attack_chain_memory import (
            capabilities_present,
            export_chain_summary,
        )

        chain_summary = export_chain_summary(kb)
        unlocked = sorted(capabilities_present(kb))
    except Exception:
        chain_summary = {}
        unlocked = []

    phase = str(getattr(state, "current_phase", "") or "reason")
    goal = str(getattr(state, "campaign_goal", "") or "")
    try:
        from interfaces.command_system.builtin.agent.operator_archetypes import (
            operator_context_for_phase,
        )

        operator = operator_context_for_phase(phase, campaign_goal=goal)
    except Exception:
        operator = {}

    packed_kb = {}
    try:
        from interfaces.command_system.builtin.agent.context_pack import pack_knowledge_context

        packed_kb = pack_knowledge_context(
            kb,
            objective=goal,
            prior_intel=str(complexity.get("summary") or ""),
        )
    except Exception:
        packed_kb = {}

    api_candidates = []
    try:
        from interfaces.command_system.builtin.agent.goal_planner import SHELL_API_MODULE_LADDER

        api_candidates = [path for path, _needle in SHELL_API_MODULE_LADDER]
    except Exception:
        api_candidates = []

    return {
        "strategic_triggers": triggers,
        "llm_budget_remaining": llm_budget_remaining(state),
        "playbook_hint": playbook_hint,
        "unlocked_capabilities": unlocked[:24],
        "attack_chain_summary": chain_summary,
        "operator": operator,
        "packed_knowledge": {
            "text": packed_kb.get("text", ""),
            "included_sections": packed_kb.get("included_sections", []),
            "dropped_sections": packed_kb.get("dropped_sections", []),
            "tokens_used": packed_kb.get("tokens_used", 0),
            "token_budget": packed_kb.get("token_budget", 0),
        },
        "recent_http_probes": list(kb.get("llm_http_requests") or [])[-8:],
        "api_module_candidates": api_candidates,
        "discovered_endpoints": list(kb.get("discovered_endpoints") or [])[:24],
    }


def strategic_llm_instruction_extension(context: Mapping[str, Any]) -> str:
    """Append to the base LLM task when strategic mode is active."""
    triggers = context.get("strategic_triggers") or []
    if not triggers:
        return ""

    parts = [
        "STRATEGIC MODE: triggers="
        + ",".join(str(t) for t in triggers[:8])
        + ". ",
    ]
    if "waf_or_blocking" in triggers:
        parts.append(
            "WAF or blocking detected: prefer low-noise validation, alternative encodings, "
            "different HTTP verbs/paths, or modules not yet blocked. "
            "Do not repeat modules that already failed with filter/blocked errors. "
        )
    if "chain_blocked" in triggers:
        parts.append(
            "Attack-chain memory has unlocked capabilities but no catalog module matched. "
            "Propose the best next run_followup or run_exploit using option_bindings from "
            "unlocked_capabilities, or a creative bounded variant (parameter rename, nested path, "
            "header-based bypass) grounded in request_intelligence — never invent out-of-scope hosts. "
        )
    if "playbook_reachable" in triggers:
        hint = context.get("playbook_hint") or {}
        steps = hint.get("next_steps") or []
        if steps:
            parts.append(
                f"A reachable playbook [{hint.get('playbook_id')}] expects next modules: "
                f"{', '.join(str(s) for s in steps[:4])}. Prefer these unless policy blocks them. "
            )
    if "api_surface_ambiguous" in triggers or "http_recon_needed" in triggers:
        parts.append(
            "ENGINEER RECON MODE: act like a security engineer controlling the tool. "
            "Form a hypothesis, issue up to a few bounded http_request probes (GET/HEAD/OPTIONS) "
            "against candidate endpoints, read status/headers/body samples, then pick the best "
            "run_followup from api_module_candidates (swagger_detect, graphql_detect, api_fuzzer, …). "
            "Do not run a fixed script — adapt to what the last probes showed. "
        )
    unlocked = context.get("unlocked_capabilities") or []
    if unlocked:
        parts.append(f"Unlocked capabilities: {', '.join(str(c) for c in unlocked[:12])}. ")
    if context.get("operator"):
        op = context["operator"]
        if isinstance(op, dict) and op.get("name"):
            parts.append(
                f"Active operator: {op.get('name')} "
                f"(archetype={op.get('archetype', '')}, maturity={op.get('maturity', '')}). "
            )
    return "".join(parts)
