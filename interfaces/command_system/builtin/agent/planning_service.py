#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared LLM planning helpers for the agent workflow and MCP bridge."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.llm_response_cache import get_llm_response_cache
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

AGENT_REASON_INSTRUCTION = (
    "You are a pentest planning assistant operating as a mission coordinator. "
    "Reply ONLY a valid JSON object. "
    "Required keys: selected_paths (array), rationale (string). "
    "Optional keys: next_actions (array of {type,path,priority,options}), "
    "max_requests_next_phase (int), stop_conditions (array), reasoning_confidence (0..1). "
    "Allowed next_actions.type values: prioritize, http_request, surface_scan, run_followup, run_exploit, run_post, skip. "
    "Use http_request for one bounded in-scope HTTP request when a raw response will clarify routing, "
    "auth state, version, CSRF token, API shape, or exploit preconditions; set path to a target-relative "
    "path or same-target URL and options.method to GET/HEAD/OPTIONS unless active replay is explicitly needed. "
    "Use surface_scan as a bounded equivalent of `scanner -u` when the stack/surface is still unclear; "
    "set options.limit low (e.g. 4-8) and optional options.protocol. "
    "Use run_followup for scanner/auxiliary validation, run_post for post/ modules, "
    "run_exploit for exploits/ paths. "
    "Use run_followup when manual verification is needed for potential vulnerabilities."
)

MCP_SEARCH_ASSIST_INSTRUCTION = (
    "You are KittySploit's search-query assistant. "
    "Reply ONLY a valid JSON object. "
    "Required keys: search_terms (array), module_types (array), rationale (string). "
    "Optional keys: rewritten_request (string), boost_terms (array), intent_override (string), "
    "target_hint (string), reasoning_confidence (0..1). "
    "Use only module_types from the provided module_families list. "
    "search_terms must be short tokens or short phrases useful for matching module paths, names, tags, or descriptions."
)

MCP_NATURAL_PLANNER_INSTRUCTION = (
    "You are KittySploit MCP's natural-language planner. "
    "Reply ONLY a valid JSON object. "
    "Required keys: rationale (string), command_sequence (array), selected_paths (array). "
    "Optional keys: should_execute_now (boolean), execution_mode (string), reasoning_confidence (0..1), notes (array). "
    "Each item of command_sequence must be an object with keys: command (string), reason (string). "
    "Use only realistic KittySploit commands. Prefer safe stateful preparation commands first. "
    "Do not invent modules outside candidate_modules unless they are already in selected_paths."
)


def slim_strategic_context(strategic_context: Mapping[str, Any]) -> Dict[str, Any]:
    """Drop packed knowledge already sent in the primary context block."""
    if not isinstance(strategic_context, Mapping):
        return {}
    return {
        key: value
        for key, value in strategic_context.items()
        if key != "packed_knowledge"
    }


def build_reason_prompt_payload(
    *,
    raw_target: str,
    campaign_goal: str,
    auth_first: bool,
    strategic_context: Mapping[str, Any],
    packed_knowledge: Mapping[str, Any],
    specialist_hints: Sequence[Any],
    compressed_context: str,
    knowledge_base: Mapping[str, Any],
    redirect_observation: Any,
    auth_session: bool,
    auth_context: Mapping[str, Any],
    potential_findings: Sequence[Any],
    decision_findings: Sequence[Any],
    strategic_instruction_extension: str,
) -> Dict[str, Any]:
    """Build a deduplicated reason-phase payload for the local LLM."""
    request_intel = (
        knowledge_base.get("request_intel", {})
        if isinstance(knowledge_base.get("request_intel", {}), dict)
        else {}
    )
    packed_text = str(packed_knowledge.get("text") or "")[:6000]
    auth_task = (
        (
            "AUTH-FIRST MODE ACTIVE: login surface confirmed with known login_paths, no authenticated session, no CMS lock. "
            "Put 'auxiliary/scanner/http/login/admin_login_bruteforce' as the FIRST run_followup (priority 1). "
            "Do not allocate budget to spa_scanner, security_headers, sensitive_files, robots/crawler, or generic tech detection until auth is resolved or bruteforce is exhausted. "
        )
        if auth_first
        else ""
    )
    base_task = (
        "You operate as a security engineer controlling this framework for strategy.campaign_goal. "
        "Do not follow a fixed script: adapt next probes and modules to observations. "
        "Prefer a coherent mini-plan: optional http_request probes (up to 5), then one priority-1 "
        "run_followup or run_exploit grounded in evidence. "
        "Return strict JSON with keys: "
        "selected_paths (array, optional legacy hints), rationale (string), "
        "next_actions (array of objects: {type, path, priority, options}), "
        "max_requests_next_phase (int, keep this low, e.g. 2-6), stop_conditions (array), reasoning_confidence (0..1). "
        "Use next_actions.type='surface_scan' when you need a compact scanner -u style overview before going deeper. "
        "You may emit several next_actions.type='http_request' for a bounded mini-batch of in-scope probes "
        "(path plus options.method/headers/body; prefer GET/HEAD/OPTIONS) to disambiguate APIs/endpoints "
        "before selecting swagger/graphql/api_fuzzer or other catalog modules. "
        "If root response is a redirect (e.g. 301/302) or there is very little discovery surface, assume it is an authentication portal. "
        "In that case, explicitly prioritize 'auxiliary/scanner/http/login/admin_login_bruteforce' for bruteforcing instead of noisy or broad crawler fuzzing. "
        "Use request_intelligence.interesting_requests as concrete observed traffic: prefer modules that fit captured endpoints, parameters, methods, auth boundaries, and replay results. "
        "If post_auth_context.authenticated_session is true, a credential milestone succeeded: use landing_html_excerpt only as evidence "
        "(infer stack from distinctive tokens and structure; do not invent a product unless the HTML supports it). "
        "When credential_reuse_ready is true, prefer authenticated follow-up or exploit paths and keep reusing the known login path/cookies instead of re-running login discovery. "
        "After a valid access, keep pushing toward a session/shell with grounded exploit paths before resuming any generic crawling. "
        "Prefer next_actions that align matched_catalog_paths_from_landing_html with run_followup/run_exploit when paths exist in the catalog. "
        "If matches are empty or low confidence, propose a short crawler pass then narrow XSS/SQLi/LFI only on parameters/endpoints that were actually observed. "
        "Avoid paths tied to outbound email, newsletters, ticketing, or mass messaging (irresponsible / noisy). "
        "Be methodical: one coherent hypothesis per phase, small request budgets."
    )
    post_auth_context: Dict[str, Any] = {
        "authenticated_session": auth_session,
        "credential_reuse_ready": bool(auth_context),
    }
    if auth_session or auth_first:
        post_auth_context.update(
            {
                "auth_milestone": knowledge_base.get("auth_milestone", {}),
                "login_path": auth_context.get("login_path", ""),
                "landing_path": auth_context.get("final_path", ""),
                "has_session_cookie": bool((auth_context.get("cookies") or {})),
                "matched_catalog_paths_from_landing_html": knowledge_base.get("post_auth_catalog_paths", [])[:20],
                "landing_html_excerpt": (knowledge_base.get("authenticated_page_excerpt") or "")[:2500],
            }
        )

    return sanitize_nested(
        {
            "target": raw_target,
            "strategy": {
                "campaign_goal": campaign_goal,
                "auth_first_mode": auth_first,
                "strategic_mode": bool(strategic_context.get("strategic_triggers")),
            },
            "strategic_context": slim_strategic_context(strategic_context),
            "knowledge_context": {
                "packed_text": packed_text,
                "included_sections": packed_knowledge.get("included_sections", []),
                "dropped_sections": packed_knowledge.get("dropped_sections", []),
                "compressed_summary": compressed_context,
                "endpoint_count": len(knowledge_base.get("discovered_endpoints", [])),
                "parameter_count": len(knowledge_base.get("discovered_params", [])),
                "redirect_observation": redirect_observation,
                "request_intelligence": {
                    "captured_flows": request_intel.get("analyzed_flows", 0),
                    "interesting_requests": request_intel.get("interesting_requests", [])[:10],
                    "sent_requests": request_intel.get("sent_requests", [])[:6],
                }
                if request_intel
                else {},
                "recent_http_probes": list(knowledge_base.get("llm_http_requests") or [])[-8:],
                "api_module_candidates": list(
                    strategic_context.get("api_module_candidates")
                    or [
                        "scanner/http/swagger_detect",
                        "scanner/http/graphql_detect",
                        "auxiliary/scanner/http/api_fuzzer",
                    ]
                ),
                "discovered_endpoints": list(knowledge_base.get("discovered_endpoints") or [])[:24],
                "module_catalog": {
                    "total_modules": knowledge_base.get("module_capability_catalog", {}).get("total_modules", 0),
                    "by_family": knowledge_base.get("module_capability_catalog", {}).get("by_family", {}),
                    "notable_modules": knowledge_base.get("module_capability_catalog", {}).get("notable_modules", [])[:40],
                },
            },
            "post_auth_context": post_auth_context,
            "specialist_hints": list(specialist_hints or [])[:3],
            "potential_findings": [
                {
                    "path": item.get("path"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                }
                for item in (potential_findings or [])[:20]
                if isinstance(item, dict)
            ],
            "vulnerabilities": [
                {
                    "path": item.get("path"),
                    "module": item.get("module"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                    "exploit_module": item.get("exploit_module"),
                    "context_score": item.get("context_score"),
                    "context_hints": item.get("context_hints", []),
                    "evidence_state": item.get("evidence_state"),
                    "proof_quality": item.get("proof_quality"),
                }
                for item in (decision_findings or [])
                if isinstance(item, dict)
            ],
            "task": auth_task + base_task + str(strategic_instruction_extension or ""),
        }
    )


class PlanningService:
    """Unified JSON planning queries with optional response caching."""

    def __init__(self, llm_service: Any, *, cache_enabled: bool = True) -> None:
        self._llm = llm_service
        self._cache_enabled = cache_enabled
        self._cache = get_llm_response_cache()

    def query_json_cached(
        self,
        *,
        phase: str,
        endpoint: str,
        model: str,
        instruction: str,
        payload: Dict[str, Any],
        timeout: int = 20,
        goal: str = "",
        allow_remote: bool = False,
        on_cache_hit: Optional[Callable[[], None]] = None,
    ) -> Optional[Dict[str, Any]]:
        safe_payload = sanitize_nested(payload)
        cache_key = self._cache.cache_key(
            phase=phase,
            model=model,
            endpoint=endpoint,
            goal=goal,
            payload=safe_payload,
        )
        if self._cache_enabled:
            cached = self._cache.get(cache_key)
            if cached is not None:
                if on_cache_hit is not None:
                    on_cache_hit()
                return cached

        response = self._llm.query_json(
            endpoint=endpoint,
            model=model,
            instruction=instruction,
            payload=safe_payload,
            timeout=timeout,
            allow_remote=allow_remote,
        )
        if isinstance(response, dict) and self._cache_enabled:
            self._cache.put(cache_key, response)
        return response

    def query_agent_reason(
        self,
        *,
        endpoint: str,
        model: str,
        payload: Dict[str, Any],
        timeout: int = 25,
        goal: str = "",
        strategic: bool = False,
        on_cache_hit: Optional[Callable[[], None]] = None,
    ) -> Optional[Dict[str, Any]]:
        instruction = AGENT_REASON_INSTRUCTION
        if strategic:
            instruction += (
                " STRATEGIC MODE: chain or WAF blockers may be present in strategic_context. "
                "Prefer grounded bypass variants, option_bindings from unlocked_capabilities, "
                "and playbook_hint next_steps over repeating failed modules."
            )
        return self.query_json_cached(
            phase="agent_reason",
            endpoint=endpoint,
            model=model,
            instruction=instruction,
            payload=payload,
            timeout=timeout,
            goal=goal,
            on_cache_hit=on_cache_hit,
        )
