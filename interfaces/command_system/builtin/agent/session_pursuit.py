#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist agent campaigns with LLM-assisted replanning until a verified session exists."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.goal_planner import (
    is_shell_operator_goal,
    normalize_goal,
)
from interfaces.command_system.builtin.agent.typed_models import AgentAction


SESSION_PURSUIT_INSTRUCTION = (
    "SESSION PURSUIT MODE: continue until a verified interactive shell or session is obtained. "
    "Exhaust auth paths, web exploits, service logins, and chained follow-ups. "
    "Do not repeat failed modules; prefer novel paths from candidate_modules and selected_paths. "
    "Prioritize run_exploit and run_followup over passive recon when evidence supports weaponization."
)


@dataclass(frozen=True)
class SessionPursuitLoopLimits:
    max_iterations: int = 64
    max_replans: int = 24


def default_goal_when_unset() -> str:
    env = os.environ.get("KITTYSPLOIT_AGENT_DEFAULT_GOAL", "").strip().lower().replace("_", "-")
    if env:
        return normalize_goal(env)
    if os.environ.get("KITTYSPLOIT_AGENT_UNTIL_SESSION", "").strip().lower() in {"1", "true", "yes", "on"}:
        return "obtain-shell"
    return "obtain-shell"


def session_pursuit_active(state: Any = None) -> bool:
    if state is None:
        return False
    if getattr(state, "session_pursuit_enabled", None) is False:
        return False
    if getattr(state, "session_pursuit_enabled", None) is True:
        return True
    if getattr(state, "until_session", False):
        return True
    if getattr(state, "shell_hunter", False):
        return True
    goal = normalize_goal(getattr(state, "campaign_goal", "") or getattr(state, "operator_goal", ""))
    if is_shell_operator_goal(goal) or goal in {"post-auth", "exploit"}:
        return True
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict) and kb.get("shell_hunter_mode"):
        return True
    if os.environ.get("KITTYSPLOIT_AGENT_UNTIL_SESSION", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return False


def has_verified_session(state: Any) -> bool:
    verified = [str(s).strip() for s in (getattr(state, "verified_sessions", None) or []) if str(s).strip()]
    if verified:
        return True
    new_sess = [str(s).strip() for s in (getattr(state, "new_sessions", None) or []) if str(s).strip()]
    if new_sess:
        return True
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict):
        if kb.get("verified_session_ids"):
            return True
        blob = kb.get("session_broker")
        if isinstance(blob, dict):
            sessions = blob.get("sessions")
            if isinstance(sessions, dict):
                for row in sessions.values():
                    if (
                        isinstance(row, dict)
                        and row.get("verified")
                        and str(row.get("status") or "") == "verified"
                    ):
                        return True
    try:
        core = getattr(state, "_session_check_core", None)
        if core is not None and hasattr(core, "_has_shell_milestone"):
            return bool(core._has_shell_milestone(state))
    except Exception:
        pass
    return False


def loop_limits_for_session_pursuit(state: Any = None) -> SessionPursuitLoopLimits:
    env_iter = os.environ.get("KITTYSPLOIT_AGENT_SESSION_MAX_ITER", "").strip()
    env_replan = os.environ.get("KITTYSPLOIT_AGENT_SESSION_MAX_REPLAN", "").strip()
    base = SessionPursuitLoopLimits()
    if env_iter.isdigit():
        base = SessionPursuitLoopLimits(
            max_iterations=max(8, int(env_iter)),
            max_replans=base.max_replans,
        )
    if env_replan.isdigit():
        base = SessionPursuitLoopLimits(
            max_iterations=base.max_iterations,
            max_replans=max(4, int(env_replan)),
        )
    profile = str(getattr(state, "safety_profile", "") or "").strip().lower()
    if profile == "aggressive":
        return SessionPursuitLoopLimits(
            max_iterations=max(base.max_iterations, 80),
            max_replans=max(base.max_replans, 32),
        )
    return base


def apply_session_pursuit_defaults(
    state: Any,
    *,
    explicit_goal: Optional[str] = None,
    until_session: bool = False,
    no_exploit: bool = False,
    plan_only: bool = False,
    safety_profile: str = "normal",
) -> None:
    goal = normalize_goal(explicit_goal) if explicit_goal else ""
    if until_session or not goal:
        if not no_exploit and not plan_only and safety_profile != "safe":
            if not goal:
                goal = default_goal_when_unset()
            state.session_pursuit_enabled = True  # type: ignore[attr-defined]
            state.until_session = bool(until_session)  # type: ignore[attr-defined]
    if goal:
        state.campaign_goal = goal  # type: ignore[attr-defined]
        state.operator_goal = goal  # type: ignore[attr-defined]
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            kb["operator_campaign_goal"] = goal
            if is_shell_operator_goal(goal) or until_session:
                kb["shell_hunter_mode"] = True


def _action_from_mapping(row: Mapping[str, Any], *, default_reason: str) -> Optional[AgentAction]:
    path = str(row.get("path") or "").strip()
    if not path:
        return None
    action_type = str(row.get("type") or "run_followup").strip().lower()
    if action_type == "prioritize":
        action_type = "run_followup"
    risk = "intrusive" if action_type in {"run_exploit", "run_post"} else "active"
    if action_type == "http_request":
        risk = "read"
    try:
        priority = int(row.get("priority", 5))
    except (TypeError, ValueError):
        priority = 5
    return AgentAction(
        type=action_type,
        path=path,
        priority=max(1, min(priority, 10)),
        risk=risk,
        reason=str(row.get("reason") or default_reason)[:240],
        status="planned",
        approved=True,
        options=dict(row.get("options") or {}) if isinstance(row.get("options"), dict) else {},
    )


def _llm_session_wave(state: Any, observation: Mapping[str, Any], services: Any) -> List[AgentAction]:
    if getattr(state, "dry_run", False) or getattr(state, "plan_only", False):
        return []
    if not getattr(state, "llm_local", False) and not str(getattr(state, "llm_endpoint", "") or "").strip():
        return []
    metrics = getattr(state, "metrics", None)
    llm_budget = int(getattr(state, "llm_budget", 0) or 0)
    if llm_budget > 0 and metrics is not None:
        used = int(getattr(metrics, "llm_calls", 0) or 0)
        if used >= llm_budget:
            return []

    from interfaces.command_system.builtin.agent.planning_service import (
        PlanningService,
        build_reason_prompt_payload,
    )
    from interfaces.command_system.builtin.agent.planner_context import (
        attach_planner_context,
        build_planner_llm_context,
    )

    kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
    modules = observation.get("catalog_modules") or []
    catalog_paths = [
        str(row.get("path") or "").strip()
        for row in modules
        if isinstance(row, dict) and row.get("path")
    ][:48]
    attach_planner_context(
        state,
        observation,
        catalog_action_ids=[],
        findings=getattr(state, "vulnerable_results", None) or getattr(state, "contextual_findings", None),
        learning_store=getattr(services, "learning", None),
    )
    strategic_context = build_planner_llm_context(
        state,
        observation,
        findings=getattr(state, "vulnerable_results", None) or getattr(state, "contextual_findings", None),
        learning_store=getattr(services, "learning", None),
    )
    payload = build_reason_prompt_payload(
        raw_target=str(getattr(state, "raw_target", "") or ""),
        campaign_goal=str(getattr(state, "campaign_goal", "") or "obtain-shell"),
        auth_first=bool(getattr(state, "auth_first", False)),
        strategic_context=strategic_context,
        packed_knowledge={"text": ""},
        specialist_hints=[],
        compressed_context="",
        knowledge_base=kb if isinstance(kb, dict) else {},
        redirect_observation=None,
        auth_session=False,
        auth_context={},
        potential_findings=getattr(state, "potential_findings", []) or [],
        decision_findings=getattr(state, "vulnerable_results", []) or [],
        strategic_instruction_extension=SESSION_PURSUIT_INSTRUCTION,
    )
    payload["candidate_modules"] = catalog_paths
    payload["session_pursuit"] = True
    payload["verified_sessions"] = list(getattr(state, "verified_sessions", []) or [])

    planner = PlanningService(getattr(services, "llm", None))
    endpoint = str(getattr(state, "llm_endpoint", "") or "http://127.0.0.1:11434/api/chat")
    model = str(getattr(state, "llm_model", "") or "llama3.1:8b")
    response = planner.query_agent_reason(
        endpoint=endpoint,
        model=model,
        payload=payload,
        timeout=int(getattr(state, "llm_timeout", 30) or 30),
        goal=str(getattr(state, "campaign_goal", "") or "obtain-shell"),
        strategic=True,
    )
    if metrics is not None:
        metrics.llm_calls = int(getattr(metrics, "llm_calls", 0) or 0) + 1
    if not isinstance(response, dict):
        return []

    state.last_session_pursuit_llm = {  # type: ignore[attr-defined]
        "rationale": str(response.get("rationale") or "")[:500],
        "selected_paths": response.get("selected_paths") or [],
    }
    actions: List[AgentAction] = []
    for row in response.get("next_actions") or []:
        if not isinstance(row, dict):
            continue
        built = _action_from_mapping(row, default_reason="session_pursuit:llm")
        if built is not None:
            actions.append(built)
    for path in response.get("selected_paths") or []:
        token = str(path or "").strip()
        if not token:
            continue
        built = _action_from_mapping(
            {"type": "run_exploit" if "exploit" in token else "run_followup", "path": token},
            default_reason="session_pursuit:llm_selected",
        )
        if built is not None:
            actions.append(built)
    return actions


def plan_session_pursuit_wave(
    state: Any,
    observation: Mapping[str, Any],
    services: Any,
) -> List[AgentAction]:
    """Heuristic shell ladder + LLM reason wave when the planner queue is empty."""
    if not session_pursuit_active(state) or has_verified_session(state):
        return []

    actions: List[AgentAction] = []
    seen: set[str] = set()
    core = getattr(services, "core", None)

    if core is not None and hasattr(core, "_next_best_action_for_shell_goal"):
        kb = getattr(state, "knowledge_base", None)
        if not isinstance(kb, dict):
            kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        findings = list(getattr(state, "vulnerable_results", None) or getattr(state, "contextual_findings", None) or [])
        row = core._next_best_action_for_shell_goal(state, kb, findings)
        if isinstance(row, dict):
            built = _action_from_mapping(row, default_reason="session_pursuit:shell_ladder")
            if built is not None and built.path not in seen:
                seen.add(str(built.path))
                actions.append(built)

    for built in _llm_session_wave(state, observation, services):
        path = str(built.path or "")
        if path in seen:
            continue
        seen.add(path)
        actions.append(built)

    if not actions and core is not None:
        try:
            from interfaces.command_system.builtin.agent.adaptive_loop import AdaptiveLoopEngine

            engine = AdaptiveLoopEngine(services)
            kb = getattr(state, "knowledge_base", None) or {}
            fallback = engine._fallback_shell_auth_actions(state, kb if isinstance(kb, dict) else {})
            for row in fallback[:4]:
                path = str(row.path or "")
                if path in seen:
                    continue
                seen.add(path)
                actions.append(row)
        except Exception:
            pass

    return actions[:6]


def extend_session_pursuit_budget(state: Any, services: Any) -> bool:
    """Grant extra network budget while chasing a session (bounded extensions)."""
    if not session_pursuit_active(state) or has_verified_session(state):
        return False
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    count = int(kb.get("_session_pursuit_budget_extensions") or 0)
    max_ext = 6
    env = os.environ.get("KITTYSPLOIT_AGENT_SESSION_BUDGET_EXTENSIONS", "").strip()
    if env.isdigit():
        max_ext = max(1, int(env))
    if count >= max_ext:
        return False

    core = getattr(services, "core", None)
    if core is not None and hasattr(core, "_maybe_extend_budget_for_shell_chain"):
        if core._maybe_extend_budget_for_shell_chain(state):
            kb["_session_pursuit_budget_extensions"] = count + 1
            return True

    budget = int(getattr(state, "request_budget", 0) or 0)
    if budget <= 0:
        return False
    extend_by = 50
    state.request_budget = budget + extend_by
    network_budget = getattr(state, "network_budget", None)
    if network_budget is not None and getattr(network_budget, "bounded", False):
        try:
            network_budget.extend(extend_by, reason="session_pursuit")
        except Exception:
            pass
    kb["_session_pursuit_budget_extensions"] = count + 1
    state.campaign_stop_reason = None
    return True
