#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Multi-turn LLM tool loop for off-catalog / terminal / browser autonomy."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.adhoc_autonomy import adhoc_autonomy_enabled, adhoc_max_turns
from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event
from interfaces.command_system.builtin.agent.agent_runtime_tools import (
    AgentRuntimeToolExecutor,
    runtime_tools_for_llm,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import AgentAction


ADHOC_TOOL_INSTRUCTION = (
    "You are the KittySploit ad hoc operator. Pick ONE tool per turn to progress the campaign "
    "toward the stated goal. Prefer framework modules when a path is known; use discover_modules "
    "when stuck; use http_request for quick validation; use framework_command for sessions/browser_server; "
    "use browser_eval only when a browser hook session exists; use shell_exec for local recon helpers "
    "(curl/openssl/nmap) when modules are insufficient. Stay in scope. Reply JSON only with keys: "
    "tool (string), arguments (object), rationale (string), done (boolean optional)."
)


def _tool_history(state: Any) -> List[Dict[str, Any]]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    rows = kb.get("adhoc_tool_history") or []
    return [row for row in rows if isinstance(row, dict)][-12:]


def _record_tool_history(state: Any, step: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return
    rows = list(kb.get("adhoc_tool_history") or [])
    rows.append(sanitize_nested({
        "tool": step.get("tool"),
        "arguments": step.get("arguments"),
        "ok": result.get("ok"),
        "error": result.get("error"),
    }))
    kb["adhoc_tool_history"] = rows[-24:]


def build_adhoc_tool_payload(state: Any, observation: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    kb = getattr(state, "knowledge_base", {}) or {}
    obs = observation or {}
    target = str(getattr(state, "raw_target", "") or "")
    return sanitize_nested({
        "target": target,
        "campaign_goal": getattr(state, "campaign_goal", "") or getattr(state, "operator_goal", ""),
        "phase": getattr(state, "current_phase", ""),
        "risk_signals": list(kb.get("risk_signals") or [])[:24],
        "discovered_endpoints": list(kb.get("discovered_endpoints") or [])[:20],
        "observed_modules": list(kb.get("observed_modules") or [])[-20:],
        "adhoc_discovered_modules": list(kb.get("adhoc_discovered_modules") or [])[-15:],
        "recent_http": list(kb.get("llm_http_requests") or [])[-5:],
        "catalog_hint_count": len(obs.get("catalog_modules") or []),
        "new_sessions": list(getattr(state, "new_sessions", []) or [])[:8],
        "runtime_tools": runtime_tools_for_llm(),
        "prior_tool_steps": _tool_history(state),
        "stop_reason": getattr(state, "campaign_stop_reason", None),
    })


def plan_adhoc_tool_step(
    state: Any,
    services: Any,
    observation: Optional[Mapping[str, Any]] = None,
    *,
    allow_heuristic: bool = True,
) -> Optional[Dict[str, Any]]:
    step: Optional[Dict[str, Any]] = None
    llm = getattr(services, "llm", None)
    endpoint = str(getattr(state, "llm_endpoint", "") or "")
    model = str(getattr(state, "llm_model", "") or "")
    if llm is not None and endpoint and model and getattr(state, "llm_local", False):
        payload = build_adhoc_tool_payload(state, observation)
        step = llm.query_raw_json(
            endpoint=endpoint,
            model=model,
            instruction=ADHOC_TOOL_INSTRUCTION,
            payload=payload,
            timeout=45,
            allow_remote=bool(getattr(state, "llm_allow_remote", False)),
        )
        if not isinstance(step, dict):
            step = None
    if step is None and allow_heuristic:
        try:
            from interfaces.command_system.builtin.agent.adhoc_heuristics import heuristic_adhoc_step

            step = heuristic_adhoc_step(state)
        except Exception:
            step = None
    if not isinstance(step, dict):
        return None
    tool = str(step.get("tool") or "").strip()
    if not tool and step.get("done"):
        return {"tool": "done", "arguments": {"reason": step.get("rationale") or "llm_done"}}
    if not tool:
        return None
    return {
        "tool": tool,
        "arguments": step.get("arguments") if isinstance(step.get("arguments"), dict) else {},
        "rationale": str(step.get("rationale") or "")[:500],
    }


def adhoc_turn_to_actions(state: Any, step: Mapping[str, Any], result: Mapping[str, Any]) -> List[AgentAction]:
    tool = str(step.get("tool") or "").lower()
    if tool != "run_module" or not result.get("ok"):
        discovered = (getattr(state, "knowledge_base", {}) or {}).get("adhoc_discovered_modules") or []
        if tool == "discover_modules" and discovered:
            path = str(discovered[-1])
            return [
                AgentAction(
                    type="run_exploit" if path.startswith("exploits/") else "run_followup",
                    path=path,
                    priority=70,
                    risk="intrusive" if path.startswith("exploits/") else "active",
                    reason="adhoc:discover_followup",
                    status="planned",
                )
            ]
        return []
    path = str((step.get("arguments") or {}).get("path") or result.get("path") or "")
    if path:
        return []
    return []


def run_adhoc_tool_turn(
    state: Any,
    services: Any,
    observation: Optional[Mapping[str, Any]] = None,
    *,
    actor: str = "adhoc_loop",
) -> bool:
    """Execute one LLM-planned tool step. Returns True if the caller should retry planning."""
    if not adhoc_autonomy_enabled(state):
        return False
    step = plan_adhoc_tool_step(state, services, observation)
    if step is None:
        return False
    tool = str(step.get("tool") or "").lower()
    if tool == "done":
        append_journal_event(state, kind="adhoc_done", summary=str(step.get("rationale") or "done"), actor=actor)
        return False
    executor = AgentRuntimeToolExecutor(state, services)
    result = executor.handle(tool, step.get("arguments") or {})
    _record_tool_history(state, step, result)
    metrics = getattr(state, "metrics", None)
    if metrics is not None and not str(step.get("rationale") or "").startswith("heuristic:"):
        metrics.llm_calls = int(getattr(metrics, "llm_calls", 0) or 0) + 1
    summary = f"{tool}: {'ok' if result.get('ok') else 'fail'} — {step.get('rationale') or result.get('error') or ''}"
    append_journal_event(
        state,
        kind="adhoc_tool",
        summary=summary[:500],
        payload={"tool": tool, "result_ok": result.get("ok"), "error": result.get("error")},
        actor=actor,
    )
    try:
        from interfaces.command_system.builtin.agent.session_pursuit import has_verified_session

        if has_verified_session(state):
            state.campaign_stop_reason = None
            return False
    except Exception:
        pass
    return bool(result.get("ok")) or tool in {"discover_modules", "framework_command", "browser_eval"}


def run_adhoc_tool_tail(state: Any, services: Any, loop_state: Any = None) -> None:
    if not adhoc_autonomy_enabled(state):
        return
    try:
        from interfaces.command_system.builtin.agent.session_pursuit import has_verified_session, session_pursuit_active
    except Exception:
        has_verified_session = lambda _s: False  # noqa: E731
        session_pursuit_active = lambda _s: False  # noqa: E731

    observation: Dict[str, Any] = {}
    engine = getattr(services, "adaptive_engine", None)
    if engine is not None and hasattr(engine, "_default_observe"):
        try:
            observation = engine._default_observe(state)
        except Exception:
            observation = {}

    turns = adhoc_max_turns(state)
    for _ in range(turns):
        if session_pursuit_active(state) and has_verified_session(state):
            break
        if not run_adhoc_tool_turn(state, services, observation, actor="adhoc_tail"):
            break
    if loop_state is not None:
        pivots = list(getattr(loop_state, "pivots", []) or [])
        pivots.append("adhoc_tool_tail")
        loop_state.pivots = pivots


def try_adhoc_recovery_actions(
    state: Any,
    services: Any,
    observation: Mapping[str, Any],
) -> List[AgentAction]:
    """When the catalog planner is empty, run one ad hoc tool turn and surface follow-up actions."""
    if not adhoc_autonomy_enabled(state):
        return []
    step = plan_adhoc_tool_step(state, services, observation)
    if step is None:
        return []
    if str(step.get("tool") or "").lower() == "done":
        return []
    executor = AgentRuntimeToolExecutor(state, services)
    result = executor.handle(str(step.get("tool")), step.get("arguments") or {})
    _record_tool_history(state, step, result)
    append_journal_event(
        state,
        kind="adhoc_recovery",
        summary=f"recovery {step.get('tool')}",
        payload={"ok": result.get("ok")},
        actor="adhoc_recovery",
    )
    return adhoc_turn_to_actions(state, step, result)
