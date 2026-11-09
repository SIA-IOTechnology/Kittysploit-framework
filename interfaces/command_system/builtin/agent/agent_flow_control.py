#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Flow control API: status, patch subtasks, operator answer (PentAGI flow management)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_flow_barrier import (
    flow_awaiting_operator,
    submit_operator_answer,
)
from interfaces.command_system.builtin.agent.plan_subtask_refiner import apply_subtask_patch
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_campaign_memory import search_typed_memory


def get_flow_status(state: Any, *, verbose: bool = False) -> Dict[str, Any]:
    kb = getattr(state, "knowledge_base", None)
    kb_map = kb if isinstance(kb, dict) else {}
    flow = kb_map.get("agent_flow") if isinstance(kb_map.get("agent_flow"), dict) else {}
    subtasks = list(flow.get("subtasks") or [])
    planned = [s for s in subtasks if isinstance(s, dict) and s.get("status") == "planned"]
    done = [s for s in subtasks if isinstance(s, dict) and s.get("status") == "done"]
    barrier = flow.get("barrier") if isinstance(flow.get("barrier"), dict) else None
    validation = kb_map.get("finding_validation_queue") if isinstance(kb_map.get("finding_validation_queue"), dict) else {}
    power: Dict[str, Any] = {}
    try:
        from interfaces.command_system.builtin.agent.compound_validation_engine import power_status

        power = power_status(kb_map)
    except Exception:
        pass
    status = sanitize_nested({
        "run_id": getattr(state, "run_id", None),
        "power": power,
        "campaign_goal": getattr(state, "campaign_goal", None),
        "phase": getattr(state, "current_phase", None),
        "campaign_stop_reason": getattr(state, "campaign_stop_reason", None),
        "awaiting_operator": flow_awaiting_operator(kb_map),
        "barrier": barrier if verbose else ({"type": barrier.get("type")} if barrier else None),
        "subtasks_planned": len(planned),
        "subtasks_done": len(done),
        "subtasks": subtasks if verbose else subtasks[:16],
        "plan_revision": int((kb_map.get("plan_recalc") or {}).get("revision") or 0),
        "validation_pending": len([
            r for r in (validation.get("pending") or []) if isinstance(r, dict)
        ]),
        "journal_tail": (getattr(state, "run_journal", []) or [])[-8:] if verbose else [],
        "typed_memory_hits": search_typed_memory(kb_map, query="", limit=4) if verbose else [],
    })
    return status


def patch_planned_subtasks(state: Any, operations: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return {"applied": [], "error": "no knowledge_base"}
    return apply_subtask_patch(kb, operations, state=state)


def request_flow_stop(state: Any, *, reason: str = "operator_stop") -> Dict[str, Any]:
    token = str(reason or "operator_stop")[:120]
    state.campaign_stop_reason = token
    setattr(state, "operator_stop_requested", True)
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict):
        flow = kb.setdefault("agent_flow", {})
        flow["stop_requested"] = True
        flow["stop_reason"] = token
    return {"stopped": True, "reason": token}


def _load_state_from_run_checkpoint(run_id: str, framework: Any = None) -> Any:
    from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore
    from interfaces.command_system.builtin.agent.state import agent_state_from_dict

    paths = AgentPathService(framework)
    store = AgentRunStore(paths, run_id)
    payload = store.load_checkpoint()
    if not payload:
        return None
    inner = payload.get("state") if isinstance(payload.get("state"), dict) else {}
    return agent_state_from_dict(inner)


def flow_status_for_run_id(run_id: str, framework: Any = None, *, verbose: bool = False) -> Dict[str, Any]:
    state = _load_state_from_run_checkpoint(run_id, framework)
    if state is None:
        return {"error": "checkpoint_not_found", "run_id": run_id}
    status = get_flow_status(state, verbose=verbose)
    status["run_id"] = run_id
    return status


def patch_checkpoint_subtasks(
    run_id: str,
    operations: Sequence[Mapping[str, Any]],
    framework: Any = None,
) -> Dict[str, Any]:
    from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore
    from interfaces.command_system.builtin.agent.state import agent_state_checkpoint_dict, agent_state_from_dict

    state = _load_state_from_run_checkpoint(run_id, framework)
    if state is None:
        return {"error": "checkpoint_not_found", "run_id": run_id}
    result = patch_planned_subtasks(state, operations)
    paths = AgentPathService(framework)
    store = AgentRunStore(paths, run_id)
    phase = str(getattr(state, "current_phase", "") or "mcp_patch")
    store.save_checkpoint(phase, agent_state_checkpoint_dict(state))
    result["run_id"] = run_id
    result["checkpoint_saved"] = True
    return result


def submit_flow_input(state: Any, text: str) -> Dict[str, Any]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return {"ok": False, "error": "no knowledge_base"}
    if flow_awaiting_operator(kb):
        ok = submit_operator_answer(kb, text, state=state)
        return {"ok": ok, "mode": "barrier_answer"}
    kb.setdefault("operator_inputs", []).append(str(text or "")[:4000])
    state.campaign_stop_reason = None
    return {"ok": True, "mode": "new_task_hint"}
