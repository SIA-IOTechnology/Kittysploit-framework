#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
In-iteration tool micro-loop: HTTP probe → observe KB → enqueue module actions
without flushing the rest of the pending queue or forcing a full replan.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_catalog import build_admissible_catalog
from interfaces.command_system.builtin.agent.typed_models import AgentAction


MODULE_ACTION_TYPES = frozenset({"run_followup", "run_exploit", "run_post", "surface_scan"})


@dataclass
class MicroLoopDecision:
    prepend_actions: List[AgentAction] = field(default_factory=list)
    clear_pending: bool = False
    reason: str = ""

    @property
    def chained(self) -> bool:
        return bool(self.prepend_actions) and not self.clear_pending


def micro_loop_enabled(state: Any = None) -> bool:
    env = os.environ.get("KITTYSPLOIT_AGENT_MICRO_LOOP", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    try:
        from interfaces.command_system.builtin.agent.performance_planner import turbo_mode_enabled

        return turbo_mode_enabled(state)
    except Exception:
        return True


def micro_loop_max_per_iteration(state: Any = None) -> int:
    env = os.environ.get("KITTYSPLOIT_AGENT_MICRO_LOOP_MAX", "").strip()
    if env.isdigit():
        return max(1, min(int(env), 4))
    return 2


def micro_loop_followup_limit(state: Any = None) -> int:
    env = os.environ.get("KITTYSPLOIT_AGENT_MICRO_LOOP_MODULES", "").strip()
    if env.isdigit():
        return max(1, min(int(env), 3))
    return 2


def _executed_paths(state: Any) -> set[str]:
    paths: set[str] = set()
    for item in getattr(state, "executed_actions", []) or []:
        if isinstance(item, dict):
            paths.add(str(item.get("path") or ""))
        else:
            paths.add(str(getattr(item, "path", "") or ""))
    observed = getattr(state, "knowledge_base", None)
    if isinstance(observed, dict):
        for token in observed.get("observed_modules") or []:
            paths.add(str(token))
    return {p for p in paths if p}


def _action_from_path(path: str, *, reason: str, priority: int = 8) -> Optional[AgentAction]:
    path = str(path or "").strip()
    if not path:
        return None
    if path.startswith(("exploit/", "exploits/")):
        action_type = "run_exploit"
        risk = "intrusive"
    elif path.startswith("post/"):
        action_type = "run_post"
        risk = "intrusive"
    else:
        action_type = "run_followup"
        risk = "active"
    return AgentAction(
        type=action_type,
        path=path,
        priority=priority,
        risk=risk,
        reason=reason,
        status="planned",
        approved=True,
    )


def _paths_from_playbooks(kb: Mapping[str, Any], *, limit: int) -> List[str]:
    try:
        from interfaces.command_system.builtin.agent.planner_context import retrieve_playbook_hints

        paths: List[str] = []
        for row in retrieve_playbook_hints(kb, limit=3):
            for module in row.get("next_modules") or []:
                token = str(module or "").strip()
                if token and token not in paths:
                    paths.append(token)
                if len(paths) >= limit:
                    return paths
    except Exception:
        pass
    return []


def plan_module_followups_after_http(
    state: Any,
    observation: Mapping[str, Any],
    *,
    limit: Optional[int] = None,
) -> List[AgentAction]:
    """Rank module actions from fresh KB signals (no extra LLM call)."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
    modules = observation.get("catalog_modules") or []
    executed = _executed_paths(state)
    cap = micro_loop_followup_limit(state) if limit is None else max(1, int(limit))
    candidates: List[str] = []

    nxt = kb.get("attack_graph_next_action")
    if isinstance(nxt, dict):
        graph_path = str(nxt.get("action") or "").strip()
        if graph_path:
            candidates.append(graph_path)

    for path in _paths_from_playbooks(kb, limit=cap):
        if path not in candidates:
            candidates.append(path)

    try:
        catalog = build_admissible_catalog(
            modules=modules,
            kb=kb,
            goal=getattr(state, "campaign_goal", ""),
            executed_actions=getattr(state, "executed_actions", []) or [],
            state=state,
        )
        from interfaces.command_system.builtin.agent.model_router import build_heuristic_tactical_plan

        tactical = build_heuristic_tactical_plan(catalog, rationale="micro_loop:http_observe")
        for action in [tactical.selected_action, *(tactical.alternatives or [])]:
            if action is None:
                continue
            path = str(action.path or "")
            action_type = str(action.type or "").lower()
            if action_type not in MODULE_ACTION_TYPES:
                continue
            if path and path not in candidates:
                candidates.append(path)
    except Exception:
        pass

    actions: List[AgentAction] = []
    for idx, path in enumerate(candidates):
        if path in executed:
            continue
        built = _action_from_path(path, reason=f"micro_loop:http_chain:{path}", priority=9 - idx)
        if built is not None:
            actions.append(built)
        if len(actions) >= cap:
            break
    return actions


def handle_http_intel_micro_loop(
    state: Any,
    observation: Mapping[str, Any],
    http_action: AgentAction,
    raw: Mapping[str, Any],
    pending: Sequence[AgentAction],
    *,
    micro_loops_done: int = 0,
) -> MicroLoopDecision:
    """
    Decide whether to chain modules after an interesting HTTP probe.

    Preserves existing ``pending`` when chaining; only clears on fallback replan.
    """
    if not micro_loop_enabled(state):
        return MicroLoopDecision(clear_pending=True, reason="micro_loop_disabled")

    if micro_loops_done >= micro_loop_max_per_iteration(state):
        return MicroLoopDecision(clear_pending=True, reason="micro_loop_cap")

    if str(http_action.type or "").lower() != "http_request":
        return MicroLoopDecision(clear_pending=True, reason="not_http_request")

    if not raw.get("http_intel_replan"):
        return MicroLoopDecision(clear_pending=False, reason="no_intel_delta")

    fresh_obs = dict(observation)
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict):
        fresh_obs["knowledge_base"] = kb

    followups = plan_module_followups_after_http(state, fresh_obs)
    if not followups:
        return MicroLoopDecision(clear_pending=True, reason="no_module_followup")

    pending_paths = {str(a.path or "") for a in pending}
    deduped: List[AgentAction] = []
    for action in followups:
        path = str(action.path or "")
        if not path or path in pending_paths:
            continue
        if path == str(http_action.path or ""):
            continue
        deduped.append(action)
        pending_paths.add(path)

    if not deduped:
        # Intel changed but queue already has the right modules — keep going.
        return MicroLoopDecision(clear_pending=False, reason="pending_already_covers_followup")

    return MicroLoopDecision(
        prepend_actions=deduped,
        clear_pending=False,
        reason=f"chained_{len(deduped)}_module(s)_after_http",
    )
