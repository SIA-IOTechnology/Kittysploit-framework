#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offline replay and divergence analysis for agent runs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.explain_service import AgentExplainService
from interfaces.command_system.builtin.agent.goal_planner import build_goal_plan, filter_actions_for_goal
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_store import AgentPathService
from interfaces.command_system.builtin.agent.timeline import load_events_from_store


class AgentReplayService:
    def __init__(self, framework: Any, paths: Optional[AgentPathService] = None) -> None:
        self.framework = framework
        self.paths = paths or AgentPathService(framework)
        self._explain = AgentExplainService(framework, self.paths)

    def replay_offline(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "error": "network replay requires explicit operator authorization",
                "approval_needed": True,
            }
        store = self._explain._store_for_run(run_id)
        events = load_events_from_store(store)
        checkpoint = self._explain._load_checkpoint_safe(store)
        state = checkpoint.get("state") or {}
        old_plan = dict(state.get("execution_plan") or {})
        goal = state.get("campaign_goal") or old_plan.get("campaign_goal")
        new_plan = build_goal_plan(goal, request_budget=int(state.get("request_budget", 0) or 0))
        old_actions = list(old_plan.get("next_actions") or [])
        new_actions = filter_actions_for_goal(old_actions, goal)
        divergences = self._diff_plans(old_plan, new_plan, old_actions, new_actions)
        return sanitize_nested({
            "run_id": run_id,
            "mode": "offline",
            "network_emitted": False,
            "event_count": len(events),
            "old_plan": old_plan,
            "replayed_plan": new_plan,
            "divergences": divergences,
        })

    @staticmethod
    def _diff_plans(
        old_plan: Dict[str, Any],
        new_plan: Dict[str, Any],
        old_actions: List[Dict[str, Any]],
        new_actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        rows = []
        if old_plan.get("campaign_goal") != new_plan.get("campaign_goal"):
            rows.append({
                "field": "campaign_goal",
                "old": old_plan.get("campaign_goal"),
                "new": new_plan.get("campaign_goal"),
            })
        if int(old_plan.get("max_requests_next_phase", 0)) != int(
            new_plan.get("max_requests_next_phase", 0)
        ):
            rows.append({
                "field": "max_requests_next_phase",
                "old": old_plan.get("max_requests_next_phase"),
                "new": new_plan.get("max_requests_next_phase"),
            })
        old_paths = {str(row.get("path", "")) for row in old_actions}
        new_paths = {str(row.get("path", "")) for row in new_actions}
        removed = sorted(old_paths - new_paths)
        kept = sorted(old_paths & new_paths)
        if removed:
            rows.append({"field": "actions_removed_by_goal", "values": removed})
        if kept:
            rows.append({"field": "actions_retained", "values": kept})
        return rows
