#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offline replay and divergence analysis for agent runs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.action_trace import load_action_traces_from_store
from interfaces.command_system.builtin.agent.explain_service import AgentExplainService
from interfaces.command_system.builtin.agent.goal_planner import build_goal_plan, filter_actions_for_goal
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_snapshot import build_run_snapshot, load_run_snapshot, persist_run_snapshot
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
        """Backward-compatible alias for decision replay."""
        return self.replay_decision(run_id, allow_network=allow_network)

    def replay_decision(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "decision",
                "error": "decision replay is offline-only; use replay_execution for attested lab reruns",
                "approval_needed": True,
            }

        store = self._explain._store_for_run(run_id)
        events = load_events_from_store(store)
        checkpoint = self._explain._load_checkpoint_safe(store)
        state = checkpoint.get("state") or {}
        traces = load_action_traces_from_store(store)
        snapshot = load_run_snapshot(store)
        if not snapshot:
            snapshot = persist_run_snapshot(store, state)

        old_plan = dict(state.get("execution_plan") or {})
        goal = state.get("campaign_goal") or old_plan.get("campaign_goal")
        new_plan = build_goal_plan(goal, request_budget=int(state.get("request_budget", 0) or 0))
        old_actions = list(old_plan.get("next_actions") or [])
        new_actions = filter_actions_for_goal(old_actions, goal)
        divergences = self._diff_plans(old_plan, new_plan, old_actions, new_actions)
        explanation = self._explain.explain(run_id)

        return sanitize_nested({
            "run_id": run_id,
            "mode": "decision",
            "network_emitted": False,
            "event_count": len(events),
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "config": snapshot.get("config"),
            "scheduling_order": snapshot.get("scheduling_order") or build_run_snapshot(
                run_id, state, events=events, action_traces=traces
            ).get("scheduling_order"),
            "proposals": snapshot.get("proposals"),
            "cost": snapshot.get("cost"),
            "cancellations": snapshot.get("cancellations"),
            "decisions": explanation.get("decisions"),
            "old_plan": old_plan,
            "replayed_plan": new_plan,
            "divergences": divergences,
        })

    def replay_shadow(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "shadow",
                "error": "shadow replay is offline-only",
                "approval_needed": True,
            }
        from interfaces.command_system.builtin.agent.shadow_planner import ShadowPlannerService

        service = ShadowPlannerService(self._agent_services())
        return service.replay_run(run_id, framework=self.framework)

    def replay_specialists(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "specialists",
                "error": "specialist replay is offline-only",
                "approval_needed": True,
            }
        from interfaces.command_system.builtin.agent.specialist_runner import SpecialistComparisonService

        service = SpecialistComparisonService(self._agent_services())
        return service.replay_run(run_id, framework=self.framework)

    def replay_chaos(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "chaos",
                "error": "chaos replay is offline-only",
                "approval_needed": True,
            }
        from interfaces.command_system.builtin.agent.specialist_chaos import SpecialistChaosReplayService

        payload = SpecialistChaosReplayService().run_scenarios()
        payload["run_id"] = run_id
        store = self._explain._store_for_run(run_id)
        save = getattr(store, "save_specialist_chaos_report", None)
        if callable(save):
            save(payload)
        return payload

    def replay_adversarial(
        self,
        run_id: str,
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "adversarial",
                "error": "adversarial replay is offline-only",
                "approval_needed": True,
            }
        from interfaces.command_system.builtin.agent.adversarial_guard import AdversarialReplayService

        payload = AdversarialReplayService().run_scenarios()
        payload["run_id"] = run_id
        store = self._explain._store_for_run(run_id)
        save = getattr(store, "save_adversarial_report", None)
        if callable(save):
            save(payload)
        return payload

    def _agent_services(self) -> Any:
        from types import SimpleNamespace

        from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService

        return SimpleNamespace(
            core=SimpleNamespace(framework=self.framework),
            module_catalog=ModuleCatalogService(self.framework),
        )

    def replay_execution(
        self,
        run_id: str,
        *,
        lab_id: Optional[str] = None,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        if allow_network:
            return {
                "run_id": run_id,
                "mode": "execution",
                "error": "network execution replay requires explicit operator authorization and attested lab reset",
                "approval_needed": True,
            }

        store = self._explain._store_for_run(run_id)
        checkpoint = self._explain._load_checkpoint_safe(store)
        state = checkpoint.get("state") or {}
        traces = load_action_traces_from_store(store)
        snapshot = load_run_snapshot(store)
        if not snapshot:
            snapshot = persist_run_snapshot(store, state)

        attestation_valid = None
        attestation = None
        attestation_detail = ""
        if lab_id:
            from core.lab_orchestrator.runner import LabOrchestrator

            orchestrator = LabOrchestrator(self.framework)
            scenario = orchestrator.get_scenario(lab_id)
            attestation = orchestrator.get_reset_attestation(lab_id)
            attestation_valid, attestation_detail = orchestrator.verify_reset_attestation(
                scenario,
                require_digest_pin=False,
            )

        action_queue = [
            {
                "action_key": row.get("action_key"),
                "phase": row.get("phase"),
                "module_path": row.get("module_path"),
                "verified_verdict": row.get("verified_verdict"),
                "duration_ms": row.get("duration_ms"),
                "candidates": row.get("candidates") or [],
            }
            for row in traces
            if str(row.get("module_path") or "").strip()
        ]

        return sanitize_nested({
            "run_id": run_id,
            "mode": "execution",
            "lab_id": lab_id,
            "network_emitted": False,
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "reset_attestation": attestation,
            "attestation_valid": attestation_valid,
            "attestation_detail": attestation_detail or None,
            "action_queue": action_queue,
            "replayable_actions": len(action_queue),
            "ready_for_attested_reset": bool(attestation_valid) if lab_id else None,
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
