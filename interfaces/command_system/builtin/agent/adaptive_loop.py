#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Observe/plan/act/verify/reflect adaptive loop (Phase 1)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_trace import infer_verified_verdict
from interfaces.command_system.builtin.agent.recovery_planner import RecoveryPlanner
from interfaces.command_system.builtin.agent.egress_gateway import is_cancellation_requested
from interfaces.command_system.builtin.agent.transactional_scheduler import (
    release_action_lease,
    reserve_action_lease,
)
from interfaces.command_system.builtin.agent.typed_models import (
    ActionLease,
    ActionOutcome,
    AgentAction,
    BlackboardEvent,
    GoalProgress,
    HARD_STOP_REASONS,
    Hypothesis,
    SOFT_STOP_REASONS,
    StopDecision,
)


ObserveFn = Callable[[Any], Dict[str, Any]]
PlanFn = Callable[[Any, Dict[str, Any]], List[AgentAction]]
ActFn = Callable[[Any, AgentAction], Dict[str, Any]]
VerifyFn = Callable[[Any, AgentAction, Dict[str, Any]], ActionOutcome]
ReflectFn = Callable[[Any, AgentAction, ActionOutcome], None]


@dataclass
class AdaptiveLoopConfig:
    max_iterations: int = 24
    max_replans: int = 8
    min_novelty_to_continue: int = 1
    checkpoint_each_action: bool = True


@dataclass
class AdaptiveLoopState:
    iteration: int = 0
    replans: int = 0
    pivots: List[str] = field(default_factory=list)
    outcomes: List[ActionOutcome] = field(default_factory=list)
    refuted_hypotheses: List[Hypothesis] = field(default_factory=list)
    blackboard: List[BlackboardEvent] = field(default_factory=list)
    leases: List[ActionLease] = field(default_factory=list)
    stop: Optional[StopDecision] = None
    goal_progress: Optional[GoalProgress] = None


class AdaptiveLoopEngine:
    """Bounded action-centric loop replacing single replan after exploit."""

    def __init__(
        self,
        services: Any,
        *,
        config: Optional[AdaptiveLoopConfig] = None,
        observe_fn: Optional[ObserveFn] = None,
        plan_fn: Optional[PlanFn] = None,
        act_fn: Optional[ActFn] = None,
        verify_fn: Optional[VerifyFn] = None,
        reflect_fn: Optional[ReflectFn] = None,
    ) -> None:
        self.services = services
        self.config = config or AdaptiveLoopConfig()
        self._recovery = RecoveryPlanner()
        self._observe = observe_fn or self._default_observe
        self._plan = plan_fn or self._default_plan
        self._act = act_fn or self._default_act
        self._verify = verify_fn or self._default_verify
        self._reflect = reflect_fn or self._default_reflect

    def run(self, state: Any) -> Any:
        loop_state = AdaptiveLoopState()
        state.adaptive_loop = loop_state
        pending: List[AgentAction] = []

        while loop_state.iteration < self.config.max_iterations:
            loop_state.iteration += 1
            observation = self._observe(state)
            loop_state.goal_progress = self._goal_progress(state, observation)

            stop = self._evaluate_stop(state, loop_state, observation)
            if stop.stop:
                loop_state.stop = stop
                state.campaign_stop_reason = stop.reason
                break

            if not pending:
                pending = self._plan(state, observation)
                if not pending:
                    stop = StopDecision(
                        stop=True,
                        kind="soft",
                        reason="branch_exhausted",
                        detail="No admissible actions from planner",
                    )
                    loop_state.stop = stop
                    state.campaign_stop_reason = stop.reason
                    break

            action = pending.pop(0)
            if self._is_refuted(state, action):
                continue

            lease = self._acquire_budget(state, action)
            loop_state.leases.append(lease)
            if lease.reserved_requests <= 0 and int(getattr(state, "request_budget", 0) or 0) > 0:
                loop_state.stop = StopDecision(
                    stop=True,
                    kind="hard",
                    reason="budget_exhausted",
                    detail="Could not reserve request budget for action",
                )
                state.campaign_stop_reason = "budget_exhausted"
                break

            raw = self._act(state, action)
            outcome = self._verify(state, action, raw)
            self._release_budget(state, lease, outcome)
            loop_state.outcomes.append(outcome)
            self._reflect(state, action, outcome)
            self._record_blackboard(loop_state, action, outcome)

            from interfaces.command_system.builtin.agent.plan_recalc import consume_plan_recalc

            replan_reasons = consume_plan_recalc(state)
            if replan_reasons:
                pending.clear()
                loop_state.replans += 1
                loop_state.pivots.append(f"plan_recalc:{replan_reasons[0]}")

            if outcome.verdict in {"confirmed"} and self._goal_reached(state, loop_state):
                loop_state.stop = StopDecision(
                    stop=True,
                    kind="soft",
                    reason="goal_reached",
                    detail="Goal milestones satisfied",
                )
                break

            if outcome.verdict in {"module_error", "refuted", "no_signal", "blocked"}:
                if loop_state.replans >= self.config.max_replans:
                    loop_state.stop = StopDecision(
                        stop=True,
                        kind="soft",
                        reason="branch_exhausted",
                        detail="Max replans reached after failures",
                    )
                    break
                recovery_actions = self._recovery.suggest(
                    outcome,
                    hypotheses=self._hypotheses(state),
                    available_modules=observation.get("catalog_modules") or [],
                )
                if recovery_actions:
                    loop_state.replans += 1
                    loop_state.pivots.append(recovery_actions[0].reason or recovery_actions[0].path or "pivot")
                    pending = recovery_actions + pending

            if self.config.checkpoint_each_action:
                self._checkpoint_action(state, action, outcome)

        self._finalize_state(state, loop_state)
        return state

    def _default_observe(self, state: Any) -> Dict[str, Any]:
        kb = getattr(state, "knowledge_base", {}) or {}
        catalog = []
        try:
            expanded = bool(getattr(state, "expanded_surface", False))
            catalog = self.services.module_catalog.discover_campaign_modules(expanded=expanded)[:48]
        except Exception:
            catalog = []
        return {
            "phase": getattr(state, "current_phase", ""),
            "goal": getattr(state, "campaign_goal", ""),
            "knowledge_base": kb,
            "catalog_modules": catalog,
            "metrics": getattr(state, "metrics", None),
        }

    def _default_plan(self, state: Any, observation: Mapping[str, Any]) -> List[AgentAction]:
        from interfaces.command_system.builtin.agent.hierarchical_planner import (
            HierarchicalPlannerEngine,
            hierarchical_planner_enabled,
        )
        if hierarchical_planner_enabled(state):
            return HierarchicalPlannerEngine(self.services).plan_actions(state, observation)

        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        modules = observation.get("catalog_modules") or []
        actions = self._heuristic_plan_actions(modules, kb)
        from interfaces.command_system.builtin.agent.shadow_planner import (
            shadow_mode_enabled,
        )
        from interfaces.command_system.builtin.agent.hierarchical_planner import hierarchical_planner_enabled as _hp

        if shadow_mode_enabled(state) and not _hp(state):
            from interfaces.command_system.builtin.agent.shadow_planner import ShadowPlannerService

            ShadowPlannerService(self.services).evaluate_shadow(state, observation, actions)
        return actions

    @staticmethod
    def _heuristic_plan_actions(
        modules: Sequence[Any],
        kb: Mapping[str, Any],
    ) -> List[AgentAction]:
        from interfaces.command_system.builtin.agent.action_planner import (
            ActionScorer,
            action_profile_from_module,
            planner_alignment_bonus,
            planner_state_from_kb,
        )

        scored: List[tuple[float, AgentAction]] = []
        scorer = ActionScorer()
        planner_state = planner_state_from_kb(kb if isinstance(kb, dict) else {})
        for row in modules:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "")
            if not path:
                continue
            profile = action_profile_from_module(row)
            score = scorer.score(profile, planner_state) + planner_alignment_bonus(row, kb if isinstance(kb, dict) else {})
            action_type = "run_exploit" if path.startswith("exploits/") else "run_followup"
            scored.append((
                score,
                AgentAction(
                    type=action_type,
                    path=path,
                    priority=int(max(0.0, score)),
                    risk="intrusive" if "exploit" in path else "active",
                    reason="adaptive_loop:scored",
                    status="planned",
                ),
            ))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [action for _score, action in scored[:5]]

    def _default_act(self, state: Any, action: AgentAction) -> Dict[str, Any]:
        if getattr(state, "dry_run", False) or getattr(state, "plan_only", False):
            return {"blocked": False, "planned": True, "execution": None}
        action_type = str(action.type or "").strip().lower()
        if action_type == "http_request":
            from interfaces.command_system.builtin.agent.http_probe_actions import (
                execute_agent_http_request,
                record_llm_http_requests,
            )

            raw = execute_agent_http_request(
                state,
                {
                    "type": "http_request",
                    "path": action.path,
                    "options": dict(action.options or {}),
                },
            )
            kb = getattr(state, "knowledge_base", None)
            if isinstance(kb, dict):
                record_llm_http_requests(kb, [raw])
                state.knowledge_base = kb
            return {
                "blocked": str(raw.get("status") or "").lower() in {"skipped", "error"},
                "error": str(raw.get("message") or ""),
                "execution": None,
                "http_result": raw,
                "planned": False,
            }
        if action_type == "surface_scan":
            # Surface scan expands to highest-scoring scanner modules from observation catalog.
            modules = []
            try:
                modules = self.services.module_catalog.discover_campaign_modules(
                    expanded=bool(getattr(state, "expanded_surface", False))
                )
            except Exception:
                modules = []
            scanners = [
                row for row in modules
                if isinstance(row, dict)
                and str(row.get("path", "")).startswith(("scanner/", "auxiliary/scanner/"))
            ][: max(1, min(int((action.options or {}).get("limit") or 4), 8))]
            results = []
            for row in scanners:
                path = str(row.get("path") or "")
                if not path:
                    continue
                sub = AgentAction(
                    type="run_followup",
                    path=path,
                    priority=action.priority,
                    risk="active",
                    reason="surface_scan:delegate",
                    status="planned",
                )
                results.append(self._default_act(state, sub))
            return {
                "blocked": False,
                "error": "",
                "execution": None,
                "surface_scan_results": results,
                "planned": False,
            }
        path = str(action.path or "")
        module = self.services.core.framework.module_loader.load_module(
            path,
            framework=self.services.core.framework,
            load_only=False,
        )
        if module is None:
            return {"blocked": True, "error": f"module not found: {path}", "execution": None}
        from interfaces.command_system.builtin.agent.execution_service import AgentModuleExecutionService

        executor = AgentModuleExecutionService(self.services.core.framework)
        phase = str(getattr(state, "current_phase", "") or "act")
        loop = getattr(state, "adaptive_loop", None)
        prior = loop.outcomes if isinstance(loop, AdaptiveLoopState) else []
        candidates = [row.module_path for row in prior if row.module_path]
        option_patch = (action.options or {}).get("option_patch")
        return executor.execute(
            module,
            path,
            state,
            phase=phase,
            candidates=candidates,
            score=float(action.priority or 0),
            decision_source="adaptive_loop",
            option_patch=option_patch if isinstance(option_patch, dict) else None,
        )

    def _default_verify(self, state: Any, action: AgentAction, raw: Mapping[str, Any]) -> ActionOutcome:
        verdict = infer_verified_verdict(raw)
        network = 0
        execution = raw.get("execution")
        if execution is not None:
            metrics = getattr(execution, "metrics", None)
            if metrics is not None:
                network = int(getattr(metrics, "requests", 0) or 0)
        return ActionOutcome(
            action_id=action.id,
            verdict=verdict,
            module_path=action.path,
            phase=str(getattr(state, "current_phase", "") or "act"),
            network_requests=network,
            message=str(raw.get("error") or "") or None,
            raw_summary={"blocked": bool(raw.get("blocked")), "planned": bool(raw.get("planned"))},
        )

    def _default_reflect(self, state: Any, action: AgentAction, outcome: ActionOutcome) -> None:
        kb = getattr(state, "knowledge_base", None)
        if not isinstance(kb, dict):
            kb = {}
            state.knowledge_base = kb
        refuted = kb.setdefault("refuted_hypotheses", [])
        if outcome.verdict == "refuted":
            hyp = Hypothesis(
                statement=f"{action.path} refuted",
                module_path=action.path,
                status="refuted",
                fingerprint=f"{action.path}:{action.type}",
            ).to_dict()
            if hyp not in refuted:
                refuted.append(hyp)
        observed = kb.setdefault("observed_modules", [])
        if action.path and action.path not in observed:
            observed.append(action.path)

    def _evaluate_stop(
        self,
        state: Any,
        loop_state: AdaptiveLoopState,
        observation: Mapping[str, Any],
    ) -> StopDecision:
        metrics = getattr(state, "metrics", None)
        if metrics is not None and int(getattr(metrics, "scope_blocks", 0) or 0) > 0:
            return StopDecision(stop=True, kind="hard", reason="scope_violation")
        if is_cancellation_requested(getattr(state, "cancellation_token", None)):
            token = getattr(state, "cancellation_token", None)
            reason = getattr(token, "reason", "") if token is not None else ""
            return StopDecision(stop=True, kind="hard", reason="cancelled", detail=reason or None)
        budget = int(getattr(state, "request_budget", 0) or 0)
        if budget > 0:
            used = int(getattr(metrics, "network_units_used", 0) or 0) if metrics else 0
            if used >= budget:
                return StopDecision(stop=True, kind="hard", reason="budget_exhausted")
        if loop_state.iteration > 1 and not loop_state.pivots and loop_state.replans == 0:
            if all(row.verdict in {"no_signal", "blocked"} for row in loop_state.outcomes[-2:]):
                return StopDecision(stop=True, kind="soft", reason="low_novelty")
        return StopDecision(stop=False)

    def _acquire_budget(self, state: Any, action: AgentAction) -> ActionLease:
        lease = reserve_action_lease(state, action)
        if lease is None:
            return ActionLease(action_id=action.id, reserved_requests=0, non_idempotent=False)
        return lease

    def _release_budget(self, state: Any, lease: ActionLease, outcome: ActionOutcome) -> None:
        if lease.reserved_requests <= 0 or lease.released:
            return
        release_action_lease(
            state,
            lease,
            consumed=int(getattr(outcome, "network_requests", 0) or 0),
            success=str(getattr(outcome, "verdict", "") or "") not in {"module_error", "policy_denied"},
            latency_ms=float(getattr(outcome, "duration_ms", 0) or 0) or None,
        )

    def _goal_progress(self, state: Any, observation: Mapping[str, Any]) -> GoalProgress:
        goal = str(getattr(state, "campaign_goal", "") or observation.get("goal") or "recon")
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        signals = {str(item).lower() for item in (kb.get("risk_signals") or [])}
        milestones: List[str] = []
        if signals:
            milestones.append("signals_observed")
        if kb.get("observed_modules"):
            milestones.append("modules_executed")
        ratio = min(1.0, len(milestones) / 3.0)
        return GoalProgress(goal=goal, completion_ratio=ratio, milestones=milestones)

    def _goal_reached(self, state: Any, loop_state: AdaptiveLoopState) -> bool:
        goal = str(getattr(state, "campaign_goal", "") or "").lower()
        post = getattr(state, "post_exploit_mission", {}) or {}
        if isinstance(post, dict) and post.get("all_complete"):
            return True
        kb = getattr(state, "knowledge_base", {}) or {}
        if isinstance(kb, dict):
            kb_post = kb.get("post_exploit") if isinstance(kb.get("post_exploit"), dict) else {}
            if kb_post.get("all_complete"):
                return True
        if goal in {"recon", "validate"}:
            return len(loop_state.outcomes) >= 2 and any(row.verdict == "confirmed" for row in loop_state.outcomes)
        if "shell" in goal:
            sessions = getattr(state, "new_sessions", []) or []
            return bool(sessions)
        return loop_state.goal_progress.completion_ratio >= 0.66 if loop_state.goal_progress else False

    def _is_refuted(self, state: Any, action: AgentAction) -> bool:
        kb = getattr(state, "knowledge_base", {}) or {}
        for row in kb.get("refuted_hypotheses") or []:
            if not isinstance(row, dict):
                continue
            if str(row.get("module_path") or "") == str(action.path or ""):
                return True
            if str(row.get("fingerprint") or "") == f"{action.path}:{action.type}":
                return True
        return False

    def _hypotheses(self, state: Any) -> List[Hypothesis]:
        kb = getattr(state, "knowledge_base", {}) or {}
        rows = []
        for item in kb.get("refuted_hypotheses") or []:
            if isinstance(item, dict):
                rows.append(Hypothesis.from_dict(item))
        return rows

    def _record_blackboard(
        self,
        loop_state: AdaptiveLoopState,
        action: AgentAction,
        outcome: ActionOutcome,
    ) -> None:
        loop_state.blackboard.append(
            BlackboardEvent(
                kind="action_outcome",
                summary=f"{action.path} -> {outcome.verdict}",
                payload={"action_id": action.id, "outcome_id": outcome.id, "verdict": outcome.verdict},
            )
        )

    def _checkpoint_action(self, state: Any, action: AgentAction, outcome: ActionOutcome) -> None:
        store = getattr(state, "run_store", None)
        if store is None:
            return
        from interfaces.command_system.builtin.agent.state import agent_state_checkpoint_dict
        from interfaces.command_system.builtin.agent.run_snapshot import persist_run_snapshot

        payload = agent_state_checkpoint_dict(state)
        store.save_checkpoint(str(getattr(state, "current_phase", "") or "act"), payload)
        persist_run_snapshot(store, payload)

    def _finalize_state(self, state: Any, loop_state: AdaptiveLoopState) -> None:
        state.current_phase = "report"
        state.replan_count = loop_state.replans
        if not hasattr(state, "adaptive_loop") or state.adaptive_loop is None:
            state.adaptive_loop = loop_state
        try:
            state.report_path = self.services.report.generate_report(
                state.raw_target,
                state.target_info,
                state.results,
                state.sql_findings,
                state.new_sessions,
                state.llm_plan,
                state.knowledge_base,
                state.execution_plan,
                contextual_findings=state.contextual_findings,
                decision_timeline=state.decision_timeline,
                run_id=state.run_id,
                workspace=state.workspace,
                metrics=state.metrics,
                campaign_stop_reason=state.campaign_stop_reason,
                network_budget=state.network_budget,
                runtime_policy=state.runtime_policy,
                decision_source="adaptive_loop",
            )
        except Exception:
            pass


def adaptive_loop_enabled(state: Any) -> bool:
    if getattr(state, "adaptive_loop_enabled", False):
        return True
    return os.environ.get("KITTYSPLOIT_AGENT_ADAPTIVE", "").strip().lower() in {"1", "true", "yes"}
