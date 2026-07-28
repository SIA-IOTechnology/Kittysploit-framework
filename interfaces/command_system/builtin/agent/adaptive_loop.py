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
    # Checkpoint every N actions (1 = each action). Higher = less I/O latency.
    checkpoint_each_action: bool = False
    checkpoint_every_n: int = 4


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
    actions_since_checkpoint: int = 0


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
            if self._already_observed(state, action):
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
            else:
                every_n = max(1, int(self.config.checkpoint_every_n or 4))
                loop_state.actions_since_checkpoint += 1
                if loop_state.actions_since_checkpoint >= every_n:
                    self._checkpoint_action(state, action, outcome)
                    loop_state.actions_since_checkpoint = 0

        self._finalize_state(state, loop_state)
        return state

    def _default_observe(self, state: Any) -> Dict[str, Any]:
        kb = getattr(state, "knowledge_base", {}) or {}
        catalog = []
        try:
            expanded = bool(getattr(state, "expanded_surface", False))
            catalog = self.services.module_catalog.discover_campaign_modules(expanded=expanded)
            catalog = self._filter_catalog_for_target(state, catalog)[:48]
        except Exception:
            catalog = []
        learning = getattr(self.services, "learning", None)
        similar_episodes: List[Dict[str, Any]] = []
        if learning is not None and isinstance(kb, dict):
            try:
                from interfaces.command_system.builtin.agent.planner_context import (
                    retrieve_similar_episodes,
                )

                similar_episodes = retrieve_similar_episodes(
                    kb,
                    learning_store=learning,
                    state=state,
                    limit=4,
                )
                if similar_episodes:
                    kb["adaptive_similar_episodes"] = similar_episodes
                    state.knowledge_base = kb
            except Exception:
                similar_episodes = []
        return {
            "phase": getattr(state, "current_phase", ""),
            "goal": getattr(state, "campaign_goal", ""),
            "knowledge_base": kb,
            "catalog_modules": catalog,
            "metrics": getattr(state, "metrics", None),
            "similar_episodes": similar_episodes,
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
        actions = self._heuristic_plan_actions(modules, kb, state=state)
        self._record_plan_preferences(state, actions, modules)
        from interfaces.command_system.builtin.agent.shadow_planner import (
            shadow_mode_enabled,
        )
        from interfaces.command_system.builtin.agent.hierarchical_planner import hierarchical_planner_enabled as _hp

        if shadow_mode_enabled(state) and not _hp(state):
            from interfaces.command_system.builtin.agent.shadow_planner import ShadowPlannerService

            ShadowPlannerService(self.services).evaluate_shadow(state, observation, actions)
        return actions

    def _filter_catalog_for_target(self, state: Any, modules: Sequence[Any]) -> List[Any]:
        from interfaces.command_system.builtin.agent.goal_planner import (
            path_matches_forced_protocol,
            resolve_campaign_protocol,
        )
        from interfaces.command_system.builtin.agent.module_stack_gate import hard_stack_skip_reason

        protocol = resolve_campaign_protocol(
            state,
            getattr(state, "knowledge_base", None)
            if isinstance(getattr(state, "knowledge_base", None), dict)
            else {},
        )
        kb = getattr(state, "knowledge_base", None)
        kb_map = kb if isinstance(kb, dict) else {}
        observed = {
            str(item).strip()
            for item in (kb_map.get("observed_modules") or [])
            if str(item).strip()
        }
        catalog = getattr(self.services, "module_catalog", None)
        get_meta = getattr(catalog, "get_agent_metadata", None) if catalog is not None else None
        filtered: List[Any] = []
        for row in modules or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "").strip()
            if not path:
                continue
            if path in observed:
                continue
            if not path_matches_forced_protocol(path, protocol):
                continue
            agent = None
            if callable(get_meta):
                try:
                    agent = get_meta(path)
                except Exception:
                    agent = None
            # Prefer agent metadata already on the catalog row when present.
            if agent is None and isinstance(row.get("agent"), dict):
                agent = row.get("agent")
            skip = hard_stack_skip_reason(path, kb_map, agent if isinstance(agent, dict) else None)
            if skip:
                continue
            filtered.append(row)
        return filtered

    def _heuristic_plan_actions(
        self,
        modules: Sequence[Any],
        kb: Mapping[str, Any],
        state: Any = None,
    ) -> List[AgentAction]:
        """Score catalog rows with ActionScorer + LearningStore bandit / episode hints."""
        from interfaces.command_system.builtin.agent.action_planner import (
            ActionScorer,
            action_profile_from_module,
            planner_alignment_bonus,
            planner_state_from_kb,
        )
        from interfaces.command_system.builtin.agent.goal_planner import (
            path_matches_forced_protocol,
            resolve_campaign_protocol,
        )

        protocol = resolve_campaign_protocol(state, kb if isinstance(kb, dict) else {})
        learning = getattr(self.services, "learning", None)
        similar = list(kb.get("adaptive_similar_episodes") or []) if isinstance(kb, dict) else []
        boosted_paths = {
            str(row.get("module_path") or "")
            for row in similar
            if isinstance(row, dict)
            and str(row.get("status") or "").lower() in {"confirmed", "success"}
        }
        demoted_paths = {
            str(row.get("module_path") or "")
            for row in similar
            if isinstance(row, dict)
            and str(row.get("status") or "").lower() in {"refuted", "blocked", "error"}
        }
        scored: List[tuple[float, AgentAction]] = []
        scorer = ActionScorer()
        planner_state = planner_state_from_kb(kb if isinstance(kb, dict) else {})
        for row in modules:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "")
            if not path:
                continue
            if not path_matches_forced_protocol(path, protocol):
                continue
            profile = action_profile_from_module(row)
            score = scorer.score(profile, planner_state) + planner_alignment_bonus(
                row, kb if isinstance(kb, dict) else {}
            )
            if learning is not None:
                try:
                    score *= float(
                        learning.utility_multiplier(
                            path, kb if isinstance(kb, dict) else {}, state
                        )
                    )
                except Exception:
                    pass
            if path in boosted_paths:
                score += 12.0
            if path in demoted_paths:
                score -= 8.0
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

    def _record_plan_preferences(
        self,
        state: Any,
        actions: Sequence[AgentAction],
        modules: Sequence[Any],
    ) -> None:
        learning = getattr(self.services, "learning", None)
        if learning is None or not actions:
            return
        chosen = str(actions[0].path or "").strip()
        if not chosen:
            return
        rejected: List[Dict[str, Any]] = []
        seen = {chosen}
        for action in list(actions)[1:6]:
            path = str(getattr(action, "path", "") or "").strip()
            if path and path not in seen:
                rejected.append({"path": path, "reason": "lower_ranked_plan_action"})
                seen.add(path)
        if not rejected:
            for row in modules:
                if not isinstance(row, dict):
                    continue
                path = str(row.get("path") or "").strip()
                if not path or path in seen:
                    continue
                rejected.append({"path": path, "reason": "not_selected_by_adaptive_plan"})
                seen.add(path)
                if len(rejected) >= 4:
                    break
        if not rejected:
            return
        try:
            learning.record_preferences(
                state,
                chosen_path=chosen,
                rejected_alternatives=rejected,
                outcome="adaptive_plan",
            )
        except Exception:
            pass

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
                modules = self._filter_catalog_for_target(state, modules)
            except Exception:
                modules = []
            kb = getattr(state, "knowledge_base", {}) or {}
            limit = max(1, min(int((action.options or {}).get("limit") or 4), 8))
            ranked = self._heuristic_plan_actions(
                [
                    row for row in modules
                    if isinstance(row, dict)
                    and str(row.get("path", "")).startswith(("scanner/", "auxiliary/scanner/"))
                ],
                kb if isinstance(kb, dict) else {},
                state=state,
            )[:limit]
            results = []
            for sub in ranked:
                results.append(self._default_act(state, sub))
            return {
                "blocked": False,
                "error": "",
                "execution": None,
                "surface_results": results,
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
        kb_before = {
            "tech_hints": list(kb.get("tech_hints") or []),
            "risk_signals": list(kb.get("risk_signals") or []),
            "discovered_endpoints": list(kb.get("discovered_endpoints") or [])[:40],
            "discovered_params": list(kb.get("discovered_params") or [])[:40],
        }
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

        learning = getattr(self.services, "learning", None)
        if learning is None:
            return
        try:
            catalog = getattr(self.services, "module_catalog", None)
            meta_fn = getattr(catalog, "get_agent_metadata", None) if catalog is not None else None
            learning.record_action_outcome(
                state,
                action,
                outcome,
                phase="adaptive",
                get_agent_metadata=meta_fn if callable(meta_fn) else None,
                kb_before=kb_before,
            )
        except Exception:
            pass

    def _evaluate_stop(
        self,
        state: Any,
        loop_state: AdaptiveLoopState,
        observation: Mapping[str, Any],
    ) -> StopDecision:
        if self._goal_reached(state, loop_state):
            return StopDecision(
                stop=True,
                kind="soft",
                reason="goal_reached",
                detail="Goal milestones already satisfied",
            )
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
        # Avoid premature low-novelty soft-stop while chasing auth/shell with room to replan.
        if loop_state.iteration > 1 and not loop_state.pivots and loop_state.replans == 0:
            if all(row.verdict in {"no_signal", "blocked"} for row in loop_state.outcomes[-2:]):
                goal = str(getattr(state, "campaign_goal", "") or "").lower().replace("_", "-")
                pursuing = (
                    "shell" in goal
                    or goal in {"obtain-auth", "post-auth"}
                    or bool(getattr(state, "shell_hunter", False))
                )
                if pursuing and loop_state.iteration < max(4, self.config.max_iterations // 3):
                    return StopDecision(stop=False)
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
        goal_raw = str(getattr(state, "campaign_goal", "") or observation.get("goal") or "recon")
        goal = goal_raw.lower().replace("_", "-")
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        signals = {str(item).lower() for item in (kb.get("risk_signals") or [])}
        milestones: List[str] = []
        if signals:
            milestones.append("signals_observed")
        if kb.get("observed_modules"):
            milestones.append("modules_executed")
        if signals.intersection({
            "login_form_detected",
            "login_surface_detected",
            "login_redirect_detected",
        }):
            milestones.append("login_surface")
        if signals.intersection({"credentials_obtained", "authenticated_session", "auth_obtained"}):
            milestones.append("auth_obtained")
        if signals.intersection({"interactive_shell", "shell_obtained"}) or getattr(state, "new_sessions", None):
            milestones.append("shell_obtained")

        if goal in {"obtain-auth"} or goal.endswith("-auth"):
            needed = ("login_surface", "auth_obtained")
            hit = sum(1 for m in needed if m in milestones)
            ratio = hit / float(len(needed))
        elif "shell" in goal:
            needed = ("signals_observed", "modules_executed", "shell_obtained")
            hit = sum(1 for m in needed if m in milestones)
            # Auth on the way to shell counts as partial progress.
            if "auth_obtained" in milestones and "shell_obtained" not in milestones:
                hit = max(hit, 2)
            ratio = hit / float(len(needed))
        elif goal in {"recon", "validate"}:
            ratio = min(1.0, len([m for m in milestones if m in {"signals_observed", "modules_executed"}]) / 2.0)
        else:
            ratio = min(1.0, len(milestones) / 4.0)
        return GoalProgress(goal=goal_raw, completion_ratio=min(1.0, float(ratio)), milestones=milestones)

    def _goal_reached(self, state: Any, loop_state: AdaptiveLoopState) -> bool:
        goal = str(getattr(state, "campaign_goal", "") or "").lower().replace("_", "-")
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
        if goal in {"obtain-auth", "obtain_auth"} or goal.endswith("-auth") or goal.endswith("_auth"):
            from interfaces.command_system.builtin.agent.goal_planner import kb_auth_terminal_reached
            return kb_auth_terminal_reached(kb)
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

    @staticmethod
    def _already_observed(state: Any, action: AgentAction) -> bool:
        path = str(getattr(action, "path", "") or "").strip()
        if not path:
            return False
        kb = getattr(state, "knowledge_base", {}) or {}
        observed = kb.get("observed_modules") or []
        return path in {str(item).strip() for item in observed if str(item).strip()}

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
            from interfaces.command_system.builtin.agent.network_budget import (
                sync_metrics_from_budget,
            )

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
                metrics=getattr(state.metrics, "__dict__", None) or state.metrics,
                campaign_stop_reason=state.campaign_stop_reason,
                network_budget=sync_metrics_from_budget(state),
                runtime_policy={
                    "safety_profile": getattr(state, "safety_profile", ""),
                    "dry_run": bool(getattr(state, "dry_run", False)),
                    "plan_only": bool(getattr(state, "plan_only", False)),
                    "tls_verify": bool(
                        getattr(getattr(state, "runtime_policy", None), "tls_verify", True)
                    ),
                    "mission_profile": str(
                        getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
                    ),
                },
                decision_source="adaptive_loop",
            )
        except Exception:
            pass

        # End-of-run console debrief (stack, panels, findings) even without a shell.
        try:
            core = getattr(self.services, "core", None)
            if core is None:
                return
            results = [row for row in (getattr(state, "results", None) or []) if isinstance(row, dict)]
            kb = getattr(state, "knowledge_base", None)
            if results and isinstance(kb, dict):
                paths = [str(row.get("path") or "") for row in results if str(row.get("path") or "").strip()]
                core._update_knowledge_base_from_results(
                    kb,
                    results,
                    paths,
                    list(kb.get("tech_hints") or []),
                    list(kb.get("specializations") or []),
                    phase="report",
                )
                try:
                    core._promote_corroborated_web_apps(kb)
                except Exception:
                    pass
                state.knowledge_base = kb
            try:
                core._print_timeline_preview(state)
            except Exception:
                pass
            core._print_session_discoveries_debrief(state)
        except Exception:
            pass


def adaptive_loop_enabled(state: Any) -> bool:
    """
    Adaptive observe/plan/act loop is ON by default (pairs with hierarchical planner).

    Force off with ``state.adaptive_loop_enabled=False``,
    ``KITTYSPLOIT_AGENT_ADAPTIVE=0``, or safety profile ``safe``.
    """
    env = os.environ.get("KITTYSPLOIT_AGENT_ADAPTIVE", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    flag = getattr(state, "adaptive_loop_enabled", None)
    if flag is True:
        return True
    if flag is False:
        return False
    profile = str(getattr(state, "safety_profile", "") or "").strip().lower()
    if profile == "safe":
        return False
    return True
