#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Hierarchical planner: strategic sub-goals, tactical action, commander vs policy gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_catalog import (
    CAPABILITY_LADDER,
    CatalogAction,
    build_admissible_catalog,
    current_capability_rung,
)
from interfaces.command_system.builtin.agent.delegation_policy import DelegationPolicy
from interfaces.command_system.builtin.agent.goal_planner import build_goal_plan, normalize_goal
from interfaces.command_system.builtin.agent.proposal_arbiter import arbitrate_proposals
from interfaces.command_system.builtin.agent.refutation_panel import refute_finding_panel
from interfaces.command_system.builtin.agent.specialist_registry import (
    DEFAULT_SPECIALIST_REGISTRY,
    MAX_FAN_OUT,
    SpecialistRegistry,
)
from interfaces.command_system.builtin.agent.typed_models import (
    AgentAction,
    BlackboardEvent,
    GoalProgress,
    SpecialistProposal,
)


@dataclass
class StrategicPlan:
    goal: str
    sub_goals: List[str] = field(default_factory=list)
    capability_rung: str = ""
    next_capability: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "sub_goals": list(self.sub_goals),
            "capability_rung": self.capability_rung,
            "next_capability": self.next_capability,
            "rationale": self.rationale,
        }


@dataclass
class TacticalPlan:
    selected_action: Optional[AgentAction] = None
    alternatives: List[AgentAction] = field(default_factory=list)
    strategic: Optional[StrategicPlan] = None
    source: str = "heuristic"
    confidence: float = 0.0
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selected_action": self.selected_action.to_dict() if self.selected_action else None,
            "alternatives": [row.to_dict() for row in self.alternatives],
            "strategic": self.strategic.to_dict() if self.strategic else None,
            "source": self.source,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


class StrategicPlanner:
    """Produce capability-oriented sub-goals without selecting modules."""

    def plan(self, state: Any, observation: Mapping[str, Any]) -> StrategicPlan:
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        goal = normalize_goal(getattr(state, "campaign_goal", "") or observation.get("goal") or "recon")
        rung = current_capability_rung(kb if isinstance(kb, dict) else {})
        try:
            idx = CAPABILITY_LADDER.index(rung)
            next_cap = CAPABILITY_LADDER[min(idx + 1, len(CAPABILITY_LADDER) - 1)]
        except ValueError:
            next_cap = CAPABILITY_LADDER[0]
        goal_plan = build_goal_plan(goal, request_budget=int(getattr(state, "request_budget", 0) or 0))
        sub_goals = [f"advance:{next_cap}"]
        for stop in goal_plan.get("stop_conditions") or []:
            token = str(stop)
            if token and token not in sub_goals:
                sub_goals.append(f"until:{token}")
        return StrategicPlan(
            goal=goal,
            sub_goals=sub_goals,
            capability_rung=rung,
            next_capability=next_cap,
            rationale=f"Capability ladder at {rung}; push toward {next_cap}",
        )


class MissionCommander:
    """Propose ranked actions and specialist views — never executes."""

    def __init__(
        self,
        registry: Optional[SpecialistRegistry] = None,
        delegation: Optional[DelegationPolicy] = None,
    ) -> None:
        self.registry = registry or DEFAULT_SPECIALIST_REGISTRY
        self.delegation = delegation or DelegationPolicy()

    def propose(
        self,
        state: Any,
        observation: Mapping[str, Any],
        catalog: Sequence[CatalogAction],
        *,
        strategic: Optional[StrategicPlan] = None,
        llm_available: bool = True,
    ) -> List[SpecialistProposal]:
        from interfaces.command_system.builtin.agent.specialist_runner import (
            run_specialists,
            specialist_execution_mode,
        )

        mode = specialist_execution_mode(state)
        if mode in {"sequential", "parallel"}:
            proposals, _records = run_specialists(
                mode,
                state,
                observation,
                catalog,
                strategic=strategic,
                llm_available=llm_available,
            )
            if proposals:
                return proposals
            if getattr(state, "specialist_fallback_reason", ""):
                return self._propose_heuristic_catalog(
                    catalog,
                    strategic=strategic,
                )

        return self._propose_inline(
            state,
            observation,
            catalog,
            strategic=strategic,
            llm_available=llm_available,
        )

    def _propose_inline(
        self,
        state: Any,
        observation: Mapping[str, Any],
        catalog: Sequence[CatalogAction],
        *,
        strategic: Optional[StrategicPlan] = None,
        llm_available: bool = True,
    ) -> List[SpecialistProposal]:
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        phase = str(getattr(state, "current_phase", "") or observation.get("phase") or "reason")
        from interfaces.command_system.builtin.agent.host_specialist_factory import (
            collect_specialists_for_phase,
            gate_host_specialist,
        )

        specialists = collect_specialists_for_phase(
            self.registry,
            state,
            observation,
            limit=MAX_FAN_OUT,
        )
        proposals: List[SpecialistProposal] = []
        fan_out = 0

        for specialist in specialists:
            if str(specialist.key).startswith("host/"):
                allowed, gate_reason = gate_host_specialist(state, specialist, kb)
                if not allowed:
                    continue
            decision = self.delegation.evaluate(
                specialist,
                depth=0,
                fan_out=fan_out,
                phase=phase,
                llm_available=llm_available,
            )
            if not decision.allowed:
                continue
            fan_out += 1
            ranked = sorted(catalog, key=lambda row: row.heuristic_score, reverse=True)
            family_tokens = tuple(str(f).lower() for f in (specialist.module_families or ()))
            if family_tokens:
                preferred = [
                    row for row in ranked
                    if any(tok in str(row.module_path).lower() or tok in str(row.action.type).lower() for tok in family_tokens)
                    or (specialist.key == "web_recon" and row.action.type in {"http_request", "surface_scan"})
                    or (specialist.key == "session_post" and str(row.module_path).startswith("post/"))
                ]
                if preferred:
                    ranked = preferred + [row for row in ranked if row not in preferred]
            for row in ranked[:2]:
                proposals.append(
                    SpecialistProposal(
                        specialist=specialist.key,
                        action=AgentAction(
                            id=row.action_id,
                            type=row.action.type,
                            path=row.module_path,
                            priority=row.action.priority,
                            risk=row.action.risk,
                            reason=f"{specialist.key}:{row.action.reason}",
                            status="planned",
                            expected_requests=row.expected_requests,
                            options=dict(row.action.options or {}),
                        ),
                        confidence=min(0.95, 0.45 + row.heuristic_score / 200.0),
                        rationale=f"{specialist.name} proposes {row.module_path} toward {strategic.next_capability if strategic else 'goal'}",
                    )
                )
        return proposals

    @staticmethod
    def _propose_heuristic_catalog(
        catalog: Sequence[CatalogAction],
        *,
        strategic: Optional[StrategicPlan] = None,
    ) -> List[SpecialistProposal]:
        ranked = sorted(catalog, key=lambda row: row.heuristic_score, reverse=True)
        proposals: List[SpecialistProposal] = []
        for row in ranked[:3]:
            proposals.append(
                SpecialistProposal(
                    specialist="heuristic",
                    action=AgentAction(
                        id=row.action_id,
                        type=row.action.type,
                        path=row.module_path,
                        priority=row.action.priority,
                        risk=row.action.risk,
                        reason=f"heuristic_fallback:{row.module_path}",
                        status="planned",
                        expected_requests=row.expected_requests,
                    ),
                    confidence=min(0.9, 0.5 + row.heuristic_score / 150.0),
                    rationale=(
                        f"Heuristic fallback proposes {row.module_path} toward "
                        f"{strategic.next_capability if strategic else 'goal'}"
                    ),
                )
            )
        return proposals


class PolicyGateway:
    """Owns transactional authority: validate and approve exactly one action."""

    def authorize(
        self,
        state: Any,
        catalog: Sequence[CatalogAction],
        proposals: Sequence[SpecialistProposal],
        *,
        strategic: Optional[StrategicPlan] = None,
    ) -> TacticalPlan:
        catalog_map = {row.action_id: row.action for row in catalog}
        heuristic_scores = {row.action_id: row.heuristic_score for row in catalog}
        ranked = arbitrate_proposals(
            proposals,
            catalog_action_ids=catalog_map,
            heuristic_scores=heuristic_scores,
            limit=5,
        )

        selected: Optional[AgentAction] = None
        alternatives: List[AgentAction] = []
        rationale = "heuristic_catalog_fallback"
        confidence = 0.35
        source = "heuristic"

        candidates: List[tuple[str, AgentAction, float, str]] = []
        for proposal in ranked:
            candidates.append(
                (f"specialist:{proposal.specialist}", proposal.action, float(proposal.confidence or 0.0), proposal.rationale or "")
            )
        if catalog:
            for row in sorted(catalog, key=lambda item: item.heuristic_score, reverse=True)[:5]:
                candidates.append(
                    ("catalog", row.action, row.heuristic_score / 150.0, f"catalog:{row.module_path}")
                )

        for candidate_source, candidate_action, candidate_conf, candidate_reason in candidates:
            validated = self._validate_action(state, candidate_action, catalog)
            if validated is None:
                continue
            if self._needs_critic(state, validated):
                validated = self._apply_critic_gate(state, validated)
                if validated is None:
                    continue
            for row in catalog:
                if row.module_path == validated.path and row.action.type == validated.type:
                    validated.id = row.action_id
                    break
            validated.status = "approved"
            validated.approved = True
            validated.reason = candidate_reason or validated.reason
            # Preserve OptionPatch from proposal/catalog action options when present.
            if candidate_action.options and not validated.options.get("option_patch"):
                patch = candidate_action.options.get("option_patch")
                if isinstance(patch, dict):
                    validated.options = dict(validated.options or {})
                    validated.options["option_patch"] = patch
            selected = validated
            rationale = candidate_reason or rationale
            confidence = min(0.95, max(confidence, candidate_conf))
            source = candidate_source
            break

        if ranked:
            alternatives = [row.action for row in ranked[1:3]]

        return TacticalPlan(
            selected_action=selected,
            alternatives=alternatives,
            strategic=strategic,
            source=source,
            confidence=confidence,
            rationale=rationale,
        )

    def _validate_action(
        self,
        state: Any,
        action: AgentAction,
        catalog: Sequence[CatalogAction],
    ) -> Optional[AgentAction]:
        path = str(action.path or "").strip()
        if not path:
            return None
        action_type = str(action.type or "").strip().lower()
        if action_type in {"http_request", "surface_scan"}:
            for row in catalog:
                if row.action.type == action_type and (
                    row.module_path == path or row.action_id == action.id
                ):
                    if action_type == "http_request":
                        from interfaces.command_system.builtin.agent.http_probe_actions import (
                            build_agent_http_request_url,
                        )

                        if not build_agent_http_request_url(state, path):
                            return None
                    return action
            # Allow any catalog http_request/surface_scan of matching type
            typed = [row for row in catalog if row.action.type == action_type]
            if not typed:
                return None
            if action_type == "http_request":
                from interfaces.command_system.builtin.agent.http_probe_actions import (
                    build_agent_http_request_url,
                )

                if not build_agent_http_request_url(state, path):
                    return None
            return action
        allowed_paths = {row.module_path for row in catalog}
        if path not in allowed_paths:
            return None
        policy = getattr(state, "runtime_policy", None)
        if policy is not None:
            from interfaces.command_system.builtin.agent.runtime_policy import evaluate_module_catalog_policy

            block = evaluate_module_catalog_policy(
                policy,
                {"path": path, "agent": {}},
                path,
                phase=str(getattr(state, "current_phase", "") or "act"),
                knowledge_base=getattr(state, "knowledge_base", {}) or {},
            )
            if block is not None:
                return None
        return action

    @staticmethod
    def _needs_critic(state: Any, action: AgentAction) -> bool:
        if str(action.risk or "") == "destructive":
            return True
        if str(action.type or "") in {"run_exploit", "run_post"}:
            return True
        if int(getattr(action, "expected_requests", 0) or 0) >= 8:
            return True
        return False

    @staticmethod
    def _apply_critic_gate(state: Any, action: AgentAction) -> Optional[AgentAction]:
        finding = {
            "path": action.path,
            "message": action.reason or "terminal action candidate",
            "severity": "high" if action.risk in {"intrusive", "destructive"} else "medium",
        }
        panel = refute_finding_panel(finding, refuters=1, llm_service=None)
        verdict = str(panel.get("verdict") or panel.get("final_verdict") or "SURVIVED").upper()
        if verdict == "REFUTED":
            return None
        return action


class TacticalPlanner:
    """Select a single next action from an authorized tactical plan."""

    def select(self, tactical: TacticalPlan) -> List[AgentAction]:
        if tactical.selected_action is None:
            return []
        return [tactical.selected_action]


class HierarchicalPlannerEngine:
    """End-to-end planning cycle for adaptive loop integration."""

    def __init__(
        self,
        services: Any,
        *,
        registry: Optional[SpecialistRegistry] = None,
        llm_ranker: Optional[Callable[..., TacticalPlan]] = None,
    ) -> None:
        self.services = services
        self.strategic = StrategicPlanner()
        self.commander = MissionCommander(registry=registry)
        self.gateway = PolicyGateway()
        self.tactical = TacticalPlanner()
        self.llm_ranker = llm_ranker

    def plan_actions(self, state: Any, observation: Mapping[str, Any]) -> List[AgentAction]:
        tactical = self.plan_shadow_cycle(state, observation, mutate_state=True)
        return self.tactical.select(tactical)

    def plan_shadow_cycle(
        self,
        state: Any,
        observation: Mapping[str, Any],
        *,
        mutate_state: bool = False,
    ) -> TacticalPlan:
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        modules = observation.get("catalog_modules") or []
        strategic = self.strategic.plan(state, observation)
        catalog = build_admissible_catalog(
            modules=modules,
            kb=kb,
            goal=getattr(state, "campaign_goal", ""),
            executed_actions=getattr(state, "executed_actions", []) or [],
            state=state,
        )
        from interfaces.command_system.builtin.agent.planner_context import (
            attach_planner_context,
            calibrate_proposals,
        )

        attach_planner_context(
            state,
            observation,
            catalog_action_ids=[row.action_id for row in catalog],
            findings=getattr(state, "contextual_findings", None) or getattr(state, "vulnerable_results", None),
        )
        from interfaces.command_system.builtin.agent.model_router import (
            TASK_HTTP_RECON,
            TASK_TACTICAL_RANK,
            attach_model_route,
            attempt_llm_tactical_rank,
            build_heuristic_tactical_plan,
            planner_uses_heuristic_only,
        )

        llm_available = not planner_uses_heuristic_only(state)
        proposals = self.commander.propose(
            state,
            observation,
            catalog,
            strategic=strategic,
            llm_available=llm_available,
        )
        proposals = calibrate_proposals(proposals, kb)

        task = TASK_TACTICAL_RANK
        try:
            from interfaces.command_system.builtin.agent.http_probe_actions import (
                api_surface_ambiguous,
                http_surface_observed,
                llm_connected,
            )

            if llm_connected(state) and (
                api_surface_ambiguous(kb, state) or http_surface_observed(kb, state)
            ):
                specialist_keys = {p.specialist for p in proposals}
                if "web_recon" in specialist_keys or api_surface_ambiguous(kb, state):
                    task = TASK_HTTP_RECON
        except Exception:
            task = TASK_TACTICAL_RANK

        route = attach_model_route(state, observation, task=task)

        if planner_uses_heuristic_only(state):
            tactical = self.gateway.authorize(state, catalog, proposals, strategic=strategic)
            if tactical.selected_action is None:
                tactical = build_heuristic_tactical_plan(catalog, strategic=strategic)
        else:
            tactical = self.gateway.authorize(state, catalog, proposals, strategic=strategic)
            if route.tier != "heuristic":
                action_id = attempt_llm_tactical_rank(state, observation, catalog, route=route)
                if action_id:
                    catalog_map = {row.action_id: row for row in catalog}
                    row = catalog_map.get(action_id)
                    if row is not None:
                        llm_action = AgentAction(
                            id=row.action_id,
                            type=row.action.type,
                            path=row.module_path,
                            priority=row.action.priority,
                            risk=row.action.risk,
                            reason=f"llm_rank:{route.tier}:{row.module_path}",
                            status="approved",
                            expected_requests=row.expected_requests,
                            approved=True,
                            options=dict(row.action.options or {}),
                        )
                        validated = self.gateway._validate_action(state, llm_action, catalog)
                        if validated is not None and not self.gateway._needs_critic(state, validated):
                            tactical = TacticalPlan(
                                selected_action=validated,
                                alternatives=[row.action for row in catalog[:3]],
                                strategic=strategic,
                                source=f"llm:{route.tier}",
                                confidence=0.7,
                                rationale=f"LLM tactical rank via {route.model}",
                            )
                        elif validated is not None:
                            critic_action = self.gateway._apply_critic_gate(state, validated)
                            if critic_action is not None:
                                tactical = TacticalPlan(
                                    selected_action=critic_action,
                                    strategic=strategic,
                                    source=f"llm:{route.tier}",
                                    confidence=0.65,
                                    rationale=f"LLM tactical rank via {route.model} (critic passed)",
                                )
            if tactical.selected_action is None:
                tactical = build_heuristic_tactical_plan(
                    catalog,
                    strategic=strategic,
                    rationale="heuristic_fallback_after_llm",
                )
        if mutate_state:
            self._record_blackboard(state, strategic, tactical, catalog, proposals)
            state.hierarchical_plan = tactical.to_dict()
            state.goal_progress = GoalProgress(
                goal=strategic.goal,
                completion_ratio=self._completion_ratio(strategic.capability_rung),
                milestones=strategic.sub_goals,
                blockers=[] if tactical.selected_action else ["no_admissible_action"],
            )
            loop = getattr(state, "adaptive_loop", None)
            if loop is not None and getattr(state, "planner_llm_context", None):
                events = list(getattr(loop, "blackboard", []) or [])
                events.append(
                    BlackboardEvent(
                        kind="planner_context",
                        summary="compact host/service context attached",
                        payload=getattr(state, "planner_llm_context", {}),
                        source="planner_context",
                    )
                )
                if getattr(state, "llm_route", None):
                    events.append(
                        BlackboardEvent(
                            kind="llm_route",
                            summary=str((state.llm_route or {}).get("tier") or "heuristic"),
                            payload=getattr(state, "llm_route", {}),
                            source="model_router",
                        )
                    )
                loop.blackboard = events[-12:]
        return tactical

    @staticmethod
    def _completion_ratio(rung: str) -> float:
        try:
            idx = CAPABILITY_LADDER.index(rung)
            return round((idx + 1) / len(CAPABILITY_LADDER), 3)
        except ValueError:
            return 0.0

    @staticmethod
    def _record_blackboard(
        state: Any,
        strategic: StrategicPlan,
        tactical: TacticalPlan,
        catalog: Sequence[CatalogAction],
        proposals: Sequence[SpecialistProposal],
    ) -> None:
        loop = getattr(state, "adaptive_loop", None)
        if loop is None:
            return
        events = list(getattr(loop, "blackboard", []) or [])
        events.append(
            BlackboardEvent(
                kind="strategic_plan",
                summary=strategic.rationale,
                payload=strategic.to_dict(),
                source="strategic_planner",
            )
        )
        events.append(
            BlackboardEvent(
                kind="catalog",
                summary=f"{len(catalog)} admissible actions",
                payload={"count": len(catalog), "top": [row.action_id for row in catalog[:5]]},
                source="action_catalog",
            )
        )
        events.append(
            BlackboardEvent(
                kind="proposals",
                summary=f"{len(proposals)} specialist proposals",
                payload={"specialists": [row.specialist for row in proposals[:MAX_FAN_OUT]]},
                source="mission_commander",
            )
        )
        events.append(
            BlackboardEvent(
                kind="tactical_plan",
                summary=tactical.rationale,
                payload=tactical.to_dict(),
                source="policy_gateway",
            )
        )
        loop.blackboard = events[-12:]


def hierarchical_planner_enabled(state: Any) -> bool:
    if getattr(state, "hierarchical_planner_enabled", False):
        return True
    return os.environ.get("KITTYSPLOIT_AGENT_HIERARCHICAL", "").strip().lower() in {"1", "true", "yes"}


def parse_llm_tactical_rank(
    payload: Mapping[str, Any],
    catalog: Sequence[CatalogAction],
    *,
    kb: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    """Validate LLM rank response and return a catalog action_id."""
    if not isinstance(payload, dict):
        return None
    action_id = str(payload.get("action_id") or "").strip()
    allowed = {row.action_id for row in catalog}
    if action_id not in allowed:
        return None
    try:
        from core.schemas.validation import validate_instance
        from interfaces.command_system.builtin.agent.planner_context import ConfidenceCalibrator

        declared_confidence = float(payload.get("confidence") or 0)
        module_path = ""
        for row in catalog:
            if row.action_id == action_id:
                module_path = row.module_path
                break
        calibrated = ConfidenceCalibrator().calibrate(
            module_path,
            kb if isinstance(kb, dict) else {},
            declared_confidence,
        )

        validate_instance(
            "agent_tactical_rank",
            {
                "schema_version": payload.get("schema_version") or "1.0",
                "action_id": action_id,
                "hypothesis": str(payload.get("hypothesis") or "")[:500],
                "expected_gain": float(payload.get("expected_gain") or 0),
                "estimated_cost": float(payload.get("estimated_cost") or 0),
                "confidence": calibrated,
                "verification": str(payload.get("verification") or "")[:500],
            },
        )
    except Exception:
        return None
    return action_id
