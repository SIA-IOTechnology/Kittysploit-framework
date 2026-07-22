#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shadow-mode planner: compare hierarchical decisions without executing them."""

from __future__ import annotations

import copy
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_catalog import stable_action_id
from interfaces.command_system.builtin.agent.hierarchical_planner import (
    HierarchicalPlannerEngine,
    TacticalPlan,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import AgentAction


@dataclass
class ShadowComparison:
    step_index: int
    phase: str
    executed_path: Optional[str] = None
    shadow_path: Optional[str] = None
    match: bool = False
    same_module_family: bool = False
    executed_action_id: Optional[str] = None
    shadow_action_id: Optional[str] = None
    shadow_confidence: float = 0.0
    shadow_source: str = ""
    divergence_reason: str = ""
    strategic: Dict[str, Any] = field(default_factory=dict)
    shadow_plan: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested(asdict(self))


def shadow_mode_enabled(state: Any) -> bool:
    if getattr(state, "shadow_mode_enabled", False):
        return True
    return os.environ.get("KITTYSPLOIT_AGENT_SHADOW", "").strip().lower() in {"1", "true", "yes"}


def _module_family(path: str) -> str:
    token = str(path or "").strip()
    if not token:
        return ""
    parts = token.split("/")
    if len(parts) >= 2 and parts[0] == "auxiliary":
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def compare_actions(
    executed: Optional[AgentAction],
    shadow_plan: TacticalPlan,
    *,
    step_index: int = 0,
    phase: str = "",
) -> ShadowComparison:
    executed_path = str(executed.path or "") if executed is not None else ""
    shadow_action = shadow_plan.selected_action
    shadow_path = str(shadow_action.path or "") if shadow_action is not None else ""
    match = bool(executed_path and shadow_path and executed_path == shadow_path)
    same_family = bool(
        executed_path
        and shadow_path
        and _module_family(executed_path) == _module_family(shadow_path)
    )
    reason = ""
    if not shadow_path:
        reason = "shadow_no_admissible_action"
    elif not executed_path:
        reason = "no_executed_action"
    elif match:
        reason = "exact_match"
    elif same_family:
        reason = "same_family_different_module"
    else:
        reason = "divergent_module_choice"

    executed_id = None
    if executed is not None and executed_path:
        executed_id = executed.id or stable_action_id(
            executed_path,
            str(executed.type or "run_followup"),
        )
    shadow_id = None
    if shadow_action is not None and shadow_path:
        shadow_id = shadow_action.id or stable_action_id(
            shadow_path,
            str(shadow_action.type or "run_followup"),
        )

    return ShadowComparison(
        step_index=step_index,
        phase=str(phase or ""),
        executed_path=executed_path or None,
        shadow_path=shadow_path or None,
        match=match,
        same_module_family=same_family,
        executed_action_id=executed_id,
        shadow_action_id=shadow_id,
        shadow_confidence=float(shadow_plan.confidence or 0.0),
        shadow_source=str(shadow_plan.source or ""),
        divergence_reason=reason,
        strategic=shadow_plan.strategic.to_dict() if shadow_plan.strategic else {},
        shadow_plan=shadow_plan.to_dict(),
    )


class ShadowPlannerService:
    """Run hierarchical planner in shadow and persist comparisons."""

    def __init__(self, services: Any) -> None:
        self.services = services
        self.engine = HierarchicalPlannerEngine(services)

    def evaluate_shadow(
        self,
        state: Any,
        observation: Mapping[str, Any],
        executed_actions: Sequence[AgentAction],
    ) -> ShadowComparison:
        shadow_plan = self.engine.plan_shadow_cycle(state, observation)
        executed = executed_actions[0] if executed_actions else None
        phase = str(getattr(state, "current_phase", "") or observation.get("phase") or "")
        step_index = len(getattr(state, "executed_actions", []) or [])
        comparison = compare_actions(
            executed,
            shadow_plan,
            step_index=step_index,
            phase=phase,
        )
        self._persist_comparison(state, comparison)
        reports = list(getattr(state, "shadow_reports", []) or [])
        reports.append(comparison.to_dict())
        state.shadow_reports = reports[-64:]
        return comparison

    def replay_run(
        self,
        run_id: str,
        *,
        store: Any = None,
        framework: Any = None,
    ) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.action_trace import load_action_traces_from_store
        from interfaces.command_system.builtin.agent.explain_service import AgentExplainService
        from interfaces.command_system.builtin.agent.run_store import AgentPathService

        framework = framework or getattr(self.services, "core", None)
        framework = getattr(framework, "framework", framework)
        paths = AgentPathService(framework)
        explain = AgentExplainService(framework, paths)
        run_store = store or explain._store_for_run(run_id)
        checkpoint = explain._load_checkpoint_safe(run_store)
        base_state = checkpoint.get("state") if isinstance(checkpoint.get("state"), dict) else {}
        traces = load_action_traces_from_store(run_store)

        state = self._state_from_checkpoint(base_state, run_id)
        comparisons: List[Dict[str, Any]] = []
        executed_keys: List[str] = []

        for index, trace in enumerate(traces):
            if not isinstance(trace, dict):
                continue
            state.executed_actions = list(executed_keys)
            state.current_phase = str(trace.get("phase") or state.current_phase or "act")
            observation = self._build_observation(state)
            shadow_plan = self.engine.plan_shadow_cycle(state, observation)
            executed = AgentAction(
                type="run_exploit" if str(trace.get("module_path") or "").startswith("exploits/") else "run_followup",
                path=str(trace.get("module_path") or "") or None,
                reason="trace:executed",
            )
            row = compare_actions(
                executed,
                shadow_plan,
                step_index=index,
                phase=str(trace.get("phase") or ""),
            )
            comparisons.append(row.to_dict())
            action_key = str(trace.get("action_key") or "")
            if action_key:
                executed_keys.append(action_key)
            elif trace.get("module_path"):
                executed_keys.append(f"{trace.get('phase')}:{trace.get('module_path')}")

        summary = self._summarize(comparisons)
        payload = sanitize_nested({
            "run_id": run_id,
            "mode": "shadow",
            "network_emitted": False,
            "trace_count": len(traces),
            "comparisons": comparisons,
            "summary": summary,
        })
        self._save_offline_report(run_store, payload)
        return payload

    def _build_observation(self, state: Any) -> Dict[str, Any]:
        kb = getattr(state, "knowledge_base", {}) or {}
        catalog: List[Dict[str, Any]] = []
        try:
            catalog = self.services.module_catalog.discover_campaign_modules(
                expanded=bool(getattr(state, "expanded_surface", False)),
            )[:48]
        except Exception:
            catalog = []
        return {
            "phase": getattr(state, "current_phase", ""),
            "goal": getattr(state, "campaign_goal", ""),
            "knowledge_base": kb,
            "catalog_modules": catalog,
            "metrics": getattr(state, "metrics", None),
        }

    @staticmethod
    def _state_from_checkpoint(base_state: Mapping[str, Any], run_id: str) -> Any:
        from types import SimpleNamespace

        state = SimpleNamespace(
            run_id=run_id,
            campaign_goal=base_state.get("campaign_goal") or "recon",
            current_phase=base_state.get("current_phase") or "act",
            knowledge_base=copy.deepcopy(base_state.get("knowledge_base") or {}),
            executed_actions=list(base_state.get("executed_actions") or []),
            runtime_policy=None,
            expanded_surface=bool(base_state.get("expanded_surface", False)),
            shadow_mode_enabled=True,
            hierarchical_planner_enabled=False,
            shadow_reports=[],
        )
        return state

    @staticmethod
    def _summarize(comparisons: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        total = len(comparisons)
        if total == 0:
            return {"total": 0, "match_rate": 0.0, "family_match_rate": 0.0}
        exact = sum(1 for row in comparisons if row.get("match"))
        family = sum(1 for row in comparisons if row.get("match") or row.get("same_module_family"))
        reasons: Dict[str, int] = {}
        for row in comparisons:
            reason = str(row.get("divergence_reason") or "unknown")
            reasons[reason] = int(reasons.get(reason, 0)) + 1
        return {
            "total": total,
            "exact_matches": exact,
            "family_matches": family,
            "match_rate": round(exact / total, 4),
            "family_match_rate": round(family / total, 4),
            "divergence_reasons": reasons,
        }

    @staticmethod
    def _persist_comparison(state: Any, comparison: ShadowComparison) -> None:
        store = getattr(state, "run_store", None)
        if store is None:
            return
        append = getattr(store, "append_shadow_comparison", None)
        if callable(append):
            append(comparison.to_dict())

    @staticmethod
    def _save_offline_report(store: Any, payload: Dict[str, Any]) -> None:
        save = getattr(store, "save_shadow_report", None)
        if callable(save):
            save(payload)


def load_shadow_report(store: Any) -> Dict[str, Any]:
    loader = getattr(store, "load_shadow_report", None)
    if callable(loader):
        payload = loader()
        return payload if isinstance(payload, dict) else {}
    return {}


def load_shadow_comparisons_from_store(store: Any) -> List[Dict[str, Any]]:
    path = getattr(store, "shadow_path", None)
    if path is None or not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                import json

                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows
