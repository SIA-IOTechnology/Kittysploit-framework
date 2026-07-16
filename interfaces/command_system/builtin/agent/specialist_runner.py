#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sequential and parallel read-only specialist execution tiers."""

from __future__ import annotations

import copy
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.action_catalog import CatalogAction
from interfaces.command_system.builtin.agent.delegation_policy import DelegationPolicy
from interfaces.command_system.builtin.agent.hierarchical_planner import StrategicPlan
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.specialist_registry import (
    DEFAULT_SPECIALIST_REGISTRY,
    MAX_FAN_OUT,
    SpecialistProfile,
    SpecialistRegistry,
)
from interfaces.command_system.builtin.agent.specialist_chaos import (
    SpecialistResilienceGuard,
    apply_specialist_resilience,
    bump_plan_epoch,
)
from interfaces.command_system.builtin.agent.typed_models import (
    ActionOutcome,
    AgentAction,
    BlackboardEvent,
    SpecialistProposal,
    SpecialistResult,
    SubAgentTask,
)
from interfaces.command_system.builtin.agent.vuln_specialists import _PATH_CATEGORY_MAP


ExecutionMode = str  # inline | sequential | parallel


@dataclass
class SpecialistRunContext:
    phase: str = ""
    kb: Dict[str, Any] = field(default_factory=dict)
    strategic: Optional[StrategicPlan] = None
    seen_paths: set[str] = field(default_factory=set)
    prior_proposals: List[SpecialistProposal] = field(default_factory=list)
    prior_results: List[SpecialistResult] = field(default_factory=list)

    def absorb(self, proposals: Sequence[SpecialistProposal], result: SpecialistResult) -> None:
        self.prior_proposals.extend(proposals)
        self.prior_results.append(result)
        for proposal in proposals:
            path = str(proposal.action.path or "")
            if path:
                self.seen_paths.add(path)


@dataclass
class SpecialistRunRecord:
    mode: str
    specialist: str
    task_id: str
    dispatch_order: int
    completion_order: int = 0
    proposals: List[SpecialistProposal] = field(default_factory=list)
    outcome_verdict: str = "proposal_only"
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "mode": self.mode,
            "specialist": self.specialist,
            "task_id": self.task_id,
            "dispatch_order": self.dispatch_order,
            "completion_order": self.completion_order,
            "proposal_count": len(self.proposals),
            "proposals": [row.to_dict() for row in self.proposals],
            "outcome_verdict": self.outcome_verdict,
            "error": self.error or None,
            "duration_ms": self.duration_ms,
        })


def specialist_execution_mode(state: Any) -> ExecutionMode:
    if getattr(state, "specialist_parallel_enabled", False):
        return "parallel"
    if getattr(state, "specialist_sequential_enabled", False):
        return "sequential"
    env = os.environ.get("KITTYSPLOIT_AGENT_SPECIALISTS", "").strip().lower()
    if env in {"parallel", "sequential", "inline"}:
        return env
    if os.environ.get("KITTYSPLOIT_AGENT_SPECIALISTS_PARALLEL", "").strip().lower() in {"1", "true", "yes"}:
        return "parallel"
    if os.environ.get("KITTYSPLOIT_AGENT_SPECIALISTS_SEQUENTIAL", "").strip().lower() in {"1", "true", "yes"}:
        return "sequential"
    return "inline"


def _path_matches_specialist(profile: SpecialistProfile, path: str, kb: Mapping[str, Any]) -> bool:
    from interfaces.command_system.builtin.agent.host_specialist_factory import path_matches_host_specialist

    if path_matches_host_specialist(profile, path):
        return True
    low = str(path or "").lower()
    if not low:
        return False
    for family in profile.module_families:
        token = str(family or "").lower()
        if token and token in low:
            return True
    if profile.key in _PATH_CATEGORY_MAP.values() or profile.key in SPECIALIST_VULN_KEYS:
        if profile.key in low:
            return True
        signals = {str(item).lower() for item in (kb.get("risk_signals") or [])}
        if profile.key in signals:
            return True
    if profile.key == "recon":
        return low.startswith(("auxiliary/scanner/", "osint/", "scanner/"))
    if profile.key == "scanner":
        return "scanner" in low or "auxiliary/scanner" in low
    if profile.key == "coordinator":
        return True
    return False


def _specialist_score(
    profile: SpecialistProfile,
    row: CatalogAction,
    ctx: SpecialistRunContext,
) -> float:
    score = float(row.heuristic_score or 0.0)
    path = row.module_path
    if _path_matches_specialist(profile, path, ctx.kb):
        score += 25.0
    if path in ctx.seen_paths:
        score -= 40.0
    for prior in ctx.prior_proposals:
        if prior.specialist != profile.key and str(prior.action.path or "") == path:
            score -= 10.0
    if ctx.strategic and row.capability_target == ctx.strategic.next_capability:
        score += 12.0
    return score


def propose_for_specialist(
    profile: SpecialistProfile,
    catalog: Sequence[CatalogAction],
    ctx: SpecialistRunContext,
    *,
    limit: int = 2,
) -> List[SpecialistProposal]:
    """Read-only specialist proposal — never executes modules."""
    ranked = sorted(
        [row for row in catalog if row.admissible],
        key=lambda row: _specialist_score(profile, row, ctx),
        reverse=True,
    )
    matched = [row for row in ranked if _path_matches_specialist(profile, row.module_path, ctx.kb)]
    pool = matched or ranked
    proposals: List[SpecialistProposal] = []
    for row in pool[: max(1, int(limit or 2))]:
        proposals.append(
            SpecialistProposal(
                specialist=profile.key,
                action=AgentAction(
                    id=row.action_id,
                    type=row.action.type,
                    path=row.module_path,
                    priority=row.action.priority,
                    risk=row.action.risk,
                    reason=f"{profile.key}:{row.action.reason or row.module_path}",
                    status="planned",
                    expected_requests=row.expected_requests,
                ),
                confidence=min(0.95, 0.4 + _specialist_score(profile, row, ctx) / 200.0),
                rationale=(
                    f"{profile.name} proposes {row.module_path} toward "
                    f"{ctx.strategic.next_capability if ctx.strategic else 'goal'}"
                ),
            )
        )
    return proposals


def dedupe_proposals(proposals: Sequence[SpecialistProposal]) -> List[SpecialistProposal]:
    """Keep highest-confidence proposal per action path."""
    best: Dict[str, SpecialistProposal] = {}
    for proposal in proposals:
        path = str(proposal.action.path or "")
        if not path:
            continue
        current = best.get(path)
        if current is None or float(proposal.confidence or 0.0) >= float(current.confidence or 0.0):
            best[path] = proposal
    ranked = sorted(best.values(), key=lambda row: float(row.confidence or 0.0), reverse=True)
    return ranked


SPECIALIST_VULN_KEYS = frozenset({"sqli", "lfi", "xss", "ssrf", "ssti", "auth"})


class SequentialSpecialistRunner:
    """Run read-only specialists one after another, enriching shared context."""

    def __init__(
        self,
        *,
        registry: Optional[SpecialistRegistry] = None,
        delegation: Optional[DelegationPolicy] = None,
        guard: Optional[SpecialistResilienceGuard] = None,
    ) -> None:
        self.registry = registry or DEFAULT_SPECIALIST_REGISTRY
        self.delegation = delegation or DelegationPolicy()
        self.guard = guard or SpecialistResilienceGuard()

    def run(
        self,
        state: Any,
        observation: Mapping[str, Any],
        catalog: Sequence[CatalogAction],
        *,
        strategic: Optional[StrategicPlan] = None,
        llm_available: bool = True,
    ) -> Tuple[List[SpecialistProposal], List[SpecialistRunRecord]]:
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        phase = str(getattr(state, "current_phase", "") or observation.get("phase") or "reason")
        plan_epoch = bump_plan_epoch(state)
        self.guard.reset_cycle_counts(state)
        from interfaces.command_system.builtin.agent.host_specialist_factory import (
            collect_specialists_for_phase,
            gate_host_specialist,
        )

        specialists = [
            row for row in collect_specialists_for_phase(self.registry, state, observation, limit=MAX_FAN_OUT)
            if row.read_only
        ]
        ctx = SpecialistRunContext(phase=phase, kb=dict(kb), strategic=strategic)
        proposals: List[SpecialistProposal] = []
        records: List[SpecialistRunRecord] = []
        fan_out = 0

        for dispatch_order, specialist in enumerate(specialists):
            if self.guard.redeligation_blocked(state, specialist.key):
                continue
            if str(specialist.key).startswith("host/"):
                mutable_kb = getattr(state, "knowledge_base", None)
                if not isinstance(mutable_kb, dict):
                    mutable_kb = kb  # type: ignore[assignment]
                allowed, _gate_reason = gate_host_specialist(state, specialist, mutable_kb)
                if not allowed:
                    continue
            decision = self.delegation.evaluate(
                specialist,
                depth=0,
                fan_out=fan_out,
                phase=phase,
                llm_available=llm_available,
                propose_only=True,
            )
            if not decision.allowed:
                continue
            fan_out += 1
            self.guard.record_delegation(state, specialist.key)
            task = SubAgentTask(
                specialist=specialist.key,
                objective=f"propose:{phase}",
                budget_requests=specialist.budget_requests,
                depth=0,
                status="running",
            )
            started = time.monotonic()
            try:
                batch = propose_for_specialist(specialist, catalog, ctx)
                outcome = ActionOutcome(
                    action_id=task.id,
                    verdict="proposal_only",
                    phase=phase,
                    network_requests=0,
                    message=f"{len(batch)} proposals",
                    raw_summary={"specialist": specialist.key, "read_only": True},
                )
                result = SpecialistResult(
                    proposal_id=batch[0].id if batch else task.id,
                    specialist=specialist.key,
                    outcome=outcome,
                )
                ctx.absorb(batch, result)
                proposals.extend(batch)
                records.append(
                    SpecialistRunRecord(
                        mode="sequential",
                        specialist=specialist.key,
                        task_id=task.id,
                        dispatch_order=dispatch_order,
                        completion_order=len(records),
                        proposals=batch,
                        duration_ms=round((time.monotonic() - started) * 1000.0, 2),
                    )
                )
            except Exception as exc:
                records.append(
                    SpecialistRunRecord(
                        mode="sequential",
                        specialist=specialist.key,
                        task_id=task.id,
                        dispatch_order=dispatch_order,
                        completion_order=len(records),
                        outcome_verdict="specialist_crash",
                        error=str(exc),
                        duration_ms=round((time.monotonic() - started) * 1000.0, 2),
                    )
                )
        merged = dedupe_proposals(proposals)
        report = apply_specialist_resilience(
            state,
            observation,
            records,
            merged,
            plan_epoch=plan_epoch,
            guard=self.guard,
        )
        final = report.merge.proposals
        _persist_specialist_run(state, records, final, mode="sequential")
        return final, records


class ParallelSpecialistScheduler:
    """Dispatch read-only specialists concurrently; merge with scheduling metadata."""

    def __init__(
        self,
        *,
        registry: Optional[SpecialistRegistry] = None,
        delegation: Optional[DelegationPolicy] = None,
        guard: Optional[SpecialistResilienceGuard] = None,
        max_workers: int = MAX_FAN_OUT,
        worker_timeout_s: float = 30.0,
    ) -> None:
        self.registry = registry or DEFAULT_SPECIALIST_REGISTRY
        self.delegation = delegation or DelegationPolicy()
        self.max_workers = max(1, int(max_workers or MAX_FAN_OUT))
        self.worker_timeout_s = max(0.01, float(worker_timeout_s or 30.0))
        self.guard = guard or SpecialistResilienceGuard()

    def run(
        self,
        state: Any,
        observation: Mapping[str, Any],
        catalog: Sequence[CatalogAction],
        *,
        strategic: Optional[StrategicPlan] = None,
        llm_available: bool = True,
        worker_delay_ms: Optional[Mapping[str, int]] = None,
        worker_timeout_s: Optional[float] = None,
    ) -> Tuple[List[SpecialistProposal], List[SpecialistRunRecord]]:
        kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
        phase = str(getattr(state, "current_phase", "") or observation.get("phase") or "reason")
        plan_epoch = bump_plan_epoch(state)
        self.guard.reset_cycle_counts(state)
        timeout_s = float(worker_timeout_s if worker_timeout_s is not None else self.worker_timeout_s)
        from interfaces.command_system.builtin.agent.host_specialist_factory import (
            collect_specialists_for_phase,
            gate_host_specialist,
        )

        specialists = [
            row for row in collect_specialists_for_phase(self.registry, state, observation, limit=MAX_FAN_OUT)
            if row.read_only
        ]
        ctx = SpecialistRunContext(phase=phase, kb=dict(kb), strategic=strategic)
        jobs: List[Tuple[int, SpecialistProfile, SubAgentTask]] = []
        fan_out = 0
        for dispatch_order, specialist in enumerate(specialists):
            if self.guard.redeligation_blocked(state, specialist.key):
                continue
            if str(specialist.key).startswith("host/"):
                mutable_kb = getattr(state, "knowledge_base", None)
                if not isinstance(mutable_kb, dict):
                    mutable_kb = kb  # type: ignore[assignment]
                allowed, _gate_reason = gate_host_specialist(state, specialist, mutable_kb)
                if not allowed:
                    continue
            decision = self.delegation.evaluate(
                specialist,
                depth=0,
                fan_out=fan_out,
                phase=phase,
                llm_available=llm_available,
                propose_only=True,
            )
            if not decision.allowed:
                continue
            fan_out += 1
            self.guard.record_delegation(state, specialist.key)
            task = SubAgentTask(
                specialist=specialist.key,
                objective=f"propose:{phase}",
                budget_requests=specialist.budget_requests,
                depth=0,
                status="running",
            )
            jobs.append((dispatch_order, specialist, task))

        records: List[SpecialistRunRecord] = []
        proposals: List[SpecialistProposal] = []

        def _worker(dispatch_order: int, specialist: SpecialistProfile, task: SubAgentTask) -> SpecialistRunRecord:
            delay = int((worker_delay_ms or {}).get(specialist.key, 0) or 0)
            if delay > 0:
                time.sleep(delay / 1000.0)
            started = time.monotonic()
            try:
                local_ctx = copy.deepcopy(ctx)
                batch = propose_for_specialist(specialist, catalog, local_ctx)
                return SpecialistRunRecord(
                    mode="parallel",
                    specialist=specialist.key,
                    task_id=task.id,
                    dispatch_order=dispatch_order,
                    proposals=batch,
                    duration_ms=round((time.monotonic() - started) * 1000.0, 2),
                )
            except Exception as exc:
                return SpecialistRunRecord(
                    mode="parallel",
                    specialist=specialist.key,
                    task_id=task.id,
                    dispatch_order=dispatch_order,
                    outcome_verdict="specialist_crash",
                    error=str(exc),
                    duration_ms=round((time.monotonic() - started) * 1000.0, 2),
                )

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(_worker, dispatch_order, specialist, task): (dispatch_order, specialist, task)
                for dispatch_order, specialist, task in jobs
            }
            done, not_done = wait(futures.keys(), timeout=timeout_s)
            completion = 0
            for future in done:
                dispatch_order, specialist, task = futures[future]
                try:
                    record = future.result()
                except Exception as exc:
                    record = SpecialistRunRecord(
                        mode="parallel",
                        specialist=specialist.key,
                        task_id=task.id,
                        dispatch_order=dispatch_order,
                        outcome_verdict="specialist_crash",
                        error=str(exc),
                    )
                record.completion_order = completion
                completion += 1
                records.append(record)
                proposals.extend(record.proposals)
            for future in not_done:
                dispatch_order, specialist, task = futures[future]
                future.cancel()
                records.append(
                    SpecialistRunRecord(
                        mode="parallel",
                        specialist=specialist.key,
                        task_id=task.id,
                        dispatch_order=dispatch_order,
                        completion_order=completion,
                        outcome_verdict="starvation",
                        error="worker_timeout",
                    )
                )
                completion += 1

        records.sort(key=lambda row: (row.dispatch_order, row.completion_order))
        merged = dedupe_proposals(proposals)
        report = apply_specialist_resilience(
            state,
            observation,
            records,
            merged,
            plan_epoch=plan_epoch,
            guard=self.guard,
        )
        final = report.merge.proposals
        _persist_specialist_run(state, records, final, mode="parallel")
        return final, records


def _persist_specialist_run(
    state: Any,
    records: Sequence[SpecialistRunRecord],
    proposals: Sequence[SpecialistProposal],
    *,
    mode: str,
) -> None:
    payload = {
        "mode": mode,
        "records": [row.to_dict() for row in records],
        "proposal_paths": [str(row.action.path or "") for row in proposals],
    }
    history = list(getattr(state, "specialist_runs", []) or [])
    history.append(payload)
    state.specialist_runs = history[-32:]
    store = getattr(state, "run_store", None)
    append = getattr(store, "append_specialist_run", None)
    if callable(append):
        append(payload)
    loop = getattr(state, "adaptive_loop", None)
    if loop is not None:
        events = list(getattr(loop, "blackboard", []) or [])
        events.append(
            BlackboardEvent(
                kind="specialist_run",
                summary=f"{mode} specialists produced {len(proposals)} proposals",
                payload=payload,
                source="specialist_runner",
            )
        )
        loop.blackboard = events[-12:]


def run_specialists(
    mode: ExecutionMode,
    state: Any,
    observation: Mapping[str, Any],
    catalog: Sequence[CatalogAction],
    *,
    strategic: Optional[StrategicPlan] = None,
    llm_available: bool = True,
    worker_delay_ms: Optional[Mapping[str, int]] = None,
) -> Tuple[List[SpecialistProposal], List[SpecialistRunRecord]]:
    if mode == "sequential":
        return SequentialSpecialistRunner().run(
            state,
            observation,
            catalog,
            strategic=strategic,
            llm_available=llm_available,
        )
    if mode == "parallel":
        return ParallelSpecialistScheduler().run(
            state,
            observation,
            catalog,
            strategic=strategic,
            llm_available=llm_available,
            worker_delay_ms=worker_delay_ms,
        )
    return [], []


def fuzz_worker_delays(
    specialists: Sequence[SpecialistProfile],
    *,
    seed: int = 0,
    max_delay_ms: int = 40,
) -> Dict[str, int]:
    rng = random.Random(seed)
    return {row.key: rng.randint(0, max_delay_ms) for row in specialists}


def merge_with_scheduling_fuzz(
    records: Sequence[SpecialistRunRecord],
    *,
    seed: int = 0,
) -> List[SpecialistProposal]:
    """Reorder completed specialist records to simulate out-of-order delivery."""
    rows = list(records)
    rng = random.Random(seed)
    rng.shuffle(rows)
    proposals: List[SpecialistProposal] = []
    for row in rows:
        proposals.extend(row.proposals)
    return dedupe_proposals(proposals)


class SpecialistComparisonService:
    """Offline replay comparing inline vs sequential specialist proposals."""

    def __init__(self, services: Any) -> None:
        self.services = services

    def replay_run(
        self,
        run_id: str,
        *,
        store: Any = None,
        framework: Any = None,
    ) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.action_catalog import build_admissible_catalog
        from interfaces.command_system.builtin.agent.action_trace import load_action_traces_from_store
        from interfaces.command_system.builtin.agent.explain_service import AgentExplainService
        from interfaces.command_system.builtin.agent.hierarchical_planner import MissionCommander, StrategicPlanner
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
        commander = MissionCommander()
        strategic_planner = StrategicPlanner()
        comparisons: List[Dict[str, Any]] = []

        for index, trace in enumerate(traces):
            if not isinstance(trace, dict):
                continue
            state.current_phase = str(trace.get("phase") or state.current_phase or "act")
            observation = self._build_observation(state)
            kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
            modules = observation.get("catalog_modules") or []
            strategic = strategic_planner.plan(state, observation)
            catalog = build_admissible_catalog(
                modules=modules,
                kb=kb,
                goal=getattr(state, "campaign_goal", ""),
                executed_actions=getattr(state, "executed_actions", []) or [],
            )
            inline = commander._propose_inline(
                state,
                observation,
                catalog,
                strategic=strategic,
                llm_available=False,
            )
            sequential, _records = SequentialSpecialistRunner().run(
                state,
                observation,
                catalog,
                strategic=strategic,
                llm_available=False,
            )
            inline_paths = [str(row.action.path or "") for row in inline]
            sequential_paths = [str(row.action.path or "") for row in sequential]
            comparisons.append(sanitize_nested({
                "step_index": index,
                "phase": state.current_phase,
                "executed_path": trace.get("module_path"),
                "inline_top": inline_paths[:1],
                "sequential_top": sequential_paths[:1],
                "inline_paths": inline_paths,
                "sequential_paths": sequential_paths,
                "top_match": bool(inline_paths[:1] == sequential_paths[:1]),
                "path_overlap": len(set(inline_paths) & set(sequential_paths)),
            }))

        summary = self._summarize(comparisons)
        payload = sanitize_nested({
            "run_id": run_id,
            "mode": "specialists",
            "network_emitted": False,
            "trace_count": len(traces),
            "comparisons": comparisons,
            "summary": summary,
        })
        save = getattr(run_store, "save_specialist_report", None)
        if callable(save):
            save(payload)
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
        }

    @staticmethod
    def _state_from_checkpoint(base_state: Mapping[str, Any], run_id: str) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(
            run_id=run_id,
            campaign_goal=base_state.get("campaign_goal") or "recon",
            current_phase=base_state.get("current_phase") or "act",
            knowledge_base=copy.deepcopy(base_state.get("knowledge_base") or {}),
            executed_actions=list(base_state.get("executed_actions") or []),
            runtime_policy=None,
            expanded_surface=bool(base_state.get("expanded_surface", False)),
            specialist_sequential_enabled=True,
            specialist_runs=[],
        )

    @staticmethod
    def _summarize(comparisons: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        total = len(comparisons)
        if total == 0:
            return {"total": 0, "top_match_rate": 0.0}
        top_matches = sum(1 for row in comparisons if row.get("top_match"))
        return {
            "total": total,
            "top_matches": top_matches,
            "top_match_rate": round(top_matches / total, 4),
        }
