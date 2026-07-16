#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Chaos/resilience handling for read-only specialist scheduling."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.specialist_registry import MAX_FAN_OUT
from interfaces.command_system.builtin.agent.typed_models import AgentAction, SpecialistProposal

LISTENER_PATH_MARKERS = ("handler", "listener", "reverse_shell", "bind_shell", "multi/handler")
SESSION_ACQUIRE_MARKERS = ("session_acquire", "shell", "meterpreter", "reverse_tcp")
MAX_SAME_SPECIALIST_PER_CYCLE = 2


@dataclass
class ChaosEnvelope:
    plan_epoch: int
    task_id: str
    specialist: str
    proposals: List[SpecialistProposal] = field(default_factory=list)
    dispatch_order: int = 0
    completion_order: int = 0
    received_at: float = field(default_factory=time.monotonic)
    outcome_verdict: str = "proposal_only"

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "plan_epoch": self.plan_epoch,
            "task_id": self.task_id,
            "specialist": self.specialist,
            "dispatch_order": self.dispatch_order,
            "completion_order": self.completion_order,
            "outcome_verdict": self.outcome_verdict,
            "proposal_count": len(self.proposals),
        })


@dataclass
class SpecialistMergeResult:
    proposals: List[SpecialistProposal]
    discarded: List[Dict[str, Any]] = field(default_factory=list)
    fallback_to_heuristic: bool = False
    fallback_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "proposal_paths": [str(row.action.path or "") for row in self.proposals],
            "discarded_count": len(self.discarded),
            "discarded": self.discarded,
            "fallback_to_heuristic": self.fallback_to_heuristic,
            "fallback_reason": self.fallback_reason or None,
        })


@dataclass
class SpecialistResilienceReport:
    plan_epoch: int
    merge: SpecialistMergeResult
    guard_blocks: List[Dict[str, Any]] = field(default_factory=list)
    records_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "plan_epoch": self.plan_epoch,
            "merge": self.merge.to_dict(),
            "guard_blocks": self.guard_blocks,
            "records_summary": self.records_summary,
        })


def current_plan_epoch(state: Any) -> int:
    return int(getattr(state, "specialist_plan_epoch", 0) or 0)


def bump_plan_epoch(state: Any) -> int:
    epoch = current_plan_epoch(state) + 1
    state.specialist_plan_epoch = epoch
    return epoch


def envelopes_from_records(
    records: Sequence[Any],
    *,
    plan_epoch: int,
) -> List[ChaosEnvelope]:
    rows: List[ChaosEnvelope] = []
    for record in records:
        rows.append(
            ChaosEnvelope(
                plan_epoch=plan_epoch,
                task_id=record.task_id,
                specialist=record.specialist,
                proposals=list(record.proposals),
                dispatch_order=record.dispatch_order,
                completion_order=record.completion_order,
                outcome_verdict=record.outcome_verdict,
            )
        )
    return rows


def merge_specialist_deliveries(
    envelopes: Sequence[ChaosEnvelope],
    *,
    plan_epoch: int,
) -> Tuple[List[SpecialistProposal], List[Dict[str, Any]]]:
    """Merge duplicate, late, or out-of-order specialist deliveries."""
    from interfaces.command_system.builtin.agent.specialist_runner import dedupe_proposals

    discarded: List[Dict[str, Any]] = []
    accepted: List[ChaosEnvelope] = []
    seen_tasks: Set[str] = set()

    for envelope in sorted(
        envelopes,
        key=lambda row: (row.plan_epoch, row.dispatch_order, row.completion_order, row.received_at),
    ):
        if envelope.plan_epoch < plan_epoch:
            discarded.append({
                "reason": "stale_epoch",
                "task_id": envelope.task_id,
                "specialist": envelope.specialist,
                "plan_epoch": envelope.plan_epoch,
            })
            continue
        if envelope.task_id in seen_tasks:
            discarded.append({
                "reason": "duplicate_task",
                "task_id": envelope.task_id,
                "specialist": envelope.specialist,
            })
            continue
        seen_tasks.add(envelope.task_id)
        accepted.append(envelope)

    proposals: List[SpecialistProposal] = []
    for envelope in sorted(accepted, key=lambda row: (row.dispatch_order, row.completion_order)):
        proposals.extend(envelope.proposals)
    return dedupe_proposals(proposals), discarded


def _kb_dict(state: Any, observation: Mapping[str, Any]) -> Dict[str, Any]:
    kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
    if isinstance(getattr(state, "knowledge_base", None), dict):
        merged = dict(getattr(state, "knowledge_base", {}))
        merged.update(kb)
        return merged
    return dict(kb)


def scope_revoked(state: Any, observation: Mapping[str, Any]) -> bool:
    if bool(getattr(state, "scope_revoked", False)):
        return True
    kb = _kb_dict(state, observation)
    return bool(kb.get("scope_revoked") or kb.get("scope_denied"))


def _path_markers(path: str, markers: Sequence[str]) -> bool:
    low = str(path or "").lower()
    return any(token in low for token in markers)


class SpecialistResilienceGuard:
    """Policy checks for specialist proposals before planner merge."""

    def __init__(
        self,
        *,
        max_same_specialist_per_cycle: int = MAX_SAME_SPECIALIST_PER_CYCLE,
    ) -> None:
        self.max_same_specialist_per_cycle = max(1, int(max_same_specialist_per_cycle))

    def filter_proposals(
        self,
        proposals: Sequence[SpecialistProposal],
        state: Any,
        observation: Mapping[str, Any],
    ) -> Tuple[List[SpecialistProposal], List[Dict[str, Any]]]:
        if scope_revoked(state, observation):
            return [], [{"reason": "scope_revoked"}]

        kb = _kb_dict(state, observation)
        active_listeners = {
            str(item).lower()
            for item in (kb.get("active_listeners") or kb.get("listeners") or [])
        }
        unstable_sessions = {
            str(item).lower()
            for item in (kb.get("unstable_sessions") or kb.get("session_conflicts") or [])
        }
        blocks: List[Dict[str, Any]] = []
        kept: List[SpecialistProposal] = []

        for proposal in proposals:
            path = str(proposal.action.path or "")
            block_reason = self._block_reason(path, active_listeners, unstable_sessions)
            if block_reason:
                blocks.append({
                    "reason": block_reason,
                    "path": path,
                    "specialist": proposal.specialist,
                })
                continue
            kept.append(proposal)
        return kept, blocks

    @staticmethod
    def _block_reason(
        path: str,
        active_listeners: Set[str],
        unstable_sessions: Set[str],
    ) -> Optional[str]:
        low = path.lower()
        if _path_markers(low, LISTENER_PATH_MARKERS):
            for listener in active_listeners:
                if listener and listener in low:
                    return "listener_conflict"
            if active_listeners:
                return "listener_conflict"
        if _path_markers(low, SESSION_ACQUIRE_MARKERS) and unstable_sessions:
            return "session_conflict"
        return None

    def redeligation_blocked(self, state: Any, specialist: str) -> bool:
        counts = dict(getattr(state, "specialist_delegation_counts", {}) or {})
        return int(counts.get(str(specialist or ""), 0) or 0) >= self.max_same_specialist_per_cycle

    def record_delegation(self, state: Any, specialist: str) -> None:
        counts = dict(getattr(state, "specialist_delegation_counts", {}) or {})
        key = str(specialist or "")
        counts[key] = int(counts.get(key, 0) or 0) + 1
        state.specialist_delegation_counts = counts

    def reset_cycle_counts(self, state: Any) -> None:
        state.specialist_delegation_counts = {}


def should_fallback_to_heuristic(
    records: Sequence[Any],
    proposals: Sequence[SpecialistProposal],
    *,
    scope_revoked_flag: bool = False,
    guard_blocks: Optional[Sequence[Mapping[str, Any]]] = None,
    starvation: bool = False,
) -> Tuple[bool, str]:
    if scope_revoked_flag:
        return True, "scope_revoked"
    if starvation:
        return True, "starvation"
    if not records:
        return False, ""
    crashes = sum(1 for row in records if row.outcome_verdict in {"specialist_crash", "starvation"})
    if crashes == len(records):
        return True, "all_specialists_failed"
    if not proposals:
        blocks = list(guard_blocks or [])
        if blocks and all(row.get("reason") == "scope_revoked" for row in blocks):
            return True, "scope_revoked"
        if crashes > 0 and not proposals:
            return True, "specialist_failures_no_proposals"
    return False, ""


def apply_specialist_resilience(
    state: Any,
    observation: Mapping[str, Any],
    records: Sequence[Any],
    raw_proposals: Sequence[SpecialistProposal],
    *,
    plan_epoch: Optional[int] = None,
    guard: Optional[SpecialistResilienceGuard] = None,
    extra_envelopes: Optional[Sequence[ChaosEnvelope]] = None,
) -> SpecialistResilienceReport:
    from interfaces.command_system.builtin.agent.specialist_runner import dedupe_proposals

    guard = guard or SpecialistResilienceGuard()
    epoch = int(plan_epoch if plan_epoch is not None else current_plan_epoch(state))
    envelopes = envelopes_from_records(records, plan_epoch=epoch)
    if extra_envelopes:
        envelopes.extend(list(extra_envelopes))

    merged, discarded = merge_specialist_deliveries(envelopes, plan_epoch=epoch)
    if raw_proposals and not merged:
        merged = dedupe_proposals(list(raw_proposals))

    filtered, guard_blocks = guard.filter_proposals(merged, state, observation)
    revoked = scope_revoked(state, observation)
    starvation = any(row.outcome_verdict == "starvation" for row in records)
    fallback, reason = should_fallback_to_heuristic(
        records,
        filtered,
        scope_revoked_flag=revoked,
        guard_blocks=guard_blocks,
        starvation=starvation,
    )

    merge_result = SpecialistMergeResult(
        proposals=filtered if not fallback else [],
        discarded=discarded,
        fallback_to_heuristic=fallback,
        fallback_reason=reason,
    )
    report = SpecialistResilienceReport(
        plan_epoch=epoch,
        merge=merge_result,
        guard_blocks=guard_blocks,
        records_summary={
            "total": len(records),
            "crashes": sum(1 for row in records if row.outcome_verdict == "specialist_crash"),
            "starvation": sum(1 for row in records if row.outcome_verdict == "starvation"),
            "discarded": len(discarded),
        },
    )
    _persist_resilience(state, report)
    if fallback:
        state.specialist_fallback_reason = reason
        state.decision_source = "heuristic"
    return report


def _persist_resilience(state: Any, report: SpecialistResilienceReport) -> None:
    history = list(getattr(state, "specialist_resilience_reports", []) or [])
    history.append(report.to_dict())
    state.specialist_resilience_reports = history[-32:]
    store = getattr(state, "run_store", None)
    append = getattr(store, "append_specialist_resilience", None)
    if callable(append):
        append(report.to_dict())


def inject_duplicate_envelope(
    envelope: ChaosEnvelope,
) -> ChaosEnvelope:
    """Test helper: simulate duplicate delivery of the same task."""
    duplicate = ChaosEnvelope(
        plan_epoch=envelope.plan_epoch,
        task_id=envelope.task_id,
        specialist=envelope.specialist,
        proposals=list(envelope.proposals),
        dispatch_order=envelope.dispatch_order,
        completion_order=envelope.completion_order + 100,
        outcome_verdict=envelope.outcome_verdict,
    )
    return duplicate


def inject_stale_envelope(
    envelope: ChaosEnvelope,
    *,
    stale_epoch: int,
) -> ChaosEnvelope:
    """Test helper: simulate late delivery from a previous planning epoch."""
    return ChaosEnvelope(
        plan_epoch=stale_epoch,
        task_id=f"{envelope.task_id}:stale",
        specialist=envelope.specialist,
        proposals=list(envelope.proposals),
        dispatch_order=envelope.dispatch_order,
        completion_order=envelope.completion_order,
        outcome_verdict="stale",
    )


class SpecialistChaosReplayService:
    """Offline chaos scenarios against recorded or synthetic specialist deliveries."""

    def run_scenarios(self) -> Dict[str, Any]:
        catalog_path = "auxiliary/scanner/http/crawler"
        action = AgentAction(type="run_followup", path=catalog_path)
        base = SpecialistProposal(specialist="recon", action=action, confidence=0.7)
        envelope = ChaosEnvelope(
            plan_epoch=2,
            task_id="task_recon_1",
            specialist="recon",
            proposals=[base],
            dispatch_order=0,
        )
        scenarios: List[Dict[str, Any]] = []

        merged, discarded = merge_specialist_deliveries([envelope, inject_duplicate_envelope(envelope)], plan_epoch=2)
        scenarios.append({
            "name": "duplicate_delivery",
            "passed": len(merged) == 1 and any(row.get("reason") == "duplicate_task" for row in discarded),
            "discarded": discarded,
        })

        stale = inject_stale_envelope(envelope, stale_epoch=1)
        merged_stale, discarded_stale = merge_specialist_deliveries([envelope, stale], plan_epoch=2)
        scenarios.append({
            "name": "stale_epoch",
            "passed": len(merged_stale) == 1 and any(row.get("reason") == "stale_epoch" for row in discarded_stale),
            "discarded": discarded_stale,
        })

        late = ChaosEnvelope(
            plan_epoch=2,
            task_id="task_scanner_1",
            specialist="scanner",
            proposals=[
                SpecialistProposal(
                    specialist="scanner",
                    action=AgentAction(type="run_followup", path="auxiliary/scanner/portscan/tcp"),
                    confidence=0.6,
                )
            ],
            dispatch_order=0,
            completion_order=1,
        )
        early = ChaosEnvelope(
            plan_epoch=2,
            task_id="task_recon_2",
            specialist="recon",
            proposals=[base],
            dispatch_order=1,
            completion_order=0,
        )
        merged_order, _ = merge_specialist_deliveries([late, early], plan_epoch=2)
        scenarios.append({
            "name": "out_of_order_merge",
            "passed": [row.action.path for row in merged_order] == [catalog_path, "auxiliary/scanner/portscan/tcp"],
        })

        state = __import__("types").SimpleNamespace(
            scope_revoked=True,
            knowledge_base={},
            specialist_delegation_counts={},
        )
        guard = SpecialistResilienceGuard()
        kept, blocks = guard.filter_proposals([base], state, {"knowledge_base": {}})
        scenarios.append({
            "name": "scope_revocation",
            "passed": not kept and blocks[0]["reason"] == "scope_revoked",
        })

        listener_state = __import__("types").SimpleNamespace(
            scope_revoked=False,
            knowledge_base={"active_listeners": ["reverse_tcp"]},
            specialist_delegation_counts={},
        )
        listener_proposal = SpecialistProposal(
            specialist="exploiter",
            action=AgentAction(type="run_exploit", path="exploits/multi/handler/reverse_tcp"),
            confidence=0.9,
        )
        kept_listener, blocks_listener = guard.filter_proposals(
            [listener_proposal],
            listener_state,
            {"knowledge_base": listener_state.knowledge_base},
        )
        scenarios.append({
            "name": "listener_conflict",
            "passed": not kept_listener and blocks_listener[0]["reason"] == "listener_conflict",
        })

        guard.record_delegation(state, "recon")
        guard.record_delegation(state, "recon")
        scenarios.append({
            "name": "redeligation_loop",
            "passed": guard.redeligation_blocked(state, "recon"),
        })

        crash_record = __import__(
            "interfaces.command_system.builtin.agent.specialist_runner",
            fromlist=["SpecialistRunRecord"],
        ).SpecialistRunRecord(
            mode="parallel",
            specialist="recon",
            task_id="crash_1",
            dispatch_order=0,
            outcome_verdict="specialist_crash",
        )
        fallback, reason = should_fallback_to_heuristic([crash_record], [])
        scenarios.append({
            "name": "child_crash_fallback",
            "passed": fallback and reason == "all_specialists_failed",
        })

        passed = sum(1 for row in scenarios if row.get("passed"))
        return sanitize_nested({
            "mode": "chaos",
            "network_emitted": False,
            "scenario_count": len(scenarios),
            "passed": passed,
            "failed": len(scenarios) - passed,
            "all_passed": passed == len(scenarios),
            "scenarios": scenarios,
        })
