#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Transactional scheduler: action leases, child budgets, cancel, stale results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union

from interfaces.command_system.builtin.agent.host_specialist_factory import reserve_specialist_budget
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.specialist_chaos import bump_plan_epoch, current_plan_epoch
from interfaces.command_system.builtin.agent.typed_models import (
    ActionLease,
    AgentAction,
    BlackboardEvent,
    SpecialistProposal,
    SubAgentTask,
)

SCHEMA_VERSION = "1.0"

EVENT_ACTION_LEASED = "ActionLeased"
EVENT_ACTION_APPROVED = "ActionApproved"
EVENT_OUTCOME_VERIFIED = "OutcomeVerified"
EVENT_TASK_CANCELLED = "TaskCancelled"
EVENT_RESULT_STALE = "ResultStale"

REASON_ACCEPTED = "accepted"
REASON_CANCELLED = "cancelled"
REASON_RESULT_STALE = "ResultStale"
REASON_DUPLICATE = "duplicate_lease"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _kb(state: Any) -> MutableMapping[str, Any]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    return kb


def _scheduler_store(state: Any) -> Dict[str, Any]:
    kb = _kb(state)
    store = kb.get("scheduler")
    if not isinstance(store, dict):
        store = {}
        kb["scheduler"] = store
    store.setdefault("schema_version", SCHEMA_VERSION)
    store.setdefault("active_leases", {})
    store.setdefault("consumed_non_idempotent", [])
    store.setdefault("child_tasks", {})
    store.setdefault("cancelled_task_ids", [])
    store.setdefault("accepted_task_ids", [])
    store.setdefault("accepted_lease_keys", [])
    store.setdefault("blackboard", [])
    store.setdefault("counters", {
        "accepted": 0,
        "verified": 0,
        "stale": 0,
        "duplicates": 0,
        "cancels": 0,
        "leases_granted": 0,
        "leases_refused": 0,
        "child_reserves": 0,
        "child_refused": 0,
        "cost_requests": 0,
    })
    store.setdefault("latency_ms", [])
    store.setdefault("plan_epoch", int(getattr(state, "specialist_plan_epoch", 0) or 0))
    return store


def _persist(state: Any, store: Mapping[str, Any]) -> None:
    kb = _kb(state)
    kb["scheduler"] = sanitize_nested(dict(store))


def _as_set(values: Sequence[Any]) -> Set[str]:
    return {str(item) for item in values if item is not None and str(item)}


def _append_event(store: Dict[str, Any], event: BlackboardEvent) -> None:
    events = list(store.get("blackboard") or [])
    events.append(event.to_dict())
    store["blackboard"] = events[-64:]


def _emit_loop_blackboard(state: Any, event: BlackboardEvent) -> None:
    loop = getattr(state, "adaptive_loop", None)
    if loop is None:
        return
    events = list(getattr(loop, "blackboard", []) or [])
    events.append(event)
    loop.blackboard = events[-32:]


def _p95(samples: Sequence[float]) -> Optional[float]:
    rows = sorted(float(x) for x in samples if x is not None)
    if not rows:
        return None
    idx = min(len(rows) - 1, max(0, int(round(0.95 * (len(rows) - 1)))))
    return rows[idx]


@dataclass
class TransactionalScheduler:
    """Single authority for action leases, child budgets, cancel, and stale accept."""

    source: str = "transactional_scheduler"

    def reserve_action_lease(self, state: Any, action: AgentAction) -> Optional[ActionLease]:
        store = _scheduler_store(state)
        counters = store.setdefault("counters", {})
        action_id = str(action.id or "")
        consumed = _as_set(store.get("consumed_non_idempotent") or [])
        if action_id and action_id in consumed:
            counters["leases_refused"] = int(counters.get("leases_refused") or 0) + 1
            _persist(state, store)
            return None

        reserve = max(1, int(action.expected_requests or 1))
        budget = int(getattr(state, "request_budget", 0) or 0)
        metrics = getattr(state, "metrics", None)
        used = int(getattr(metrics, "network_units_used", 0) or 0) if metrics is not None else 0
        child_reserved = self._child_reserved(state)
        if budget > 0 and used + child_reserved + reserve > budget:
            counters["leases_refused"] = int(counters.get("leases_refused") or 0) + 1
            _persist(state, store)
            return None

        if metrics is not None:
            metrics.network_units_used = used + reserve

        non_idempotent = action.type in {"run_exploit", "run_post"}
        lease = ActionLease(
            action_id=action_id,
            reserved_requests=reserve,
            non_idempotent=non_idempotent,
        )
        active = dict(store.get("active_leases") or {})
        active[action_id or lease.acquired_at] = lease.to_dict()
        store["active_leases"] = active
        counters["leases_granted"] = int(counters.get("leases_granted") or 0) + 1
        counters["cost_requests"] = int(counters.get("cost_requests") or 0) + reserve

        event = BlackboardEvent(
            kind=EVENT_ACTION_LEASED,
            summary=f"leased {action.path or action_id} ({reserve} req)",
            payload={
                "action_id": action_id,
                "path": action.path,
                "reserved_requests": reserve,
                "non_idempotent": non_idempotent,
            },
            source=self.source,
        )
        _append_event(store, event)
        _emit_loop_blackboard(state, event)
        _persist(state, store)
        return lease

    def release_action_lease(
        self,
        state: Any,
        lease: ActionLease,
        *,
        consumed: int = 0,
        success: bool = True,
        latency_ms: Optional[float] = None,
    ) -> None:
        store = _scheduler_store(state)
        counters = store.setdefault("counters", {})
        action_id = str(lease.action_id or "")
        reserved = max(0, int(lease.reserved_requests or 0))
        used = max(0, min(reserved, int(consumed or 0)))
        refund = 0
        if not lease.non_idempotent and reserved > used:
            refund = reserved - used
            metrics = getattr(state, "metrics", None)
            if metrics is not None and refund > 0:
                current = int(getattr(metrics, "network_units_used", 0) or 0)
                metrics.network_units_used = max(0, current - refund)
            counters["cost_requests"] = max(
                0, int(counters.get("cost_requests") or 0) - refund
            )

        if lease.non_idempotent and action_id:
            consumed_set = list(store.get("consumed_non_idempotent") or [])
            if action_id not in consumed_set:
                consumed_set.append(action_id)
            store["consumed_non_idempotent"] = consumed_set[-256:]

        active = dict(store.get("active_leases") or {})
        key = action_id if action_id in active else None
        if key is None:
            for candidate, row in list(active.items()):
                if isinstance(row, dict) and str(row.get("action_id") or "") == action_id:
                    key = candidate
                    break
        if key is not None:
            row = dict(active.get(key) or {})
            row["released"] = True
            row["consumed"] = used
            row["refunded"] = refund
            row["success"] = bool(success)
            active[key] = row
            store["active_leases"] = active

        lease.released = True
        if latency_ms is not None:
            samples = list(store.get("latency_ms") or [])
            samples.append(float(latency_ms))
            store["latency_ms"] = samples[-256:]

        if success:
            event = BlackboardEvent(
                kind=EVENT_OUTCOME_VERIFIED,
                summary=f"released lease {action_id}",
                payload={
                    "action_id": action_id,
                    "consumed": used,
                    "refunded": refund,
                    "non_idempotent": bool(lease.non_idempotent),
                },
                source=self.source,
            )
            _append_event(store, event)
            _emit_loop_blackboard(state, event)
            counters["verified"] = int(counters.get("verified") or 0) + 1

        _persist(state, store)

    def reserve_child_budget(self, state: Any, task: SubAgentTask) -> bool:
        store = _scheduler_store(state)
        counters = store.setdefault("counters", {})
        kb = _kb(state)
        cost = max(1, int(task.budget_requests or 1))
        ok, reason = reserve_specialist_budget(state, kb, cost)
        child_tasks = dict(store.get("child_tasks") or {})
        row = task.to_dict() if hasattr(task, "to_dict") else {
            "id": task.id,
            "specialist": task.specialist,
            "objective": task.objective,
            "budget_requests": cost,
            "status": task.status,
        }
        if not ok:
            row["status"] = "budget_denied"
            row["deny_reason"] = reason
            child_tasks[str(task.id)] = row
            store["child_tasks"] = child_tasks
            counters["child_refused"] = int(counters.get("child_refused") or 0) + 1
            _persist(state, store)
            return False

        row["status"] = "reserved"
        row["reserved_at"] = _now_iso()
        child_tasks[str(task.id)] = row
        store["child_tasks"] = child_tasks
        counters["child_reserves"] = int(counters.get("child_reserves") or 0) + 1
        counters["cost_requests"] = int(counters.get("cost_requests") or 0) + cost
        _persist(state, store)
        return True

    def cancel_children(
        self,
        state: Any,
        *,
        reason: str,
        plan_epoch: Optional[int] = None,
        bump_epoch: bool = True,
    ) -> int:
        store = _scheduler_store(state)
        counters = store.setdefault("counters", {})
        child_tasks = dict(store.get("child_tasks") or {})
        cancelled = list(store.get("cancelled_task_ids") or [])
        count = 0
        for task_id, row in list(child_tasks.items()):
            if not isinstance(row, dict):
                continue
            status = str(row.get("status") or "")
            if status in {"cancelled", "accepted"}:
                continue
            row = dict(row)
            row["status"] = "cancelled"
            row["cancel_reason"] = str(reason or "cancelled")
            row["cancelled_at"] = _now_iso()
            child_tasks[task_id] = row
            if task_id not in cancelled:
                cancelled.append(task_id)
            count += 1

        store["child_tasks"] = child_tasks
        store["cancelled_task_ids"] = cancelled[-256:]
        counters["cancels"] = int(counters.get("cancels") or 0) + count

        if plan_epoch is not None:
            epoch = int(plan_epoch)
            state.specialist_plan_epoch = epoch
            store["plan_epoch"] = epoch
        elif bump_epoch:
            epoch = bump_plan_epoch(state)
            store["plan_epoch"] = epoch
        else:
            store["plan_epoch"] = current_plan_epoch(state)

        event = BlackboardEvent(
            kind=EVENT_TASK_CANCELLED,
            summary=f"cancelled {count} child tasks: {reason}",
            payload={
                "reason": str(reason or ""),
                "count": count,
                "plan_epoch": int(store.get("plan_epoch") or 0),
                "task_ids": cancelled[-count:] if count else [],
            },
            source=self.source,
        )
        _append_event(store, event)
        _emit_loop_blackboard(state, event)
        _persist(state, store)
        return count

    def accept_result(
        self,
        state: Any,
        *,
        plan_epoch: int,
        task_id: str,
        proposals: Union[Sequence[SpecialistProposal], Sequence[Mapping[str, Any]], None] = None,
    ) -> Tuple[bool, str]:
        store = _scheduler_store(state)
        counters = store.setdefault("counters", {})
        tid = str(task_id or "")
        current = current_plan_epoch(state)
        store_epoch = int(store.get("plan_epoch") or current or 0)
        effective_epoch = max(current, store_epoch)

        if int(plan_epoch) < effective_epoch:
            counters["stale"] = int(counters.get("stale") or 0) + 1
            event = BlackboardEvent(
                kind=EVENT_RESULT_STALE,
                summary=f"stale result for {tid}",
                payload={
                    "task_id": tid,
                    "plan_epoch": int(plan_epoch),
                    "current_epoch": effective_epoch,
                },
                source=self.source,
            )
            _append_event(store, event)
            _emit_loop_blackboard(state, event)
            _persist(state, store)
            return False, REASON_RESULT_STALE

        cancelled = _as_set(store.get("cancelled_task_ids") or [])
        child_tasks = dict(store.get("child_tasks") or {})
        row = child_tasks.get(tid) if isinstance(child_tasks.get(tid), dict) else None
        if tid in cancelled or (row and str(row.get("status") or "") == "cancelled"):
            counters["cancels"] = int(counters.get("cancels") or 0) + 1
            _persist(state, store)
            return False, REASON_CANCELLED

        accepted_ids = _as_set(store.get("accepted_task_ids") or [])
        lease_keys = _as_set(store.get("accepted_lease_keys") or [])
        lease_key = f"{effective_epoch}:{tid}"
        if tid in accepted_ids or lease_key in lease_keys:
            counters["duplicates"] = int(counters.get("duplicates") or 0) + 1
            _persist(state, store)
            return False, REASON_DUPLICATE

        proposal_count = len(list(proposals or []))
        accepted_list = list(store.get("accepted_task_ids") or [])
        accepted_list.append(tid)
        store["accepted_task_ids"] = accepted_list[-256:]
        lease_list = list(store.get("accepted_lease_keys") or [])
        lease_list.append(lease_key)
        store["accepted_lease_keys"] = lease_list[-256:]
        if row is not None:
            row = dict(row)
            row["status"] = "accepted"
            row["accepted_at"] = _now_iso()
            row["proposal_count"] = proposal_count
            child_tasks[tid] = row
            store["child_tasks"] = child_tasks
        else:
            child_tasks[tid] = {
                "id": tid,
                "status": "accepted",
                "accepted_at": _now_iso(),
                "proposal_count": proposal_count,
            }
            store["child_tasks"] = child_tasks

        counters["accepted"] = int(counters.get("accepted") or 0) + 1
        counters["verified"] = int(counters.get("verified") or 0) + 1

        approved = BlackboardEvent(
            kind=EVENT_ACTION_APPROVED,
            summary=f"accepted result for {tid}",
            payload={
                "task_id": tid,
                "plan_epoch": int(plan_epoch),
                "proposal_count": proposal_count,
            },
            source=self.source,
        )
        verified = BlackboardEvent(
            kind=EVENT_OUTCOME_VERIFIED,
            summary=f"verified result for {tid}",
            payload={
                "task_id": tid,
                "plan_epoch": int(plan_epoch),
                "proposal_count": proposal_count,
            },
            source=self.source,
        )
        _append_event(store, approved)
        _append_event(store, verified)
        _emit_loop_blackboard(state, approved)
        _emit_loop_blackboard(state, verified)
        _persist(state, store)
        return True, REASON_ACCEPTED

    def dashboard_snapshot(self, state: Any) -> Dict[str, Any]:
        store = _scheduler_store(state)
        counters = dict(store.get("counters") or {})
        latency = list(store.get("latency_ms") or [])
        return sanitize_nested({
            "schema_version": str(store.get("schema_version") or SCHEMA_VERSION),
            "plan_epoch": int(store.get("plan_epoch") or current_plan_epoch(state) or 0),
            "accepted": int(counters.get("accepted") or 0),
            "verified": int(counters.get("verified") or 0),
            "stale": int(counters.get("stale") or 0),
            "duplicates": int(counters.get("duplicates") or 0),
            "cancels": int(counters.get("cancels") or 0),
            "cost": int(counters.get("cost_requests") or 0),
            "p95_latency_ms": _p95(latency),
            "active_leases": len(store.get("active_leases") or {}),
            "child_tasks": len(store.get("child_tasks") or {}),
            "consumed_non_idempotent": len(store.get("consumed_non_idempotent") or []),
        })

    def _child_reserved(self, state: Any) -> int:
        kb = _kb(state)
        lease = kb.get("specialist_lease") if isinstance(kb.get("specialist_lease"), dict) else {}
        return int(lease.get("reserved_requests") or 0)


def reserve_action_lease(state: Any, action: AgentAction) -> Optional[ActionLease]:
    return TransactionalScheduler().reserve_action_lease(state, action)


def release_action_lease(
    state: Any,
    lease: ActionLease,
    *,
    consumed: int = 0,
    success: bool = True,
    latency_ms: Optional[float] = None,
) -> None:
    TransactionalScheduler().release_action_lease(
        state,
        lease,
        consumed=consumed,
        success=success,
        latency_ms=latency_ms,
    )


def reserve_child_budget(state: Any, task: SubAgentTask) -> bool:
    return TransactionalScheduler().reserve_child_budget(state, task)


def cancel_children(
    state: Any,
    *,
    reason: str,
    plan_epoch: Optional[int] = None,
    bump_epoch: bool = True,
) -> int:
    return TransactionalScheduler().cancel_children(
        state,
        reason=reason,
        plan_epoch=plan_epoch,
        bump_epoch=bump_epoch,
    )


def accept_result(
    state: Any,
    *,
    plan_epoch: int,
    task_id: str,
    proposals: Union[Sequence[SpecialistProposal], Sequence[Mapping[str, Any]], None] = None,
) -> Tuple[bool, str]:
    return TransactionalScheduler().accept_result(
        state,
        plan_epoch=plan_epoch,
        task_id=task_id,
        proposals=proposals,
    )


def dashboard_snapshot(state: Any) -> Dict[str, Any]:
    return TransactionalScheduler().dashboard_snapshot(state)


def run_team005_scenarios() -> List[Dict[str, Any]]:
    """Offline TEAM-005 scenarios; returns [{name, passed}, ...]."""
    from types import SimpleNamespace

    scenarios: List[Dict[str, Any]] = []
    scheduler = TransactionalScheduler()

    # budget exhaustion refuses lease
    state = SimpleNamespace(
        request_budget=3,
        metrics=SimpleNamespace(network_units_used=2),
        knowledge_base={},
        specialist_plan_epoch=1,
    )
    action = AgentAction(type="run_followup", path="auxiliary/scanner/http/crawler", expected_requests=2)
    lease = scheduler.reserve_action_lease(state, action)
    scenarios.append({"name": "budget_exhaustion_refuses_lease", "passed": lease is None})

    # release refunds unused requests when idempotent
    state2 = SimpleNamespace(
        request_budget=20,
        metrics=SimpleNamespace(network_units_used=0),
        knowledge_base={},
        specialist_plan_epoch=1,
    )
    action2 = AgentAction(type="run_followup", path="auxiliary/scanner/portscan/tcp", expected_requests=5)
    lease2 = scheduler.reserve_action_lease(state2, action2)
    before = int(state2.metrics.network_units_used)
    scheduler.release_action_lease(state2, lease2, consumed=2, success=True)
    after = int(state2.metrics.network_units_used)
    scenarios.append({
        "name": "release_refunds_idempotent",
        "passed": lease2 is not None and before == 5 and after == 2,
    })

    # non-idempotent lease not replayable after release
    state3 = SimpleNamespace(
        request_budget=50,
        metrics=SimpleNamespace(network_units_used=0),
        knowledge_base={},
        specialist_plan_epoch=1,
    )
    action3 = AgentAction(type="run_exploit", path="exploits/multi/http/demo", expected_requests=3, id="act_ni_1")
    lease3 = scheduler.reserve_action_lease(state3, action3)
    scheduler.release_action_lease(state3, lease3, consumed=3, success=True)
    replay = scheduler.reserve_action_lease(state3, action3)
    consumed = state3.knowledge_base.get("scheduler", {}).get("consumed_non_idempotent") or []
    scenarios.append({
        "name": "non_idempotent_not_replayable",
        "passed": lease3 is not None and replay is None and "act_ni_1" in consumed,
    })

    # child budget reserve respects global budget
    state4 = SimpleNamespace(
        request_budget=4,
        metrics=SimpleNamespace(network_units_used=3),
        knowledge_base={},
        specialist_plan_epoch=1,
    )
    task_ok = SubAgentTask(specialist="recon", objective="scan", budget_requests=1)
    task_deny = SubAgentTask(specialist="scanner", objective="deep", budget_requests=2)
    ok = scheduler.reserve_child_budget(state4, task_ok)
    denied = scheduler.reserve_child_budget(state4, task_deny)
    scenarios.append({
        "name": "child_budget_respects_global",
        "passed": ok is True and denied is False,
    })

    # cancel_children makes accept_result return cancelled
    state5 = SimpleNamespace(
        request_budget=50,
        metrics=SimpleNamespace(network_units_used=0),
        knowledge_base={},
        specialist_plan_epoch=2,
    )
    task5 = SubAgentTask(specialist="recon", objective="enum", budget_requests=1, id="subtask_cancel_1")
    scheduler.reserve_child_budget(state5, task5)
    scheduler.cancel_children(state5, reason="replan", bump_epoch=False)
    accepted, reason = scheduler.accept_result(
        state5,
        plan_epoch=2,
        task_id="subtask_cancel_1",
        proposals=[],
    )
    scenarios.append({
        "name": "cancel_blocks_accept",
        "passed": accepted is False and reason == REASON_CANCELLED,
    })

    # stale plan_epoch rejected as ResultStale
    state6 = SimpleNamespace(
        request_budget=50,
        metrics=SimpleNamespace(network_units_used=0),
        knowledge_base={},
        specialist_plan_epoch=5,
    )
    task6 = SubAgentTask(specialist="recon", objective="enum", budget_requests=1, id="subtask_stale_1")
    scheduler.reserve_child_budget(state6, task6)
    store = _scheduler_store(state6)
    store["plan_epoch"] = 5
    _persist(state6, store)
    accepted_stale, reason_stale = scheduler.accept_result(
        state6,
        plan_epoch=3,
        task_id="subtask_stale_1",
        proposals=[],
    )
    scenarios.append({
        "name": "stale_epoch_rejected",
        "passed": accepted_stale is False and reason_stale == REASON_RESULT_STALE,
    })

    # dashboard_snapshot keys present
    snap = scheduler.dashboard_snapshot(state6)
    required = {"accepted", "verified", "stale", "duplicates", "cancels", "cost", "p95_latency_ms"}
    scenarios.append({
        "name": "dashboard_snapshot_keys",
        "passed": required.issubset(set(snap.keys())),
    })

    return scenarios
