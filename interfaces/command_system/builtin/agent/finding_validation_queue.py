#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compound validation queue: parallel multi-step chains (Strix++)."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import AgentAction

QUEUE_SCHEMA = "2.0"
MAX_QUEUE = 48


def _queue(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    store = kb.get("finding_validation_queue")
    if not isinstance(store, dict):
        store = {"schema_version": QUEUE_SCHEMA, "pending": [], "completed": []}
        kb["finding_validation_queue"] = store
    store.setdefault("schema_version", QUEUE_SCHEMA)
    return store


def _fanout() -> int:
    try:
        from interfaces.command_system.builtin.agent.compound_validation_engine import validation_fanout_limit

        return validation_fanout_limit()
    except Exception:
        try:
            return max(1, min(8, int(os.environ.get("KITTYSPLOIT_VALIDATION_FANOUT", "4") or "4")))
        except (TypeError, ValueError):
            return 4


def enqueue_compound_validation(
    kb: MutableMapping[str, Any],
    *,
    module_path: str,
    steps: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    finding_id: str = "",
    panel_verdict: str = "",
    phase: str = "",
    state: Any = None,
) -> Optional[str]:
    path = str(module_path or "").strip()
    if not path or not steps:
        return None
    store = _queue(kb)
    pending: List[Dict[str, Any]] = list(store.get("pending") or [])
    if any(
        str(r.get("source_module") or "") == path
        and r.get("status") in ("pending", "running")
        for r in pending
        if isinstance(r, dict)
    ):
        return None
    item = sanitize_nested({
        "id": f"val_{len(pending) + 1}_{path[-20:]}",
        "source_module": path,
        "finding_id": finding_id,
        "panel_verdict": panel_verdict,
        "phase": str(phase or "")[:64],
        "status": "pending",
        "step_index": 0,
        "steps": [dict(s) for s in steps if isinstance(s, Mapping)],
        "evidence_count": len(list(evidence or [])),
        "compound": True,
    })
    pending.append(item)
    store["pending"] = pending[-MAX_QUEUE:]
    try:
        from interfaces.command_system.builtin.agent.compound_specialist_fanout import register_class_for_wave

        register_class_for_wave(kb, module_path=path, state=state)
    except Exception:
        pass
    if state is not None:
        try:
            from interfaces.command_system.builtin.agent.compound_validation_engine import bump_power_metrics

            bump_power_metrics(kb, parallel_validations=1)
        except Exception:
            pass
        append_journal_event(
            state,
            kind="finding_validation_queued",
            summary=f"Compound validation ({len(steps)} steps) for {path}",
            payload={"id": item.get("id"), "steps": len(steps)},
        )
    return str(item.get("id") or "")


def enqueue_finding_validation(
    kb: MutableMapping[str, Any],
    *,
    module_path: str,
    evidence: Sequence[Mapping[str, Any]],
    phase: str = "",
    state: Any = None,
) -> Optional[str]:
    """Legacy single-step enqueue — upgraded to minimal compound chain."""
    from interfaces.command_system.builtin.agent.compound_validation_engine import build_validation_chain

    steps = build_validation_chain(module_path)
    if not steps:
        steps = [{"tier": "retest", "path": module_path, "reason": "fallback"}]
    return enqueue_compound_validation(
        kb,
        module_path=module_path,
        steps=steps,
        evidence=evidence,
        phase=phase,
        state=state,
    )


def _current_step(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    steps = row.get("steps") if isinstance(row.get("steps"), list) else []
    idx = int(row.get("step_index") or 0)
    if idx < 0 or idx >= len(steps):
        return None
    step = steps[idx]
    return dict(step) if isinstance(step, dict) else None


def pop_validation_actions(state: Any, *, max_actions: Optional[int] = None) -> List[AgentAction]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    limit = max_actions if max_actions is not None else _fanout()
    store = _queue(kb)
    pending = [
        dict(r)
        for r in (store.get("pending") or [])
        if isinstance(r, dict) and r.get("status") in ("pending", "running")
    ]
    if not pending:
        return []

    actions: List[AgentAction] = []
    still_pending: List[Dict[str, Any]] = []
    completed = list(store.get("completed") or [])

    for row in pending:
        if len(actions) >= max(1, limit):
            still_pending.append(row)
            continue
        step = _current_step(row)
        if not step:
            row["status"] = "done"
            row["reason"] = "chain_complete"
            completed.append(row)
            continue
        path = str(step.get("path") or row.get("source_module") or "").strip()
        if not path:
            row["step_index"] = int(row.get("step_index") or 0) + 1
            still_pending.append(row)
            continue
        row["status"] = "running"
        still_pending.append(row)
        actions.append(
            AgentAction(
                type="run_followup",
                path=path,
                priority=96,
                risk="read",
                reason=f"compound_{step.get('tier', 'validate')}:{row.get('source_module')}",
                options={
                    "validation_for": row.get("source_module"),
                    "validation_id": row.get("id"),
                    "validation_tier": step.get("tier"),
                    "validation_step": int(row.get("step_index") or 0),
                    "compound": True,
                },
            )
        )

    store["pending"] = still_pending[-MAX_QUEUE:]
    store["completed"] = completed[-MAX_QUEUE:]
    kb["finding_validation_queue"] = store
    return actions


def complete_validation(
    kb: MutableMapping[str, Any],
    validation_id: str,
    *,
    verdict: str,
    state: Any = None,
) -> bool:
    store = _queue(kb)
    vid = str(validation_id or "")
    confirmed = str(verdict or "").lower() == "confirmed"
    chain_finished = False
    pending = [dict(r) for r in (store.get("pending") or []) if isinstance(r, dict)]
    completed = list(store.get("completed") or [])
    updated_pending: List[Dict[str, Any]] = []
    matched = False

    for row in pending:
        if str(row.get("id") or "") != vid:
            updated_pending.append(row)
            continue
        matched = True
        steps = row.get("steps") if isinstance(row.get("steps"), list) else []
        row["last_verdict"] = verdict
        if not confirmed:
            row["status"] = "failed"
            completed.append(row)
            chain_finished = True
            continue
        next_idx = int(row.get("step_index") or 0) + 1
        row["step_index"] = next_idx
        if next_idx >= len(steps):
            row["status"] = "done"
            completed.append(row)
            chain_finished = True
        else:
            row["status"] = "pending"
            updated_pending.append(row)

    if matched:
        store["pending"] = updated_pending[-MAX_QUEUE:]
        store["completed"] = completed[-MAX_QUEUE:]
        kb["finding_validation_queue"] = store

    if state is not None:
        append_journal_event(
            state,
            kind="finding_validation_done",
            summary=f"{vid} -> {verdict}" + (" (chain complete)" if chain_finished else " (next step)"),
            payload={"validation_id": vid, "verdict": verdict, "chain_finished": chain_finished},
        )
    if matched:
        try:
            from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness

            step_row = None
            for row in (store.get("pending") or []) + (store.get("completed") or []):
                if isinstance(row, dict) and str(row.get("id") or "") == vid:
                    step_row = row
                    break
            tier = ""
            if isinstance(step_row, dict):
                steps = step_row.get("steps") if isinstance(step_row.get("steps"), list) else []
                idx = max(0, int(step_row.get("step_index") or 0) - 1)
                if idx < len(steps) and isinstance(steps[idx], dict):
                    tier = str(steps[idx].get("tier") or "")
            append_compound_witness(
                kb,
                stage="validation",
                kind="step_complete" if not chain_finished else "chain_complete",
                summary=f"{vid} verdict={verdict} tier={tier or 'n/a'}",
                payload={
                    "validation_id": vid,
                    "verdict": verdict,
                    "chain_finished": chain_finished,
                    "tier": tier,
                    "source_module": (step_row or {}).get("source_module") if step_row else "",
                },
                state=state,
            )
        except Exception:
            pass
    if state is not None:
        if chain_finished and confirmed:
            try:
                from interfaces.command_system.builtin.agent.compound_validation_engine import (
                    bump_power_metrics,
                    spawn_exploit_chain_actions,
                )

                bump_power_metrics(kb, validation_depth=1)
                spawned = spawn_exploit_chain_actions(state, limit=6)
                if spawned:
                    pending_attr = getattr(state, "_compound_exploit_pending", None)
                    if not isinstance(pending_attr, list):
                        pending_attr = []
                    pending_attr.extend(spawned)
                    state._compound_exploit_pending = pending_attr[-24:]  # type: ignore[attr-defined]
            except Exception:
                pass

    kb["finding_validation_queue"] = store
    return chain_finished and confirmed
