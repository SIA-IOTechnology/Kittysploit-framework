#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build and persist comparable run snapshots for offline replay."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.schemas import SCHEMA_VERSION
from interfaces.command_system.builtin.agent.action_trace import load_action_traces_from_store
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.timeline import load_events_from_store

PLANNER_PROMPT_MARKER = "pentest planning assistant"


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_prefix(payload: Mapping[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(payload).encode('utf-8')).hexdigest()[:16]}"


def extract_scheduling_order(
    action_traces: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
) -> List[str]:
    if action_traces:
        return [str(row.get("action_key") or "") for row in action_traces if row.get("action_key")]
    order: List[str] = []
    for row in events:
        if str(row.get("kind", "")).lower() not in {"decision", "phase", "module"}:
            continue
        module = str(row.get("module") or row.get("path") or "").strip()
        phase = str(row.get("phase") or "").strip()
        if module:
            order.append(f"{phase}:{module}" if phase else module)
    return order


def extract_proposals(events: Sequence[Mapping[str, Any]], state: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    accepted: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    plan = state.get("execution_plan") if isinstance(state.get("execution_plan"), dict) else {}
    for row in plan.get("next_actions") or []:
        if isinstance(row, dict) and row.get("path"):
            accepted.append({
                "path": row.get("path"),
                "type": row.get("type"),
                "priority": row.get("priority"),
                "source": "execution_plan",
            })
    for row in events:
        if str(row.get("kind", "")).lower() != "decision":
            continue
        data = row.get("data") if isinstance(row.get("data"), dict) else row
        explanation = data.get("decision_explanation") if isinstance(data.get("decision_explanation"), dict) else {}
        chosen = explanation.get("chosen") or data.get("summary")
        if chosen:
            accepted.append({
                "path": data.get("module") or data.get("path"),
                "type": data.get("type"),
                "summary": chosen,
                "source": "timeline_decision",
            })
        for alt in explanation.get("rejected_alternatives") or []:
            if isinstance(alt, dict):
                rejected.append(dict(alt))
            elif alt:
                rejected.append({"path": str(alt), "source": "timeline_decision"})
    return {"accepted": accepted[:64], "rejected": rejected[:64]}


def extract_cost(state: Mapping[str, Any], action_traces: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
    actual_requests = int(metrics.get("requests_used", 0) or metrics.get("requests", 0) or 0)
    for row in action_traces:
        network = row.get("network_cost") if isinstance(row.get("network_cost"), dict) else {}
        actual_requests += int(network.get("requests", 0) or 0)
    duration_ms = sum(float(row.get("duration_ms", 0) or 0) for row in action_traces)
    plan = state.get("execution_plan") if isinstance(state.get("execution_plan"), dict) else {}
    estimated = int(plan.get("max_requests_next_phase", 0) or state.get("request_budget", 0) or 0)
    return {
        "estimated_requests": estimated,
        "actual_requests": actual_requests,
        "duration_ms": duration_ms,
    }


def extract_cancellations(events: Sequence[Mapping[str, Any]], state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    stop_reason = str(state.get("campaign_stop_reason") or "").strip()
    if stop_reason:
        rows.append({"kind": "stop", "reason": stop_reason})
    for row in events:
        if str(row.get("kind", "")).lower() in {"stop", "cancel"}:
            rows.append({
                "kind": row.get("kind"),
                "summary": row.get("summary"),
                "phase": row.get("phase"),
            })
    return rows[:32]


def build_catalog_hash(state: Mapping[str, Any], action_traces: Sequence[Mapping[str, Any]]) -> str:
    paths = sorted({
        str(row.get("module_path") or "").strip()
        for row in action_traces
        if str(row.get("module_path") or "").strip()
    })
    if not paths:
        for row in state.get("executed_actions") or []:
            token = str(row).split(":", 1)[-1].strip()
            if token:
                paths.append(token)
    return _sha256_prefix({"module_paths": sorted(set(paths))})


def build_prompt_hash(state: Mapping[str, Any]) -> str:
    plan = state.get("execution_plan") if isinstance(state.get("execution_plan"), dict) else {}
    payload = {
        "decision_source": state.get("decision_source"),
        "rationale": plan.get("rationale"),
        "goal": state.get("campaign_goal") or plan.get("campaign_goal"),
        "marker": PLANNER_PROMPT_MARKER,
    }
    return _sha256_prefix(payload)


def build_run_snapshot(
    run_id: str,
    state: Mapping[str, Any],
    *,
    events: Optional[Sequence[Mapping[str, Any]]] = None,
    action_traces: Optional[Sequence[Mapping[str, Any]]] = None,
    reset_attestation: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    event_rows = list(events or [])
    trace_rows = list(action_traces or [])
    body = {
        "schema_version": SCHEMA_VERSION,
        "run_id": str(run_id),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "model": state.get("llm_model"),
            "goal": state.get("campaign_goal"),
            "profile": getattr(state.get("runtime_policy"), "mission_profile", None)
            if not isinstance(state.get("runtime_policy"), dict)
            else (state.get("runtime_policy") or {}).get("mission_profile"),
            "workspace": state.get("workspace"),
            "prompt_hash": build_prompt_hash(state),
            "catalog_hash": build_catalog_hash(state, trace_rows),
            "random_seed": state.get("random_seed"),
        },
        "scheduling_order": extract_scheduling_order(trace_rows, event_rows),
        "proposals": extract_proposals(event_rows, state),
        "cost": extract_cost(state, trace_rows),
        "cancellations": extract_cancellations(event_rows, state),
        "reset_attestation": dict(reset_attestation) if reset_attestation else None,
    }
    body["snapshot_hash"] = _sha256_prefix(
        {k: v for k, v in body.items() if k not in ("snapshot_hash", "created_at")}
    )
    return sanitize_nested(body)


def persist_run_snapshot(store: Any, state: Mapping[str, Any], *, reset_attestation: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    events = load_events_from_store(store)
    traces = load_action_traces_from_store(store)
    snapshot = build_run_snapshot(
        str(getattr(store, "run_id", "") or state.get("run_id") or ""),
        state,
        events=events,
        action_traces=traces,
        reset_attestation=reset_attestation,
    )
    save = getattr(store, "save_snapshot", None)
    if callable(save):
        save(snapshot)
    return snapshot


def load_run_snapshot(store: Any) -> Dict[str, Any]:
    load = getattr(store, "load_snapshot", None)
    if callable(load):
        payload = load()
        if isinstance(payload, dict):
            return payload
    return {}
