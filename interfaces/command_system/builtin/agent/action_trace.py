#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Capture per-action traces for agent runs (state delta, policy, cost, verdict)."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.schemas import SCHEMA_VERSION
from interfaces.command_system.builtin.agent.redaction import sanitize_nested


VERIFIED_VERDICTS = frozenset({
    "confirmed",
    "no_signal",
    "refuted",
    "blocked",
    "module_error",
    "policy_denied",
    "planned",
    "skipped",
})


def state_fingerprint(state: Any) -> str:
    kb = getattr(state, "knowledge_base", {}) or {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    payload = {
        "phase": str(getattr(state, "current_phase", "") or ""),
        "sessions": len(getattr(state, "new_sessions", []) or []),
        "results": len(getattr(state, "results", []) or []),
        "observations": len(chain.get("observations") or []),
        "executed": len(getattr(state, "executed_actions", []) or []),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def infer_verified_verdict(result: Mapping[str, Any]) -> str:
    if result.get("planned"):
        return "planned"
    if result.get("quarantine"):
        return "skipped"
    if result.get("blocked"):
        if result.get("policy_block"):
            return "policy_denied"
        return "blocked"
    normalized = result.get("normalized_outcome")
    if isinstance(normalized, dict):
        observation = normalized.get("observation")
        if isinstance(observation, dict):
            status = str(observation.get("status") or "").strip()
            if status in VERIFIED_VERDICTS:
                return status
    execution = result.get("execution")
    if execution is None:
        return "no_signal"
    if bool(getattr(execution, "blocked", False)):
        return "blocked"
    if not bool(getattr(execution, "success", False)) and str(getattr(execution, "error", "") or "").strip():
        return "module_error"
    if bool(getattr(execution, "success", False) or getattr(execution, "command_success", False)):
        return "confirmed"
    return "no_signal"


def summarize_raw_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    execution = result.get("execution")
    summary: Dict[str, Any] = {
        "blocked": bool(result.get("blocked")),
        "planned": bool(result.get("planned")),
        "error": str(result.get("error") or "")[:500] or None,
    }
    if execution is not None:
        summary.update({
            "success": bool(getattr(execution, "success", False)),
            "command_success": bool(getattr(execution, "command_success", False)),
            "duration_ms": getattr(execution, "duration_ms", None),
        })
        metrics = getattr(execution, "metrics", None)
        if metrics is not None:
            summary["metrics"] = {
                key: getattr(metrics, key, None)
                for key in ("requests", "bytes_sent", "bytes_received", "errors")
                if getattr(metrics, key, None) is not None
            }
    if result.get("policy_block"):
        summary["policy_block"] = dict(result.get("policy_block") or {})
    return sanitize_nested(summary)


def extract_network_cost(result: Mapping[str, Any]) -> Dict[str, Any]:
    execution = result.get("execution")
    if execution is None:
        return {}
    metrics = getattr(execution, "metrics", None)
    if metrics is None:
        return {}
    return sanitize_nested({
        "requests": int(getattr(metrics, "requests", 0) or 0),
        "bytes_sent": int(getattr(metrics, "bytes_sent", 0) or 0),
        "bytes_received": int(getattr(metrics, "bytes_received", 0) or 0),
    })


@dataclass
class ActionTraceRecord:
    run_id: str
    action_key: str
    phase: str = ""
    module_path: Optional[str] = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0
    before_state_fingerprint: str = ""
    after_state_fingerprint: str = ""
    candidates: List[str] = field(default_factory=list)
    score: Optional[float] = None
    decision_source: Optional[str] = None
    policy: Dict[str, Any] = field(default_factory=dict)
    network_cost: Dict[str, Any] = field(default_factory=dict)
    raw_result: Dict[str, Any] = field(default_factory=dict)
    verified_verdict: str = "no_signal"
    risk: Optional[str] = None
    blocked: bool = False
    error: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: f"act_{uuid.uuid4().hex[:12]}")

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        if payload["verified_verdict"] not in VERIFIED_VERDICTS:
            payload["verified_verdict"] = "no_signal"
        return sanitize_nested(payload)


def build_action_trace(
    *,
    state: Any,
    phase: str,
    module_path: str,
    result: Mapping[str, Any],
    before_fingerprint: str,
    duration_ms: float,
    candidates: Optional[Sequence[str]] = None,
    score: Optional[float] = None,
    decision_source: Optional[str] = None,
) -> ActionTraceRecord:
    risk = getattr(result.get("risk"), "level", None)
    policy_block = dict(result.get("policy_block") or {})
    return ActionTraceRecord(
        run_id=str(getattr(state, "run_id", "") or ""),
        action_key=f"{phase}:{module_path}",
        phase=str(phase or ""),
        module_path=str(module_path or "") or None,
        duration_ms=max(0.0, float(duration_ms or 0.0)),
        before_state_fingerprint=before_fingerprint,
        after_state_fingerprint=state_fingerprint(state),
        candidates=[str(item) for item in (candidates or []) if str(item).strip()],
        score=score,
        decision_source=str(decision_source or getattr(state, "decision_source", "") or "") or None,
        policy=policy_block,
        network_cost=extract_network_cost(result),
        raw_result=summarize_raw_result(result),
        verified_verdict=infer_verified_verdict(result),
        risk=str(risk) if risk is not None else None,
        blocked=bool(result.get("blocked")),
        error=str(result.get("error") or "")[:500] or None,
    )


def record_action_trace(store: Any, trace: ActionTraceRecord) -> None:
    append = getattr(store, "append_action_trace", None)
    if callable(append):
        append(trace.to_dict())


def load_action_traces_from_store(store: Any) -> List[Dict[str, Any]]:
    path = getattr(store, "actions_path", None)
    if path is None:
        run_dir = getattr(store, "paths", None)
        run_id = getattr(store, "run_id", "")
        if run_dir is not None and run_id:
            path = run_dir.run_dir(run_id) / "actions.jsonl"
        else:
            return []
    file_path = path() if callable(path) else path
    if not file_path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


class ActionTraceRecorder:
    """Context helper to time and record a module execution."""

    def __init__(
        self,
        state: Any,
        *,
        phase: str,
        module_path: str,
        candidates: Optional[Sequence[str]] = None,
        score: Optional[float] = None,
        decision_source: Optional[str] = None,
    ) -> None:
        self.state = state
        self.phase = phase
        self.module_path = module_path
        self.candidates = list(candidates or [])
        self.score = score
        self.decision_source = decision_source
        self.before_fingerprint = state_fingerprint(state)
        self._started = time.monotonic()

    def finalize(self, result: Mapping[str, Any]) -> ActionTraceRecord:
        duration_ms = (time.monotonic() - self._started) * 1000.0
        trace = build_action_trace(
            state=self.state,
            phase=self.phase,
            module_path=self.module_path,
            result=result,
            before_fingerprint=self.before_fingerprint,
            duration_ms=duration_ms,
            candidates=self.candidates,
            score=self.score,
            decision_source=self.decision_source,
        )
        store = getattr(self.state, "run_store", None)
        if store is not None:
            record_action_trace(store, trace)
        return trace
