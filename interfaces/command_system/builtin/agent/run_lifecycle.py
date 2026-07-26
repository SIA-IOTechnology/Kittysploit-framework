#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Checkpoint, stop conditions, timeline, and error recording for agent runs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.runtime_policy import StopConditionEvaluator
from interfaces.command_system.builtin.agent.state import AgentState, agent_state_checkpoint_dict

PHASE_SUCCESSORS = {
    "scan": "analyze",
    "analyze": "reason",
    "reason": "exploit",
    "exploit": "report",
    "report": "report",
}


class RunLifecycle:
    """Injectable run lifecycle helpers (no CLI dependency)."""

    def __init__(self, stop_evaluator: Optional[StopConditionEvaluator] = None) -> None:
        self._stop_evaluator = stop_evaluator or StopConditionEvaluator()

    def record_error(
        self,
        state: AgentState,
        component: str,
        exc: Any,
        *,
        fatal: bool = False,
        phase: str = "",
        append_timeline: Optional[Callable[..., None]] = None,
    ) -> None:
        event = {
            "ts": datetime.now().isoformat(),
            "phase": phase or state.current_phase,
            "component": component,
            "fatal": bool(fatal),
            "error_type": type(exc).__name__ if isinstance(exc, BaseException) else "AgentError",
            "message": str(exc)[:500],
        }
        state.error_events.append(event)
        timeline_fn = append_timeline or self.append_timeline_event
        timeline_fn(
            state,
            phase or state.current_phase,
            f"{component}: {event['message']}",
            kind="error",
            extra={"fatal": bool(fatal), "error_type": event["error_type"]},
        )
        store = getattr(state, "run_store", None)
        if store is not None:
            try:
                store.append_event(sanitize_nested(event))
            except OSError:
                pass

    def checkpoint_state(self, state: AgentState, phase: str) -> None:
        next_phase = PHASE_SUCCESSORS.get(phase, phase)
        state.current_phase = next_phase
        store = getattr(state, "run_store", None)
        if not state.checkpoint_enabled or store is None:
            return
        try:
            payload = sanitize_nested(agent_state_checkpoint_dict(state))
            store.save_checkpoint(next_phase, payload)
            from interfaces.command_system.builtin.agent.run_snapshot import persist_run_snapshot

            persist_run_snapshot(store, payload)
        except Exception as exc:
            self.record_error(state, "checkpoint", exc, phase=phase)

    def phase_stop_reason(self, state: AgentState, phase: str) -> Optional[str]:
        reason = self._stop_evaluator.evaluate(state, phase=phase)
        if reason:
            state.campaign_stop_reason = reason
            self.append_timeline_event(
                state,
                phase,
                f"Campaign stopped before phase `{phase}`: {reason}",
                kind="stop",
            )
        return reason

    def append_timeline_event(
        self,
        state: AgentState,
        phase: str,
        summary: str,
        *,
        kind: str = "phase",
        modules: Optional[List[Any]] = None,
        results: Optional[List[Dict[str, Any]]] = None,
        extra: Optional[Dict[str, Any]] = None,
        is_actionable_finding: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        timeline = state.decision_timeline if isinstance(state.decision_timeline, list) else []
        module_paths: List[str] = []
        if isinstance(modules, list):
            for row in modules:
                if isinstance(row, dict):
                    path = str(row.get("path", "")).strip()
                else:
                    path = str(row or "").strip()
                if path:
                    module_paths.append(path)
        result_summary: Dict[str, Any] = {}
        predicate = is_actionable_finding or (lambda _row: False)
        if isinstance(results, list):
            vuln = [r for r in results if isinstance(r, dict) and r.get("vulnerable")]
            errors = [r for r in results if isinstance(r, dict) and r.get("status") == "error"]
            actionable = [r for r in results if isinstance(r, dict) and predicate(r)]
            result_summary = {
                "total_results": len(results),
                "vulnerable": len(vuln),
                "actionable": len(actionable),
                "errors": len(errors),
                "top_paths": [
                    str(r.get("path", "")).strip()
                    for r in actionable[:4]
                    if isinstance(r, dict) and str(r.get("path", "")).strip()
                ],
            }
        event = {
            "ts": datetime.now().isoformat(),
            "kind": kind,
            "phase": phase,
            "summary": summary,
        }
        if module_paths:
            event["modules"] = module_paths
        if result_summary:
            event["result_summary"] = result_summary
        if extra:
            event["extra"] = extra
        timeline.append(event)
        state.decision_timeline = timeline
        store = getattr(state, "run_store", None)
        if store is not None:
            try:
                store.append_event(sanitize_nested(event))
            except OSError as exc:
                state.error_events.append(
                    {
                        "ts": datetime.now().isoformat(),
                        "phase": phase,
                        "component": "event_store",
                        "fatal": False,
                        "error_type": type(exc).__name__,
                        "message": str(exc)[:500],
                    }
                )
