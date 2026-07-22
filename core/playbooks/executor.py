#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Automatic execution of reachable attack playbooks.

When campaign state matches a playbook with ``coverage == reachable``, the agent
can run the next unexecuted chain step(s) sequentially instead of only using
playbook hints as planner bonuses.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set

from core.playbooks.coverage import (
    COVERAGE_ACHIEVED,
    COVERAGE_PARTIAL,
    COVERAGE_REACHABLE,
    assess_playbook,
    assess_playbook_coverage,
)
from core.playbooks.loader import load_all_playbooks

logger = logging.getLogger(__name__)

PLAYBOOK_EXECUTION_KEY = "playbook_execution_state"

_ALLOWED_PREFIXES = (
    "scanner/",
    "auxiliary/scanner/",
    "auxiliary/osint/",
    "auxiliary/aws/",
    "auxiliary/azure/",
    "auxiliary/gcp/",
    "post/",
    "exploits/",
    "exploit/",
)


def _normalize_path(value: Any) -> str:
    return str(value or "").strip()


def _observed_modules(kb: Mapping[str, Any]) -> Set[str]:
    observed: Set[str] = set()
    for item in kb.get("observed_modules", []) or []:
        token = _normalize_path(item).lower()
        if token:
            observed.add(token)
            if "/" in token:
                observed.add(token.rstrip("/").split("/")[-1])
    return observed


def _module_executed(module_path: str, observed: Set[str]) -> bool:
    norm = _normalize_path(module_path).lower()
    if not norm:
        return False
    if norm in observed:
        return True
    base = norm.rstrip("/").split("/")[-1]
    return base in observed


def _action_type_for_module(module_path: str) -> str:
    path = _normalize_path(module_path).lower()
    if path.startswith(("exploits/", "exploit/")):
        return "run_exploit"
    if path.startswith("post/"):
        return "run_post"
    return "run_followup"


def pick_active_playbook(
    kb: Mapping[str, Any],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    min_relevance: float = 0.35,
) -> Optional[Dict[str, Any]]:
    report = assess_playbook_coverage(kb, findings, min_relevance=min_relevance, limit=6)
    rows = report.get("playbooks") or []
    for row in rows:
        if isinstance(row, dict) and row.get("coverage") == COVERAGE_REACHABLE:
            return row
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("coverage") == COVERAGE_PARTIAL and float(row.get("relevance", 0) or 0) >= 0.45:
            return row
    return None


def next_playbook_steps(
    playbook_row: Mapping[str, Any],
    kb: Mapping[str, Any],
    *,
    max_steps: int = 3,
) -> List[Dict[str, Any]]:
    if not isinstance(playbook_row, Mapping):
        return []
    observed = _observed_modules(kb)
    steps_out: List[Dict[str, Any]] = []
    for step in playbook_row.get("steps") or []:
        if not isinstance(step, dict):
            continue
        if bool(step.get("optional")):
            continue
        status = str(step.get("status") or "")
        module = _normalize_path(step.get("module"))
        if status in ("executed", "capability_unlocked"):
            continue
        if status == "gap" or not module:
            break
        if status == "missing_module":
            break
        if _module_executed(module, observed):
            continue
        steps_out.append({
            "step_id": step.get("step_id"),
            "module": module,
            "capability": step.get("capability"),
            "description": step.get("description"),
            "action_type": _action_type_for_module(module),
            "playbook_id": playbook_row.get("playbook_id"),
            "playbook_name": playbook_row.get("name"),
        })
        if len(steps_out) >= max(1, int(max_steps)):
            break
    return steps_out


def build_playbook_execution_plan(
    kb: Mapping[str, Any],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    max_steps: int = 2,
    base_priority: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Build an execution_plan fragment for the next reachable playbook step(s).

    Returns ``None`` when no playbook is actionable.
    """
    playbook = pick_active_playbook(kb, findings)
    if not playbook:
        return None
    steps = next_playbook_steps(playbook, kb, max_steps=max_steps)
    if not steps:
        if playbook.get("coverage") == COVERAGE_ACHIEVED:
            return None
        return None

    actions: List[Dict[str, Any]] = []
    for offset, step in enumerate(steps):
        actions.append({
            "type": step.get("action_type", "run_followup"),
            "path": step.get("module"),
            "priority": base_priority + offset,
            "reason": (
                f"Playbook chain [{playbook.get('playbook_id')}]: "
                f"{step.get('description') or step.get('step_id')}"
            ),
            "playbook_id": playbook.get("playbook_id"),
            "playbook_step": step.get("step_id"),
        })

    return {
        "playbook_id": playbook.get("playbook_id"),
        "playbook_name": playbook.get("name"),
        "playbook_coverage": playbook.get("coverage"),
        "playbook_relevance": playbook.get("relevance"),
        "next_actions": actions,
        "max_requests_next_phase": min(12, max(4, len(actions) * 3)),
        "reasoning_confidence": min(0.95, 0.55 + float(playbook.get("relevance", 0) or 0) * 0.4),
        "source": "playbook_executor",
    }


def merge_playbook_into_execution_plan(
    execution_plan: MutableMapping[str, Any],
    playbook_plan: Mapping[str, Any],
) -> None:
    """Prepend playbook actions to an existing execution plan."""
    if not isinstance(execution_plan, MutableMapping) or not isinstance(playbook_plan, Mapping):
        return
    existing = list(execution_plan.get("next_actions") or [])
    playbook_actions = list(playbook_plan.get("next_actions") or [])
    merged: List[Dict[str, Any]] = []
    seen_paths: Set[str] = set()
    for action in playbook_actions + existing:
        if not isinstance(action, dict):
            continue
        path = _normalize_path(action.get("path")).lower()
        if path and path in seen_paths:
            continue
        if path:
            seen_paths.add(path)
        merged.append(action)
    execution_plan["next_actions"] = merged
    execution_plan["playbook_id"] = playbook_plan.get("playbook_id")
    execution_plan["playbook_name"] = playbook_plan.get("playbook_name")
    execution_plan["playbook_coverage"] = playbook_plan.get("playbook_coverage")
    execution_plan["playbook_relevance"] = playbook_plan.get("playbook_relevance")
    execution_plan["reasoning_confidence"] = max(
        float(execution_plan.get("reasoning_confidence", 0) or 0),
        float(playbook_plan.get("reasoning_confidence", 0) or 0),
    )
    execution_plan["max_requests_next_phase"] = max(
        int(execution_plan.get("max_requests_next_phase", 0) or 0),
        int(playbook_plan.get("max_requests_next_phase", 0) or 0),
    )


def record_playbook_execution(
    kb: MutableMapping[str, Any],
    *,
    playbook_id: str,
    step_id: str,
    module_path: str,
    success: bool,
) -> None:
    if not isinstance(kb, MutableMapping):
        return
    state = kb.setdefault(PLAYBOOK_EXECUTION_KEY, {})
    if not isinstance(state, dict):
        state = {}
        kb[PLAYBOOK_EXECUTION_KEY] = state
    history = state.setdefault("history", [])
    if isinstance(history, list):
        history.append({
            "playbook_id": playbook_id,
            "step_id": step_id,
            "module": module_path,
            "success": bool(success),
        })
        state["history"] = history[-48:]
    state["last_playbook_id"] = playbook_id
    state["last_step_id"] = step_id


def module_path_allowed_for_playbook(module_path: str) -> bool:
    path = _normalize_path(module_path).lower()
    return any(path.startswith(prefix) for prefix in _ALLOWED_PREFIXES)


def summarize_playbook_execution(kb: Mapping[str, Any]) -> Dict[str, Any]:
    state = kb.get(PLAYBOOK_EXECUTION_KEY) if isinstance(kb, Mapping) else None
    if not isinstance(state, dict):
        return {}
    history = state.get("history") or []
    return {
        "last_playbook_id": state.get("last_playbook_id"),
        "last_step_id": state.get("last_step_id"),
        "steps_executed": len(history) if isinstance(history, list) else 0,
    }
