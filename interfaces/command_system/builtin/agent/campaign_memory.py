#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Operator decisions for a workspace, replayed on the next run."""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

from core.engagement.graph import EngagementGraph, agent_finding_from_graph
from interfaces.command_system.builtin.agent.module_confidence import ModuleConfidenceIndex


def prepare_parsed_run(paths: Any, parsed: Any) -> EngagementGraph:
    """Apply remembered approvals, refusals, and target corrections before planning."""
    graph = EngagementGraph.open(paths)
    ModuleConfidenceIndex.configure(_catalog_dir(), getattr(paths, "memory_dir", None))
    if not list(getattr(parsed, "approve_risk", None) or []):
        remembered = graph.remembered_approvals()
        if remembered:
            parsed.approve_risk = list(remembered)
            parsed._resumed_approvals = list(remembered)
    requested = str(getattr(parsed, "target", "") or "")
    corrected = graph.corrected_target(requested)
    if corrected and corrected != requested:
        parsed.target = corrected
        parsed._resumed_target_correction = {"from": requested, "to": corrected}
    denied = list(getattr(parsed, "deny_module", None) or [])
    denied.extend(path for path in graph.remembered_refusals() if path not in denied)
    parsed.deny_module = denied
    ModuleConfidenceIndex.current().set_refusals(denied)
    return graph


def record_operator_commands(
    graph: EngagementGraph,
    *,
    run_id: str,
    approved_risks: List[str],
    denied_modules: List[str],
    requested_target: str,
    effective_target: str,
    goal: str = "",
) -> None:
    for risk in approved_risks:
        token = str(risk or "").strip().lower()
        if token:
            graph.remember_approval(run_id, token, goal=goal)
    for module_path in denied_modules:
        path = str(module_path or "").strip()
        if path:
            graph.remember_refusal(
                run_id,
                reason=f"operator refused module {path}",
                module_path=path,
                goal=goal,
            )
    source = str(requested_target or "").strip()
    corrected = str(effective_target or "").strip()
    if source and corrected and source != corrected:
        graph.remember_target_correction(run_id, source, corrected, goal=goal)


def seed_state_from_graph(state: Any, graph: EngagementGraph, *, fresh: bool = False) -> Optional[dict]:
    """Resume the mission from the last proven fact for this target."""
    kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
    kb["operator_refusals"] = graph.remembered_refusals()
    kb["operator_decisions"] = graph.records("decisions")
    ModuleConfidenceIndex.current().set_refusals(kb["operator_refusals"])
    state.knowledge_base = kb
    if fresh:
        return None
    aliases = _state_target_keys(state)
    findings: List[dict] = []
    for key in aliases:
        findings = graph.proven_findings(target_key=key)
        if findings:
            break
    if not findings:
        return None
    restored = [agent_finding_from_graph(row) for row in findings]
    existing = list(getattr(state, "contextual_findings", None) or [])
    state.contextual_findings = restored + existing
    fact = graph.last_proven_fact(target_key=aliases[0] if aliases else "")
    kb["resume_cursor"] = fact or {}
    observed = set(kb.get("observed_modules") or [])
    for row in restored:
        module_path = str(row.get("path") or "")
        if module_path:
            observed.add(module_path)
    kb["observed_modules"] = sorted(observed)
    state.knowledge_base = kb
    if str(getattr(state, "current_phase", "") or "") in {"", "init", "scan"}:
        state.current_phase = "analyze"
    return fact


def _state_target_keys(state: Any) -> List[str]:
    keys = [str(getattr(state, "raw_target", "") or "").strip().lower()]
    info = getattr(state, "target_info", None)
    if isinstance(info, dict):
        for name in ("url", "hostname", "host", "address"):
            keys.append(str(info.get(name) or "").strip().lower())
    return [key for key in keys if key]


def _catalog_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "data"
