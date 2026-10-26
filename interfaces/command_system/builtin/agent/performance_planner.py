#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Performance-oriented planning: consensus fast-path, orchestrator direct actions,
and bounded multi-action turbo batches (fewer LLM round-trips, more work per cycle).
"""

from __future__ import annotations

import os
from typing import Any, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.action_catalog import CatalogAction
from interfaces.command_system.builtin.agent.proposal_arbiter import arbitrate_proposals
from interfaces.command_system.builtin.agent.typed_models import AgentAction, SpecialistProposal


READ_RISKS = frozenset({"read", "passive", "info"})
TURBO_ACTION_TYPES = frozenset({"http_request", "surface_scan", "prioritize", "run_followup"})


def turbo_mode_enabled(state: Any = None) -> bool:
    env = os.environ.get("KITTYSPLOIT_AGENT_TURBO", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    if state is not None and getattr(state, "turbo_mode_enabled", None) is False:
        return False
    if state is not None and getattr(state, "turbo_mode_enabled", None) is True:
        return True
    profile = str(getattr(state, "safety_profile", "") or "").strip().lower()
    if profile == "safe":
        return False
    return profile in {"normal", "aggressive", ""}


def turbo_batch_size(state: Any = None) -> int:
    env = os.environ.get("KITTYSPLOIT_AGENT_TURBO_BATCH", "").strip()
    if env.isdigit():
        return max(1, min(int(env), 6))
    if str(getattr(state, "safety_profile", "") or "").lower() == "discreet":
        return 2
    return 3


def llm_skip_on_consensus_enabled(state: Any = None) -> bool:
    env = os.environ.get("KITTYSPLOIT_AGENT_FAST_CONSENSUS", "").strip().lower()
    if env in {"0", "false", "no"}:
        return False
    return turbo_mode_enabled(state)


def fast_path_consensus(
    proposals: Sequence[SpecialistProposal],
    catalog: Sequence[CatalogAction],
    *,
    min_confidence: float = 0.78,
    min_supporters: int = 2,
) -> Optional[SpecialistProposal]:
    """When the army agrees, skip an extra LLM tactical-rank call."""
    if not proposals:
        return None
    catalog_map = {row.action_id: row.action for row in catalog}
    heuristic_scores = {row.action_id: row.heuristic_score for row in catalog}
    ranked = arbitrate_proposals(
        proposals,
        catalog_action_ids=catalog_map,
        heuristic_scores=heuristic_scores,
        limit=3,
    )
    if not ranked:
        return None
    top = ranked[0]
    path = str(top.action.path or "")
    if not path:
        return None
    confidence = float(top.confidence or 0.0)
    supporters = sum(
        1 for row in proposals if str(row.action.path or "") == path and str(row.action.type) == str(top.action.type)
    )
    if confidence >= 0.9 and supporters >= 1:
        return top
    if confidence >= min_confidence and supporters >= min_supporters:
        return top
    if supporters >= max(3, min_supporters + 1):
        return top
    return None


def consensus_to_tactical(
    proposal: SpecialistProposal,
    catalog: Sequence[CatalogAction],
    *,
    gateway: Any,
    state: Any,
) -> Optional[Any]:
    from interfaces.command_system.builtin.agent.hierarchical_planner import TacticalPlan

    catalog_map = {row.action_id: row for row in catalog}
    row = None
    for candidate in catalog:
        if candidate.module_path == proposal.action.path and candidate.action.type == proposal.action.type:
            row = candidate
            break
    if row is None:
        return None
    action = AgentAction(
        id=row.action_id,
        type=row.action.type,
        path=row.module_path,
        priority=row.action.priority,
        risk=row.action.risk,
        reason=f"consensus:{proposal.specialist}:{row.module_path}",
        status="approved",
        expected_requests=row.expected_requests,
        approved=True,
        options=dict(proposal.action.options or row.action.options or {}),
    )
    validated = gateway._validate_action(state, action, catalog)
    if validated is None:
        return None
    if gateway._needs_critic(state, validated):
        validated = gateway._apply_critic_gate(state, validated)
        if validated is None:
            return None
    return TacticalPlan(
        selected_action=validated,
        alternatives=[],
        source="fast_consensus",
        confidence=min(0.95, float(proposal.confidence or 0.8) + 0.05),
        rationale=f"Specialist consensus ({proposal.specialist}); LLM rank skipped",
    )


def resolve_orchestrator_direct_action(
    state: Any,
    catalog: Sequence[CatalogAction],
    *,
    gateway: Any,
) -> Optional[Any]:
    """Apply orchestrator tool output (run_module / http_request) without a second LLM pass."""
    from interfaces.command_system.builtin.agent.hierarchical_planner import TacticalPlan

    delegation = getattr(state, "domain_delegation", None)
    if not isinstance(delegation, dict):
        kb = getattr(state, "knowledge_base", None)
        delegation = kb.get("domain_delegation") if isinstance(kb, dict) else None
    if not isinstance(delegation, dict):
        return None
    action_id = str(delegation.get("action_id") or "").strip()
    tool = str(delegation.get("tool") or "").strip().lower()
    try:
        confidence = float(delegation.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    if not action_id or confidence < 0.72:
        return None
    if tool not in {"run_module", "http_request", "rank_catalog_action"}:
        return None
    catalog_map = {row.action_id: row for row in catalog}
    row = catalog_map.get(action_id)
    if row is None:
        return None
    action = AgentAction(
        id=row.action_id,
        type=row.action.type,
        path=row.module_path,
        priority=row.action.priority,
        risk=row.action.risk,
        reason=f"orchestrator_direct:{tool}:{row.module_path}",
        status="approved",
        expected_requests=row.expected_requests,
        approved=True,
        options=dict(row.action.options or {}),
    )
    validated = gateway._validate_action(state, action, catalog)
    if validated is None:
        return None
    if gateway._needs_critic(state, validated):
        validated = gateway._apply_critic_gate(state, validated)
        if validated is None:
            return None
    return TacticalPlan(
        selected_action=validated,
        alternatives=[],
        source="orchestrator_direct",
        confidence=confidence,
        rationale=str(delegation.get("rationale") or "Orchestrator direct tool selection"),
    )


def _executed_paths(state: Any) -> set[str]:
    paths: set[str] = set()
    for item in getattr(state, "executed_actions", []) or []:
        if isinstance(item, dict):
            paths.add(str(item.get("path") or ""))
        else:
            paths.add(str(getattr(item, "path", "") or ""))
    return {p for p in paths if p}


def _action_admissible_for_batch(action: AgentAction, *, executed: set[str], state: Any) -> bool:
    path = str(action.path or "")
    if not path or path in executed:
        return False
    risk = str(action.risk or "read").lower()
    if risk not in READ_RISKS:
        return False
    action_type = str(action.type or "").lower()
    if action_type not in TURBO_ACTION_TYPES:
        return False
    profile = str(getattr(state, "safety_profile", "") or "").lower()
    if profile == "discreet" and action_type == "surface_scan":
        return False
    return True


def build_turbo_action_batch(
    state: Any,
    tactical: Any,
    catalog: Sequence[CatalogAction],
    proposals: Sequence[SpecialistProposal],
) -> List[AgentAction]:
    """Queue several low-risk actions per planning cycle."""
    if not turbo_mode_enabled(state):
        if tactical.selected_action is not None:
            return [tactical.selected_action]
        return []

    limit = turbo_batch_size(state)
    executed = _executed_paths(state)
    batch: List[AgentAction] = []
    seen: set[Tuple[str, str]] = set()

    def _push(action: Optional[AgentAction]) -> None:
        if action is None:
            return
        key = (str(action.type), str(action.path))
        if key in seen:
            return
        if not _action_admissible_for_batch(action, executed=executed, state=state):
            return
        seen.add(key)
        approved = AgentAction(
            id=action.id,
            type=action.type,
            path=action.path,
            priority=action.priority,
            risk=action.risk,
            reason=action.reason or "turbo_batch",
            status="approved",
            expected_requests=action.expected_requests,
            approved=True,
            options=dict(action.options or {}),
        )
        batch.append(approved)

    _push(tactical.selected_action)
    for alt in getattr(tactical, "alternatives", []) or []:
        if len(batch) >= limit:
            break
        _push(alt)

    if len(batch) < limit:
        catalog_map = {row.action_id: row.action for row in catalog}
        heuristic_scores = {row.action_id: row.heuristic_score for row in catalog}
        for proposal in arbitrate_proposals(
            proposals,
            catalog_action_ids=catalog_map,
            heuristic_scores=heuristic_scores,
            limit=limit * 2,
        ):
            if len(batch) >= limit:
                break
            _push(proposal.action)

    if len(batch) < limit:
        kb = getattr(state, "knowledge_base", None)
        kb_map = kb if isinstance(kb, dict) else {}
        try:
            from interfaces.command_system.builtin.agent.http_probe_actions import (
                api_surface_ambiguous,
                suggest_probe_paths,
            )

            if api_surface_ambiguous(kb_map, state):
                for probe in suggest_probe_paths(kb_map)[: max(0, limit - len(batch))]:
                    for row in catalog:
                        if row.action.type != "http_request":
                            continue
                        if str(row.module_path) != str(probe):
                            continue
                        _push(row.action)
                        break
        except Exception:
            pass

    return batch[:limit]


def catalog_cache_key(state: Any, modules: Sequence[Any]) -> tuple[Any, ...]:
    exec_ids = tuple(
        sorted(
            str(x.get("id") if isinstance(x, dict) else getattr(x, "id", ""))
            for x in (getattr(state, "executed_actions", []) or [])
        )
    )
    return (len(modules or []), exec_ids, str(getattr(state, "campaign_goal", "") or ""))


def get_cached_catalog(state: Any, key: tuple[Any, ...]) -> Optional[List[CatalogAction]]:
    if getattr(state, "_perf_catalog_key", None) != key:
        return None
    cached = getattr(state, "_perf_catalog_rows", None)
    if not cached:
        return None
    return list(cached)


def store_catalog_cache(state: Any, key: tuple[Any, ...], catalog: Sequence[CatalogAction]) -> None:
    state._perf_catalog_key = key  # type: ignore[attr-defined]
    state._perf_catalog_rows = list(catalog)  # type: ignore[attr-defined]
