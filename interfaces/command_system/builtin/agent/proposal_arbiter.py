#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Merge and rank contradictory specialist proposals without naive majority vote."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.typed_models import AgentAction, SpecialistProposal


def _proposal_key(proposal: SpecialistProposal) -> str:
    path = str(proposal.action.path or "")
    return f"{proposal.specialist}:{proposal.action.type}:{path}"


def arbitrate_proposals(
    proposals: Sequence[SpecialistProposal],
    *,
    catalog_action_ids: Optional[Mapping[str, AgentAction]] = None,
    heuristic_scores: Optional[Mapping[str, float]] = None,
    limit: int = 5,
) -> List[SpecialistProposal]:
    """Cluster proposals by action identity and rank by calibrated score."""
    catalog_action_ids = catalog_action_ids or {}
    heuristic_scores = heuristic_scores or {}
    buckets: Dict[str, List[SpecialistProposal]] = {}

    for proposal in proposals:
        action_id = str(getattr(proposal.action, "id", "") or "")
        catalog_id = ""
        for cid, action in catalog_action_ids.items():
            if action.path == proposal.action.path and action.type == proposal.action.type:
                catalog_id = cid
                break
        key = catalog_id or f"{proposal.action.type}:{proposal.action.path or ''}"
        buckets.setdefault(key, []).append(proposal)

    ranked: List[tuple[float, SpecialistProposal]] = []
    for key, group in buckets.items():
        if not group:
            continue
        best = max(group, key=lambda row: float(row.confidence or 0.0))
        support = len(group)
        dissent = [row for row in group if row is not best]
        penalty = 0.08 * len(dissent)
        heuristic = float(heuristic_scores.get(key, 0.0) or 0.0)
        score = float(best.confidence or 0.0) + 0.05 * support + 0.01 * heuristic - penalty
        if dissent:
            best.rationale = (
                f"{best.rationale} | merged {support} proposal(s); "
                f"{len(dissent)} alternate specialist view(s)"
            ).strip()
        ranked.append((score, best))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [proposal for _score, proposal in ranked[: max(1, int(limit or 5))]]
