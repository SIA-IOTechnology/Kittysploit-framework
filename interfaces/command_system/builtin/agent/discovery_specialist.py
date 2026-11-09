#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discovery specialist: map open hypotheses to safe catalog actions (probes, crawlers)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from interfaces.command_system.builtin.agent.action_catalog import CatalogAction, stable_action_id
from interfaces.command_system.builtin.agent.discovery import (
    DiscoveryHypothesis,
    build_application_surface,
    propose_hypotheses,
)
from interfaces.command_system.builtin.agent.typed_models import AgentAction, SpecialistProposal

_DISCOVERY_KIND_WEIGHT: Dict[str, float] = {
    "cross_role_invariant": 55.0,
    "spec_drift": 42.0,
    "uncovered_surface": 38.0,
    "catalog_overlap": 5.0,
}

_PASSIVE_MODULE_TOKENS: Tuple[str, ...] = (
    "crawler",
    "spider",
    "surface",
    "enum",
    "directory",
    "swagger",
    "openapi",
    "tech_detect",
    "login_page",
)


def _is_discovery_safe_action(row: CatalogAction) -> bool:
    if not row.admissible:
        return False
    action_type = str(row.action.type or "").lower()
    path = str(row.module_path or "").lower()
    risk = str(row.action.risk or "").lower()
    if action_type in {"http_request", "surface_scan"}:
        return True
    if path.startswith("exploits/") or path.startswith("post/"):
        return False
    if action_type in {"run_exploit", "run_post"}:
        return False
    if risk in {"intrusive", "destructive"}:
        return False
    if path.startswith(("scanner/", "auxiliary/scanner/", "osint/", "auxiliary/osint/")):
        return True
    if any(token in path for token in _PASSIVE_MODULE_TOKENS):
        return True
    return False


def _open_hypotheses(kb: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw = kb.get("discovery") if isinstance(kb.get("discovery"), Mapping) else {}
    rows: List[Dict[str, Any]] = []
    for item in raw.get("hypotheses") or []:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("status") or "open") != "open":
            continue
        rows.append(dict(item))
    if rows:
        return rows
    surface = build_application_surface(kb)
    for hyp in propose_hypotheses(surface):
        if hyp.status == "open":
            rows.append(hyp.to_dict())
    return rows


def _route_matches_action_path(route: str, action_path: str) -> bool:
    route_t = str(route or "").strip()
    path_t = str(action_path or "").strip()
    if not route_t or not path_t:
        return False
    if path_t == route_t:
        return True
    if path_t.startswith("http"):
        try:
            from urllib.parse import urlsplit

            path_t = urlsplit(path_t).path or path_t
        except Exception:
            pass
    return path_t.split("?", 1)[0] == route_t or path_t.startswith(route_t.rstrip("/") + "/")


def _synthetic_probe_actions(
    hypotheses: Sequence[Mapping[str, Any]],
    *,
    goal: str,
    existing_paths: Set[str],
) -> List[CatalogAction]:
    rows: List[CatalogAction] = []
    for hyp in hypotheses:
        kind = str(hyp.get("kind") or "")
        if kind not in _DISCOVERY_KIND_WEIGHT or kind == "catalog_overlap":
            continue
        route = str(hyp.get("route") or "").strip()
        if not route or route in existing_paths:
            continue
        action = AgentAction(
            type="http_request",
            path=route,
            priority=75 if kind == "cross_role_invariant" else 65,
            risk="read",
            reason=f"discovery:hypothesis:{kind}",
            status="planned",
            expected_requests=1,
            options={"method": "GET"},
        )
        rows.append(
            CatalogAction(
                action_id=stable_action_id(route, "http_request", goal=goal),
                action=action,
                module_path=route,
                heuristic_score=_DISCOVERY_KIND_WEIGHT[kind],
                capability_target="discovery",
                prerequisites=[],
                expected_requests=1,
                admissible=True,
            )
        )
        existing_paths.add(route)
    return rows


def _discovery_action_score(
    row: CatalogAction,
    hypotheses: Sequence[Mapping[str, Any]],
) -> float:
    if not _is_discovery_safe_action(row):
        return -1.0
    score = float(row.heuristic_score or 0.0) * 0.35
    action_type = str(row.action.type or "").lower()
    path = str(row.module_path or "")
    low = path.lower()

    matched_hyp = False
    for hyp in hypotheses:
        kind = str(hyp.get("kind") or "")
        route = str(hyp.get("route") or "")
        weight = _DISCOVERY_KIND_WEIGHT.get(kind, 0.0)
        if not route:
            continue
        if action_type == "http_request" and _route_matches_action_path(route, path):
            score += weight
            matched_hyp = True
        elif kind == "uncovered_surface" and action_type != "http_request":
            if "crawler" in low or "spider" in low or action_type == "surface_scan":
                score += weight * 0.85
                matched_hyp = True
        elif kind == "spec_drift" and action_type == "http_request" and _route_matches_action_path(route, path):
            score += weight
            matched_hyp = True

    if action_type == "surface_scan" and hypotheses:
        score += 18.0
    if not matched_hyp and action_type == "http_request":
        score += 8.0
    if "crawler" in low or "spider" in low:
        score += 12.0
    return score


def propose_discovery_specialist(
    catalog: Sequence[CatalogAction],
    ctx: Mapping[str, Any],
    *,
    state: Any = None,
    limit: int = 2,
) -> List[SpecialistProposal]:
    """Propose read-only discovery actions tied to open hypotheses."""
    if hasattr(ctx, "kb"):
        kb = dict(getattr(ctx, "kb") or {})
    elif isinstance(ctx, Mapping):
        kb = dict(ctx.get("kb") or {})
    else:
        kb = {}
    if state is not None:
        try:
            from interfaces.command_system.builtin.agent.discovery import (
                discovery_mode_enabled,
                sync_discovery,
            )

            if discovery_mode_enabled(state):
                sync_discovery(state)
                live = getattr(state, "knowledge_base", None)
                if isinstance(live, dict):
                    kb = live
        except Exception:
            pass

    hypotheses = _open_hypotheses(kb)
    goal = str(getattr(state, "campaign_goal", "") or kb.get("campaign_goal") or "discovery")

    existing_paths = {
        str(row.module_path or "")
        for row in catalog
        if str(getattr(row.action, "type", "") or "") == "http_request"
    }
    synthetic = _synthetic_probe_actions(hypotheses, goal=goal, existing_paths=existing_paths)
    pool: List[CatalogAction] = [
        row for row in catalog if _is_discovery_safe_action(row)
    ] + synthetic

    if not pool:
        return []

    ranked = sorted(
        pool,
        key=lambda row: _discovery_action_score(row, hypotheses),
        reverse=True,
    )
    proposals: List[SpecialistProposal] = []
    for row in ranked:
        score = _discovery_action_score(row, hypotheses)
        if score < 0:
            continue
        rationale = _rationale_for(row, hypotheses)
        proposals.append(
            SpecialistProposal(
                specialist="discovery",
                action=AgentAction(
                    id=row.action_id,
                    type=row.action.type,
                    path=row.module_path,
                    priority=row.action.priority,
                    risk=row.action.risk,
                    reason=f"discovery:{row.action.reason or row.module_path}",
                    status="planned",
                    expected_requests=row.expected_requests,
                    options=dict(row.action.options or {}),
                ),
                confidence=min(0.92, 0.45 + score / 120.0),
                rationale=rationale[:500],
            )
        )
        if len(proposals) >= max(1, int(limit or 2)):
            break
    return proposals


def _rationale_for(row: CatalogAction, hypotheses: Sequence[Mapping[str, Any]]) -> str:
    path = str(row.module_path or "")
    action_type = str(row.action.type or "")
    for hyp in hypotheses:
        route = str(hyp.get("route") or "")
        kind = str(hyp.get("kind") or "")
        if route and _route_matches_action_path(route, path):
            stmt = str(hyp.get("statement") or "")[:180]
            return f"Discovery ({kind}): {stmt or route}"
    if action_type == "surface_scan":
        return "Discovery: widen HTTP surface before testing access-control invariants."
    if "crawler" in path.lower() or "spider" in path.lower():
        return "Discovery: crawl to cover uncovered routes from the application model."
    return f"Discovery specialist proposes safe action {path or action_type}."
