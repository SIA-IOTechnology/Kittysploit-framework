#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deterministic admissible action catalog for constrained LLM ranking."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_planner import (
    action_profile_from_module,
    planner_alignment_bonus,
    planner_state_from_kb,
    ActionScorer,
)
from interfaces.command_system.builtin.agent.goal_planner import filter_actions_for_goal, normalize_goal
from interfaces.command_system.builtin.agent.http_probe_actions import (
    api_surface_ambiguous,
    http_surface_observed,
    llm_connected,
    suggest_probe_paths,
)
from interfaces.command_system.builtin.agent.typed_models import AgentAction


CAPABILITY_LADDER: Sequence[str] = (
    "service_identified",
    "primitive_confirmed",
    "access",
    "authenticated_session",
    "session",
    "privilege",
)


@dataclass
class CatalogAction:
    action_id: str
    action: AgentAction
    module_path: str
    heuristic_score: float = 0.0
    capability_target: str = ""
    prerequisites: List[str] = field(default_factory=list)
    expected_requests: int = 1
    admissible: bool = True
    rejection_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action.to_dict(),
            "module_path": self.module_path,
            "heuristic_score": self.heuristic_score,
            "capability_target": self.capability_target,
            "prerequisites": list(self.prerequisites),
            "expected_requests": self.expected_requests,
            "admissible": self.admissible,
            "rejection_reason": self.rejection_reason,
        }


def stable_action_id(module_path: str, action_type: str, *, goal: str = "") -> str:
    digest = hashlib.sha256(f"{goal}:{action_type}:{module_path}".encode("utf-8")).hexdigest()
    return f"cat_{digest[:12]}"


def _action_type_for_path(path: str) -> str:
    if path.startswith("exploits/"):
        return "run_exploit"
    if path.startswith("post/"):
        return "run_post"
    return "run_followup"


def _capability_target_for_path(path: str) -> str:
    low = path.lower()
    if "session_acquire" in low or "reverse_shell" in low:
        return "session"
    if "privesc" in low or "getsystem" in low:
        return "privilege"
    if "login" in low or "bruteforce" in low or "auth" in low:
        return "authenticated_session"
    if low.startswith("exploits/"):
        return "access"
    if "sqli" in low or "lfi" in low or "xss" in low or "rce" in low:
        return "primitive_confirmed"
    return "service_identified"


def current_capability_rung(kb: Mapping[str, Any]) -> str:
    if not isinstance(kb, dict):
        return CAPABILITY_LADDER[0]
    if kb.get("root_shell") or kb.get("privilege_level") in {"root", "system", "admin"}:
        return "privilege"
    sessions = kb.get("verified_session_ids") or kb.get("verified_sessions") or kb.get("new_sessions") or kb.get("sessions") or []
    if sessions:
        return "session"
    if kb.get("auth_milestone") or kb.get("authenticated_session"):
        return "authenticated_session"
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    observations = chain.get("observations") or []
    for row in observations:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").lower()
        cap = str(row.get("capability") or "").lower()
        if status == "confirmed" and cap in CAPABILITY_LADDER:
            return cap
    services = kb.get("identified_services") or kb.get("services") or []
    if services:
        return "service_identified"
    return CAPABILITY_LADDER[0]


def _was_executed(path: str, executed: set[str]) -> bool:
    return any(entry == path or entry.endswith(f":{path}") for entry in executed)


def _build_probe_catalog_actions(
    *,
    kb: Mapping[str, Any],
    goal: str,
    state: Any = None,
    executed: set[str],
) -> List[CatalogAction]:
    """Emit http_request / surface_scan catalog entries when HTTP surface warrants probes."""
    if not http_surface_observed(kb, state):
        return []
    include_probes = llm_connected(state) or api_surface_ambiguous(kb, state) or bool(
        kb.get("discovered_endpoints") or kb.get("risk_signals")
    )
    if not include_probes:
        return []

    rows: List[CatalogAction] = []
    probe_paths = suggest_probe_paths(kb)
    for path in probe_paths[:5]:
        marker = f"agent/http_request:{path}"
        if marker in executed or any(marker in item for item in executed):
            continue
        action = AgentAction(
            type="http_request",
            path=path,
            priority=70,
            risk="read",
            reason="catalog:http_probe",
            status="planned",
            expected_requests=1,
            options={"method": "GET"},
        )
        rows.append(
            CatalogAction(
                action_id=stable_action_id(path, "http_request", goal=goal),
                action=action,
                module_path=path,
                heuristic_score=72.0 if api_surface_ambiguous(kb, state) else 55.0,
                capability_target="service_identified",
                prerequisites=[],
                expected_requests=1,
                admissible=True,
            )
        )

    surface_marker = "agent/surface_scan"
    if surface_marker not in executed and not any(surface_marker in item for item in executed):
        surface = AgentAction(
            type="surface_scan",
            path="scanner -u",
            priority=60,
            risk="active",
            reason="catalog:surface_scan",
            status="planned",
            expected_requests=4,
            options={"limit": 6, "protocol": "http"},
        )
        rows.append(
            CatalogAction(
                action_id=stable_action_id("scanner -u", "surface_scan", goal=goal),
                action=surface,
                module_path="scanner -u",
                heuristic_score=58.0,
                capability_target="service_identified",
                prerequisites=[],
                expected_requests=4,
                admissible=True,
            )
        )
    return rows


def build_admissible_catalog(
    *,
    modules: Sequence[Mapping[str, Any]],
    kb: Mapping[str, Any],
    goal: str = "",
    executed_actions: Optional[Sequence[str]] = None,
    limit: int = 48,
    state: Any = None,
) -> List[CatalogAction]:
    """Return deterministic catalog entries the LLM may rank but not invent."""
    kb = kb if isinstance(kb, dict) else {}
    goal_n = normalize_goal(goal or kb.get("campaign_goal") or "recon")
    executed = {str(item) for item in (executed_actions or [])}
    scorer = ActionScorer()
    planner_state = planner_state_from_kb(kb)
    rung = current_capability_rung(kb)
    rows: List[CatalogAction] = []
    rows.extend(_build_probe_catalog_actions(kb=kb, goal=goal_n, state=state, executed=executed))

    for module_row in modules:
        if not isinstance(module_row, dict):
            continue
        path = str(module_row.get("path") or "").strip()
        if not path:
            continue
        action_type = _action_type_for_path(path)
        if not filter_actions_for_goal([{"type": action_type, "path": path}], goal_n):
            continue
        if _was_executed(path, executed):
            continue
        profile = action_profile_from_module(module_row)
        score = scorer.score(profile, planner_state) + planner_alignment_bonus(module_row, kb)
        low_path = path.lower()
        protocol = str(kb.get("protocol") or getattr(state, "protocol", "") or "").lower()
        if protocol in {"smb", "cifs"} or "smb" in " ".join(str(s).lower() for s in (kb.get("services") or [])):
            if "/smb/" in low_path or "smb_" in low_path:
                score += 35.0
        if protocol == "ssh" or "ssh" in " ".join(str(s).lower() for s in (kb.get("services") or [])):
            if "/ssh/" in low_path or "ssh_" in low_path:
                score += 35.0
        sessions = kb.get("verified_session_ids") or kb.get("verified_sessions") or kb.get("sessions") or []
        if sessions and low_path.startswith("post/"):
            score += 40.0
        cap_target = _capability_target_for_path(path)
        admissible = True
        reason = ""
        try:
            rung_idx = CAPABILITY_LADDER.index(rung)
            target_idx = CAPABILITY_LADDER.index(cap_target)
            if target_idx > rung_idx + 2:
                admissible = False
                reason = "capability_jump_too_large"
        except ValueError:
            pass

        action = AgentAction(
            type=action_type,
            path=path,
            priority=int(max(0.0, score)),
            risk=str(module_row.get("risk") or ("intrusive" if "exploit" in path else "active")),
            reason="catalog:heuristic",
            status="planned",
            expected_requests=int(module_row.get("expected_requests") or profile.cost // 2 or 1),
        )
        rows.append(
            CatalogAction(
                action_id=stable_action_id(path, action_type, goal=goal_n),
                action=action,
                module_path=path,
                heuristic_score=score,
                capability_target=cap_target,
                prerequisites=[rung] if rung else [],
                expected_requests=action.expected_requests,
                admissible=admissible,
                rejection_reason=reason,
            )
        )

    rows.sort(key=lambda row: row.heuristic_score, reverse=True)
    return [row for row in rows[:limit] if row.admissible]
