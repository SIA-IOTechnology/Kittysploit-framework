#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compact host/service planner context, playbook retrieval, and confidence calibration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.action_catalog import current_capability_rung
from interfaces.command_system.builtin.agent.attack_chain_memory import get_observations
from interfaces.command_system.builtin.agent.learning_episode import (
    build_context_fingerprint,
    build_context_index,
    retrieve_mission_episodes,
)
from interfaces.command_system.builtin.agent.module_performance_memory import (
    ModulePerformanceMemory,
    classify_target_profile,
    kb_light_copy,
    kb_metrics_snapshot,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import SpecialistProposal

MAX_HOST_CONTEXT_CHARS = 1800
MAX_PLAYBOOK_HINTS = 3
MAX_EPISODE_HINTS = 4


@dataclass
class HostServiceContext:
    host: str = ""
    host_id: str = ""
    service_id: str = ""
    protocol: str = ""
    services: List[str] = field(default_factory=list)
    capability_rung: str = ""
    target_profile: str = ""
    fingerprint: str = ""
    tech_hints: List[str] = field(default_factory=list)
    risk_signals: List[str] = field(default_factory=list)
    login_paths: List[str] = field(default_factory=list)
    endpoint_count: int = 0
    param_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "host": self.host,
            "host_id": self.host_id,
            "service_id": self.service_id,
            "protocol": self.protocol,
            "services": self.services[:6],
            "capability_rung": self.capability_rung,
            "target_profile": self.target_profile,
            "fingerprint": self.fingerprint,
            "tech_hints": self.tech_hints[:8],
            "risk_signals": self.risk_signals[:8],
            "login_paths": self.login_paths[:4],
            "endpoint_count": self.endpoint_count,
            "param_count": self.param_count,
        })


def _kb_from(state: Any, observation: Mapping[str, Any]) -> Dict[str, Any]:
    kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
    if isinstance(getattr(state, "knowledge_base", None), dict):
        merged = dict(getattr(state, "knowledge_base", {}))
        merged.update(kb)
        return merged
    return dict(kb)


def _resolve_host(state: Any, kb: Mapping[str, Any]) -> str:
    target_info = getattr(state, "target_info", {}) or {}
    if isinstance(target_info, dict):
        for key in ("host", "hostname", "ip", "target"):
            token = str(target_info.get(key) or "").strip()
            if token:
                return token[:200]
    return str(getattr(state, "raw_target", "") or kb.get("target_host") or "")[:200]


def _resolve_services(state: Any, kb: Mapping[str, Any]) -> List[str]:
    host_profile = getattr(state, "host_profile", {}) or {}
    services: List[str] = []
    if isinstance(host_profile, dict):
        for row in host_profile.get("service_fingerprints") or []:
            if not isinstance(row, dict):
                continue
            label = str(row.get("service") or row.get("name") or "").strip()
            port = row.get("port")
            if label and port is not None:
                services.append(f"{label}:{port}")
            elif label:
                services.append(label)
    for item in kb.get("identified_services") or []:
        token = str(item or "").strip()
        if token and token not in services:
            services.append(token)
    protocol = str(getattr(state, "protocol", "") or kb.get("protocol") or "").strip()
    if protocol and protocol not in services:
        services.insert(0, protocol)
    return services[:8]


def compute_context_fingerprint(host: str, kb: Mapping[str, Any], capability_rung: str) -> str:
    profile = classify_target_profile(kb if isinstance(kb, dict) else {})
    digest = hashlib.sha256(
        f"{host}:{profile}:{capability_rung}".encode("utf-8"),
    ).hexdigest()
    return f"fp_{digest[:12]}"


def build_host_service_context(
    state: Any,
    observation: Mapping[str, Any],
    *,
    service_id: Optional[str] = None,
) -> HostServiceContext:
    kb = _kb_from(state, observation)
    from interfaces.command_system.builtin.agent.campaign_world import (
        campaign_world_from_kb,
        get_service_context_slice,
        list_host_services,
        sync_campaign_world,
    )

    sync_campaign_world(kb, state=state)
    if isinstance(getattr(state, "knowledge_base", None), dict):
        state.knowledge_base.update(kb)

    world = campaign_world_from_kb(kb)
    focus_service_id = str(service_id or getattr(state, "active_service_id", "") or world.active_service_id or "")
    focus_host_id = str(getattr(state, "active_host_id", "") or world.active_host_id or "")
    svc = get_service_context_slice(world, host_id=focus_host_id, service_id=focus_service_id)

    host = _resolve_host(state, kb)
    if focus_host_id and focus_host_id in world.hosts:
        host = world.hosts[focus_host_id].hostname or host

    rung = svc.capability_rung if svc is not None and svc.capability_rung else current_capability_rung(kb)
    profile = classify_target_profile(kb)
    tech_hints = list(kb.get("tech_hints") or [])
    risk_signals = list(kb.get("risk_signals") or [])
    if svc is not None:
        tech_hints = sorted(set(tech_hints) | set(svc.tech_hints))[:12]
        risk_signals = sorted(set(risk_signals) | set(svc.risk_signals))[:12]

    return HostServiceContext(
        host=host,
        host_id=focus_host_id,
        service_id=focus_service_id,
        protocol=str(svc.protocol if svc is not None else getattr(state, "protocol", "") or kb.get("protocol") or ""),
        services=list_host_services(world, focus_host_id) or _resolve_services(state, kb),
        capability_rung=rung,
        target_profile=profile,
        fingerprint=compute_context_fingerprint(host, kb, rung),
        tech_hints=[str(item) for item in tech_hints[:12]],
        risk_signals=[str(item) for item in risk_signals[:12]],
        login_paths=[str(item) for item in (kb.get("login_paths") or [])[:6]],
        endpoint_count=len(kb.get("discovered_endpoints") or []),
        param_count=len(kb.get("discovered_params") or []),
    )


def retrieve_playbook_hints(
    kb: Mapping[str, Any],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    limit: int = MAX_PLAYBOOK_HINTS,
) -> List[Dict[str, Any]]:
    from core.playbooks.coverage import assess_playbook_coverage

    report = assess_playbook_coverage(kb, findings, limit=max(1, int(limit or MAX_PLAYBOOK_HINTS)))
    hints: List[Dict[str, Any]] = []
    for row in report.get("playbooks") or []:
        if not isinstance(row, dict):
            continue
        next_modules: List[str] = []
        for step in row.get("steps") or []:
            if not isinstance(step, dict):
                continue
            status = str(step.get("status") or "")
            module = str(step.get("module") or "").strip()
            if module and status not in {"executed", "capability_unlocked"}:
                next_modules.append(module)
        hints.append(sanitize_nested({
            "playbook_id": row.get("playbook_id"),
            "coverage": row.get("coverage"),
            "relevance": round(float(row.get("relevance") or 0.0), 3),
            "next_modules": next_modules[:3],
            "summary": str(row.get("summary") or "")[:220],
        }))
        if len(hints) >= limit:
            break
    return hints


def retrieve_similar_episodes(
    kb: Mapping[str, Any],
    *,
    target_profile: str = "",
    capability_rung: str = "",
    limit: int = MAX_EPISODE_HINTS,
    learning_store: Any = None,
    state: Any = None,
) -> List[Dict[str, Any]]:
    profile = str(target_profile or classify_target_profile(kb if isinstance(kb, dict) else {}))
    fingerprint = ""
    if state is not None:
        fingerprint = build_context_fingerprint(build_context_index(state, kb if isinstance(kb, Mapping) else {}))
    elif isinstance(kb, Mapping):
        fingerprint = build_context_fingerprint(build_context_index(
            type("_S", (), {"knowledge_base": kb, "target_info": {}, "host_profile": {}})(),
            kb,
        ))
    learned_rows: List[Dict[str, Any]] = []
    if learning_store is not None and fingerprint:
        try:
            learned_rows = learning_store.query_similar_episodes(
                kb if isinstance(kb, Mapping) else {},
                context_fingerprint=fingerprint,
                limit=limit,
            )
        except Exception:
            learned_rows = []
    if not learned_rows:
        learned_rows = retrieve_mission_episodes(
            kb if isinstance(kb, MutableMapping) else {},
            context_fingerprint=fingerprint,
            limit=limit,
        )
    if learned_rows:
        hints: List[Dict[str, Any]] = []
        for row in learned_rows[-limit:]:
            if not isinstance(row, dict):
                continue
            hints.append(sanitize_nested({
                "module_path": row.get("action_path") or row.get("module_path"),
                "status": row.get("verdict") or row.get("status"),
                "capability": row.get("capability") or "",
                "reason": str(row.get("failure_type") or row.get("reason") or "")[:160],
                "proof_summary": f"gain={row.get('real_gain', 0)}",
                "source": "learning_episode",
            }))
        if hints:
            return hints[:limit]

    rows = get_observations(kb if isinstance(kb, Mapping) else {})
    scored: List[tuple[float, Dict[str, Any]]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        module_path = str(row.get("module_path") or "")
        if not module_path:
            continue
        status = str(row.get("status") or "")
        score = 0.0
        if status in {"confirmed", "success", "validated"}:
            score += 2.0
        elif status in {"refuted", "blocked", "error"}:
            score += 0.4
        else:
            score += 0.8
        cap = str(row.get("capability") or "")
        if capability_rung and cap == capability_rung:
            score += 1.5
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if str(meta.get("target_profile") or "") == profile:
            score += 1.0
        scored.append((
            score,
            sanitize_nested({
                "module_path": module_path,
                "status": status,
                "capability": cap or None,
                "reason": str(row.get("reason") or "")[:160],
                "proof_summary": str(row.get("proof_summary") or "")[:160],
            }),
        ))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [row for _score, row in scored[: max(1, int(limit or MAX_EPISODE_HINTS))]]


class ConfidenceCalibrator:
    """Map declared LLM confidence to observed module success proxies."""

    def __init__(self, memory: Optional[ModulePerformanceMemory] = None) -> None:
        self.memory = memory or ModulePerformanceMemory()

    def observed_success_rate(self, module_path: str, kb: Mapping[str, Any]) -> float:
        if not module_path:
            return 0.35
        multiplier = self.memory.utility_multiplier(module_path, kb if isinstance(kb, dict) else {})
        normalized = (multiplier - 0.72) / max(0.01, (1.28 - 0.72))
        return round(max(0.05, min(0.92, 0.18 + normalized * 0.62)), 4)

    def calibrate(
        self,
        module_path: str,
        kb: Mapping[str, Any],
        declared_confidence: float,
        *,
        declared_weight: float = 0.4,
    ) -> float:
        observed = self.observed_success_rate(module_path, kb)
        declared = max(0.0, min(1.0, float(declared_confidence or 0.0)))
        weight = max(0.0, min(1.0, float(declared_weight or 0.4)))
        calibrated = (weight * declared) + ((1.0 - weight) * observed)
        return round(max(0.05, min(0.95, calibrated)), 4)


def calibrate_proposals(
    proposals: Sequence[SpecialistProposal],
    kb: Mapping[str, Any],
    *,
    calibrator: Optional[ConfidenceCalibrator] = None,
) -> List[SpecialistProposal]:
    calibrator = calibrator or ConfidenceCalibrator()
    calibrated: List[SpecialistProposal] = []
    for proposal in proposals:
        path = str(proposal.action.path or "")
        confidence = calibrator.calibrate(path, kb, float(proposal.confidence or 0.0))
        proposal.confidence = confidence
        calibrated.append(proposal)
    return calibrated


def build_planner_llm_context(
    state: Any,
    observation: Mapping[str, Any],
    *,
    catalog_action_ids: Optional[Sequence[str]] = None,
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    kb = _kb_from(state, observation)
    host_ctx = build_host_service_context(state, observation)
    playbooks = retrieve_playbook_hints(kb, findings)
    episodes = retrieve_similar_episodes(
        kb,
        target_profile=host_ctx.target_profile,
        capability_rung=host_ctx.capability_rung,
    )
    from interfaces.command_system.builtin.agent.adversarial_guard import sanitize_finding_rows

    safe_findings = sanitize_finding_rows(findings or [])
    scope_lateral = kb.get("scope_lateral") if isinstance(kb.get("scope_lateral"), dict) else {}
    payload = sanitize_nested({
        "schema_version": "1.0",
        "host_service": host_ctx.to_dict(),
        "campaign_goal": getattr(state, "campaign_goal", "") or observation.get("goal") or "",
        "phase": getattr(state, "current_phase", "") or observation.get("phase") or "",
        "admissible_action_ids": list(catalog_action_ids or [])[:12],
        "playbook_hints": playbooks,
        "similar_episodes": episodes,
        "sanitized_findings": safe_findings[:8],
        "credential_reuse_ready": bool(scope_lateral.get("credential_reuse_ready")),
        "lateral_proposals": list(scope_lateral.get("proposals") or [])[:3],
        "plan_revision": int((kb.get("plan_recalc") or {}).get("revision") or 0),
        "plan_recalc_pending": bool((kb.get("plan_recalc") or {}).get("replan_required")),
    })
    text = str(payload)
    if len(text) > MAX_HOST_CONTEXT_CHARS:
        payload["truncated"] = True
        payload["similar_episodes"] = episodes[:2]
        payload["playbook_hints"] = playbooks[:2]
    return payload


def attach_planner_context(
    state: Any,
    observation: Mapping[str, Any],
    *,
    catalog_action_ids: Optional[Sequence[str]] = None,
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    context = build_planner_llm_context(
        state,
        observation,
        catalog_action_ids=catalog_action_ids,
        findings=findings,
    )
    state.planner_llm_context = context
    host_service = context.get("host_service") if isinstance(context.get("host_service"), dict) else {}
    if host_service.get("host_id"):
        state.active_host_id = str(host_service.get("host_id") or "")
    if host_service.get("service_id"):
        state.active_service_id = str(host_service.get("service_id") or "")
    return context
