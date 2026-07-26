#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize module execution results into observation, evidence and capabilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.framework.base_module import normalize_module_result
from interfaces.command_system.builtin.agent.evidence import attach_result_evidence, evidence_records_from_result
from interfaces.command_system.builtin.agent.module_contract import ModuleContract, build_module_contract

SESSION_ACQUIRE_MARKERS = (
    "session_acquire",
    "/session_acquire",
    "session_stabilize",
)
SUCCESS_TEXT_MARKERS = ("success", "shell obtained", "session opened")


@dataclass
class NormalizedOutcome:
    module_path: str
    observation: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    capabilities: List[Dict[str, Any]] = field(default_factory=list)
    session_claim_valid: bool = False
    capability_claims_suppressed: int = 0
    rejection_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def resolve_module_contract(module_instance: Any, module_path: str) -> Optional[ModuleContract]:
    info = getattr(module_instance, "__info__", {}) or {}
    if not isinstance(info, dict):
        return None
    agent = info.get("agent")
    return build_module_contract(
        module_path,
        static_meta=info,
        agent_meta=agent if isinstance(agent, dict) else None,
    )


def apply_normalized_outcome_to_state(
    state: Any,
    normalized: NormalizedOutcome,
    *,
    phase: str = "",
    framework: Any = None,
    structured_details: Optional[Mapping[str, Any]] = None,
) -> None:
    """Merge validated observations, evidence and sessions into campaign state."""
    from interfaces.command_system.builtin.agent.attack_chain_memory import (
        ChainObservation,
        OBS_BLOCKED,
        OBS_CONFIRMED,
        OBS_ERROR,
        OBS_NO_SIGNAL,
        OBS_REFUTED,
        apply_observations_to_kb,
    )

    status_map = {
        "confirmed": OBS_CONFIRMED,
        "refuted": OBS_REFUTED,
        "blocked": OBS_BLOCKED,
        "module_error": OBS_ERROR,
        "no_signal": OBS_NO_SIGNAL,
    }
    obs = normalized.observation if isinstance(normalized.observation, dict) else {}
    chain_status = status_map.get(str(obs.get("status") or "no_signal"), OBS_NO_SIGNAL)
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb

    from interfaces.command_system.builtin.agent.campaign_world import sync_campaign_world

    sync_campaign_world(kb, state=state)

    from interfaces.command_system.builtin.agent.scope_lateral import sync_scope_lateral

    sync_scope_lateral(kb, state=state, structured_details=structured_details)

    from interfaces.command_system.builtin.agent.plan_recalc import sync_plan_recalc

    sync_plan_recalc(kb, state=state)

    session_id = obs.get("session_id")
    if normalized.session_claim_valid and session_id and framework is not None:
        from interfaces.command_system.builtin.agent.session_broker import SessionBroker

        broker = SessionBroker.from_kb(framework, kb)
        ok, broker_reason = broker.gate_session_claim(
            str(session_id),
            evidence_rows=normalized.evidence,
            structured_details=structured_details,
            state=state,
        )
        if not ok:
            normalized.session_claim_valid = False
            normalized.rejection_reasons.append(broker_reason)
            chain_status = OBS_REFUTED
            obs["status"] = "refuted"
            session_id = None

    observation = ChainObservation(
        module_path=normalized.module_path,
        status=chain_status,
        capability=str((normalized.capabilities[0] or {}).get("capability") or "") if normalized.capabilities else "",
        value="",
        phase=phase or str(obs.get("phase") or ""),
        confidence=0.85 if chain_status == OBS_CONFIRMED else 0.35,
        proof_summary="; ".join(normalized.rejection_reasons[:3]) or str(obs.get("message") or ""),
        reason=str(obs.get("message") or ""),
    )
    apply_observations_to_kb(kb, [observation])

    if normalized.session_claim_valid and session_id:
        verified = list(getattr(state, "verified_sessions", []) or [])
        token = str(session_id)
        if token and token not in verified:
            verified.append(token)
            state.verified_sessions = verified
        sessions = list(getattr(state, "new_sessions", []) or [])
        if token and token not in sessions:
            sessions.append(token)
            state.new_sessions = sessions
        kb["verified_session_ids"] = list(getattr(state, "verified_sessions", []) or [])

    if normalized.evidence:
        results = list(getattr(state, "results", []) or [])
        results.append({
            "path": normalized.module_path,
            "phase": phase,
            "evidence_records": normalized.evidence,
            "evidence_state": obs.get("status"),
            "session_id": session_id if normalized.session_claim_valid else None,
            "vulnerable": chain_status == OBS_CONFIRMED,
        })
        state.results = results


def enrich_execution_payload(
    payload: Dict[str, Any],
    *,
    module_instance: Any,
    module_path: str,
    state: Any,
    phase: str,
    framework: Any = None,
) -> Dict[str, Any]:
    contract = resolve_module_contract(module_instance, module_path)
    normalized = normalize_module_outcome(
        payload,
        module_path=module_path,
        contract=contract,
        phase=phase,
    )
    payload["normalized_outcome"] = normalized.to_dict()
    payload["evidence_records"] = normalized.evidence
    if normalized.rejection_reasons:
        payload["outcome_rejections"] = list(normalized.rejection_reasons)
    execution = payload.get("execution")
    structured_details = _execution_to_result_dict(execution).get("details")
    if not isinstance(structured_details, dict):
        structured_details = _execution_to_result_dict(execution)
    apply_normalized_outcome_to_state(
        state,
        normalized,
        phase=phase,
        framework=framework,
        structured_details=structured_details if isinstance(structured_details, dict) else None,
    )
    if execution is not None and not normalized.session_claim_valid:
        for attr in ("session_id",):
            if hasattr(execution, attr):
                setattr(execution, attr, None)
    return payload


def _execution_to_result_dict(execution: Any) -> Dict[str, Any]:
    if execution is None:
        return {}
    if isinstance(execution, dict):
        return dict(execution)
    for attr in ("to_dict", "as_dict"):
        fn = getattr(execution, attr, None)
        if callable(fn):
            try:
                payload = fn()
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
    row: Dict[str, Any] = {}
    for key in (
        "success",
        "command_success",
        "blocked",
        "error",
        "message",
        "session_id",
        "finding",
        "evidence",
        "schema_evidence",
        "vulnerable",
        "details",
    ):
        if hasattr(execution, key):
            row[key] = getattr(execution, key)
    return row


def _message_claims_success(message: str) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    return any(marker in text for marker in SUCCESS_TEXT_MARKERS)


def validate_session_claim(
    result: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    *,
    contract: Optional[ModuleContract] = None,
) -> tuple[bool, str]:
    """Sessions require structured proof, not return codes or success strings alone."""
    session_id = str(result.get("session_id") or "").strip()
    if not session_id:
        return False, "no_session_id"

    module_path = str(result.get("path") or result.get("module_path") or "").lower()
    if any(marker in module_path for marker in SESSION_ACQUIRE_MARKERS):
        if result.get("command_success") or result.get("success"):
            return True, "session_acquire_module"

    if evidence_rows:
        best = max(float(row.get("confidence", 0.0) or 0.0) for row in evidence_rows)
        if best >= 0.65:
            return True, "confirmed_evidence"

    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    if details.get("command_output") or details.get("proof") or details.get("authenticated_as"):
        return True, "structured_proof"

    message = str(result.get("message") or "")
    if _message_claims_success(message) and not evidence_rows:
        return False, "message_only_success"

    if result.get("success") and not evidence_rows and not details:
        return False, "return_code_only"

    validators = list((contract.success_validators if contract else []) or [])
    if "session_neutral_check" in validators and evidence_rows:
        return True, "neutral_check_passed"
    return False, "insufficient_session_proof"


def validate_capability_claim(
    capability: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    *,
    contract: Optional[ModuleContract] = None,
) -> tuple[bool, str]:
    cap = str(capability.get("capability") or capability.get("name") or "").strip().lower()
    if not cap:
        return False, "missing_capability_name"
    if cap in {"shell", "authenticated_session", "session_cookie"}:
        ok, reason = validate_session_claim(
            {
                "session_id": capability.get("value") or capability.get("session_id"),
                "message": capability.get("summary") or "",
                "path": contract.module_path if contract else "",
            },
            evidence_rows,
            contract=contract,
        )
        return ok, reason
    if not evidence_rows and "evidence_or_observation" in (contract.success_validators if contract else []):
        return False, "capability_requires_evidence"
    return bool(evidence_rows), "evidence_present" if evidence_rows else "no_evidence"


def normalize_module_outcome(
    raw_result: Mapping[str, Any],
    *,
    module_path: str,
    contract: Optional[ModuleContract] = None,
    phase: str = "",
) -> NormalizedOutcome:
    """ModuleResult → observation → evidence → capability with terminal validators."""
    execution = raw_result.get("execution")
    row = _execution_to_result_dict(execution)
    if not row and isinstance(raw_result, dict):
        row = dict(raw_result)
    row.setdefault("path", module_path)

    normalized = normalize_module_result(row)
    payload = normalized.to_dict() if hasattr(normalized, "to_dict") else dict(row)
    payload["path"] = module_path
    enriched = attach_result_evidence(payload)
    evidence = [
        dict(item) for item in (enriched.get("evidence_records") or []) if isinstance(item, dict)
    ]

    session_ok, session_reason = validate_session_claim(enriched, evidence, contract=contract)
    rejection_reasons: List[str] = []
    if enriched.get("session_id") and not session_ok:
        rejection_reasons.append(session_reason)

    capabilities: List[Dict[str, Any]] = []
    suppressed = 0
    if contract is not None:
        for spec in contract.produces_capabilities:
            candidate = {
                "capability": spec.get("capability"),
                "source_module": module_path,
                "from_detail": spec.get("from_detail") or "",
            }
            ok, reason = validate_capability_claim(candidate, evidence, contract=contract)
            if ok:
                capabilities.append(candidate)
            else:
                suppressed += 1
                rejection_reasons.append(f"{candidate.get('capability')}: {reason}")

    verdict = "confirmed" if evidence and enriched.get("vulnerable") else "no_signal"
    if enriched.get("session_id") and session_ok:
        verdict = "confirmed"
    elif enriched.get("session_id"):
        verdict = "refuted"

    observation = {
        "module_path": module_path,
        "phase": phase,
        "status": verdict,
        "message": str(enriched.get("message") or enriched.get("error") or "")[:500] or None,
        "session_id": enriched.get("session_id") if session_ok else None,
        "evidence_count": len(evidence),
        "blocked": bool(raw_result.get("blocked")),
    }

    return NormalizedOutcome(
        module_path=module_path,
        observation=observation,
        evidence=evidence,
        capabilities=capabilities,
        session_claim_valid=session_ok,
        capability_claims_suppressed=suppressed,
        rejection_reasons=rejection_reasons,
    )
