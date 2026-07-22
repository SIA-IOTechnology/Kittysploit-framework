#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed agent domain models for Phase 1 adaptive loop (validated dataclasses)."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.schemas import SCHEMA_VERSION

ACTION_TYPES = frozenset({"prioritize", "http_request", "surface_scan", "run_followup", "run_exploit", "run_post", "skip", "collect", "report"})
ACTION_STATUSES = frozenset({"planned", "approved", "blocked", "running", "completed", "failed", "skipped"})
RISK_LEVELS = frozenset({"read", "active", "intrusive", "destructive"})
OUTCOME_VERDICTS = frozenset({
    "confirmed", "no_signal", "refuted", "blocked", "module_error", "policy_denied", "planned", "skipped",
})
HYPOTHESIS_STATUSES = frozenset({"open", "confirmed", "refuted", "blocked"})
STOP_KINDS = frozenset({"hard", "soft"})
HARD_STOP_REASONS = frozenset({
    "scope_violation", "policy_denied", "budget_exhausted", "target_lost", "cancelled",
})
SOFT_STOP_REASONS = frozenset({
    "low_novelty", "branch_exhausted", "goal_reached", "operator_stop",
})


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AgentAction:
    type: str
    path: Optional[str] = None
    priority: int = 0
    risk: str = "read"
    approval_required: bool = False
    approved: bool = False
    expected_requests: int = 0
    options: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    status: str = "planned"
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("act"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AgentAction":
        data = dict(payload or {})
        return cls(
            type=str(data.get("type") or "run_followup"),
            path=data.get("path"),
            priority=int(data.get("priority", 0) or 0),
            risk=str(data.get("risk") or "read"),
            approval_required=bool(data.get("approval_required")),
            approved=bool(data.get("approved")),
            expected_requests=int(data.get("expected_requests", 0) or 0),
            options=dict(data.get("options") or {}),
            reason=data.get("reason"),
            status=str(data.get("status") or "planned"),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("act")),
        )


@dataclass
class ActionOutcome:
    action_id: str
    verdict: str
    module_path: Optional[str] = None
    phase: str = ""
    duration_ms: float = 0.0
    network_requests: int = 0
    evidence_ids: List[str] = field(default_factory=list)
    message: Optional[str] = None
    raw_summary: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("outcome"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionOutcome":
        data = dict(payload or {})
        return cls(
            action_id=str(data.get("action_id") or ""),
            verdict=str(data.get("verdict") or "no_signal"),
            module_path=data.get("module_path"),
            phase=str(data.get("phase") or ""),
            duration_ms=float(data.get("duration_ms", 0) or 0),
            network_requests=int(data.get("network_requests", 0) or 0),
            evidence_ids=[str(item) for item in (data.get("evidence_ids") or [])],
            message=data.get("message"),
            raw_summary=dict(data.get("raw_summary") or {}),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("outcome")),
        )


@dataclass
class Hypothesis:
    statement: str
    module_path: Optional[str] = None
    capability: Optional[str] = None
    status: str = "open"
    evidence_ids: List[str] = field(default_factory=list)
    fingerprint: str = ""
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("hyp"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Hypothesis":
        data = dict(payload or {})
        return cls(
            statement=str(data.get("statement") or ""),
            module_path=data.get("module_path"),
            capability=data.get("capability"),
            status=str(data.get("status") or "open"),
            evidence_ids=[str(item) for item in (data.get("evidence_ids") or [])],
            fingerprint=str(data.get("fingerprint") or ""),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("hyp")),
        )


@dataclass
class Capability:
    id: str
    name: str
    source_module: Optional[str] = None
    confidence: float = 0.0
    consumed: bool = False
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Capability":
        data = dict(payload or {})
        return cls(
            id=str(data.get("id") or _new_id("cap")),
            name=str(data.get("name") or ""),
            source_module=data.get("source_module"),
            confidence=float(data.get("confidence", 0) or 0),
            consumed=bool(data.get("consumed")),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
        )


@dataclass
class GoalProgress:
    goal: str
    completion_ratio: float = 0.0
    milestones: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "GoalProgress":
        data = dict(payload or {})
        return cls(
            goal=str(data.get("goal") or ""),
            completion_ratio=float(data.get("completion_ratio", 0) or 0),
            milestones=[str(item) for item in (data.get("milestones") or [])],
            blockers=[str(item) for item in (data.get("blockers") or [])],
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
        )


@dataclass
class StopDecision:
    stop: bool
    kind: str = "soft"
    reason: str = ""
    detail: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("stop"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "StopDecision":
        data = dict(payload or {})
        return cls(
            stop=bool(data.get("stop")),
            kind=str(data.get("kind") or "soft"),
            reason=str(data.get("reason") or ""),
            detail=data.get("detail"),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("stop")),
        )


@dataclass
class OptionPatch:
    module_path: str
    options: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)
    expected_effect: Optional[str] = None
    idempotency_key: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("patch"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "OptionPatch":
        data = dict(payload or {})
        return cls(
            module_path=str(data.get("module_path") or ""),
            options=dict(data.get("options") or {}),
            evidence_ids=[str(item) for item in (data.get("evidence_ids") or [])],
            expected_effect=data.get("expected_effect"),
            idempotency_key=data.get("idempotency_key"),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("patch")),
        )


@dataclass
class OptionResolution:
    patch_id: str
    accepted: bool
    merged_options: Dict[str, Any] = field(default_factory=dict)
    rejected_keys: List[str] = field(default_factory=list)
    policy_verdict: str = "pending"
    redacted_diff: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("optres"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "OptionResolution":
        data = dict(payload or {})
        return cls(
            patch_id=str(data.get("patch_id") or ""),
            accepted=bool(data.get("accepted")),
            merged_options=dict(data.get("merged_options") or {}),
            rejected_keys=[str(item) for item in (data.get("rejected_keys") or [])],
            policy_verdict=str(data.get("policy_verdict") or "pending"),
            redacted_diff=dict(data.get("redacted_diff") or {}),
            reason=data.get("reason"),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            id=str(data.get("id") or _new_id("optres")),
        )


@dataclass
class SubAgentTask:
    specialist: str
    objective: str
    budget_requests: int = 0
    depth: int = 0
    parent_task_id: Optional[str] = None
    status: str = "pending"
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("subtask"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SpecialistProposal:
    specialist: str
    action: AgentAction
    confidence: float = 0.0
    rationale: str = ""
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("proposal"))

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["action"] = self.action.to_dict()
        return payload


@dataclass
class SpecialistResult:
    proposal_id: str
    specialist: str
    outcome: ActionOutcome
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("specres"))

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["outcome"] = self.outcome.to_dict()
        return payload


@dataclass
class BlackboardEvent:
    kind: str
    summary: str
    payload: Dict[str, Any] = field(default_factory=dict)
    source: str = "agent"
    created_at: str = field(default_factory=_now_iso)
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=lambda: _new_id("bb"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionLease:
    action_id: str
    reserved_requests: int = 0
    non_idempotent: bool = False
    acquired_at: str = field(default_factory=_now_iso)
    released: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_agent_action(payload: Mapping[str, Any]) -> AgentAction:
    from core.schemas.validation import validate_instance

    validate_instance("agent_action", dict(payload))
    return AgentAction.from_dict(payload)
