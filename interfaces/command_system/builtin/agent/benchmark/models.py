#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed models for agent benchmark results."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.schemas import SCHEMA_VERSION

OUTCOME_VERDICT_KEYS = (
    "module_error",
    "no_signal",
    "refuted",
    "blocked",
    "policy_denied",
    "confirmed",
)


def new_benchmark_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"bench_{timestamp}_{uuid.uuid4().hex[:10]}"


def empty_outcome_verdicts() -> Dict[str, int]:
    return {key: 0 for key in OUTCOME_VERDICT_KEYS}


@dataclass
class OutcomeVerdictCounts:
    module_error: int = 0
    no_signal: int = 0
    refuted: int = 0
    blocked: int = 0
    policy_denied: int = 0
    confirmed: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]]) -> "OutcomeVerdictCounts":
        data = payload if isinstance(payload, dict) else {}
        return cls(**{key: int(data.get(key, 0) or 0) for key in OUTCOME_VERDICT_KEYS})

    def add(self, other: "OutcomeVerdictCounts") -> None:
        for key in OUTCOME_VERDICT_KEYS:
            setattr(self, key, getattr(self, key) + getattr(other, key))


@dataclass
class NorthStarMetrics:
    mission_completion_rate: float = 0.0
    human_interventions_median: float = 0.0
    repeated_actions_without_new_info_rate: float = 0.0
    false_success_rate: float = 0.0
    recovery_after_module_error_rate: float = 0.0
    out_of_scope_actions: int = 0
    reproducibility_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FailureCause:
    cause: str
    count: int
    example_run_id: Optional[str] = None
    example_transition: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkRunResult:
    run_index: int
    run_id: str
    mission_completed: bool
    outcome_verdicts: OutcomeVerdictCounts = field(default_factory=OutcomeVerdictCounts)
    seed: Optional[int] = None
    human_interventions: int = 0
    duration_seconds: float = 0.0
    stop_reason: Optional[str] = None
    report_path: Optional[str] = None
    repeated_actions_without_new_info: int = 0
    false_successes: int = 0
    scope_violations: int = 0
    module_errors_recovered: int = 0
    module_errors_total: int = 0
    evidence_confirmed: bool = False
    session_obtained: bool = False
    failure_transition: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["outcome_verdicts"] = self.outcome_verdicts.to_dict()
        return payload


@dataclass
class AgentBenchmarkResult:
    suite: str
    config: Dict[str, Any]
    north_star: NorthStarMetrics
    outcome_verdicts: OutcomeVerdictCounts
    runs: List[BenchmarkRunResult] = field(default_factory=list)
    failure_causes: List[FailureCause] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    id: str = field(default_factory=new_benchmark_id)
    suite_version: str = "1.0"
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Optional[str] = None
    comparable_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "suite": self.suite,
            "suite_version": self.suite_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "config": dict(self.config),
            "north_star": self.north_star.to_dict(),
            "outcome_verdicts": self.outcome_verdicts.to_dict(),
            "runs": [row.to_dict() for row in self.runs],
            "failure_causes": [row.to_dict() for row in self.failure_causes],
            "comparable_hash": self.comparable_hash,
            "metadata": dict(self.metadata),
        }

    def finalize(self) -> "AgentBenchmarkResult":
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.comparable_hash = compute_comparable_hash(self)
        return self


def compute_comparable_hash(result: AgentBenchmarkResult) -> str:
    """Stable hash over config and per-run mission outcomes for CI regression diffing."""
    payload = {
        "suite": result.suite,
        "suite_version": result.suite_version,
        "config": result.config,
        "runs": [
            {
                "run_index": row.run_index,
                "seed": row.seed,
                "mission_completed": row.mission_completed,
                "stop_reason": row.stop_reason,
                "failure_transition": row.failure_transition,
                "outcome_verdicts": row.outcome_verdicts.to_dict(),
            }
            for row in result.runs
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
