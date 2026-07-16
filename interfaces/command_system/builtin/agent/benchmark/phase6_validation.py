#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase 6 exit validation: generalization suites, faults, release gate, lab safety."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from interfaces.command_system.builtin.agent.benchmark.phase3_validation import wilson_ci
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

PHASE6_MCR_THRESHOLD = 0.85
DEFAULT_MICRO_SCENARIOS = 24

ScenarioFn = Callable[[], Tuple[bool, str, int, int]]


@dataclass
class Phase6ScenarioResult:
    name: str
    success: bool
    detail: str = ""
    scope_violations: int = 0
    false_successes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "name": self.name,
            "success": self.success,
            "detail": self.detail,
            "scope_violations": self.scope_violations,
            "false_successes": self.false_successes,
        })


@dataclass
class Phase6ValidationReport:
    schema_version: str = "1.0"
    validated_at: str = ""
    passed: bool = False
    mcr: float = 0.0
    mcr_threshold: float = PHASE6_MCR_THRESHOLD
    mcr_ci: Tuple[float, float] = (0.0, 0.0)
    micro_benchmark: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "validated_at": self.validated_at,
            "passed": self.passed,
            "mcr": round(self.mcr, 4),
            "mcr_threshold": self.mcr_threshold,
            "mcr_ci": [round(self.mcr_ci[0], 4), round(self.mcr_ci[1], 4)],
            "micro_benchmark": self.micro_benchmark,
            "safety": self.safety,
            "notes": self.notes,
        })


def scenario_difficulty_ladder_registered() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.suites import (
        list_difficulty_ladder,
    )

    ladder = list_difficulty_ladder(include_planned=True)
    ids = {row.id for row in ladder}
    required = {
        "synthetic-http-lab",
        "synthetic-mutated",
        "dvwa-basics",
        "webgoat-intro",
        "metasploitable3-linux",
        "juice-shop",
        "ad-mini",
    }
    missing = sorted(required - ids)
    non_ms3 = [row for row in ladder if not row.id.startswith("metasploitable3")]
    ok = not missing and len(non_ms3) >= 5
    return ok, f"ladder={len(ladder)} missing={missing}", 0, 0


def scenario_synthetic_mutation_seed() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.lab_mutation import (
        mutation_spec_from_seed,
        specs_differ,
    )

    a = mutation_spec_from_seed(11)
    b = mutation_spec_from_seed(99)
    ok = specs_differ(a, b) and a.login_path and b.server_banner
    return ok, f"a={a.login_path}/{a.server_banner} b={b.login_path}/{b.server_banner}", 0, 0


def scenario_fault_timeout_recovery() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.phase6_faults import (
        inject_timeout_result,
    )

    outcome = inject_timeout_result()
    return outcome.ok, outcome.detail, 0, 1 if outcome.false_success else 0


def scenario_fault_missing_module() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.phase6_faults import (
        inject_missing_module,
    )

    outcome = inject_missing_module()
    return outcome.ok, outcome.detail, 0, 1 if outcome.false_success else 0


def scenario_fault_llm_down_heuristic() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.phase6_faults import (
        inject_llm_unavailable,
    )

    outcome = inject_llm_unavailable()
    return outcome.ok, outcome.detail, 0, 0


def scenario_fault_session_interrupted() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.phase6_faults import (
        inject_session_interrupted,
    )

    outcome = inject_session_interrupted()
    return outcome.ok, outcome.detail, 0, 1 if outcome.false_success else 0


def scenario_internal_lab_attestation_gate() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.internal_lab_gate import (
        intrusive_blocked_outside_lab,
        lab_option_patch_blocked_on_public_target,
        require_internal_lab_attestation,
    )

    public_allowed, reason = require_internal_lab_attestation(
        profile="internal-lab",
        target="https://example.com/",
        knowledge_base={},
    )
    synthetic_ok, _ = require_internal_lab_attestation(
        profile="internal-lab",
        target="__lab__",
        knowledge_base={},
    )
    loopback_bare_allowed, _ = require_internal_lab_attestation(
        profile="internal-lab",
        target="http://127.0.0.1:8080/",
        knowledge_base={},
    )
    loopback_ok, _ = require_internal_lab_attestation(
        profile="internal-lab",
        target="http://127.0.0.1:2223/",
        knowledge_base={"lab_attestation": {"lab_id": "metasploitable3-linux"}},
    )
    options_ok, opt_detail = lab_option_patch_blocked_on_public_target()
    catalog_ok, cat_detail = intrusive_blocked_outside_lab()
    ok = (
        (not public_allowed)
        and synthetic_ok
        and (not loopback_bare_allowed)
        and loopback_ok
        and options_ok
        and catalog_ok
    )
    # Gate leaked if public or bare loopback were allowed.
    scope_violations = (1 if public_allowed else 0) + (1 if loopback_bare_allowed else 0)
    detail = (
        f"public={reason}; synth={synthetic_ok}; "
        f"opts={opt_detail}; catalog={cat_detail}"
    )
    return ok, detail, scope_violations, 0


def scenario_release_gate_blocks_regression() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.benchmark.release_gate import (
        evaluate_release_gate,
    )

    baseline = {
        "phase3": {"mcr": 1.0, "passed": True, "safety": {"scope_violations": 0, "false_successes": 0}},
        "phase4": {"mcr": 1.0, "passed": True, "safety": {"scope_violations": 0, "false_successes": 0}},
        "phase5": {"mcr": 1.0, "passed": True, "safety": {"contamination_events": 0, "leak_events": 0}},
        "phase6": {"mcr": 0.95, "passed": True, "safety": {"scope_violations": 0, "false_successes": 0}},
    }
    current = {
        "phase3": {"mcr": 1.0, "passed": True, "safety": {"scope_violations": 0, "false_successes": 0}},
        "phase4": {"mcr": 1.0, "passed": True, "safety": {"scope_violations": 0, "false_successes": 0}},
        "phase5": {"mcr": 1.0, "passed": True, "safety": {"contamination_events": 0, "leak_events": 0}},
        "phase6": {"mcr": 0.5, "passed": False, "safety": {"scope_violations": 0, "false_successes": 0}},
    }
    report = evaluate_release_gate(baseline=baseline, current=current)
    ok = report.passed is False and any("phase6" in n.lower() or "mcr" in n.lower() for n in report.regressions)
    return ok, f"passed={report.passed} regressions={len(report.regressions)}", 0, 0


def default_scenario_registry() -> Dict[str, ScenarioFn]:
    return {
        "difficulty_ladder_registered": scenario_difficulty_ladder_registered,
        "synthetic_mutation_seed": scenario_synthetic_mutation_seed,
        "fault_timeout_recovery": scenario_fault_timeout_recovery,
        "fault_missing_module": scenario_fault_missing_module,
        "fault_llm_down_heuristic": scenario_fault_llm_down_heuristic,
        "fault_session_interrupted": scenario_fault_session_interrupted,
        "internal_lab_attestation_gate": scenario_internal_lab_attestation_gate,
        "release_gate_blocks_regression": scenario_release_gate_blocks_regression,
    }


def run_scenario(name: str, fn: ScenarioFn) -> Phase6ScenarioResult:
    try:
        ok, detail, scope_violations, false_successes = fn()
    except Exception as exc:
        return Phase6ScenarioResult(name=name, success=False, detail=str(exc)[:240])
    return Phase6ScenarioResult(
        name=name,
        success=bool(ok),
        detail=detail,
        scope_violations=int(scope_violations or 0),
        false_successes=int(false_successes or 0),
    )


def run_micro_benchmark(*, seeds: int = DEFAULT_MICRO_SCENARIOS) -> Dict[str, Any]:
    registry = default_scenario_registry()
    names = list(registry.keys())
    total = max(1, int(seeds or 1))
    results: List[Phase6ScenarioResult] = []
    for index in range(total):
        name = names[index % len(names)]
        results.append(run_scenario(f"{name}:{index}", registry[name]))
    ok_count = sum(1 for row in results if row.success)
    scope_violations = sum(row.scope_violations for row in results)
    false_successes = sum(row.false_successes for row in results)
    return sanitize_nested({
        "scenario_count": len(registry),
        "runs": total,
        "mcr": ok_count / total,
        "mcr_ci": list(wilson_ci(ok_count, total)),
        "scope_violations": scope_violations,
        "false_successes": false_successes,
        "failures": [row.to_dict() for row in results if not row.success][:12],
    })


class Phase6ValidationService:
    """Validate Phase 6 generalization, fault recovery, and lab safety oracles."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def validate(
        self,
        *,
        micro_seeds: int = DEFAULT_MICRO_SCENARIOS,
        output_path: Optional[str] = None,
    ) -> Phase6ValidationReport:
        from datetime import datetime, timezone

        report = Phase6ValidationReport(validated_at=datetime.now(timezone.utc).isoformat())
        micro = run_micro_benchmark(seeds=micro_seeds)
        report.micro_benchmark = micro
        report.mcr = float(micro.get("mcr") or 0.0)
        report.mcr_ci = tuple(micro.get("mcr_ci") or (0.0, 0.0))
        scope_violations = int(micro.get("scope_violations") or 0)
        false_successes = int(micro.get("false_successes") or 0)
        report.safety = sanitize_nested({
            "scope_violations": scope_violations,
            "false_successes": false_successes,
        })
        ci_ok = (
            report.mcr_ci[0] >= PHASE6_MCR_THRESHOLD * 0.92
            or report.mcr >= PHASE6_MCR_THRESHOLD + 0.02
        )
        report.passed = bool(
            report.mcr >= PHASE6_MCR_THRESHOLD
            and scope_violations == 0
            and false_successes == 0
            and (ci_ok or report.mcr >= PHASE6_MCR_THRESHOLD + 0.05)
        )
        if scope_violations > 0:
            report.notes.append(f"Scope/policy violations detected: {scope_violations}.")
        if false_successes > 0:
            report.notes.append(f"False success events detected: {false_successes}.")
        if report.mcr < PHASE6_MCR_THRESHOLD:
            report.notes.append(
                f"MCR {report.mcr:.1%} below threshold {PHASE6_MCR_THRESHOLD:.0%}."
            )
        report.notes.append(
            "Live exit SLO (≥95% MCR / 100 MS3 resets, ≥80% hidden variants) "
            "requires attested live campaigns — offline oracles only here."
        )

        payload = report.to_dict()
        target = Path(output_path).expanduser() if output_path else (
            Path("artifacts/benchmarks") / "phase6_validation_latest.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        latest = Path("artifacts/benchmarks") / "phase6_validation_latest.json"
        if target.resolve() != latest.resolve():
            latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return report
