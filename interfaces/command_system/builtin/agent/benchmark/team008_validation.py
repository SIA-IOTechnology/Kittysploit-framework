#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TEAM-008: A/B benchmark mono-agent vs multi-agent (specialists + arbiter + gateway)."""

from __future__ import annotations

import json
import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.action_catalog import build_admissible_catalog
from interfaces.command_system.builtin.agent.benchmark.phase3_validation import (
    PlannerScenario,
    score_selected_path,
    wilson_ci,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested


MCR_DELTA_THRESHOLD = 0.10
USELESS_REDUCTION_THRESHOLD = 0.20
MCR_REGRESSION_EPSILON = 0.0
DEFAULT_RUNS = 32
DEFAULT_SEED = 42
SYNTHETIC_MS_PER_REQUEST = 12.0
ARTIFACT_LATEST = Path("artifacts/benchmarks") / "team008_validation_latest.json"


@dataclass
class ArmDecisionResult:
    scenario: str
    arm: str
    selected_path: Optional[str]
    success: bool
    useless: bool
    estimated_cost: float = 0.0
    latency_ms: float = 0.0
    source: str = ""
    fallback_to_mono: bool = False
    scope_violation: bool = False
    false_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "scenario": self.scenario,
            "arm": self.arm,
            "selected_path": self.selected_path,
            "success": self.success,
            "useless": self.useless,
            "estimated_cost": round(self.estimated_cost, 4),
            "latency_ms": round(self.latency_ms, 2),
            "source": self.source,
            "fallback_to_mono": self.fallback_to_mono,
            "scope_violation": self.scope_violation,
            "false_success": self.false_success,
        })


@dataclass
class Team008ValidationReport:
    schema_version: str = "1.0"
    validated_at: str = ""
    passed: bool = False
    mono_mcr: float = 0.0
    multi_mcr: float = 0.0
    mcr_delta: float = 0.0
    mcr_delta_threshold: float = MCR_DELTA_THRESHOLD
    mono_mcr_ci: Tuple[float, float] = (0.0, 0.0)
    multi_mcr_ci: Tuple[float, float] = (0.0, 0.0)
    mono_useless_action_rate: float = 0.0
    multi_useless_action_rate: float = 0.0
    useless_reduction: float = 0.0
    useless_reduction_threshold: float = USELESS_REDUCTION_THRESHOLD
    mono_estimated_cost: float = 0.0
    multi_estimated_cost: float = 0.0
    mono_p95_latency_ms: float = 0.0
    multi_p95_latency_ms: float = 0.0
    fallback_to_mono_rate: float = 0.0
    micro_benchmark: Dict[str, Any] = field(default_factory=dict)
    integration_benchmark: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    output_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "validated_at": self.validated_at,
            "passed": self.passed,
            "mono_mcr": round(self.mono_mcr, 4),
            "multi_mcr": round(self.multi_mcr, 4),
            "mcr_delta": round(self.mcr_delta, 4),
            "mcr_delta_threshold": self.mcr_delta_threshold,
            "mono_mcr_ci": [round(self.mono_mcr_ci[0], 4), round(self.mono_mcr_ci[1], 4)],
            "multi_mcr_ci": [round(self.multi_mcr_ci[0], 4), round(self.multi_mcr_ci[1], 4)],
            "mono_useless_action_rate": round(self.mono_useless_action_rate, 4),
            "multi_useless_action_rate": round(self.multi_useless_action_rate, 4),
            "useless_reduction": round(self.useless_reduction, 4),
            "useless_reduction_threshold": self.useless_reduction_threshold,
            "mono_estimated_cost": round(self.mono_estimated_cost, 4),
            "multi_estimated_cost": round(self.multi_estimated_cost, 4),
            "mono_p95_latency_ms": round(self.mono_p95_latency_ms, 2),
            "multi_p95_latency_ms": round(self.multi_p95_latency_ms, 2),
            "fallback_to_mono_rate": round(self.fallback_to_mono_rate, 4),
            "micro_benchmark": self.micro_benchmark,
            "integration_benchmark": self.integration_benchmark,
            "safety": self.safety,
            "notes": self.notes,
            "output_path": self.output_path or None,
        })


def default_team008_scenarios() -> List[PlannerScenario]:
    """Micro oracles stressing multi-agent gains without live labs."""
    return [
        PlannerScenario(
            name="premature_exploit",
            phase="exploit",
            goal="obtain-shell",
            kb={
                "campaign_goal": "obtain-shell",
                "tech_hints": ["linux", "ssh"],
                "risk_signals": ["ssh"],
                "capabilities": [{"capability": "service_identified", "status": "confirmed"}],
            },
            modules=[
                {"path": "auxiliary/scanner/ssh/enum", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/ssh/example", "risk": "intrusive", "expected_requests": 4},
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
            ],
            oracle_paths=("auxiliary/scanner/ssh/enum",),
            oracle_capabilities=("service_identified",),
        ),
        PlannerScenario(
            name="multi_service_parallel_recon",
            phase="scan",
            goal="recon",
            kb={
                "campaign_goal": "recon",
                "tech_hints": ["http", "ssh"],
                "risk_signals": ["http", "ssh"],
                "identified_services": ["http:80", "ssh:22"],
            },
            modules=[
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/ssh/enum", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/portscan/tcp", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/http/example", "risk": "intrusive", "expected_requests": 8},
            ],
            oracle_paths=(
                "auxiliary/scanner/http/crawler",
                "auxiliary/scanner/ssh/enum",
                "auxiliary/scanner/portscan/tcp",
            ),
            oracle_capabilities=("service_identified",),
        ),
        PlannerScenario(
            name="conflicting_proposals",
            phase="analyze",
            goal="validate",
            kb={
                "campaign_goal": "validate",
                "tech_hints": ["php", "ssh"],
                "risk_signals": ["sqli", "ssh"],
                "identified_services": ["http:80", "ssh:22"],
            },
            modules=[
                {"path": "auxiliary/scanner/http/sqli_probe", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/ssh/enum", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/http/sqli_example", "risk": "intrusive", "expected_requests": 6},
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 3},
            ],
            oracle_paths=("auxiliary/scanner/http/sqli_probe",),
            oracle_capabilities=("primitive_confirmed",),
        ),
        PlannerScenario(
            name="specialist_crash_fallback",
            phase="scan",
            goal="recon",
            kb={
                "campaign_goal": "recon",
                "tech_hints": ["http", "ssh"],
                "risk_signals": ["http", "ssh"],
                "identified_services": ["http:80", "ssh:22"],
                "team008_inject_specialist_crash": True,
            },
            modules=[
                {"path": "auxiliary/scanner/ssh/enum", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/portscan/tcp", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/http/example", "risk": "intrusive", "expected_requests": 8},
            ],
            oracle_paths=(
                "auxiliary/scanner/ssh/enum",
                "auxiliary/scanner/http/crawler",
                "auxiliary/scanner/portscan/tcp",
            ),
            oracle_capabilities=("service_identified",),
        ),
    ]


def _catalog_map(catalog: Sequence[Any]) -> Dict[str, Any]:
    return {str(row.module_path): row for row in catalog}


def _module_cost(path: Optional[str], catalog_map: Mapping[str, Any], modules: Sequence[Mapping[str, Any]]) -> float:
    token = str(path or "").strip()
    if not token:
        return 0.0
    row = catalog_map.get(token)
    if row is not None:
        return float(getattr(row, "expected_requests", 0) or 0)
    for module in modules:
        if str(module.get("path") or "").strip() == token:
            return float(module.get("expected_requests") or 1)
    return 1.0


def _is_useless(selected_path: Optional[str], *, oracle_paths: Sequence[str], success: bool) -> bool:
    """Approximate useless actions: off-oracle / premature exploit without new info."""
    if not success:
        return True
    path = str(selected_path or "").strip()
    if not path:
        return True
    oracle_set = {str(item).strip() for item in oracle_paths if str(item).strip()}
    if path not in oracle_set and path.startswith("exploits/"):
        return True
    return False


def _p95(values: Sequence[float]) -> float:
    rows = [float(v) for v in values if v is not None]
    if not rows:
        return 0.0
    if len(rows) == 1:
        return rows[0]
    try:
        return float(statistics.quantiles(rows, n=20)[18])
    except statistics.StatisticsError:
        rows_sorted = sorted(rows)
        idx = max(0, min(len(rows_sorted) - 1, int(round(0.95 * (len(rows_sorted) - 1)))))
        return float(rows_sorted[idx])


def _allowed_paths(modules: Sequence[Mapping[str, Any]]) -> set[str]:
    return {str(row.get("path") or "").strip() for row in modules if str(row.get("path") or "").strip()}


def run_mono_decision(scenario: PlannerScenario, services: Any) -> ArmDecisionResult:
    """Mono arm: pure heuristic catalog ranking (no specialist fan-out, no gateway)."""
    from interfaces.command_system.builtin.agent.model_router import build_heuristic_tactical_plan

    started = time.monotonic()
    catalog = build_admissible_catalog(
        modules=scenario.modules,
        kb=scenario.kb,
        goal=scenario.goal,
    )
    cmap = _catalog_map(catalog)
    tactical = build_heuristic_tactical_plan(catalog)
    selected = tactical.selected_action.path if tactical.selected_action else None
    success = score_selected_path(
        selected,
        oracle_paths=scenario.oracle_paths,
        oracle_capabilities=scenario.oracle_capabilities,
        catalog_map=cmap,
    )
    cost = _module_cost(selected, cmap, scenario.modules)
    latency = max(
        (time.monotonic() - started) * 1000.0,
        cost * SYNTHETIC_MS_PER_REQUEST,
    )
    allowed = _allowed_paths(scenario.modules)
    scope_violation = bool(selected) and selected not in allowed
    false_success = bool(success) and (not selected or scope_violation)
    return ArmDecisionResult(
        scenario=scenario.name,
        arm="mono",
        selected_path=selected,
        success=success and not false_success,
        useless=_is_useless(selected, oracle_paths=scenario.oracle_paths, success=success),
        estimated_cost=cost,
        latency_ms=latency,
        source=getattr(tactical, "source", "heuristic") or "heuristic",
        fallback_to_mono=False,
        scope_violation=scope_violation,
        false_success=false_success,
    )


def run_multi_decision(
    scenario: PlannerScenario,
    services: Any,
    *,
    mode: str = "sequential",
) -> ArmDecisionResult:
    """Multi arm: specialists (seq/parallel) + arbiter + PolicyGateway via hierarchical engine."""
    from interfaces.command_system.builtin.agent.hierarchical_planner import HierarchicalPlannerEngine
    import interfaces.command_system.builtin.agent.specialist_runner as specialist_runner

    inject_crash = bool(scenario.kb.get("team008_inject_specialist_crash"))
    original_propose = specialist_runner.propose_for_specialist

    def _crash_propose(*_args: Any, **_kwargs: Any):
        raise RuntimeError("team008_injected_specialist_crash")

    if inject_crash:
        specialist_runner.propose_for_specialist = _crash_propose  # type: ignore[assignment]

    started = time.monotonic()
    try:
        state = SimpleNamespace(
            campaign_goal=scenario.goal,
            current_phase=scenario.phase,
            knowledge_base=dict(scenario.kb),
            executed_actions=[],
            runtime_policy=None,
            hierarchical_planner_enabled=True,
            adaptive_loop_enabled=True,
            replan_count=0,
            heuristic_planner_only=True,
            specialist_sequential_enabled=(mode == "sequential"),
            specialist_parallel_enabled=(mode == "parallel"),
            specialist_runs=[],
            specialist_resilience_reports=[],
            specialist_fallback_reason="",
        )
        observation = {
            "phase": scenario.phase,
            "goal": scenario.goal,
            "knowledge_base": scenario.kb,
            "catalog_modules": scenario.modules,
        }
        engine = HierarchicalPlannerEngine(services)
        tactical = engine.plan_shadow_cycle(state, observation, mutate_state=False)
        selected = tactical.selected_action.path if tactical.selected_action else None
        catalog = build_admissible_catalog(
            modules=scenario.modules,
            kb=scenario.kb,
            goal=scenario.goal,
        )
        cmap = _catalog_map(catalog)
        success = score_selected_path(
            selected,
            oracle_paths=scenario.oracle_paths,
            oracle_capabilities=scenario.oracle_capabilities,
            catalog_map=cmap,
        )
        cost = _module_cost(selected, cmap, scenario.modules)
        specialist_ms = 0.0
        for run in getattr(state, "specialist_runs", []) or []:
            if not isinstance(run, dict):
                continue
            for record in run.get("records") or []:
                if isinstance(record, dict):
                    specialist_ms += float(record.get("duration_ms") or 0.0)
        wall_ms = (time.monotonic() - started) * 1000.0
        latency = max(wall_ms, specialist_ms, cost * SYNTHETIC_MS_PER_REQUEST)
        fallback = bool(getattr(state, "specialist_fallback_reason", "") or "")
        if not fallback:
            for report in getattr(state, "specialist_resilience_reports", []) or []:
                if isinstance(report, dict):
                    merge = report.get("merge") if isinstance(report.get("merge"), dict) else {}
                    if merge.get("fallback_to_heuristic"):
                        fallback = True
                        break
        allowed = _allowed_paths(scenario.modules)
        scope_violation = bool(selected) and selected not in allowed
        false_success = bool(success) and (not selected or scope_violation)
        return ArmDecisionResult(
            scenario=scenario.name,
            arm="multi",
            selected_path=selected,
            success=success and not false_success,
            useless=_is_useless(selected, oracle_paths=scenario.oracle_paths, success=success),
            estimated_cost=cost,
            latency_ms=latency,
            source=getattr(tactical, "source", "") or "",
            fallback_to_mono=fallback,
            scope_violation=scope_violation,
            false_success=false_success,
        )
    finally:
        if inject_crash:
            specialist_runner.propose_for_specialist = original_propose


def _multi_mode_for_scenario(scenario: PlannerScenario) -> str:
    if scenario.name.startswith("multi_service_parallel_recon"):
        return "parallel"
    return "sequential"


def run_ab_micro_benchmark(
    services: Any,
    *,
    scenarios: Optional[Sequence[PlannerScenario]] = None,
    runs: int = DEFAULT_RUNS,
    seed: int = DEFAULT_SEED,
) -> Dict[str, Any]:
    base = list(scenarios or default_team008_scenarios())
    if not base:
        return {
            "mono_mcr": 0.0,
            "multi_mcr": 0.0,
            "runs": [],
        }

    mono_results: List[ArmDecisionResult] = []
    multi_results: List[ArmDecisionResult] = []
    rng = random.Random(int(seed))
    total = max(1, int(runs or 1))

    for index in range(total):
        scenario = base[index % len(base)]
        modules = list(scenario.modules)
        rng.shuffle(modules)
        perturbed = PlannerScenario(
            name=f"{scenario.name}:{index}",
            phase=scenario.phase,
            goal=scenario.goal,
            kb=dict(scenario.kb),
            modules=modules,
            oracle_paths=scenario.oracle_paths,
            oracle_capabilities=scenario.oracle_capabilities,
        )
        mono_results.append(run_mono_decision(perturbed, services))
        multi_results.append(
            run_multi_decision(perturbed, services, mode=_multi_mode_for_scenario(scenario))
        )

    mono_ok = sum(1 for row in mono_results if row.success)
    multi_ok = sum(1 for row in multi_results if row.success)
    mono_useless = sum(1 for row in mono_results if row.useless)
    multi_useless = sum(1 for row in multi_results if row.useless)
    mono_cost = sum(row.estimated_cost for row in mono_results) / total
    multi_cost = sum(row.estimated_cost for row in multi_results) / total
    fallbacks = sum(1 for row in multi_results if row.fallback_to_mono)
    mono_scope = sum(1 for row in mono_results if row.scope_violation)
    multi_scope = sum(1 for row in multi_results if row.scope_violation)
    mono_false = sum(1 for row in mono_results if row.false_success)
    multi_false = sum(1 for row in multi_results if row.false_success)

    mono_useless_rate = mono_useless / total
    multi_useless_rate = multi_useless / total
    if mono_useless_rate <= 0:
        useless_reduction = 0.0 if multi_useless_rate <= 0 else 0.0
    else:
        useless_reduction = (mono_useless_rate - multi_useless_rate) / mono_useless_rate

    return sanitize_nested({
        "scenario_count": len(base),
        "runs_per_arm": total,
        "seed": int(seed),
        "mono_mcr": mono_ok / total,
        "multi_mcr": multi_ok / total,
        "mono_mcr_ci": list(wilson_ci(mono_ok, total)),
        "multi_mcr_ci": list(wilson_ci(multi_ok, total)),
        "mono_useless_action_rate": mono_useless_rate,
        "multi_useless_action_rate": multi_useless_rate,
        "useless_reduction": useless_reduction,
        "mono_estimated_cost": mono_cost,
        "multi_estimated_cost": multi_cost,
        "mono_p95_latency_ms": _p95([row.latency_ms for row in mono_results]),
        "multi_p95_latency_ms": _p95([row.latency_ms for row in multi_results]),
        "fallback_to_mono_rate": fallbacks / total,
        "mono_scope_violations": mono_scope,
        "multi_scope_violations": multi_scope,
        "mono_false_successes": mono_false,
        "multi_false_successes": multi_false,
        "mono_failures": [row.to_dict() for row in mono_results if not row.success][:8],
        "multi_failures": [row.to_dict() for row in multi_results if not row.success][:8],
    })


def _evaluate_pass(report: Team008ValidationReport) -> None:
    safety_ok = (
        int(report.safety.get("mono_scope_violations", 0) or 0) == 0
        and int(report.safety.get("multi_scope_violations", 0) or 0) == 0
        and int(report.safety.get("mono_false_successes", 0) or 0) == 0
        and int(report.safety.get("multi_false_successes", 0) or 0) == 0
    )
    no_mcr_regression = report.multi_mcr + 1e-12 >= report.mono_mcr - MCR_REGRESSION_EPSILON
    mcr_gain = report.mcr_delta >= MCR_DELTA_THRESHOLD
    useless_gain = report.useless_reduction >= USELESS_REDUCTION_THRESHOLD
    report.passed = bool(safety_ok and no_mcr_regression and (mcr_gain or useless_gain))

    if not safety_ok:
        report.notes.append("Safety failure: scope violations or false successes must be zero on both arms.")
    if not no_mcr_regression:
        report.notes.append(
            f"MCR regression: multi {report.multi_mcr:.1%} < mono {report.mono_mcr:.1%}."
        )
    if not mcr_gain and not useless_gain:
        report.notes.append(
            f"Neither +{MCR_DELTA_THRESHOLD:.0%} MCR nor "
            f"{USELESS_REDUCTION_THRESHOLD:.0%} useless-action reduction achieved "
            f"(delta={report.mcr_delta:.1%}, useless_reduction={report.useless_reduction:.1%})."
        )
    if report.passed:
        if mcr_gain:
            report.notes.append(
                f"Multi-agent MCR gain +{report.mcr_delta:.0%} meets +{MCR_DELTA_THRESHOLD:.0%} threshold."
            )
        if useless_gain:
            report.notes.append(
                f"Useless-action reduction {report.useless_reduction:.0%} meets "
                f"{USELESS_REDUCTION_THRESHOLD:.0%} threshold."
            )


def run_team008_validation(
    runs: int = DEFAULT_RUNS,
    seed: int = DEFAULT_SEED,
    skip_integration: bool = True,
    *,
    output_path: Optional[str] = None,
    framework: Any = None,
    services: Any = None,
) -> Team008ValidationReport:
    """Run TEAM-008 mono vs multi A/B validation and write the latest JSON report."""
    from datetime import datetime, timezone

    if services is None:
        if framework is not None:
            from interfaces.command_system.builtin.agent.facades import AgentServices

            services = AgentServices(framework)
        else:
            services = SimpleNamespace()

    report = Team008ValidationReport(validated_at=datetime.now(timezone.utc).isoformat())
    micro = run_ab_micro_benchmark(services, runs=runs, seed=seed)
    report.micro_benchmark = micro

    integration: Dict[str, Any] = {"skipped": bool(skip_integration)}
    report.integration_benchmark = integration
    if not skip_integration:
        report.notes.append("Integration A/B live suite not implemented; micro oracles are authoritative.")
        integration["skipped"] = True

    report.mono_mcr = float(micro.get("mono_mcr") or 0.0)
    report.multi_mcr = float(micro.get("multi_mcr") or 0.0)
    report.mcr_delta = report.multi_mcr - report.mono_mcr
    report.mono_mcr_ci = tuple(micro.get("mono_mcr_ci") or (0.0, 0.0))
    report.multi_mcr_ci = tuple(micro.get("multi_mcr_ci") or (0.0, 0.0))
    report.mono_useless_action_rate = float(micro.get("mono_useless_action_rate") or 0.0)
    report.multi_useless_action_rate = float(micro.get("multi_useless_action_rate") or 0.0)
    report.useless_reduction = float(micro.get("useless_reduction") or 0.0)
    report.mono_estimated_cost = float(micro.get("mono_estimated_cost") or 0.0)
    report.multi_estimated_cost = float(micro.get("multi_estimated_cost") or 0.0)
    report.mono_p95_latency_ms = float(micro.get("mono_p95_latency_ms") or 0.0)
    report.multi_p95_latency_ms = float(micro.get("multi_p95_latency_ms") or 0.0)
    report.fallback_to_mono_rate = float(micro.get("fallback_to_mono_rate") or 0.0)
    report.safety = sanitize_nested({
        "mono_scope_violations": int(micro.get("mono_scope_violations") or 0),
        "multi_scope_violations": int(micro.get("multi_scope_violations") or 0),
        "mono_false_successes": int(micro.get("mono_false_successes") or 0),
        "multi_false_successes": int(micro.get("multi_false_successes") or 0),
    })
    report.notes.append("Primary score from mono (heuristic) vs multi (specialists+arbiter+gateway) micro oracles.")

    _evaluate_pass(report)

    target = Path(output_path).expanduser() if output_path else ARTIFACT_LATEST
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict()
    payload["output_path"] = str(target)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    report.output_path = str(target)
    return report


class Team008ValidationService:
    """CLI-facing wrapper around TEAM-008 A/B validation."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def validate(
        self,
        *,
        runs: int = DEFAULT_RUNS,
        seed: int = DEFAULT_SEED,
        skip_integration: bool = True,
        output_path: Optional[str] = None,
    ) -> Team008ValidationReport:
        return run_team008_validation(
            runs=runs,
            seed=seed,
            skip_integration=skip_integration,
            output_path=output_path,
            framework=self.framework,
        )
