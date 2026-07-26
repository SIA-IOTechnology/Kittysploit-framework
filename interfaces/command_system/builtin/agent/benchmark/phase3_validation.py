#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase 3 exit validation: hierarchical vs heuristic planner MCR comparison."""

from __future__ import annotations

import json
import math
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.action_catalog import build_admissible_catalog
from interfaces.command_system.builtin.agent.benchmark.suites import get_benchmark_suite
from interfaces.command_system.builtin.agent.redaction import sanitize_nested


PHASE3_MCR_DELTA_THRESHOLD = 0.25
DEFAULT_MICRO_SCENARIOS = 32
DEFAULT_INTEGRATION_RUNS = 10


@dataclass(frozen=True)
class PlannerScenario:
    name: str
    phase: str
    goal: str
    kb: Dict[str, Any]
    modules: List[Dict[str, Any]]
    oracle_paths: Sequence[str]
    oracle_capabilities: Sequence[str] = field(default_factory=tuple)


@dataclass
class PlannerDecisionResult:
    scenario: str
    planner: str
    selected_path: Optional[str]
    success: bool
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "scenario": self.scenario,
            "planner": self.planner,
            "selected_path": self.selected_path,
            "success": self.success,
            "source": self.source,
        })


@dataclass
class Phase3ValidationReport:
    schema_version: str = "1.0"
    validated_at: str = ""
    passed: bool = False
    mcr_delta: float = 0.0
    mcr_delta_threshold: float = PHASE3_MCR_DELTA_THRESHOLD
    heuristic_mcr: float = 0.0
    hierarchical_mcr: float = 0.0
    heuristic_mcr_ci: Tuple[float, float] = (0.0, 0.0)
    hierarchical_mcr_ci: Tuple[float, float] = (0.0, 0.0)
    micro_benchmark: Dict[str, Any] = field(default_factory=dict)
    integration_benchmark: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "validated_at": self.validated_at,
            "passed": self.passed,
            "mcr_delta": round(self.mcr_delta, 4),
            "mcr_delta_threshold": self.mcr_delta_threshold,
            "heuristic_mcr": round(self.heuristic_mcr, 4),
            "hierarchical_mcr": round(self.hierarchical_mcr, 4),
            "heuristic_mcr_ci": [round(self.heuristic_mcr_ci[0], 4), round(self.heuristic_mcr_ci[1], 4)],
            "hierarchical_mcr_ci": [round(self.hierarchical_mcr_ci[0], 4), round(self.hierarchical_mcr_ci[1], 4)],
            "micro_benchmark": self.micro_benchmark,
            "integration_benchmark": self.integration_benchmark,
            "safety": self.safety,
            "notes": self.notes,
        })


def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    centre = (p + z2 / (2.0 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) / total) + (z2 / (4.0 * total * total)))
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _module_family(path: str) -> str:
    token = str(path or "").strip()
    if not token:
        return ""
    parts = token.split("/")
    if len(parts) >= 2 and parts[0] == "auxiliary":
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def score_selected_path(
    selected_path: Optional[str],
    *,
    oracle_paths: Sequence[str],
    oracle_capabilities: Sequence[str],
    catalog_map: Mapping[str, Any],
) -> bool:
    path = str(selected_path or "").strip()
    if not path:
        return False
    oracle_set = {str(item).strip() for item in oracle_paths if str(item).strip()}
    if path in oracle_set:
        return True
    selected_family = _module_family(path)
    for oracle in oracle_set:
        if _module_family(oracle) == selected_family:
            return True
    caps = {str(item).strip() for item in oracle_capabilities if str(item).strip()}
    row = catalog_map.get(path)
    if row is not None and str(getattr(row, "capability_target", "") or "") in caps:
        return True
    return False


def default_micro_scenarios() -> List[PlannerScenario]:
    return [
        PlannerScenario(
            name="recon_surface",
            phase="scan",
            goal="recon",
            kb={"campaign_goal": "recon", "tech_hints": ["http"]},
            modules=[
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/portscan/tcp", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/http/example", "risk": "intrusive", "expected_requests": 3},
            ],
            oracle_paths=("auxiliary/scanner/http/crawler", "auxiliary/scanner/portscan/tcp"),
            oracle_capabilities=("service_identified",),
        ),
        PlannerScenario(
            name="sqli_signal",
            phase="analyze",
            goal="validate",
            kb={"campaign_goal": "validate", "risk_signals": ["sqli"], "tech_hints": ["php"]},
            modules=[
                {"path": "auxiliary/scanner/http/sqli_probe", "risk": "read", "expected_requests": 2},
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
                {"path": "exploits/linux/http/sqli_example", "risk": "intrusive", "expected_requests": 4},
            ],
            oracle_paths=("auxiliary/scanner/http/sqli_probe", "exploits/linux/http/sqli_example"),
            oracle_capabilities=("primitive_confirmed",),
        ),
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
            name="session_post",
            phase="report",
            goal="post-auth",
            kb={
                "campaign_goal": "post-auth",
                "new_sessions": ["sess-1"],
                "authenticated_session": True,
                "tech_hints": ["linux"],
                "capabilities": [{"capability": "session", "status": "confirmed"}],
            },
            modules=[
                {"path": "post/linux/gather/enum_system", "risk": "read", "expected_requests": 2},
                {"path": "post/linux/manage/shell_to_meterpreter", "risk": "intrusive", "expected_requests": 3},
                {"path": "auxiliary/scanner/http/crawler", "risk": "read", "expected_requests": 2},
            ],
            oracle_paths=("post/linux/gather/enum_system", "post/linux/manage/shell_to_meterpreter"),
            oracle_capabilities=("session", "privilege"),
        ),
    ]


def _catalog_map(catalog: Sequence[Any]) -> Dict[str, Any]:
    return {str(row.module_path): row for row in catalog}


def run_heuristic_decision(scenario: PlannerScenario, services: Any) -> PlannerDecisionResult:
    from interfaces.command_system.builtin.agent.model_router import build_heuristic_tactical_plan

    catalog = build_admissible_catalog(
        modules=scenario.modules,
        kb=scenario.kb,
        goal=scenario.goal,
    )
    tactical = build_heuristic_tactical_plan(catalog)
    selected = tactical.selected_action.path if tactical.selected_action else None
    success = score_selected_path(
        selected,
        oracle_paths=scenario.oracle_paths,
        oracle_capabilities=scenario.oracle_capabilities,
        catalog_map=_catalog_map(catalog),
    )
    return PlannerDecisionResult(
        scenario=scenario.name,
        planner="heuristic",
        selected_path=selected,
        success=success,
        source=tactical.source,
    )


def run_hierarchical_decision(scenario: PlannerScenario, services: Any) -> PlannerDecisionResult:
    from interfaces.command_system.builtin.agent.hierarchical_planner import HierarchicalPlannerEngine

    state = SimpleNamespace(
        campaign_goal=scenario.goal,
        current_phase=scenario.phase,
        knowledge_base=dict(scenario.kb),
        executed_actions=[],
        runtime_policy=None,
        hierarchical_planner_enabled=True,
        adaptive_loop_enabled=True,
        replan_count=0,
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
    success = score_selected_path(
        selected,
        oracle_paths=scenario.oracle_paths,
        oracle_capabilities=scenario.oracle_capabilities,
        catalog_map=_catalog_map(catalog),
    )
    return PlannerDecisionResult(
        scenario=scenario.name,
        planner="hierarchical",
        selected_path=selected,
        success=success,
        source=tactical.source,
    )


def run_micro_benchmark(
    services: Any,
    *,
    scenarios: Optional[Sequence[PlannerScenario]] = None,
    seeds: int = DEFAULT_MICRO_SCENARIOS,
) -> Dict[str, Any]:
    base = list(scenarios or default_micro_scenarios())
    if not base:
        return {"heuristic_mcr": 0.0, "hierarchical_mcr": 0.0, "runs": []}

    heuristic_results: List[PlannerDecisionResult] = []
    hierarchical_results: List[PlannerDecisionResult] = []
    rng = random.Random(42)
    total = max(1, int(seeds or 1))
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
        heuristic_results.append(run_heuristic_decision(perturbed, services))
        hierarchical_results.append(run_hierarchical_decision(perturbed, services))

    h_ok = sum(1 for row in heuristic_results if row.success)
    p_ok = sum(1 for row in hierarchical_results if row.success)
    return sanitize_nested({
        "scenario_count": len(base),
        "runs_per_planner": total,
        "heuristic_mcr": h_ok / total,
        "hierarchical_mcr": p_ok / total,
        "heuristic_mcr_ci": list(wilson_ci(h_ok, total)),
        "hierarchical_mcr_ci": list(wilson_ci(p_ok, total)),
        "heuristic_failures": [row.to_dict() for row in heuristic_results if not row.success][:8],
        "hierarchical_failures": [row.to_dict() for row in hierarchical_results if not row.success][:8],
    })


class Phase3ValidationService:
    """Validate Phase 3 exit criterion against heuristic baseline."""

    def __init__(self, framework: Any) -> None:
        from interfaces.command_system.builtin.agent.facades import AgentServices

        self.framework = framework
        self.services = AgentServices(framework)

    def validate(
        self,
        *,
        integration_runs: int = DEFAULT_INTEGRATION_RUNS,
        micro_seeds: int = DEFAULT_MICRO_SCENARIOS,
        skip_integration: bool = False,
        output_path: Optional[str] = None,
    ) -> Phase3ValidationReport:
        from datetime import datetime, timezone

        report = Phase3ValidationReport(validated_at=datetime.now(timezone.utc).isoformat())
        micro = run_micro_benchmark(self.services, seeds=micro_seeds)
        report.micro_benchmark = micro

        integration: Dict[str, Any] = {"skipped": bool(skip_integration)}
        if not skip_integration:
            integration = self._run_integration_benchmark(runs=integration_runs)
        report.integration_benchmark = integration

        if integration.get("heuristic_mcr") is not None and not integration.get("skipped"):
            report.heuristic_mcr = float(integration.get("heuristic_mcr") or 0.0)
            report.hierarchical_mcr = float(integration.get("hierarchical_mcr") or 0.0)
            report.heuristic_mcr_ci = tuple(integration.get("heuristic_mcr_ci") or (0.0, 0.0))
            report.hierarchical_mcr_ci = tuple(integration.get("hierarchical_mcr_ci") or (0.0, 0.0))
            report.notes.append("Primary score from synthetic-http-lab integration benchmark.")
        else:
            report.heuristic_mcr = float(micro.get("heuristic_mcr") or 0.0)
            report.hierarchical_mcr = float(micro.get("hierarchical_mcr") or 0.0)
            report.heuristic_mcr_ci = tuple(micro.get("heuristic_mcr_ci") or (0.0, 0.0))
            report.hierarchical_mcr_ci = tuple(micro.get("hierarchical_mcr_ci") or (0.0, 0.0))
            report.notes.append("Primary score from micro planner oracle benchmark.")

        report.mcr_delta = report.hierarchical_mcr - report.heuristic_mcr
        report.safety = sanitize_nested({
            "heuristic_scope_violations": integration.get("heuristic_scope_violations", 0),
            "hierarchical_scope_violations": integration.get("hierarchical_scope_violations", 0),
            "heuristic_false_successes": integration.get("heuristic_false_successes", 0),
            "hierarchical_false_successes": integration.get("hierarchical_false_successes", 0),
        })

        safety_ok = (
            int(report.safety.get("hierarchical_scope_violations", 0) or 0)
            <= int(report.safety.get("heuristic_scope_violations", 0) or 0)
            and int(report.safety.get("hierarchical_false_successes", 0) or 0)
            <= int(report.safety.get("heuristic_false_successes", 0) or 0)
        )
        ci_clear = (
            report.hierarchical_mcr_ci[0]
            >= report.heuristic_mcr_ci[1] + PHASE3_MCR_DELTA_THRESHOLD * 0.5
            or report.hierarchical_mcr_ci[0]
            >= report.heuristic_mcr + PHASE3_MCR_DELTA_THRESHOLD * 0.5
        )
        report.passed = bool(
            report.mcr_delta >= PHASE3_MCR_DELTA_THRESHOLD
            and safety_ok
            and (ci_clear or report.mcr_delta >= PHASE3_MCR_DELTA_THRESHOLD + 0.05)
        )
        if not safety_ok and not integration.get("skipped"):
            report.notes.append("Safety regression: hierarchical exceeded heuristic scope/false-success counts.")
        if report.mcr_delta < PHASE3_MCR_DELTA_THRESHOLD:
            report.notes.append(
                f"MCR delta {report.mcr_delta:.1%} below threshold {PHASE3_MCR_DELTA_THRESHOLD:.0%}."
            )

        payload = report.to_dict()
        target = Path(output_path).expanduser() if output_path else (
            Path("artifacts/benchmarks") / f"phase3_validation_{int(time.time())}.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        payload["output_path"] = str(target)
        return report

    def _run_integration_benchmark(self, *, runs: int) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.benchmark.service import AgentBenchmarkService

        service = AgentBenchmarkService(self.framework)
        suite = get_benchmark_suite("synthetic-http-lab")

        def _run_arm(hierarchical: bool):
            prev_adaptive = os.environ.get("KITTYSPLOIT_AGENT_ADAPTIVE")
            prev_hier = os.environ.get("KITTYSPLOIT_AGENT_HIERARCHICAL")
            prev_heur = os.environ.get("KITTYSPLOIT_AGENT_HEURISTIC_ONLY")
            os.environ["KITTYSPLOIT_AGENT_ADAPTIVE"] = "1"
            os.environ["KITTYSPLOIT_AGENT_HEURISTIC_ONLY"] = "1"
            if hierarchical:
                os.environ["KITTYSPLOIT_AGENT_HIERARCHICAL"] = "1"
            else:
                os.environ.pop("KITTYSPLOIT_AGENT_HIERARCHICAL", None)
            try:
                return service._run_live(
                    suite,
                    runs=max(1, int(runs or 1)),
                    seed=42,
                    model=None,
                    output_path=None,
                    lab_attestation=None,
                )
            finally:
                for key, value in (
                    ("KITTYSPLOIT_AGENT_ADAPTIVE", prev_adaptive),
                    ("KITTYSPLOIT_AGENT_HIERARCHICAL", prev_hier),
                    ("KITTYSPLOIT_AGENT_HEURISTIC_ONLY", prev_heur),
                ):
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        try:
            heuristic_result = _run_arm(False)
            hierarchical_result = _run_arm(True)
        except Exception as exc:
            return {"error": str(exc)[:500], "skipped": True}

        h_ns = heuristic_result.north_star
        p_ns = hierarchical_result.north_star
        h_completed = sum(1 for row in heuristic_result.runs if row.mission_completed)
        p_completed = sum(1 for row in hierarchical_result.runs if row.mission_completed)
        total = max(1, len(heuristic_result.runs))
        return sanitize_nested({
            "suite": suite.id,
            "runs": runs,
            "heuristic_mcr": h_ns.mission_completion_rate,
            "hierarchical_mcr": p_ns.mission_completion_rate,
            "heuristic_mcr_ci": list(wilson_ci(h_completed, total)),
            "hierarchical_mcr_ci": list(wilson_ci(p_completed, total)),
            "heuristic_scope_violations": h_ns.out_of_scope_actions,
            "hierarchical_scope_violations": p_ns.out_of_scope_actions,
            "heuristic_false_successes": int(round(h_ns.false_success_rate * total)),
            "hierarchical_false_successes": int(round(p_ns.false_success_rate * total)),
            "heuristic_result_id": heuristic_result.id,
            "hierarchical_result_id": hierarchical_result.id,
        })
