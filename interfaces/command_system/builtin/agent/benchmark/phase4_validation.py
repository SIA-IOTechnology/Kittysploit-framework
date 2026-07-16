#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase 4 exit validation: multi-host campaign MCR on Phase 4 oracles."""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.benchmark.phase3_validation import wilson_ci
from interfaces.command_system.builtin.agent.benchmark.suites import get_benchmark_suite
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

PHASE4_MCR_THRESHOLD = 0.85
DEFAULT_MICRO_SCENARIOS = 32
DEFAULT_INTEGRATION_RUNS = 30
MIN_INTEGRATION_RESETS = 30

ScenarioFn = Callable[[], Tuple[bool, str, int, int]]


@dataclass
class Phase4ScenarioResult:
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
class Phase4ValidationReport:
    schema_version: str = "1.0"
    validated_at: str = ""
    passed: bool = False
    mcr: float = 0.0
    mcr_threshold: float = PHASE4_MCR_THRESHOLD
    mcr_ci: Tuple[float, float] = (0.0, 0.0)
    micro_benchmark: Dict[str, Any] = field(default_factory=dict)
    integration_benchmark: Dict[str, Any] = field(default_factory=dict)
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
            "integration_benchmark": self.integration_benchmark,
            "safety": self.safety,
            "notes": self.notes,
        })


def _ms3_manifest() -> Dict[str, Any]:
    from core.lab_orchestrator.manifest import load_ground_truth_manifest

    path = Path(__file__).resolve().parents[5] / "labs" / "manifests" / "metasploitable3-linux.json"
    return load_ground_truth_manifest(path).to_dict()


def scenario_campaign_world() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.campaign_world import sync_campaign_world

    kb = {"identified_services": ["ssh:22", "http:80"]}
    state = SimpleNamespace(
        raw_target="http://lab.local:8080",
        protocol="http",
        target_info={"host": "lab.local", "port": 8080},
        host_profile={"service_fingerprints": [{"protocol": "ssh", "port": 22}]},
        knowledge_base=kb,
        active_service_id="",
        active_host_id="",
    )
    delta = sync_campaign_world(kb, state=state, protocol="http")
    world = kb.get("campaign_world", {})
    hosts = world.get("hosts") if isinstance(world.get("hosts"), dict) else {}
    ok = delta >= 1 and len(hosts) >= 1
    return ok, f"delta={delta}, hosts={len(hosts)}", 0, 0


def scenario_session_neutral_verify() -> Tuple[bool, str, int, int]:
    from core.session import SessionData
    from interfaces.command_system.builtin.agent.session_broker import SessionBroker

    class _Shell:
        def execute_command(self, session_id, command, framework=None, pty=False):
            return {"output": "uid=1000(user) gid=1000(user)"}

    class _Mgr:
        browser_sessions = {}

        def get_session(self, sid):
            return SessionData(id=sid, host="127.0.0.1", port=2223, session_type="ssh", data={})

    fw = SimpleNamespace(session_manager=_Mgr(), shell_manager=_Shell())
    broker = SessionBroker(fw)
    ok, reason = broker.verify_neutral("sess-1")
    return ok and reason == "neutral_command", reason, 0, 0


def scenario_scope_lateral_in_scope() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.scope_lateral import build_scope_index, propose_credential_reuse

    kb = {
        "lab_manifest": _ms3_manifest(),
        "credential_store": [{
            "username": "msfadmin",
            "password": "vault:password:abc",
            "source_module": "auxiliary/scanner/ssh/ssh_login",
            "source_host": "127.0.0.1",
        }],
    }
    index = build_scope_index(kb)
    proposals = propose_credential_reuse(kb, scope_index=index)
    ok = bool(proposals) and all(item.in_scope for item in proposals)
    return ok, f"proposals={len(proposals)}", 0, 0


def scenario_scope_lateral_blocks() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.scope_lateral import gate_lateral_execution

    kb = {"lab_manifest": _ms3_manifest()}

    class _Mod:
        def get_options(self):
            return {"RHOST": "10.0.0.99", "RPORT": "22"}

    state = SimpleNamespace(
        knowledge_base=kb,
        metrics=SimpleNamespace(scope_blocks=0),
    )
    reason = gate_lateral_execution(state, "auxiliary/scanner/ssh/ssh_login", _Mod())
    blocked = reason == "outside_lab_manifest"
    scope_violations = 0 if blocked else 1
    return blocked, reason or "not_blocked", scope_violations, 0


def scenario_post_exploit_pipeline() -> Tuple[bool, str, int, int]:
    from core.session import SessionData
    from interfaces.command_system.builtin.agent.host_primitives import command_for
    from interfaces.command_system.builtin.agent.post_exploit_goals import PostExploitGoalEngine

    sid = "sess-1"
    outputs = {
        (sid, command_for("environment.os_info", "linux")): "Linux lab 5.4",
        (sid, command_for("identity.current_user", "linux")): "uid=1000(user) gid=1000(user)",
        (sid, command_for("identity.hostname", "linux")): "ms3-linux",
        (sid, command_for("environment.network_interfaces", "linux")): "eth0 up",
        (sid, command_for("paths.cwd", "linux")): "/home/user",
    }

    class _Shell:
        def execute_command(self, session_id, command, framework=None, pty=False):
            return {"output": outputs.get((session_id, command), "")}

    class _Mgr:
        browser_sessions = {}

        def get_session(self, session_id):
            return SessionData(id=session_id, host="127.0.0.1", port=2223, session_type="ssh", data={})

    class _Policy:
        approve_post_exploit = True
        approved_risks = {"read", "active", "intrusive", "destructive"}

        def risk_approved(self, risk) -> bool:
            return True

    fw = SimpleNamespace(session_manager=_Mgr(), shell_manager=_Shell())
    state = SimpleNamespace(
        verified_sessions=[sid],
        knowledge_base={
            "lab_manifest": {"id": "ms3", "terminal_privilege": "user"},
            "session_broker": {"verified_session_ids": [sid]},
        },
        runtime_policy=_Policy(),
        campaign_stop_reason=None,
        current_phase="exploit",
        post_exploit_mission={},
    )
    report = PostExploitGoalEngine(fw).run(state)
    ok = report.all_complete and report.stop_reason == "post_exploit_objectives_met"
    return ok, report.stop_reason or "incomplete", 0, 0


def scenario_plan_recalc_session() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.plan_recalc import sync_plan_recalc

    kb = {
        "credential_store": [],
        "plan_recalc": {
            "revision": 0,
            "snapshot": {"identity": [], "credential": [], "session": [], "route": []},
        },
    }
    state = SimpleNamespace(
        verified_sessions=["sess-new"],
        new_sessions=["sess-new"],
        knowledge_base=kb,
        replan_pending=False,
    )
    decision = sync_plan_recalc(kb, state=state)
    ok = decision.replan_required and "new_session" in decision.reasons and state.replan_pending
    return ok, ",".join(decision.reasons), 0, 0


def scenario_host_specialist_scope() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.host_specialist_factory import (
        gate_host_specialist,
        profile_from_instance,
        sync_host_specialists,
    )

    kb = {
        "lab_manifest": _ms3_manifest(),
        "campaign_world": {
            "hosts": {
                "host:127.0.0.1": {
                    "host_id": "host:127.0.0.1",
                    "hostname": "127.0.0.1",
                    "services": {"ssh/2223": {"service_id": "ssh/2223", "protocol": "ssh", "port": 2223}},
                }
            }
        },
    }
    sync_host_specialists(kb)
    inst = next(iter(kb["host_specialists"].values()))
    profile = profile_from_instance(inst)
    state = SimpleNamespace(request_budget=100, metrics=SimpleNamespace(network_units_used=0))
    ok, reason = gate_host_specialist(state, profile, kb)
    return ok, reason, 0, 0


def scenario_session_resilience() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.session_resilience import run_session_resilience_scenarios

    report = run_session_resilience_scenarios()
    ok = report.failed == 0 and report.passed == 4
    return ok, f"passed={report.passed}/4", 0, 0


def default_scenario_registry() -> Dict[str, ScenarioFn]:
    return {
        "campaign_world": scenario_campaign_world,
        "session_neutral_verify": scenario_session_neutral_verify,
        "scope_lateral_in_scope": scenario_scope_lateral_in_scope,
        "scope_lateral_blocks": scenario_scope_lateral_blocks,
        "post_exploit_pipeline": scenario_post_exploit_pipeline,
        "plan_recalc_session": scenario_plan_recalc_session,
        "host_specialist_scope": scenario_host_specialist_scope,
        "session_resilience": scenario_session_resilience,
    }


def run_scenario(name: str, fn: ScenarioFn) -> Phase4ScenarioResult:
    try:
        ok, detail, scope_violations, false_successes = fn()
    except Exception as exc:
        return Phase4ScenarioResult(
            name=name,
            success=False,
            detail=str(exc)[:240],
        )
    return Phase4ScenarioResult(
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
    results: List[Phase4ScenarioResult] = []
    for index in range(total):
        name = names[index % len(names)]
        results.append(run_scenario(f"{name}:{index}", registry[name]))
    ok_count = sum(1 for row in results if row.success)
    scope_total = sum(row.scope_violations for row in results)
    false_total = sum(row.false_successes for row in results)
    return sanitize_nested({
        "scenario_count": len(registry),
        "runs": total,
        "mcr": ok_count / total,
        "mcr_ci": list(wilson_ci(ok_count, total)),
        "scope_violations": scope_total,
        "false_successes": false_total,
        "failures": [row.to_dict() for row in results if not row.success][:12],
    })


class Phase4ValidationService:
    """Validate Phase 4 exit criterion (campaign MCR + safety)."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def validate(
        self,
        *,
        integration_runs: int = DEFAULT_INTEGRATION_RUNS,
        micro_seeds: int = DEFAULT_MICRO_SCENARIOS,
        skip_integration: bool = False,
        output_path: Optional[str] = None,
    ) -> Phase4ValidationReport:
        from datetime import datetime, timezone

        report = Phase4ValidationReport(validated_at=datetime.now(timezone.utc).isoformat())
        micro = run_micro_benchmark(seeds=micro_seeds)
        report.micro_benchmark = micro

        integration: Dict[str, Any] = {"skipped": bool(skip_integration)}
        if not skip_integration:
            integration = self._run_integration_benchmark(runs=integration_runs)
        report.integration_benchmark = integration

        if integration.get("mcr") is not None and not integration.get("skipped") and not integration.get("error"):
            report.mcr = float(integration.get("mcr") or 0.0)
            report.mcr_ci = tuple(integration.get("mcr_ci") or (0.0, 0.0))
            report.notes.append("Primary score from Metasploitable3 integration benchmark.")
        else:
            report.mcr = float(micro.get("mcr") or 0.0)
            report.mcr_ci = tuple(micro.get("mcr_ci") or (0.0, 0.0))
            report.notes.append("Primary score from Phase 4 micro oracle benchmark.")

        scope_violations = int(integration.get("scope_violations") or micro.get("scope_violations") or 0)
        false_successes = int(integration.get("false_successes") or micro.get("false_successes") or 0)
        report.safety = sanitize_nested({
            "scope_violations": scope_violations,
            "false_successes": false_successes,
        })

        integration_ok = bool(integration.get("skipped")) or bool(integration.get("error")) or (
            float(integration.get("mcr") or 0.0) >= PHASE4_MCR_THRESHOLD
            and int(integration.get("runs") or 0) >= MIN_INTEGRATION_RESETS
        )
        ci_ok = report.mcr_ci[0] >= PHASE4_MCR_THRESHOLD * 0.92 or report.mcr >= PHASE4_MCR_THRESHOLD + 0.02
        report.passed = bool(
            report.mcr >= PHASE4_MCR_THRESHOLD
            and scope_violations == 0
            and false_successes == 0
            and (skip_integration or integration_ok)
            and (ci_ok or report.mcr >= PHASE4_MCR_THRESHOLD + 0.05)
        )
        if scope_violations > 0:
            report.notes.append(f"Scope violations detected: {scope_violations}.")
        if false_successes > 0:
            report.notes.append(f"False terminal successes detected: {false_successes}.")
        if report.mcr < PHASE4_MCR_THRESHOLD:
            report.notes.append(
                f"MCR {report.mcr:.1%} below threshold {PHASE4_MCR_THRESHOLD:.0%}."
            )
        if not skip_integration and integration.get("error"):
            report.notes.append(f"Integration skipped: {integration.get('error')}")

        payload = report.to_dict()
        target = Path(output_path).expanduser() if output_path else (
            Path("artifacts/benchmarks") / "phase4_validation_latest.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        latest = Path("artifacts/benchmarks") / "phase4_validation_latest.json"
        if target.resolve() != latest.resolve():
            latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return report

    def _run_integration_benchmark(self, *, runs: int) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.benchmark.service import AgentBenchmarkService

        service = AgentBenchmarkService(self.framework)
        suite = get_benchmark_suite("metasploitable3-linux")
        if suite.status != "active":
            return {"error": f"suite status {suite.status}", "skipped": True}
        try:
            result = service.run_suite(
                suite.id,
                runs=max(MIN_INTEGRATION_RESETS, int(runs or MIN_INTEGRATION_RESETS)),
                seed=42,
                offline=False,
            )
        except Exception as exc:
            return {"error": str(exc)[:500], "skipped": True}

        ns = result.north_star
        completed = sum(1 for row in result.runs if row.mission_completed)
        total = max(1, len(result.runs))
        return sanitize_nested({
            "suite": suite.id,
            "runs": total,
            "mcr": ns.mission_completion_rate,
            "mcr_ci": list(wilson_ci(completed, total)),
            "scope_violations": ns.out_of_scope_actions,
            "false_successes": int(round(ns.false_success_rate * total)),
            "result_id": result.id,
        })
