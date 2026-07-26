#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase 5 exit validation: verified learning memory without contamination."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

from interfaces.command_system.builtin.agent.benchmark.phase3_validation import wilson_ci
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

PHASE5_MCR_THRESHOLD = 0.85
DEFAULT_MICRO_SCENARIOS = 24

ScenarioFn = Callable[[], Tuple[bool, str, int, int]]


@dataclass
class Phase5ScenarioResult:
    name: str
    success: bool
    detail: str = ""
    contamination_events: int = 0
    secret_leaks: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "name": self.name,
            "success": self.success,
            "detail": self.detail,
            "contamination_events": self.contamination_events,
            "leak_events": self.secret_leaks,
        })


@dataclass
class Phase5ValidationReport:
    schema_version: str = "1.0"
    validated_at: str = ""
    passed: bool = False
    mcr: float = 0.0
    mcr_threshold: float = PHASE5_MCR_THRESHOLD
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


def scenario_learnable_gate() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_episode import (
        VERDICT_CONFIRMED,
        VERDICT_REFUTED,
        is_learnable_verdict,
    )

    ok = is_learnable_verdict(VERDICT_CONFIRMED) and is_learnable_verdict(VERDICT_REFUTED)
    ok = ok and not is_learnable_verdict("no_signal") and not is_learnable_verdict("blocked")
    return ok, "confirmed/refuted only", 0, 0


def scenario_episode_from_result() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_episode import episode_from_module_result

    state = SimpleNamespace(
        run_id="run-a",
        knowledge_base={"tech_hints": ["ssh"], "identified_services": ["ssh:22"]},
        target_info={"hostname": "127.0.0.1"},
        host_profile={"os_family": "linux", "architecture": "x86_64"},
        protocol="ssh",
    )
    confirmed = episode_from_module_result(
        state,
        {"path": "auxiliary/scanner/ssh/ssh_login", "vulnerable": True, "details": {"port": 22}},
        phase="exploit",
        tenant_id="tenant-a",
    )
    ambiguous = episode_from_module_result(
        state,
        {"path": "scanner/http/crawler", "vulnerable": False, "message": "scan complete"},
        phase="scan",
        tenant_id="tenant-a",
    )
    ok = confirmed is not None and confirmed.learnable and ambiguous is None
    return ok, f"confirmed={confirmed is not None}, ambiguous={ambiguous is None}", 0, 0


def scenario_benchmark_freeze() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_governance import (
        freeze_learning_for_benchmark,
        should_record_learning,
    )

    state = SimpleNamespace(
        dry_run=False,
        plan_only=False,
        knowledge_base={},
        workspace="bench",
        run_id="agent_test",
    )
    freeze_learning_for_benchmark(state, suite_id="metasploitable3-linux")
    blocked = not should_record_learning(state)
    return blocked, "benchmark frozen", 0, 0


def scenario_cross_target_isolation() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_store import LearningStore

    with tempfile.TemporaryDirectory() as tmp:
        paths = SimpleNamespace(
            memory_dir=Path(tmp),
            ensure=lambda: Path(tmp).mkdir(parents=True, exist_ok=True),
        )
        store = LearningStore(paths)
        state_a = SimpleNamespace(
            run_id="run-a",
            workspace="tenant-a",
            knowledge_base={"tech_hints": ["ssh"], "identified_services": ["ssh:22"]},
            target_info={"hostname": "10.0.0.1"},
            host_profile={"os_family": "linux"},
            protocol="ssh",
        )
        state_b = SimpleNamespace(
            run_id="run-b",
            workspace="tenant-b",
            knowledge_base={"tech_hints": ["http"], "identified_services": ["http:80"]},
            target_info={"hostname": "10.0.0.2"},
            host_profile={"os_family": "linux"},
            protocol="http",
        )
        store.record_phase_results(
            state_a,
            {},
            {},
            [{"path": "auxiliary/scanner/ssh/ssh_login", "vulnerable": True, "details": {}}],
            "exploit",
        )
        store.record_phase_results(
            state_b,
            {},
            {},
            [{"path": "auxiliary/scanner/http/crawler", "vulnerable": True, "details": {}}],
            "scan",
        )
        fp_a = store.query_similar_episodes(state_a.knowledge_base, limit=1)
        fp_b = store.query_similar_episodes(state_b.knowledge_base, limit=1)
        leak = any(
            "ssh_login" in str(row.get("action_path") or row.get("module_path") or "")
            for row in fp_b
        )
        ok = bool(fp_a) and bool(fp_b) and not leak
        contamination = 1 if leak else 0
        return ok, f"tenant_a={len(fp_a)}, tenant_b={len(fp_b)}", contamination, 0


def scenario_secret_redaction() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_episode import sanitize_episode_params

    params = sanitize_episode_params({
        "RPORT": "22",
        "password": "supersecret",
        "TOKEN": "abc123",
        "TARGETURI": "/login",
    })
    leaked = "supersecret" in str(params) or "abc123" in str(params)
    ok = "rport" in params and not leaked
    return ok, f"keys={sorted(params.keys())}", 0, 1 if leaked else 0


def scenario_contextual_bandit() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.contextual_bandit import bandit_multiplier
    from interfaces.command_system.builtin.agent.learning_store import LearningStore

    class _FakeStore:
        def bandit_stats(self, module_path: str, context_fingerprint: str) -> Dict[str, float]:
            if module_path.endswith("ssh_login"):
                return {"successes": 6.0, "failures": 1.0, "samples": 7.0}
            return {"successes": 1.0, "failures": 5.0, "samples": 6.0}

    store = _FakeStore()
    good = bandit_multiplier(store, "auxiliary/scanner/ssh/ssh_login", "ctx_abc")
    bad = bandit_multiplier(store, "auxiliary/scanner/http/crawler", "ctx_abc")
    ok = good > bad and good > 1.0
    return ok, f"good={good:.3f}, bad={bad:.3f}", 0, 0


def scenario_preference_dataset() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_store import LearningStore

    with tempfile.TemporaryDirectory() as tmp:
        paths = SimpleNamespace(
            memory_dir=Path(tmp),
            ensure=lambda: Path(tmp).mkdir(parents=True, exist_ok=True),
        )
        store = LearningStore(paths)
        state = SimpleNamespace(
            run_id="run-pref",
            workspace="tenant-a",
            knowledge_base={"tech_hints": ["ssh"], "identified_services": ["ssh:22"]},
            target_info={"hostname": "127.0.0.1"},
            host_profile={"os_family": "linux"},
            protocol="ssh",
        )
        count = store.record_preferences(
            state,
            chosen_path="auxiliary/scanner/ssh/ssh_login",
            rejected_alternatives=[
                {"path": "auxiliary/scanner/http/crawler", "reason": "lower score"},
            ],
            outcome="decision",
        )
        prefs = state.knowledge_base.get("learning_mission", {}).get("preferences") or []
        ok = count == 1 and len(prefs) == 1
        return ok, f"prefs={len(prefs)}", 0, 0


def scenario_eval_corpus_frozen() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.learning_governance import attach_learning_governance

    state = SimpleNamespace(knowledge_base={})
    gov = attach_learning_governance(state, mode="eval_only", eval_only=True, corpus_frozen=True)
    ok = gov.get("corpus_frozen") is True and gov.get("eval_only") is True
    return ok, "corpus frozen for eval", 0, 0


def default_scenario_registry() -> Dict[str, ScenarioFn]:
    return {
        "learnable_gate": scenario_learnable_gate,
        "episode_from_result": scenario_episode_from_result,
        "benchmark_freeze": scenario_benchmark_freeze,
        "cross_target_isolation": scenario_cross_target_isolation,
        "secret_redaction": scenario_secret_redaction,
        "contextual_bandit": scenario_contextual_bandit,
        "preference_dataset": scenario_preference_dataset,
        "eval_corpus_frozen": scenario_eval_corpus_frozen,
    }


def run_scenario(name: str, fn: ScenarioFn) -> Phase5ScenarioResult:
    try:
        ok, detail, contamination, leaks = fn()
    except Exception as exc:
        return Phase5ScenarioResult(name=name, success=False, detail=str(exc)[:240])
    return Phase5ScenarioResult(
        name=name,
        success=bool(ok),
        detail=detail,
        contamination_events=int(contamination or 0),
        secret_leaks=int(leaks or 0),
    )


def run_micro_benchmark(*, seeds: int = DEFAULT_MICRO_SCENARIOS) -> Dict[str, Any]:
    registry = default_scenario_registry()
    names = list(registry.keys())
    total = max(1, int(seeds or 1))
    results: List[Phase5ScenarioResult] = []
    for index in range(total):
        name = names[index % len(names)]
        results.append(run_scenario(f"{name}:{index}", registry[name]))
    ok_count = sum(1 for row in results if row.success)
    contamination = sum(row.contamination_events for row in results)
    leak_events = sum(row.secret_leaks for row in results)
    return sanitize_nested({
        "scenario_count": len(registry),
        "runs": total,
        "mcr": ok_count / total,
        "mcr_ci": list(wilson_ci(ok_count, total)),
        "contamination_events": contamination,
        "leak_events": leak_events,
        "failures": [row.to_dict() for row in results if not row.success][:12],
    })


class Phase5ValidationService:
    """Validate Phase 5 learning memory safety and oracle scenarios."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def validate(
        self,
        *,
        micro_seeds: int = DEFAULT_MICRO_SCENARIOS,
        output_path: Optional[str] = None,
    ) -> Phase5ValidationReport:
        from datetime import datetime, timezone

        report = Phase5ValidationReport(validated_at=datetime.now(timezone.utc).isoformat())
        micro = run_micro_benchmark(seeds=micro_seeds)
        report.micro_benchmark = micro
        report.mcr = float(micro.get("mcr") or 0.0)
        report.mcr_ci = tuple(micro.get("mcr_ci") or (0.0, 0.0))
        contamination = int(micro.get("contamination_events") or 0)
        leak_events = int(micro.get("leak_events") or 0)
        report.safety = sanitize_nested({
            "contamination_events": contamination,
            "leak_events": leak_events,
        })
        ci_ok = report.mcr_ci[0] >= PHASE5_MCR_THRESHOLD * 0.92 or report.mcr >= PHASE5_MCR_THRESHOLD + 0.02
        report.passed = bool(
            report.mcr >= PHASE5_MCR_THRESHOLD
            and contamination == 0
            and leak_events == 0
            and (ci_ok or report.mcr >= PHASE5_MCR_THRESHOLD + 0.05)
        )
        if contamination > 0:
            report.notes.append(f"Cross-target contamination detected: {contamination}.")
        if leak_events > 0:
            report.notes.append(f"Credential leak events detected: {leak_events}.")
        if report.mcr < PHASE5_MCR_THRESHOLD:
            report.notes.append(
                f"MCR {report.mcr:.1%} below threshold {PHASE5_MCR_THRESHOLD:.0%}."
            )
        report.notes.append(
            "Hidden-variant +15pt MCR progression requires frozen eval corpus and live A/B runs."
        )

        payload = report.to_dict()
        target = Path(output_path).expanduser() if output_path else (
            Path("artifacts/benchmarks") / "phase5_validation_latest.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        latest = Path("artifacts/benchmarks") / "phase5_validation_latest.json"
        if target.resolve() != latest.resolve():
            latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return report
