#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run agent benchmark suites and produce comparable JSON results."""

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.schemas.validation import SchemaValidationError, validate_instance
from interfaces.command_system.builtin.agent import AgentServices
from interfaces.command_system.builtin.agent.benchmark.metrics import (
    aggregate_north_star,
    aggregate_outcome_verdicts,
    extract_run_metrics,
    load_state_from_run_store,
    rank_failure_causes,
)
from interfaces.command_system.builtin.agent.benchmark.models import AgentBenchmarkResult
from interfaces.command_system.builtin.agent.benchmark.suites import BenchmarkSuite, get_benchmark_suite
from interfaces.command_system.builtin.agent.goal_planner import build_goal_plan, normalize_goal
from interfaces.command_system.builtin.agent.learning_governance import freeze_learning_for_benchmark
from interfaces.command_system.builtin.agent.mission_profiles import apply_mission_profile
from interfaces.command_system.builtin.agent.network_budget import NetworkBudget
from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore, new_run_id
from interfaces.command_system.builtin.agent.runtime_policy import (
    AgentRuntimePolicy,
    AgentScopeGuard,
    CancellationToken,
)
from interfaces.command_system.builtin.agent.state import AgentMetrics, AgentState, agent_state_checkpoint_dict
from interfaces.command_system.builtin.scanner_command import ScannerCommand


class AgentBenchmarkService:
    """Execute or score benchmark suites and emit schema-validated results."""

    def __init__(self, framework: Any, *, paths: Optional[AgentPathService] = None) -> None:
        self.framework = framework
        self.paths = paths or AgentPathService(framework)
        self._agent = AgentServices(framework)

    def run_suite(
        self,
        suite_id: str,
        *,
        runs: int = 1,
        seed: Optional[int] = None,
        model: Optional[str] = None,
        offline: bool = False,
        run_ids: Optional[Sequence[str]] = None,
        output_path: Optional[str] = None,
        reset_between_runs: Optional[bool] = None,
    ) -> AgentBenchmarkResult:
        suite = get_benchmark_suite(suite_id)
        if offline:
            return self._score_offline(
                suite,
                run_ids=run_ids,
                seed=seed,
                model=model,
                output_path=output_path,
            )
        if suite.status != "active":
            raise RuntimeError(
                f"Suite '{suite.id}' is '{suite.status}'. Provision the lab first or use --offline."
            )
        lab_attestation = self._verify_lab_attestation(suite)
        if reset_between_runs is None:
            # LIVE campaigns on Metasploitable require independent attested resets.
            reset_between_runs = suite.id.startswith("metasploitable3")
        return self._run_live(
            suite,
            runs=max(1, int(runs or 1)),
            seed=seed,
            model=model,
            output_path=output_path,
            lab_attestation=lab_attestation,
            reset_between_runs=bool(reset_between_runs),
        )

    def _verify_lab_attestation(self, suite: BenchmarkSuite) -> Optional[Dict[str, Any]]:
        from interfaces.command_system.builtin.agent.benchmark.internal_lab_gate import (
            is_synthetic_lab_target,
        )

        if is_synthetic_lab_target(suite.target):
            return None
        if not suite.id.startswith("metasploitable3"):
            return None
        from core.lab_orchestrator.attestation import verify_reset_attestation
        from core.lab_orchestrator.manifest import find_ground_truth_manifest
        from core.lab_orchestrator.runner import LabOrchestrator

        orchestrator = LabOrchestrator(self.framework)
        manifest = find_ground_truth_manifest(suite.id)
        attestation = orchestrator.get_reset_attestation(suite.id)
        ok, detail = verify_reset_attestation(
            attestation,
            manifest,
            require_digest_pin=True,
            require_readiness=True,
        )
        if not ok:
            raise RuntimeError(
                f"Lab '{suite.id}' is not benchmark-ready: {detail}. "
                f"Run `lab pin-digest {suite.id}` then `lab reset {suite.id}` if needed."
            )
        return dict(attestation)

    def _reset_lab_for_run(self, suite: BenchmarkSuite) -> Dict[str, Any]:
        """Perform an attested lab reset and return the fresh attestation."""
        from core.lab_orchestrator.attestation import verify_reset_attestation
        from core.lab_orchestrator.manifest import find_ground_truth_manifest
        from core.lab_orchestrator.runner import LabOrchestrator

        orchestrator = LabOrchestrator(self.framework)
        scenario = orchestrator.get_scenario(suite.id)
        if not orchestrator.reset_lab(scenario):
            raise RuntimeError(f"Lab reset failed for '{suite.id}'")
        attestation = orchestrator.get_reset_attestation(suite.id)
        manifest = find_ground_truth_manifest(suite.id)
        ok, detail = verify_reset_attestation(
            attestation,
            manifest,
            require_digest_pin=True,
            require_readiness=True,
        )
        if not ok:
            raise RuntimeError(f"Post-reset attestation invalid for '{suite.id}': {detail}")
        return dict(attestation)

    def _run_live(
        self,
        suite: BenchmarkSuite,
        *,
        runs: int,
        seed: Optional[int],
        model: Optional[str],
        output_path: Optional[str],
        lab_attestation: Optional[Dict[str, Any]] = None,
        reset_between_runs: bool = False,
    ) -> AgentBenchmarkResult:
        base_seed = seed if seed is not None else int(time.time()) % 1_000_000
        config = {
            "runs": runs,
            "seed": base_seed,
            "model": model or "heuristic",
            "target": suite.target,
            "goal": suite.goal,
            "profile": suite.profile,
            "dry_run": False,
            "offline": False,
            "reset_between_runs": bool(reset_between_runs),
        }
        result = AgentBenchmarkResult(
            suite=suite.id,
            suite_version=suite.suite_version,
            config=config,
            north_star=aggregate_north_star([]),
            outcome_verdicts=aggregate_outcome_verdicts([]),
            metadata={"suite": suite.to_dict()},
        )
        if lab_attestation:
            result.metadata["lab_attestation"] = lab_attestation
        result.metadata["reset_attestations"] = []

        lab_server = None
        mutation_meta: Optional[Dict[str, Any]] = None
        try:
            if suite.target in ("__lab__", "__lab_mutated__"):
                if suite.target == "__lab_mutated__" or suite.id == "synthetic-mutated":
                    from interfaces.command_system.builtin.agent.benchmark.lab_mutation import (
                        build_mutated_lab,
                    )

                    mutation_seed = int(
                        suite.agent_options.get("mutation_seed", base_seed) or base_seed
                    )
                    lab_server, mut_spec = build_mutated_lab(mutation_seed)
                    lab_server.start()
                    target = lab_server.base_url
                    mutation_meta = mut_spec.to_dict()
                    result.metadata["lab_mutation"] = mutation_meta
                else:
                    from interfaces.command_system.builtin.agent.benchmark.lab_server import (
                        SyntheticHttpLab,
                    )

                    lab_server = SyntheticHttpLab().start()
                    target = lab_server.base_url
            else:
                target = suite.target

            for index in range(runs):
                run_attestation = lab_attestation
                if reset_between_runs and suite.id.startswith("metasploitable3"):
                    run_attestation = self._reset_lab_for_run(suite)
                    result.metadata["reset_attestations"].append(
                        {
                            "run_index": index,
                            "attestation_id": run_attestation.get("id"),
                            "attestation_hash": run_attestation.get("attestation_hash"),
                            "created_at": run_attestation.get("created_at"),
                            "event": run_attestation.get("event"),
                        }
                    )
                    result.metadata["lab_attestation"] = run_attestation
                run_seed = base_seed + index
                random.seed(run_seed)
                run_result = self._execute_single_run(
                    suite,
                    target=target,
                    run_index=index,
                    seed=run_seed,
                    model=model,
                    lab_attestation=run_attestation,
                )
                result.runs.append(run_result)
        finally:
            if lab_server is not None:
                lab_server.stop()

        return self._finalize_result(result, output_path=output_path)

    @staticmethod
    def _option_value(
        suite: BenchmarkSuite,
        profile_overrides: Dict[str, Any],
        key: str,
        default: Any = None,
    ) -> Any:
        if key in suite.agent_options:
            return suite.agent_options.get(key)
        if key in profile_overrides:
            return profile_overrides.get(key)
        return default

    def _bootstrap_lab_context(
        self,
        suite: BenchmarkSuite,
        *,
        lab_attestation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        kb: Dict[str, Any] = {}
        if not suite.id.startswith("metasploitable3"):
            return kb
        from core.lab_orchestrator.manifest import find_ground_truth_manifest

        manifest = find_ground_truth_manifest(suite.id)
        manifest_dict = manifest.to_dict()
        kb["lab_manifest"] = manifest_dict
        if lab_attestation:
            kb["lab_attestation"] = dict(lab_attestation)
        services: List[str] = []
        for row in manifest_dict.get("services") or []:
            if not isinstance(row, dict):
                continue
            service_id = str(row.get("id") or row.get("protocol") or "service").strip()
            host_port = row.get("host_port") or row.get("port")
            if service_id and host_port is not None:
                services.append(f"{service_id}/{host_port}")
        if services:
            kb["identified_services"] = services
        session = manifest_dict.get("session") if isinstance(manifest_dict.get("session"), dict) else {}
        if str(session.get("protocol") or "").lower() == "ssh":
            kb["protocol"] = "ssh"
        return kb

    def _execute_single_run(
        self,
        suite: BenchmarkSuite,
        *,
        target: str,
        run_index: int,
        seed: int,
        model: Optional[str],
        lab_attestation: Optional[Dict[str, Any]] = None,
    ):
        started = time.monotonic()
        run_id = new_run_id()
        run_store = AgentRunStore(self.paths, run_id)
        self._agent.report.set_paths(self.paths)

        scanner = ScannerCommand(self.framework, None, None)
        target_info = scanner._parse_target(target)
        if not target_info:
            target_info = {"url": target, "hostname": target, "port": 80, "scheme": "http"}

        workspace = (
            self.framework.get_current_workspace_name()
            if hasattr(self.framework, "get_current_workspace_name")
            else "default"
        )
        if suite.profile:
            profile_overrides = apply_mission_profile(suite.profile)
        else:
            profile_overrides = {}

        protocol = str(self._option_value(suite, profile_overrides, "protocol", "") or "").strip().lower() or None
        if protocol and target_info:
            hostname = target_info.get("hostname")
            port = target_info.get("port")
            if protocol not in {"http", "https"}:
                target_info["scheme"] = protocol
                target_info["url"] = f"{protocol}://{hostname}:{port}"

        approved_risks = list(suite.agent_options.get("approve_risk") or [])
        approved_risks.extend(profile_overrides.get("approved_risks") or [])

        runtime_policy = AgentRuntimePolicy.from_options(
            safety_profile=profile_overrides.get("safety_profile", "normal"),
            approved_risks=approved_risks,
            approve_post_exploit=bool(
                self._option_value(suite, profile_overrides, "approve_post_exploit", False)
            ),
            dry_run=bool(suite.agent_options.get("dry_run")),
            plan_only=bool(suite.agent_options.get("plan_only")),
            session_policy="never",
            mission_profile=profile_overrides.get("catalog_policy") or suite.profile or "",
        )

        request_budget = int(
            suite.agent_options.get("request_budget")
            or profile_overrides.get("request_budget", 0)
            or 0
        )
        normalized_goal = normalize_goal(suite.goal)
        http_replay = str(
            self._option_value(suite, profile_overrides, "http_replay", "safe") or "safe"
        )
        proxy_flows = bool(self._option_value(suite, profile_overrides, "proxy_flows", True))
        http_replay_max = max(
            0,
            int(self._option_value(suite, profile_overrides, "http_replay_max", 3) or 0),
        )

        state = AgentState(
            raw_target=target,
            target_info=target_info,
            scanner=scanner,
            protocol=protocol,
            campaign_goal=normalized_goal,
            operator_goal=normalized_goal,
            safety_profile=profile_overrides.get("safety_profile", "normal"),
            request_budget=request_budget,
            max_modules=int(suite.agent_options.get("max_modules", 40) or 40),
            recon_modules=int(suite.agent_options.get("recon_modules", 12) or 12),
            shell_hunter=bool(suite.agent_options.get("shell_hunter")),
            plan_only=bool(suite.agent_options.get("plan_only")),
            dry_run=bool(suite.agent_options.get("dry_run")),
            checkpoint_enabled=bool(suite.agent_options.get("checkpoint")),
            proxy_flows=proxy_flows,
            http_replay=http_replay,
            http_replay_max=http_replay_max,
            execution_plan=build_goal_plan(normalized_goal, request_budget=request_budget),
            llm_model=str(model or suite.agent_options.get("llm_model") or "llama3.1:8b"),
            llm_local=bool(model),
            random_seed=seed,
            run_id=run_id,
            workspace=workspace,
            metrics=AgentMetrics(),
            runtime_policy=runtime_policy,
            scope_guard=AgentScopeGuard(
                getattr(self.framework, "scope_manager", None),
                runtime_policy,
            ),
            network_budget=NetworkBudget(request_budget),
            cancellation_token=CancellationToken(),
            run_store=run_store,
            session_policy="never",
            knowledge_base=self._bootstrap_lab_context(suite, lab_attestation=lab_attestation),
        )
        freeze_learning_for_benchmark(state, suite_id=suite.id)

        error: Optional[str] = None
        try:
            final_state = self._agent.run_agent_flow(state)
            state_dict = agent_state_checkpoint_dict(final_state)
        except Exception as exc:
            error = str(exc)[:500]
            state_dict = agent_state_checkpoint_dict(state)

        events = []
        try:
            _, events = load_state_from_run_store(run_store)
        except Exception:
            events = []

        duration = max(0.0, time.monotonic() - started)
        return extract_run_metrics(
            run_index=run_index,
            run_id=run_id,
            state=state_dict,
            suite=suite,
            seed=seed,
            duration_seconds=duration,
            events=events,
            error=error,
        )

    def _score_offline(
        self,
        suite: BenchmarkSuite,
        *,
        run_ids: Optional[Sequence[str]],
        seed: Optional[int],
        model: Optional[str],
        output_path: Optional[str],
    ) -> AgentBenchmarkResult:
        ids = list(run_ids or [])
        if not ids:
            if self.paths.runs_dir.is_dir():
                ids = sorted(
                    path.name for path in self.paths.runs_dir.iterdir() if path.is_dir()
                )[-10:]
            else:
                ids = []

        config = {
            "runs": len(ids),
            "seed": seed,
            "model": model or "offline",
            "target": suite.target,
            "goal": suite.goal,
            "profile": suite.profile,
            "dry_run": True,
            "offline": True,
        }
        result = AgentBenchmarkResult(
            suite=suite.id,
            suite_version=suite.suite_version,
            config=config,
            north_star=aggregate_north_star([]),
            outcome_verdicts=aggregate_outcome_verdicts([]),
            metadata={"suite": suite.to_dict(), "mode": "offline"},
        )

        for index, run_id in enumerate(ids):
            store = AgentRunStore(self.paths, str(run_id))
            try:
                state, events = load_state_from_run_store(store)
            except Exception as exc:
                result.runs.append(
                    extract_run_metrics(
                        run_index=index,
                        run_id=str(run_id),
                        state={},
                        suite=suite,
                        seed=seed,
                        error=str(exc)[:500],
                    )
                )
                continue
            result.runs.append(
                extract_run_metrics(
                    run_index=index,
                    run_id=str(run_id),
                    state=state,
                    suite=suite,
                    seed=seed,
                    events=events,
                )
            )

        return self._finalize_result(result, output_path=output_path)

    def _finalize_result(
        self,
        result: AgentBenchmarkResult,
        *,
        output_path: Optional[str],
    ) -> AgentBenchmarkResult:
        result.north_star = aggregate_north_star(result.runs)
        result.outcome_verdicts = aggregate_outcome_verdicts(result.runs)
        result.failure_causes = rank_failure_causes(result.runs)
        completed = sum(1 for row in result.runs if row.mission_completed)
        total = len(result.runs)
        from interfaces.command_system.builtin.agent.benchmark.phase3_validation import wilson_ci

        lo, hi = wilson_ci(completed, total)
        result.metadata["mcr"] = {
            "successes": completed,
            "total": total,
            "rate": (completed / total) if total else 0.0,
            "wilson_ci95": [round(lo, 4), round(hi, 4)],
        }
        result.finalize()
        payload = result.to_dict()
        try:
            validate_instance("agent_benchmark_result", payload)
        except SchemaValidationError:
            raise
        if output_path:
            path = Path(output_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            latest = path.parent / f"{result.suite}_live_latest.json"
            with latest.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            result.metadata["output_path"] = str(path)
            result.metadata["latest_path"] = str(latest)
        else:
            default_dir = Path("artifacts") / "benchmarks"
            default_dir.mkdir(parents=True, exist_ok=True)
            default_path = default_dir / f"{result.id}.json"
            with default_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            latest = default_dir / f"{result.suite}_live_latest.json"
            with latest.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            result.metadata["output_path"] = str(default_path)
            result.metadata["latest_path"] = str(latest)
        return result
