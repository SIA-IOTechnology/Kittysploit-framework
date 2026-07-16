#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor
from core.lab_orchestrator.agent_verifiers import evaluate_agent_check, load_agent_run_context
from core.lab_orchestrator.attestation import (
    apply_manifest_environment_options,
    build_reset_attestation,
    verify_reset_attestation,
)
from core.lab_orchestrator.loader import default_labs_dir, find_lab_scenario
from core.lab_orchestrator.manifest import find_ground_truth_manifest
from core.lab_orchestrator.models import LabObjectiveResult, LabRunResult, LabScenario
from core.utils.paths import framework_root


class LabOrchestrator:
    """Start docker environments, score objectives, reset labs, and run validation games."""

    def __init__(self, framework, *, labs_dir: Path | None = None):
        self.framework = framework
        self.labs_dir = labs_dir or default_labs_dir()
        root = framework_root()
        self.state_root = (root / "artifacts" / "labs") if root else Path("artifacts/labs")

    def _state_path(self, lab_id: str) -> Path:
        return self.state_root / lab_id / "state.json"

    def load_state(self, lab_id: str) -> Dict[str, Any]:
        path = self._state_path(lab_id)
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return {}

    def save_state(self, lab_id: str, payload: Dict[str, Any]) -> None:
        path = self._state_path(lab_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def get_scenario(self, lab_id: str) -> LabScenario:
        return find_lab_scenario(lab_id, self.labs_dir)

    def get_manifest(self, scenario: LabScenario):
        manifest_id = str(scenario.manifest or scenario.id or "").strip()
        if not manifest_id:
            return None
        try:
            return find_ground_truth_manifest(manifest_id)
        except FileNotFoundError:
            return None

    def get_reset_attestation(self, lab_id: str) -> Dict[str, Any]:
        return dict(self.load_state(lab_id).get("reset_attestation") or {})

    def verify_reset_attestation(
        self,
        scenario: LabScenario,
        *,
        require_digest_pin: bool = False,
    ) -> tuple[bool, str]:
        manifest = self.get_manifest(scenario)
        if manifest is None:
            return False, f"Manifest not found for lab {scenario.id}"
        return verify_reset_attestation(
            self.get_reset_attestation(scenario.id),
            manifest,
            require_digest_pin=require_digest_pin,
        )

    def _record_reset_attestation(
        self,
        scenario: LabScenario,
        *,
        event: str,
        readiness_passed: bool,
        image_digest: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        manifest = self.get_manifest(scenario)
        if manifest is None:
            return {}
        attestation = build_reset_attestation(
            lab_id=scenario.id,
            manifest=manifest,
            image_digest=image_digest,
            readiness_passed=readiness_passed,
            event=event,
            extra=extra,
        )
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "reset_attestation": attestation,
            },
        )
        return attestation

    def start_lab(self, scenario: LabScenario) -> bool:
        module = self.framework.module_loader.load_module(
            scenario.environment,
            framework=self.framework,
        )
        if module is None:
            raise RuntimeError(f"Could not load environment module: {scenario.environment}")

        options = dict(scenario.environment_options)
        manifest = self.get_manifest(scenario)
        if manifest is not None:
            options = apply_manifest_environment_options(options, manifest)

        for option_name, value in options.items():
            if hasattr(module, "set_option"):
                module.set_option(option_name, value)
            elif hasattr(module, option_name):
                setattr(module, option_name, value)

        result = module.run()
        started = bool(result) if result is not None else False
        readiness = {"passed": True, "checks": []}
        if started and scenario.readiness_checks:
            readiness = self._evaluate_readiness_checks(scenario.readiness_checks)
            started = bool(readiness.get("passed"))

        image_digest = ""
        digest_fn = getattr(module, "get_image_digest", None)
        if callable(digest_fn):
            image_digest = str(digest_fn() or "").strip()

        attestation = {}
        if manifest is not None:
            attestation = self._record_reset_attestation(
                scenario,
                event="start",
                readiness_passed=bool(readiness.get("passed")),
                image_digest=image_digest,
                extra={"container_name": options.get("container_name")},
            )

        self.save_state(
            scenario.id,
            {
                "lab_id": scenario.id,
                "environment": scenario.environment,
                "manifest": scenario.manifest,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "started": started,
                "readiness": readiness,
                "reset_attestation": attestation,
                "container_name": scenario.reset.get("container_name")
                or scenario.environment_options.get("container_name"),
            },
        )
        return started

    def stop_lab(self, scenario: LabScenario, *, remove: bool = True) -> bool:
        """Stop the lab environment without restarting it."""
        env_path = scenario.reset.get("environment") or scenario.environment
        provisioner = str(scenario.reset.get("provisioner") or "").lower()
        state = self.load_state(scenario.id)

        if provisioner == "vagrant" or "vagrant_environments/" in str(env_path):
            module = self.framework.module_loader.load_module(
                env_path,
                framework=self.framework,
            )
            if module is None:
                raise RuntimeError(f"Could not load vagrant environment: {env_path}")
            for option_name, value in scenario.environment_options.items():
                if hasattr(module, "set_option"):
                    module.set_option(option_name, value)
                elif hasattr(module, option_name):
                    setattr(module, option_name, value)
            destroy_fn = getattr(module, "destroy_vm", None)
            if callable(destroy_fn):
                stopped = bool(destroy_fn())
            else:
                stop_fn = getattr(module, "stop_container", None) or getattr(module, "cleanup", None)
                if not callable(stop_fn):
                    raise RuntimeError(f"Environment {env_path} has no destroy/stop method")
                stopped = bool(stop_fn())
            self.save_state(
                scenario.id,
                {
                    **state,
                    "stopped_at": datetime.now(timezone.utc).isoformat(),
                    "started": False,
                    "provisioner": "vagrant",
                },
            )
            return stopped

        container_name = (
            scenario.reset.get("container_name")
            or scenario.environment_options.get("container_name")
            or state.get("container_name")
        )
        network_name = scenario.reset.get("network_name") or scenario.environment_options.get("lab_network_name")
        remove_network = bool(scenario.reset.get("remove_network", False))

        if not container_name:
            raise RuntimeError(
                f"No container_name configured for lab '{scenario.id}'. "
                "Set reset.container_name or environment_options.container_name."
            )

        self._stop_container(str(container_name), remove=remove)

        if remove_network and network_name:
            self._remove_network(str(network_name))

        self.save_state(
            scenario.id,
            {
                **state,
                "stopped_at": datetime.now(timezone.utc).isoformat(),
                "started": False,
                "container_name": container_name,
            },
        )
        return True

    def reset_lab(self, scenario: LabScenario) -> bool:
        env_path = scenario.reset.get("environment") or scenario.environment
        provisioner = str(scenario.reset.get("provisioner") or "").lower()
        if provisioner == "vagrant" or "vagrant_environments/" in str(env_path):
            module = self.framework.module_loader.load_module(
                env_path,
                framework=self.framework,
            )
            if module is None:
                raise RuntimeError(f"Could not load vagrant environment: {env_path}")
            for option_name, value in scenario.environment_options.items():
                if hasattr(module, "set_option"):
                    module.set_option(option_name, value)
                elif hasattr(module, option_name):
                    setattr(module, option_name, value)
            reset_fn = getattr(module, "reset_lab", None)
            if callable(reset_fn):
                started = bool(reset_fn())
            else:
                started = bool(module.run())
            self.save_state(
                scenario.id,
                {
                    **self.load_state(scenario.id),
                    "reset_at": datetime.now(timezone.utc).isoformat(),
                    "started": started,
                    "provisioner": "vagrant",
                },
            )
            if started:
                manifest = self.get_manifest(scenario)
                if manifest is not None:
                    self._record_reset_attestation(
                        scenario,
                        event="reset",
                        readiness_passed=started,
                        extra={"provisioner": "vagrant"},
                    )
            return started

        # Stop without restarting first, then bring a clean environment back up.
        self.stop_lab(scenario, remove=True)

        started = self.start_lab(scenario)
        if started:
            self._record_reset_attestation(
                scenario,
                event="reset",
                readiness_passed=True,
                image_digest=str(self.get_reset_attestation(scenario.id).get("image_digest") or ""),
            )
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "reset_at": datetime.now(timezone.utc).isoformat(),
                "started": started,
            },
        )
        return started

    def score_lab(
        self,
        scenario: LabScenario,
        *,
        agent_run_id: Optional[str] = None,
    ) -> LabRunResult:
        results: list[LabObjectiveResult] = []
        earned = 0
        for objective in scenario.objectives:
            passed, detail = self._evaluate_check(objective.check, scenario)
            points = int(objective.points or 0)
            item = LabObjectiveResult(
                objective_id=objective.id,
                title=objective.title,
                passed=passed,
                points=points,
                earned=points if passed else 0,
                detail=detail,
            )
            results.append(item)
            earned += item.earned

        agent_results: list[LabObjectiveResult] = []
        agent_earned = 0
        run_id = str(agent_run_id or self.load_state(scenario.id).get("last_agent_run_id") or "").strip()
        if scenario.agent_objectives and run_id:
            manifest = self.get_manifest(scenario)
            lab_state = self.load_state(scenario.id)
            ctx = load_agent_run_context(self.framework, run_id)
            for objective in scenario.agent_objectives:
                check = dict(objective.check or {})
                if run_id and not check.get("run_id"):
                    check["run_id"] = run_id
                passed, detail = evaluate_agent_check(
                    check,
                    framework=self.framework,
                    manifest=manifest,
                    lab_state=lab_state,
                    ctx=ctx,
                )
                points = int(objective.points or 0)
                item = LabObjectiveResult(
                    objective_id=objective.id,
                    title=objective.title,
                    passed=passed,
                    points=points,
                    earned=points if passed else 0,
                    detail=detail,
                )
                agent_results.append(item)
                agent_earned += item.earned

        run_result = LabRunResult(
            lab_id=scenario.id,
            started=bool(self.load_state(scenario.id).get("started")),
            score=earned,
            max_score=scenario.max_score,
            objectives=results,
            agent_score=agent_earned,
            max_agent_score=scenario.max_agent_score,
            agent_objectives=agent_results,
            agent_run_id=run_id or None,
        )
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "last_score": run_result.to_dict(),
                "last_agent_run_id": run_id or self.load_state(scenario.id).get("last_agent_run_id"),
                "scored_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return run_result

    def verify_agent_run(self, scenario: LabScenario, run_id: str) -> LabRunResult:
        """Score only agent objectives for a completed agent run."""
        if not scenario.agent_objectives:
            return LabRunResult(
                lab_id=scenario.id,
                started=True,
                score=0,
                max_score=0,
                error="No agent_objectives defined for this lab",
            )

        manifest = self.get_manifest(scenario)
        lab_state = self.load_state(scenario.id)
        ctx = load_agent_run_context(self.framework, run_id)
        agent_results: list[LabObjectiveResult] = []
        agent_earned = 0
        for objective in scenario.agent_objectives:
            check = dict(objective.check or {})
            check["run_id"] = run_id
            passed, detail = evaluate_agent_check(
                check,
                framework=self.framework,
                manifest=manifest,
                lab_state=lab_state,
                ctx=ctx,
            )
            points = int(objective.points or 0)
            item = LabObjectiveResult(
                objective_id=objective.id,
                title=objective.title,
                passed=passed,
                points=points,
                earned=points if passed else 0,
                detail=detail,
            )
            agent_results.append(item)
            agent_earned += item.earned

        result = LabRunResult(
            lab_id=scenario.id,
            started=True,
            score=0,
            max_score=scenario.max_score,
            agent_score=agent_earned,
            max_agent_score=scenario.max_agent_score,
            agent_objectives=agent_results,
            agent_run_id=run_id,
        )
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "last_agent_run_id": run_id,
                "last_agent_verify": result.to_dict(),
                "agent_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return result

    def record_agent_run(self, lab_id: str, run_id: str) -> None:
        self.save_state(
            lab_id,
            {
                **self.load_state(lab_id),
                "last_agent_run_id": str(run_id),
                "last_agent_recorded_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    def run_lab(
        self,
        scenario: LabScenario,
        *,
        skip_start: bool = False,
        agent_run_id: Optional[str] = None,
    ) -> LabRunResult:
        if not skip_start:
            if not self.start_lab(scenario):
                return LabRunResult(
                    lab_id=scenario.id,
                    started=False,
                    score=0,
                    max_score=scenario.max_score,
                    error="Failed to start lab environment",
                )
        return self.score_lab(scenario, agent_run_id=agent_run_id)

    def _evaluate_check(self, check: Dict[str, Any], scenario: Optional[LabScenario] = None) -> tuple[bool, str]:
        check_type = str(check.get("type") or "").lower()
        if check_type == "tcp":
            return self._check_tcp(
                str(check.get("host") or "127.0.0.1"),
                int(check.get("port") or 0),
                timeout=float(check.get("timeout") or 3.0),
            )
        if check_type == "http":
            return self._check_http(check)
        if check_type == "module":
            return self._check_module(check)
        if check_type == "manifest":
            return self._check_manifest(check, scenario)
        return False, f"Unsupported check type: {check_type or 'unknown'}"

    def _evaluate_readiness_checks(self, checks: list[Dict[str, Any]]) -> Dict[str, Any]:
        rows = []
        for check in checks:
            passed, detail = self._evaluate_check(check)
            rows.append({
                "id": str(check.get("id") or ""),
                "passed": passed,
                "detail": detail,
            })
        return {
            "passed": all(row["passed"] for row in rows) if rows else True,
            "checks": rows,
        }

    def _check_manifest(self, check: Dict[str, Any], scenario: Optional[LabScenario]) -> tuple[bool, str]:
        if scenario is None:
            return False, "Manifest check requires lab scenario context"
        manifest = self.get_manifest(scenario)
        if manifest is None:
            return False, f"Manifest not found for lab {scenario.id}"

        assertion = str(check.get("assertion") or "").lower()
        expected = check.get("expected")

        if assertion == "network_internal":
            actual = bool(manifest.network.get("internal"))
            if actual == bool(expected):
                return True, f"network.internal={actual}"
            return False, f"Expected network.internal={expected}, got {actual}"

        if assertion == "service_count":
            required = manifest.required_services()
            actual = len(required)
            try:
                target = int(expected)
            except (TypeError, ValueError):
                target = 0
            if actual >= target:
                return True, f"{actual} required services declared"
            return False, f"Expected at least {target} required services, got {actual}"

        if assertion == "session_contract":
            session = manifest.session or {}
            if session.get("protocol") and session.get("port"):
                return True, f"Session contract: {session.get('protocol')}:{session.get('port')}"
            return False, "Session contract incomplete in manifest"

        return False, f"Unsupported manifest assertion: {assertion or 'unknown'}"

    def _check_tcp(self, host: str, port: int, *, timeout: float) -> tuple[bool, str]:
        if port <= 0:
            return False, "Invalid TCP port"
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, f"TCP {host}:{port} reachable"
        except OSError as exc:
            return False, f"TCP {host}:{port} unreachable: {exc}"

    def _check_http(self, check: Dict[str, Any]) -> tuple[bool, str]:
        url = str(check.get("url") or "")
        if not url:
            return False, "Missing HTTP url"
        timeout = float(check.get("timeout") or 10.0)
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            return False, f"HTTP request failed: {exc}"

        expected_status = check.get("expect_status")
        if expected_status is not None and response.status_code != int(expected_status):
            return False, f"Expected HTTP {expected_status}, got {response.status_code}"

        expected_text = check.get("expect_body_contains")
        if expected_text and expected_text not in response.text:
            return False, f"Response body missing expected text: {expected_text!r}"

        return True, f"HTTP {url} returned {response.status_code}"

    def _check_module(self, check: Dict[str, Any]) -> tuple[bool, str]:
        module_path = str(check.get("module") or "")
        if not module_path:
            return False, "Missing module path"

        module = self.framework.module_loader.load_module(
            module_path,
            load_only=True,
            framework=self.framework,
            silent=True,
        )
        if module is None:
            return False, f"Could not load module: {module_path}"

        options = dict(check.get("options") or {})
        for option_name, value in options.items():
            if hasattr(module, "set_option"):
                module.set_option(option_name, value)

        execution = ModuleExecutor.execute(
            self.framework,
            ModuleExecutionRequest(
                module=module,
                use_exploit_wrapper=False,
                collect_metrics=False,
            ),
        )
        if execution.blocked:
            return False, execution.error or "Module execution blocked"
        if execution.success or execution.command_success:
            return True, f"Module {module_path} completed successfully"
        return False, execution.error or f"Module {module_path} failed"

    def validate_golden_paths(
        self,
        *,
        os_name: str = "linux",
        live: bool = False,
        scenario: Optional[LabScenario] = None,
    ) -> Dict[str, Any]:
        """Validate golden-path module inventory; optionally run live module checks."""
        from interfaces.command_system.builtin.agent.golden_path_matrix import list_golden_paths
        from interfaces.command_system.builtin.agent.golden_path_validation import (
            build_lab_module_checks,
            validate_golden_path_catalog,
        )

        discovered = self.framework.module_loader.discover_modules()
        if not discovered:
            catalog = getattr(self.framework, "module_catalog", None)
            if catalog is not None and hasattr(catalog, "_get_module_catalog"):
                discovered = catalog._get_module_catalog()
        extract = getattr(self.framework, "extract_static_module_metadata", None)
        if extract is None:
            catalog = getattr(self.framework, "module_catalog", None)
            extract = getattr(catalog, "extract_static_module_metadata", None) if catalog else None
        if extract is None:
            from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService

            extract = ModuleCatalogService(self.framework).extract_static_module_metadata

        static_report = validate_golden_path_catalog(
            discovered,
            extract_metadata=extract,
            os_name=os_name,
            strict=False,
        )
        live_rows: List[Dict[str, Any]] = []
        if live and scenario is not None:
            manifest = self.get_manifest(scenario)
            env = dict(getattr(scenario, "environment_options", {}) or {})
            ports = {
                "http": int(env.get("web_port") or 80),
                "ssh": int(env.get("ssh_port") or 22),
                "ftp": int(env.get("ftp_port") or 21),
                "smb": int(env.get("smb_port") or 445),
                "mysql": int(env.get("mysql_port") or 3306),
            }
            creds = {}
            if manifest is not None:
                auth = dict(getattr(manifest, "credentials", {}) or {})
                creds = {
                    "username": str(auth.get("username") or ""),
                    "password": str(auth.get("password") or ""),
                }
            for golden in list_golden_paths(os_name=os_name):
                for check in build_lab_module_checks(
                    golden,
                    host="127.0.0.1",
                    ports=ports,
                    credentials=creds,
                ):
                    passed, detail = self._check_module(check)
                    live_rows.append(
                        {
                            "golden_path": golden.id,
                            "stage": check.get("stage"),
                            "module": check.get("module"),
                            "passed": passed,
                            "detail": detail,
                        }
                    )
        live_failed = [row for row in live_rows if not row.get("passed")]
        return {
            "ok": bool(static_report.get("ok")) and not live_failed,
            "static": static_report,
            "live": {"rows": live_rows, "failed": len(live_failed)},
        }

    def _remove_network(self, network_name: str) -> None:
        try:
            import docker

            client = docker.from_env()
            networks = client.networks.list(names=[network_name])
            for network in networks:
                network.remove()
        except Exception:
            return

    def _stop_container(self, container_name: str, *, remove: bool = False) -> None:
        try:
            import docker

            client = docker.from_env()
            container = client.containers.get(container_name)
            if container.status == "running":
                container.stop(timeout=15)
            if remove:
                container.remove(force=True)
        except Exception:
            return
