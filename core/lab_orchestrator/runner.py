#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor
from core.lab_orchestrator.loader import default_labs_dir, find_lab_scenario
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

    def start_lab(self, scenario: LabScenario) -> bool:
        module = self.framework.module_loader.load_module(
            scenario.environment,
            framework=self.framework,
        )
        if module is None:
            raise RuntimeError(f"Could not load environment module: {scenario.environment}")

        for option_name, value in scenario.environment_options.items():
            if hasattr(module, "set_option"):
                module.set_option(option_name, value)
            elif hasattr(module, option_name):
                setattr(module, option_name, value)

        result = module.run()
        started = bool(result) if result is not None else False
        self.save_state(
            scenario.id,
            {
                "lab_id": scenario.id,
                "environment": scenario.environment,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "started": started,
                "container_name": scenario.reset.get("container_name")
                or scenario.environment_options.get("container_name"),
            },
        )
        return started

    def reset_lab(self, scenario: LabScenario) -> bool:
        container_name = scenario.reset.get("container_name") or scenario.environment_options.get("container_name")
        if container_name:
            self._stop_container(container_name, remove=True)

        started = self.start_lab(scenario)
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "reset_at": datetime.now(timezone.utc).isoformat(),
                "started": started,
            },
        )
        return started

    def score_lab(self, scenario: LabScenario) -> LabRunResult:
        results: list[LabObjectiveResult] = []
        earned = 0
        for objective in scenario.objectives:
            passed, detail = self._evaluate_check(objective.check)
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

        run_result = LabRunResult(
            lab_id=scenario.id,
            started=bool(self.load_state(scenario.id).get("started")),
            score=earned,
            max_score=scenario.max_score,
            objectives=results,
        )
        self.save_state(
            scenario.id,
            {
                **self.load_state(scenario.id),
                "last_score": run_result.to_dict(),
                "scored_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return run_result

    def run_lab(self, scenario: LabScenario, *, skip_start: bool = False) -> LabRunResult:
        if not skip_start:
            if not self.start_lab(scenario):
                return LabRunResult(
                    lab_id=scenario.id,
                    started=False,
                    score=0,
                    max_score=scenario.max_score,
                    error="Failed to start lab environment",
                )
        return self.score_lab(scenario)

    def _evaluate_check(self, check: Dict[str, Any]) -> tuple[bool, str]:
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
        return False, f"Unsupported check type: {check_type or 'unknown'}"

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
