#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module batch execution with budget, safety profile, and WAF hooks."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from interfaces.command_system.builtin.agent.network_budget import module_budget_units, try_consume_budget


class ModuleRunnerHooks(Protocol):
    def normalized_safety_profile(self, state: Any) -> str: ...
    def filter_modules_for_safety_profile(
        self, state: Any, modules: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]: ...
    def phase_stop_reason(self, state: Any, phase: str) -> Optional[str]: ...
    def sleep_between_agent_actions(self, state: Any, label: str) -> None: ...
    def adapt_rate_limit_from_results(self, state: Any, results: List[Any]) -> None: ...
    def record_waf_signals_from_results(
        self, state: Any, results: List[Any], phase_name: str
    ) -> bool: ...


class WorkflowModuleRunnerHooks:
    """Bridge ``AgentWorkflowCore`` private helpers to :class:`AgentModuleRunner`."""

    def __init__(self, core: Any) -> None:
        self._core = core

    def normalized_safety_profile(self, state: Any) -> str:
        return self._core._normalized_safety_profile(state)

    def filter_modules_for_safety_profile(self, state, modules):
        return self._core._filter_modules_for_safety_profile(state, modules)

    def phase_stop_reason(self, state, phase):
        return self._core._phase_stop_reason(state, phase)

    def sleep_between_agent_actions(self, state, label):
        return self._core._sleep_between_agent_actions(state, label)

    def adapt_rate_limit_from_results(self, state, results):
        return self._core._adapt_rate_limit_from_results(state, results)

    def record_waf_signals_from_results(self, state, results, phase_name):
        return self._core._record_waf_signals_from_results(state, results, phase_name)


class AgentModuleRunner:
    """Execute scanner modules under agent policy, budget, and pacing."""

    def __init__(self, hooks: ModuleRunnerHooks) -> None:
        self._hooks = hooks

    @staticmethod
    def module_uses_http_client(module: Any) -> bool:
        if isinstance(module, dict):
            path = str(module.get("path", "")).lower()
            return "/http/" in f"/{path}/" or "/cloud/" in f"/{path}/"
        return callable(getattr(module, "http_request", None))

    @staticmethod
    def budget_skip_result(module: Dict[str, Any], phase_name: str) -> Dict[str, Any]:
        path = module.get("path", "") if isinstance(module, dict) else ""
        return {
            "module": module.get("name", path) if isinstance(module, dict) else str(path),
            "path": path,
            "status": "skipped",
            "vulnerable": False,
            "message": f"{phase_name}: request budget exhausted before module launch",
            "details": {"reason": "request_budget_exhausted"},
        }

    def limit_modules_by_request_budget(
        self,
        state: Any,
        modules: List[Dict[str, Any]],
        phase_name: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        budget = getattr(state, "network_budget", None)
        if budget is not None and budget.bounded:
            remaining = budget.remaining or 0
        else:
            request_budget = int(getattr(state, "request_budget", 0) or 0)
            if request_budget <= 0:
                return list(modules or []), []
            used = int(getattr(getattr(state, "metrics", None), "network_units_used", 0) or 0)
            remaining = max(0, request_budget - used)
        if remaining <= 0:
            skipped = [self.budget_skip_result(m, phase_name) for m in modules or []]
            metrics = getattr(state, "metrics", None)
            if metrics is not None:
                metrics.network_units_skipped = int(
                    getattr(metrics, "network_units_skipped", 0)
                ) + len(skipped)
            return [], skipped
        allowed: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        units_left = remaining
        for module in modules or []:
            units = module_budget_units(module, str(module.get("path", "")))
            if self.module_uses_http_client(module):
                allowed.append(module)
                continue
            if units_left < units:
                skipped.append(self.budget_skip_result(module, phase_name))
                continue
            allowed.append(module)
            units_left -= units
        if skipped:
            metrics = getattr(state, "metrics", None)
            if metrics is not None:
                metrics.network_units_skipped = int(
                    getattr(metrics, "network_units_skipped", 0)
                ) + len(skipped)
        return allowed, skipped

    def consume_network_units(
        self,
        state: Any,
        units: int = 1,
        *,
        reason: str = "non-HTTP agent network operation",
        module: Any = None,
        module_path: str = "",
        phase: str = "",
    ) -> bool:
        if module is not None or module_path:
            units = module_budget_units(
                module if module is not None else {"path": module_path},
                module_path,
                units,
            )
        return try_consume_budget(
            state,
            units,
            reason=reason,
            phase=phase or str(getattr(state, "current_phase", "") or ""),
        )

    def execute_agent_modules(
        self,
        state: Any,
        scanner: Any,
        modules: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        threads: int,
        verbose: bool,
        phase_name: str = "phase",
        *,
        elite_auto_correct: Optional[Callable[[Any, Any, List[Dict[str, Any]]], None]] = None,
    ) -> List[Dict[str, Any]]:
        allowed, skipped = self._hooks.filter_modules_for_safety_profile(state, modules)
        allowed, budget_skipped = self.limit_modules_by_request_budget(state, allowed, phase_name)
        skipped.extend(budget_skipped)
        if not allowed:
            return skipped

        profile = self._hooks.normalized_safety_profile(state)
        effective_threads = 1 if profile in ("safe", "discreet") else max(1, int(threads or 1))
        results: List[Dict[str, Any]] = list(skipped)

        if profile in ("safe", "discreet") or float(getattr(state, "phase_timeout", 0.0) or 0.0) > 0:
            for module in allowed:
                if self._hooks.phase_stop_reason(state, phase_name):
                    break
                if not self.module_uses_http_client(module) and not self.consume_network_units(
                    state,
                    module=module,
                    module_path=str(module.get("path", "")),
                    reason=f"module {module.get('path', '')}",
                    phase=phase_name,
                ):
                    results.append(self.budget_skip_result(module, phase_name))
                    continue
                self._hooks.sleep_between_agent_actions(
                    state, f"{phase_name}:{module.get('path', '')}"
                )
                batch_results = scanner._execute_modules([module], target_info, 1, verbose)
                results.extend(batch_results)
                self._hooks.adapt_rate_limit_from_results(state, batch_results)
                if self._hooks.record_waf_signals_from_results(state, batch_results, phase_name):
                    break
            return results

        fallback_units = sum(
            module_budget_units(row, str(row.get("path", "")))
            for row in allowed
            if not self.module_uses_http_client(row)
        )
        if fallback_units and not self.consume_network_units(
            state,
            fallback_units,
            reason=f"{phase_name} module batch",
            phase=phase_name,
        ):
            results.extend([self.budget_skip_result(module, phase_name) for module in allowed])
            return results
        self._hooks.sleep_between_agent_actions(state, phase_name)
        batch_results = scanner._execute_modules(allowed, target_info, effective_threads, verbose)
        if elite_auto_correct is not None:
            elite_auto_correct(state, scanner, batch_results)
        results.extend(batch_results)
        self._hooks.adapt_rate_limit_from_results(state, batch_results)
        self._hooks.record_waf_signals_from_results(state, batch_results, phase_name)
        return results
