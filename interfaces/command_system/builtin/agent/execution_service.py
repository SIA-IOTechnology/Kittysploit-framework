#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent-aware adapter around the framework's central module executor."""

from __future__ import annotations

from typing import Any, Dict

from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor
from interfaces.command_system.builtin.agent.runtime_policy import (
    action_is_non_idempotent,
    assess_module_risk,
    evaluate_module_policy,
    module_policy_decision,
)


class AgentModuleExecutionService:
    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def execute(
        self,
        module_instance: Any,
        module_path: str,
        state: Any,
        *,
        phase: str,
        use_exploit_wrapper: bool = False,
    ):
        risk = assess_module_risk(module_instance, module_path)
        policy = getattr(state, "runtime_policy", None)
        action_key = f"{phase}:{module_path}"
        executed = set(getattr(state, "executed_actions", []) or [])
        if action_key in executed and action_is_non_idempotent(risk):
            block = evaluate_module_policy(
                policy,
                risk,
                phase=phase,
                module_path=module_path,
            )
            return {
                "blocked": True,
                "error": "non-idempotent action already executed; resume skipped replay",
                "risk": risk,
                "execution": None,
                "policy_block": (block.to_dict() if block else {
                    "phase": phase,
                    "module": module_path,
                    "risk": risk.level,
                    "reason": "non-idempotent resume guard",
                    "approval_needed": False,
                }),
            }
        if policy is not None:
            block = evaluate_module_policy(
                policy,
                risk,
                phase=phase,
                module_path=module_path,
            )
            if block is not None:
                metrics = getattr(state, "metrics", None)
                if metrics is not None:
                    metrics.approvals_denied = int(getattr(metrics, "approvals_denied", 0)) + 1
                return {
                    "blocked": True,
                    "error": block.reason,
                    "risk": risk,
                    "execution": None,
                    "policy_block": block.to_dict(),
                }
        if getattr(state, "dry_run", False):
            return {
                "blocked": False,
                "error": "",
                "risk": risk,
                "execution": None,
                "planned": True,
            }

        approved = bool(policy is not None and policy.risk_approved(risk))
        request = ModuleExecutionRequest(
            module=module_instance,
            skip_scope_confirm=approved,
            use_runtime_kernel=False,
            use_exploit_wrapper=use_exploit_wrapper,
            collect_metrics=True,
        )
        result = ModuleExecutor.execute(self.framework, request)
        if not result.blocked and not getattr(state, "dry_run", False):
            executed_actions = list(getattr(state, "executed_actions", []) or [])
            executed_actions.append(action_key)
            state.executed_actions = executed_actions
        return {
            "blocked": bool(result.blocked),
            "error": result.error or "",
            "risk": risk,
            "execution": result,
            "planned": False,
        }
