#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent-aware adapter around the framework's central module executor."""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor
from interfaces.command_system.builtin.agent.action_trace import ActionTraceRecorder
from interfaces.command_system.builtin.agent.egress_gateway import (
    EgressRevokedError,
    assert_egress_allowed,
    register_pending_egress,
    release_pending_egress,
    revalidate_module_execution,
)
from interfaces.command_system.builtin.agent.module_isolation import (
    execution_isolation_context,
    isolation_profile,
    should_use_runtime_kernel,
)
from interfaces.command_system.builtin.agent.module_quarantine import evaluate_module_quarantine
from interfaces.command_system.builtin.agent.outcome_pipeline import enrich_execution_payload
from interfaces.command_system.builtin.agent.runtime_policy import (
    ScopeViolationError,
    action_is_non_idempotent,
    assess_module_risk,
    evaluate_module_catalog_policy,
    evaluate_module_policy,
)


class AgentModuleExecutionService:
    def __init__(self, framework: Any) -> None:
        self.framework = framework

    @staticmethod
    def _finish(recorder: ActionTraceRecorder, payload: Dict[str, Any]) -> Dict[str, Any]:
        recorder.finalize(payload)
        return payload

    def execute(
        self,
        module_instance: Any,
        module_path: str,
        state: Any,
        *,
        phase: str,
        use_exploit_wrapper: bool = False,
        candidates: Optional[Sequence[str]] = None,
        score: Optional[float] = None,
        decision_source: Optional[str] = None,
        option_patch: Optional[Dict[str, Any]] = None,
    ):
        recorder = ActionTraceRecorder(
            state,
            phase=phase,
            module_path=module_path,
            candidates=candidates,
            score=score,
            decision_source=decision_source,
        )
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
            return self._finish(recorder, {
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
            })
        if policy is not None:
            block = evaluate_module_catalog_policy(
                policy,
                module_instance,
                module_path,
                phase=phase,
                knowledge_base=getattr(state, "knowledge_base", {}),
            )
            if block is not None:
                metrics = getattr(state, "metrics", None)
                if metrics is not None:
                    metrics.approvals_denied = int(getattr(metrics, "approvals_denied", 0)) + 1
                return self._finish(recorder, {
                    "blocked": True,
                    "error": block.reason,
                    "risk": risk,
                    "execution": None,
                    "policy_block": block.to_dict(),
                })
        if getattr(state, "dry_run", False):
            iso = isolation_profile(module_path, module_instance)
            return self._finish(recorder, {
                "blocked": False,
                "error": "",
                "risk": risk,
                "execution": None,
                "planned": True,
                "isolation": iso,
            })

        health = getattr(state, "module_health", None)
        if health is not None:
            kb = getattr(state, "knowledge_base", {}) or {}
            target_info = getattr(state, "target_info", {}) or {}
            quarantine = evaluate_module_quarantine(
                health,
                module_path,
                kb if isinstance(kb, dict) else {},
                service=str(target_info.get("service") or ""),
                os_name=str(target_info.get("os") or target_info.get("os_name") or ""),
            )
            if quarantine.quarantined:
                return self._finish(recorder, {
                    "blocked": True,
                    "error": f"module quarantined: {quarantine.reason}",
                    "risk": risk,
                    "execution": None,
                    "quarantine": quarantine.to_dict(),
                    "skipped": True,
                })

        option_resolution = None
        if option_patch:
            option_resolution = self._apply_option_patch(
                module_instance,
                module_path,
                state,
                option_patch,
                risk=risk,
                phase=phase,
            )
            if option_resolution is not None and not option_resolution.accepted and option_resolution.policy_verdict == "denied":
                return self._finish(recorder, {
                    "blocked": True,
                    "error": option_resolution.reason or "OptionPatch denied",
                    "risk": risk,
                    "execution": None,
                    "option_resolution": option_resolution.to_dict(),
                })

        try:
            block = revalidate_module_execution(
                state,
                module_path=module_path,
                phase=phase,
                risk=risk,
            )
            if block is not None:
                metrics = getattr(state, "metrics", None)
                if metrics is not None:
                    metrics.approvals_denied = int(getattr(metrics, "approvals_denied", 0)) + 1
                return self._finish(recorder, {
                    "blocked": True,
                    "error": block.reason,
                    "risk": risk,
                    "execution": None,
                    "policy_block": block.to_dict(),
                })
            from interfaces.command_system.builtin.agent.scope_lateral import gate_lateral_execution

            lateral_reason = gate_lateral_execution(state, module_path, module_instance)
            if lateral_reason:
                return self._finish(recorder, {
                    "blocked": True,
                    "error": f"scope lateral gate: {lateral_reason}",
                    "risk": risk,
                    "execution": None,
                    "policy_block": {
                        "phase": phase,
                        "module": module_path,
                        "risk": risk.level,
                        "reason": lateral_reason,
                        "approval_needed": False,
                    },
                })
            register_pending_egress(action_key)
            assert_egress_allowed()
        except (EgressRevokedError, ScopeViolationError) as exc:
            metrics = getattr(state, "metrics", None)
            if metrics is not None:
                metrics.scope_blocks = int(getattr(metrics, "scope_blocks", 0)) + 1
            return self._finish(recorder, {
                "blocked": True,
                "error": str(getattr(exc, "reason", "") or exc),
                "risk": risk,
                "execution": None,
                "policy_block": {
                    "phase": phase,
                    "module": module_path,
                    "risk": risk.level,
                    "reason": str(getattr(exc, "reason", "") or exc),
                    "approval_needed": False,
                },
            })

        approved = bool(policy is not None and policy.risk_approved(risk))
        iso = isolation_profile(module_path, module_instance)
        from interfaces.command_system.builtin.agent.credential_vault import resolve_module_instance_options

        resolve_module_instance_options(module_instance, state)
        request = ModuleExecutionRequest(
            module=module_instance,
            skip_scope_confirm=approved,
            use_runtime_kernel=should_use_runtime_kernel(self.framework, module_path, module_instance),
            use_exploit_wrapper=use_exploit_wrapper,
            collect_metrics=True,
        )
        try:
            with execution_isolation_context(self.framework, module_path, module_instance):
                result = ModuleExecutor.execute(self.framework, request)
        finally:
            release_pending_egress(action_key)
        if not result.blocked and not getattr(state, "dry_run", False):
            executed_actions = list(getattr(state, "executed_actions", []) or [])
            executed_actions.append(action_key)
            state.executed_actions = executed_actions
        payload: Dict[str, Any] = {
            "blocked": bool(result.blocked),
            "error": result.error or "",
            "risk": risk,
            "execution": result,
            "planned": False,
            "isolation": iso,
        }
        if option_resolution is not None:
            payload["option_resolution"] = option_resolution.to_dict()
        from interfaces.command_system.builtin.agent.session_resilience import process_execution_resilience

        process_execution_resilience(state, module_path, payload)
        if not payload["blocked"] and payload.get("execution") is not None:
            enrich_execution_payload(
                payload,
                module_instance=module_instance,
                module_path=module_path,
                state=state,
                phase=phase,
                framework=self.framework,
            )
        return self._finish(recorder, payload)

    @staticmethod
    def _apply_option_patch(
        module_instance: Any,
        module_path: str,
        state: Any,
        option_patch: Dict[str, Any],
        *,
        risk: Any,
        phase: str,
    ):
        from interfaces.command_system.builtin.agent.module_contract import (
            ModuleContract,
            build_module_contract,
            known_option_keys,
        )
        from interfaces.command_system.builtin.agent.option_resolver import (
            resolve_option_patch,
            resolve_option_patch_with_contract,
        )
        from interfaces.command_system.builtin.agent.typed_models import OptionPatch

        patch = OptionPatch.from_dict({
            **dict(option_patch or {}),
            "module_path": module_path or str(option_patch.get("module_path") or ""),
        })
        agent_meta = None
        try:
            agent_meta = getattr(module_instance, "agent", None)
            if callable(agent_meta):
                agent_meta = agent_meta()
        except Exception:
            agent_meta = None
        options_schema: Dict[str, Any] = {}
        try:
            opts = getattr(module_instance, "options", None)
            if isinstance(opts, dict):
                for key, meta in opts.items():
                    if isinstance(meta, dict):
                        options_schema[str(key).lower()] = meta
                    else:
                        options_schema[str(key).lower()] = {"type": "string"}
        except Exception:
            options_schema = {}
        contract = build_module_contract(
            module_path,
            agent_meta=agent_meta if isinstance(agent_meta, dict) else None,
            options_schema=options_schema or None,
        )
        if contract is None:
            contract = ModuleContract(module_path=module_path, options_schema=options_schema)
        base_options: Dict[str, Any] = {}
        for key in known_option_keys(contract) or options_schema.keys():
            try:
                if hasattr(module_instance, "get_option"):
                    base_options[key] = module_instance.get_option(key)
            except Exception:
                continue
        if known_option_keys(contract):
            resolution = resolve_option_patch_with_contract(
                patch,
                contract,
                base_options=base_options,
                require_evidence=True,
                runtime_policy=getattr(state, "runtime_policy", None),
                risk=risk,
                phase=phase,
            )
        else:
            resolution = resolve_option_patch(patch, base_options=base_options, require_evidence=True)
        if not resolution.accepted and resolution.policy_verdict == "denied":
            return resolution
        for key, value in (resolution.redacted_diff or {}).items():
            try:
                if hasattr(module_instance, "set_option"):
                    module_instance.set_option(key, value)
            except Exception:
                continue
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            journal = list(kb.get("option_patch_journal") or [])
            journal.append({
                "module_path": module_path,
                "patch_id": resolution.patch_id,
                "verdict": resolution.policy_verdict,
                "redacted_diff": dict(resolution.redacted_diff or {}),
                "rejected_keys": list(resolution.rejected_keys or []),
                "reason": resolution.reason,
            })
            kb["option_patch_journal"] = journal[-40:]
            state.knowledge_base = kb
        return resolution
