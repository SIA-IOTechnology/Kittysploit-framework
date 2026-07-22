#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Suggest recovery pivots after module failures and false positives."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.typed_models import ActionOutcome, AgentAction, Hypothesis


RECOVERY_STRATEGIES: Dict[str, List[str]] = {
    "module_error": ["retry_readonly_probe", "swap_module_family", "reduce_scope"],
    "timeout": ["reduce_threads", "swap_module_family", "retry_readonly_probe"],
    "invalid_option": ["drop_option_patch", "retry_readonly_probe"],
    "protocol_mismatch": ["service_fingerprint", "swap_module_family"],
    "false_positive": ["refute_hypothesis", "require_evidence_gate"],
    "unstable_session": ["session_stabilize", "retry_readonly_probe"],
    "no_signal": ["swap_module_family", "expand_surface"],
}


class RecoveryPlanner:
    """Map failure classes to bounded recovery actions (no direct execution)."""

    def suggest(
        self,
        outcome: ActionOutcome,
        *,
        hypotheses: Optional[Sequence[Hypothesis]] = None,
        available_modules: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> List[AgentAction]:
        failure_class = self.classify_failure(outcome)
        strategies = list(RECOVERY_STRATEGIES.get(failure_class, ["swap_module_family"]))
        actions: List[AgentAction] = []
        modules = list(available_modules or [])
        current = str(outcome.module_path or "")

        for strategy in strategies[:3]:
            if strategy == "retry_readonly_probe" and current:
                actions.append(AgentAction(
                    type="run_followup",
                    path=current,
                    risk="read",
                    reason=f"recovery:{failure_class}:readonly_retry",
                    status="planned",
                ))
            elif strategy == "swap_module_family" and modules:
                alternate = self._pick_alternate_module(current, modules)
                if alternate:
                    actions.append(AgentAction(
                        type="run_followup",
                        path=alternate,
                        risk="active",
                        reason=f"recovery:{failure_class}:alternate_module",
                        status="planned",
                    ))
            elif strategy == "refute_hypothesis":
                for hyp in hypotheses or []:
                    if hyp.module_path == current and hyp.status == "open":
                        actions.append(AgentAction(
                            type="skip",
                            path=current,
                            reason=f"recovery:refute:{hyp.id}",
                            status="planned",
                        ))
            elif strategy == "require_evidence_gate":
                actions.append(AgentAction(
                    type="collect",
                    path=current,
                    risk="read",
                    reason=f"recovery:{failure_class}:evidence_gate",
                    status="planned",
                ))
            elif strategy == "expand_surface":
                actions.append(AgentAction(
                    type="run_followup",
                    path="auxiliary/scanner/http/crawler",
                    risk="read",
                    reason=f"recovery:{failure_class}:expand_surface",
                    status="planned",
                ))

        return actions[:3]

    @staticmethod
    def classify_failure(outcome: ActionOutcome) -> str:
        verdict = str(outcome.verdict or "").lower()
        message = str(outcome.message or outcome.raw_summary.get("error") or "").lower()
        if verdict == "refuted":
            return "false_positive"
        if verdict == "module_error":
            if "timeout" in message:
                return "timeout"
            if "option" in message or "invalid" in message:
                return "invalid_option"
            return "module_error"
        if verdict == "no_signal":
            return "no_signal"
        if "session" in message and ("lost" in message or "unstable" in message):
            return "unstable_session"
        if "protocol" in message or "banner" in message:
            return "protocol_mismatch"
        return verdict or "no_signal"

    @staticmethod
    def _pick_alternate_module(current: str, modules: Sequence[Mapping[str, Any]]) -> Optional[str]:
        current_l = current.lower()
        family = current_l.split("/")[0] if "/" in current_l else ""
        for row in modules:
            path = str(row.get("path") or "")
            if not path or path.lower() == current_l:
                continue
            if family and path.lower().startswith(family):
                return path
        for row in modules:
            path = str(row.get("path") or "")
            if path and path.lower() != current_l:
                return path
        return None
