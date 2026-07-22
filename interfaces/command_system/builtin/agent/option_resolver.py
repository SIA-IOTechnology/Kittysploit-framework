#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve LLM-proposed option patches with protected field enforcement."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Set

from interfaces.command_system.builtin.agent.module_contract import ModuleContract, known_option_keys
from interfaces.command_system.builtin.agent.runtime_policy import (
    AgentRuntimePolicy,
    ModuleRisk,
    evaluate_module_policy,
)
from interfaces.command_system.builtin.agent.typed_models import OptionPatch, OptionResolution

PROTECTED_OPTION_KEYS: Set[str] = {
    "target",
    "rhost",
    "lhost",
    "rport",
    "lport",
    "scope",
    "destination",
    "callback",
    "listener",
    "payload",
    "credentials",
    "username",
    "password",
    "proxy",
    "proxies",
    "egress",
    "ssl",
    "domain",
}


def resolve_option_patch(
    patch: OptionPatch,
    *,
    base_options: Optional[Mapping[str, Any]] = None,
    require_evidence: bool = True,
) -> OptionResolution:
    merged = dict(base_options or {})
    rejected: list[str] = []
    redacted_diff: Dict[str, Any] = {}

    if require_evidence and patch.options and not patch.evidence_ids:
        return OptionResolution(
            patch_id=patch.id,
            accepted=False,
            merged_options=merged,
            rejected_keys=sorted(patch.options.keys()),
            policy_verdict="denied",
            reason="OptionPatch requires evidence_ids for contextual overrides",
        )

    for key, value in (patch.options or {}).items():
        normalized = str(key).strip().lower()
        if normalized in PROTECTED_OPTION_KEYS or any(
            protected in normalized for protected in PROTECTED_OPTION_KEYS
        ):
            rejected.append(normalized)
            continue
        merged[normalized] = value
        redacted_diff[normalized] = value

    accepted = bool(redacted_diff) or not patch.options
    verdict = "accepted" if accepted else "denied"
    if rejected and redacted_diff:
        verdict = "partial"
    reason = None
    if rejected:
        reason = f"Protected keys rejected: {', '.join(rejected[:8])}"

    return OptionResolution(
        patch_id=patch.id,
        accepted=accepted or verdict == "partial",
        merged_options=merged,
        rejected_keys=rejected,
        policy_verdict=verdict,
        redacted_diff=redacted_diff,
        reason=reason,
    )


def resolve_option_patch_with_contract(
    patch: OptionPatch,
    contract: ModuleContract,
    *,
    base_options: Optional[Mapping[str, Any]] = None,
    require_evidence: bool = True,
    runtime_policy: Optional[AgentRuntimePolicy] = None,
    risk: Optional[ModuleRisk] = None,
    phase: str = "act",
    scope_revalidate: Optional[Callable[[Mapping[str, Any]], Optional[str]]] = None,
) -> OptionResolution:
    """Apply schema-aware option resolution with unknown-key rejection and policy re-check."""
    allowed_keys = known_option_keys(contract)
    resolution = resolve_option_patch(
        patch,
        base_options=base_options,
        require_evidence=require_evidence,
    )
    if resolution.policy_verdict == "denied" and not resolution.redacted_diff:
        return resolution

    merged = dict(resolution.merged_options or {})
    rejected = list(resolution.rejected_keys or [])
    redacted_diff = dict(resolution.redacted_diff or {})
    unknown: list[str] = []

    if allowed_keys:
        for key in list((patch.options or {}).keys()):
            normalized = str(key).strip().lower()
            if normalized in rejected:
                continue
            if normalized not in allowed_keys:
                unknown.append(normalized)
                merged.pop(normalized, None)
                redacted_diff.pop(normalized, None)

    reason_parts = [resolution.reason] if resolution.reason else []
    if unknown:
        reason_parts.append(f"Unknown options rejected: {', '.join(sorted(unknown)[:8])}")

    if runtime_policy is not None and risk is not None:
        block = evaluate_module_policy(
            runtime_policy,
            risk,
            phase=phase,
            module_path=contract.module_path,
        )
        if block is not None:
            return OptionResolution(
                patch_id=patch.id,
                accepted=False,
                merged_options=merged,
                rejected_keys=sorted(set(rejected + unknown)),
                policy_verdict="denied",
                redacted_diff=redacted_diff,
                reason=block.reason,
            )

    if scope_revalidate is not None:
        scope_reason = scope_revalidate(merged)
        if scope_reason:
            return OptionResolution(
                patch_id=patch.id,
                accepted=False,
                merged_options=merged,
                rejected_keys=sorted(set(rejected + unknown)),
                policy_verdict="denied",
                redacted_diff=redacted_diff,
                reason=f"scope revalidation failed: {scope_reason}",
            )

    if unknown and not redacted_diff:
        verdict = "denied"
        accepted = False
    elif unknown:
        verdict = "partial"
        accepted = True
    else:
        verdict = resolution.policy_verdict
        accepted = resolution.accepted

    return OptionResolution(
        patch_id=patch.id,
        accepted=accepted,
        merged_options=merged,
        rejected_keys=sorted(set(rejected + unknown)),
        policy_verdict=verdict,
        redacted_diff=redacted_diff,
        reason="; ".join(part for part in reason_parts if part) or None,
    )
