#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automatic deprioritization for modules with repeated contextual failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.golden_path_matrix import golden_path_for_service
from interfaces.command_system.builtin.agent.module_health_memory import ModuleHealthMemory


QUARANTINE_MULTIPLIER_THRESHOLD = 0.45
QUARANTINE_FAILURE_COUNT = 4


@dataclass
class QuarantineDecision:
    module_path: str
    quarantined: bool
    health_multiplier: float
    failure_count: int = 0
    reason: str = ""
    alternate_module: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_path": self.module_path,
            "quarantined": self.quarantined,
            "health_multiplier": self.health_multiplier,
            "failure_count": self.failure_count,
            "reason": self.reason,
            "alternate_module": self.alternate_module,
        }


def _failure_count(health: ModuleHealthMemory, module_path: str, kb: Dict[str, Any]) -> int:
    profile_rows = health.top_failures_for_profile(kb if isinstance(kb, dict) else {}, limit=64)
    total = 0
    for row in profile_rows:
        if str(row.get("module_path") or "") == module_path:
            total += int(row.get("count", 0) or 0)
    return total


def suggest_alternate_module(module_path: str, *, service: str = "", os_name: str = "") -> Optional[str]:
    path = str(module_path or "")
    if "http" in path:
        candidate = golden_path_for_service("http", os_name=os_name or "linux")
    else:
        candidate = golden_path_for_service(service, os_name=os_name)
    if candidate is None:
        return None
    for step in candidate.steps:
        if step.recovery_alternate and step.recovery_alternate != path:
            return step.recovery_alternate
        if step.module_path != path:
            return step.module_path
    return None


def evaluate_module_quarantine(
    health: ModuleHealthMemory,
    module_path: str,
    kb: Dict[str, Any],
    *,
    service: str = "",
    os_name: str = "",
) -> QuarantineDecision:
    multiplier = float(health.health_multiplier(module_path, kb if isinstance(kb, dict) else {}))
    failures = _failure_count(health, module_path, kb if isinstance(kb, dict) else {})
    quarantined = multiplier <= QUARANTINE_MULTIPLIER_THRESHOLD or failures >= QUARANTINE_FAILURE_COUNT
    reason = ""
    if quarantined:
        if failures >= QUARANTINE_FAILURE_COUNT:
            reason = f"failure_count>={QUARANTINE_FAILURE_COUNT}"
        else:
            reason = f"health_multiplier<={QUARANTINE_MULTIPLIER_THRESHOLD}"
    alternate = suggest_alternate_module(module_path, service=service, os_name=os_name) if quarantined else None
    return QuarantineDecision(
        module_path=module_path,
        quarantined=quarantined,
        health_multiplier=multiplier,
        failure_count=failures,
        reason=reason,
        alternate_module=alternate,
    )
