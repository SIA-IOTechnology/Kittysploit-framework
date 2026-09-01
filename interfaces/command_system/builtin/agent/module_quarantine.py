#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automatic deprioritization for modules with repeated contextual failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from interfaces.command_system.builtin.agent.golden_path_matrix import golden_path_for_service
from interfaces.command_system.builtin.agent.module_health_memory import ModuleHealthMemory


QUARANTINE_MULTIPLIER_THRESHOLD = 0.45
QUARANTINE_FAILURE_COUNT = 4

# Auth-chain gates: hard quarantine permanently breaks login → post-auth exploit.
# Match any *login_bruteforce* (HTTP/SSH/MySQL/Postgres) plus login discovery helpers.
_AUTH_GATE_TOKENS = (
    "login_bruteforce",
    "login_page_detector",
    "simple_login_scanner",
    "wordpress_login",
    "credential_spray",
)


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


def _is_auth_gate_module(module_path: str) -> bool:
    low = str(module_path or "").lower()
    return any(token in low for token in _AUTH_GATE_TOKENS)


# Lab product OS-shell ladder: quarantine from earlier misconfig (wrong ssl/lhost)
# must not permanently block obtain-shell on DVWA and similar.
_PRODUCT_SHELL_CHAIN_TOKENS = (
    "dvwa_rce",
    "dvwa_file_upload",
    "dvwa_sqli_shell",
    "/ctf/dvwa_",
)


def _is_product_shell_chain_module(module_path: str) -> bool:
    low = str(module_path or "").lower().replace("\\", "/")
    if any(token in low for token in _PRODUCT_SHELL_CHAIN_TOKENS):
        return True
    try:
        from interfaces.command_system.builtin.agent.goal_planner import (
            _PRODUCT_SHELL_CHAINS,
        )

        leaf = low.rsplit("/", 1)[-1]
        for paths in _PRODUCT_SHELL_CHAINS.values():
            for path in paths:
                pl = path.lower()
                if pl == low or pl.rsplit("/", 1)[-1] == leaf:
                    return True
    except Exception:
        pass
    return False


def _failure_count(
    health: ModuleHealthMemory,
    module_path: str,
    kb: Dict[str, Any],
    *,
    hostname: str = "",
) -> int:
    if hostname and hasattr(health, "failure_count_for_host"):
        return int(health.failure_count_for_host(module_path, kb, hostname=hostname) or 0)
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
    hostname: str = "",
) -> QuarantineDecision:
    kb_dict = kb if isinstance(kb, dict) else {}
    host = str(hostname or "").strip()
    multiplier = float(health.health_multiplier(module_path, kb_dict, hostname=host))
    failures = _failure_count(health, module_path, kb_dict, hostname=host)
    would_quarantine = multiplier <= QUARANTINE_MULTIPLIER_THRESHOLD or failures >= QUARANTINE_FAILURE_COUNT
    reason = ""
    quarantined = would_quarantine
    if would_quarantine:
        if failures >= QUARANTINE_FAILURE_COUNT:
            reason = f"failure_count>={QUARANTINE_FAILURE_COUNT}"
        else:
            reason = f"health_multiplier<={QUARANTINE_MULTIPLIER_THRESHOLD}"
        # Auth gates: never hard-block (login → exploit chains).
        if _is_auth_gate_module(module_path):
            quarantined = False
            reason = f"soft_auth_gate:{reason}"
        # Lab product shell ladder (DVWA RCE/upload): never hard-block obtain-shell.
        elif _is_product_shell_chain_module(module_path):
            quarantined = False
            reason = f"soft_product_shell_chain:{reason}"
        # Without a host key, profile-only counts bleed across targets — soft only.
        elif not host:
            quarantined = False
            reason = f"soft_no_host:{reason}"
    alternate = suggest_alternate_module(module_path, service=service, os_name=os_name) if quarantined else None
    return QuarantineDecision(
        module_path=module_path,
        quarantined=quarantined,
        health_multiplier=multiplier,
        failure_count=failures,
        reason=reason,
        alternate_module=alternate,
    )
