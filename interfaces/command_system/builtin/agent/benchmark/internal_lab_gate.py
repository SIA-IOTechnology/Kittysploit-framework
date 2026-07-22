#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fail-closed gate: internal-lab profile must not enable lab options on real targets."""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple
from urllib.parse import urlparse


SYNTHETIC_TARGETS = frozenset({"__lab__", "__lab_mutated__"})
LAB_PRIVATE_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})


def _hostname_from_target(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    if text in SYNTHETIC_TARGETS:
        return text
    if "://" not in text and "/" not in text and ":" in text:
        # host:port style (SSH labs)
        return text.split(":", 1)[0].strip().lower()
    try:
        parsed = urlparse(text if "://" in text else f"http://{text}")
        return str(parsed.hostname or "").strip().lower()
    except Exception:
        return text.lower()


def is_synthetic_lab_target(target: str) -> bool:
    return str(target or "").strip() in SYNTHETIC_TARGETS


def is_loopback_target(target: str) -> bool:
    host = _hostname_from_target(target)
    return host in LAB_PRIVATE_HOSTS or host.startswith("127.")


def has_lab_attestation(knowledge_base: Optional[Mapping[str, Any]] = None) -> bool:
    kb = knowledge_base if isinstance(knowledge_base, Mapping) else {}
    attestation = kb.get("lab_attestation")
    if isinstance(attestation, Mapping) and attestation:
        return True
    if kb.get("lab_manifest"):
        return True
    return False


def require_internal_lab_attestation(
    *,
    profile: str,
    target: str,
    knowledge_base: Optional[Mapping[str, Any]] = None,
    allow_synthetic_lab: bool = True,
) -> Tuple[bool, str]:
    """
    Return ``(allowed, reason)``.

    - Non-internal-lab profiles: always allowed here (other policies still apply).
    - Synthetic `__lab__` / `__lab_mutated__` targets: allowed when ``allow_synthetic_lab``.
    - Loopback lab targets: allowed only with attestation/manifest in KB.
    - Public / non-lab targets with internal-lab profile: denied (fail closed).
    """
    mission = str(profile or "").strip().lower()
    if mission != "internal-lab":
        return True, "profile_not_internal_lab"

    if allow_synthetic_lab and is_synthetic_lab_target(target):
        return True, "synthetic_lab_exempt"

    if is_loopback_target(target):
        if has_lab_attestation(knowledge_base):
            return True, "loopback_with_attestation"
        return False, "internal-lab on loopback requires lab attestation or manifest"

    return False, "internal-lab profile denied for non-lab / public target without attestation"


def lab_option_patch_blocked_on_public_target() -> Tuple[bool, str]:
    """OptionResolver must reject protected destination/credential keys."""
    from interfaces.command_system.builtin.agent.option_resolver import resolve_option_patch
    from interfaces.command_system.builtin.agent.typed_models import OptionPatch

    patch = OptionPatch(
        module_path="auxiliary/scanner/ssh/ssh_login",
        id="lab-bleed",
        options={
            "rhost": "203.0.113.10",
            "password": "msfadmin",
            "username": "msfadmin",
            "TARGETURI": "/login.php",
        },
        evidence_ids=["ev-1"],
    )
    result = resolve_option_patch(patch, require_evidence=True)
    rejected = {str(k).lower() for k in (result.rejected_keys or [])}
    ok = "rhost" in rejected and "password" in rejected and "username" in rejected
    # TARGETURI may be accepted (not protected) — that's fine.
    return ok, f"rejected={sorted(rejected)}"


def intrusive_blocked_outside_lab() -> Tuple[bool, str]:
    """Non-lab mission profiles must block intrusive catalog modules."""
    from interfaces.command_system.builtin.agent.runtime_policy import (
        AgentRuntimePolicy,
        evaluate_module_catalog_policy,
    )

    policy = AgentRuntimePolicy.from_options(
        safety_profile="normal",
        mission_profile="bug-bounty-safe",
        approved_risks=["read", "active"],
    )
    block = evaluate_module_catalog_policy(
        policy,
        {
            "path": "auxiliary/scanner/ssh/ssh_login",
            "agent": {"risk": "intrusive", "effects": ["credential_spray"]},
        },
        "auxiliary/scanner/ssh/ssh_login",
        phase="catalog",
    )
    ok = block is not None
    reason = block.reason if block is not None else "not_blocked"
    return ok, reason
