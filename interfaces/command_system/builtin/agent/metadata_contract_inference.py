#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Infer Phase-2 contract fields (destinations, privileges, validators, …)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.module_stack_gate import (
    infer_stack_gate_for_path,
    merge_agent_gate_blocks,
)
from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk

_PATH_PROTOCOL_HINTS: Sequence[tuple[str, str]] = (
    ("/http/", "target_http"),
    ("/https/", "target_http"),
    ("/ssh/", "target_ssh"),
    ("/smb/", "target_smb"),
    ("/ftp/", "target_ftp"),
    ("/mysql/", "target_mysql"),
    ("/mssql/", "target_mssql"),
    ("/postgres/", "target_postgres"),
    ("/winrm/", "target_winrm"),
    ("/rdp/", "target_rdp"),
    ("/tcp/", "target_tcp"),
    ("/portscan/", "target_tcp"),
)

_TAG_PROTOCOL_HINTS: Sequence[tuple[str, str]] = (
    ("http", "target_http"),
    ("https", "target_http"),
    ("ssh", "target_ssh"),
    ("smb", "target_smb"),
    ("ftp", "target_ftp"),
    ("mysql", "target_mysql"),
    ("winrm", "target_winrm"),
    ("rdp", "target_rdp"),
)


def _module_family_key(module_path: str) -> str:
    path = str(module_path or "")
    if path.startswith("auxiliary/scanner/"):
        return "auxiliary/scanner"
    if path.startswith("scanner/"):
        return "scanner"
    if path.startswith("exploits/"):
        return "exploits"
    if path.startswith("post/"):
        return "post"
    if path.startswith("payloads/"):
        return "payloads"
    return path.split("/")[0] if "/" in path else "other"


def infer_network_destinations(
    module_path: str,
    *,
    tags: Optional[Sequence[str]] = None,
    effects: Optional[Sequence[str]] = None,
) -> List[str]:
    low = str(module_path or "").lower()
    tag_set = {str(tag).lower() for tag in (tags or []) if str(tag).strip()}
    destinations: List[str] = []
    for needle, dest in _PATH_PROTOCOL_HINTS:
        if needle in low and dest not in destinations:
            destinations.append(dest)
    for tag, dest in _TAG_PROTOCOL_HINTS:
        if tag in tag_set and dest not in destinations:
            destinations.append(dest)
    effect_set = {str(item).lower() for item in (effects or [])}
    if effect_set & {"network_probe", "active_exploitation", "credential_guess"}:
        if "target_network" not in destinations:
            destinations.append("target_network")
    return destinations or ["target_network"]


def infer_privileges_required(module_path: str, *, family_key: str = "", risk_level: str = "") -> List[str]:
    low = str(module_path or "").lower()
    family = family_key or _module_family_key(module_path)
    if family == "post":
        return ["authenticated_session"]
    if "privesc" in low or "privilege" in low or "getsystem" in low:
        return ["local_user"]
    if "session_acquire" in low or "/listeners/" in low:
        return ["network_reachability"]
    if family == "exploits" or risk_level in {"critical", "high"}:
        return ["network_reachability"]
    if family in {"scanner", "auxiliary/scanner"}:
        return ["network_reachability"]
    return []


def infer_side_effects(
    module_path: str,
    *,
    family_key: str = "",
    effects: Optional[Sequence[str]] = None,
    risk_level: str = "",
) -> List[str]:
    low = str(module_path or "").lower()
    family = family_key or _module_family_key(module_path)
    rows: List[str] = []
    if family == "exploits" or risk_level in {"critical", "high"}:
        rows.append("target_modification")
    if "session_acquire" in low or "reverse_shell" in low or "/listeners/" in low:
        rows.append("session_creation")
    if "persist" in low or "authorized_keys" in low:
        rows.append("persistence")
    if "bruteforce" in low or "wordlist" in low:
        rows.append("credential_guessing")
    effect_set = {str(item).lower() for item in (effects or [])}
    if "network_probe" in effect_set and "network_traffic" not in rows:
        rows.append("network_traffic")
    return rows or ["network_traffic"]


def infer_success_validators(module_path: str, *, family_key: str = "") -> List[str]:
    low = str(module_path or "").lower()
    family = family_key or _module_family_key(module_path)
    if "session_acquire" in low or family == "post":
        return ["session_neutral_check", "no_message_only_session"]
    if family in {"exploits"}:
        return ["evidence_or_observation", "no_message_only_session"]
    return ["evidence_or_observation", "no_message_only_session"]


def infer_idempotent_flag(module_path: str, *, info: Optional[Mapping[str, Any]] = None) -> bool:
    risk = assess_module_risk(
        {
            "tags": list((info or {}).get("tags") or []),
            "path": module_path,
            "description": str((info or {}).get("description") or ""),
            "agent": (info or {}).get("agent") if isinstance((info or {}).get("agent"), dict) else {},
        },
        module_path,
    )
    from interfaces.command_system.builtin.agent.runtime_policy import action_is_non_idempotent

    return not action_is_non_idempotent(risk)


def infer_isolation_level(module_path: str, *, family_key: str = "", risk_level: str = "") -> str:
    low = str(module_path or "").lower()
    family = family_key or _module_family_key(module_path)
    if "/extensions/" in low or low.startswith("extensions/"):
        return "required"
    if family in {"exploits", "post"} or risk_level in {"critical", "high"}:
        return "recommended"
    return "none"


def apply_extended_contract_fields(
    module_path: str,
    agent: Dict[str, Any],
    info: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge inferred Phase-2 contract fields into an agent block."""
    info = info if isinstance(info, dict) else {}
    out = dict(agent or {})
    tags = [str(tag).lower() for tag in (info.get("tags") or out.get("tags") or []) if str(tag).strip()]
    family_key = _module_family_key(module_path)
    risk_level = str(out.get("risk") or "").strip().lower()
    effects = list(out.get("effects") or [])

    stack_gate = merge_agent_gate_blocks(
        out if isinstance(out.get("incompatible_when"), dict) else None,
        infer_stack_gate_for_path(module_path),
    )
    if stack_gate:
        for key in ("requires", "incompatible_when"):
            if stack_gate.get(key) and not out.get(key):
                out[key] = stack_gate[key]

    if not out.get("network_destinations"):
        out["network_destinations"] = infer_network_destinations(module_path, tags=tags, effects=effects)
    if not out.get("privileges_required"):
        out["privileges_required"] = infer_privileges_required(
            module_path,
            family_key=family_key,
            risk_level=risk_level,
        )
    if not out.get("side_effects"):
        out["side_effects"] = infer_side_effects(
            module_path,
            family_key=family_key,
            effects=effects,
            risk_level=risk_level,
        )
    if not out.get("success_validators"):
        out["success_validators"] = infer_success_validators(module_path, family_key=family_key)
    if "idempotent" not in out:
        out["idempotent"] = infer_idempotent_flag(module_path, info=info)
    if not out.get("isolation"):
        out["isolation"] = infer_isolation_level(module_path, family_key=family_key, risk_level=risk_level)
    return out


def missing_extended_contract_fields(agent: Mapping[str, Any]) -> List[str]:
    """Return missing Phase-2 contract keys for strict validation."""
    missing: List[str] = []
    for field in (
        "network_destinations",
        "privileges_required",
        "side_effects",
        "success_validators",
        "idempotent",
        "isolation",
    ):
        if field not in agent or agent.get(field) in (None, "", []):
            missing.append(field)
    return missing
