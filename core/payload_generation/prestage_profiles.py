#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Named prestage profiles that expand to ordered module id lists."""

from __future__ import annotations

from typing import Dict, List, Optional


PrestageProfile = Dict[str, object]

PRESTAGE_PROFILES: Dict[str, PrestageProfile] = {
    "lab-safe": {
        "description": "Conservative guards for authorized lab engagements",
        "modules": ["scope_guard", "stage_verify", "resource_guard"],
    },
    "reliable": {
        "description": "Host/network probes with verified staging and telemetry",
        "modules": ["capability_probe", "network_preflight", "stage_verify", "telemetry_buffer"],
    },
    "iot": {
        "description": "Lightweight probes and resumable staging for constrained targets",
        "modules": ["capability_probe", "resource_guard", "stage_cache"],
    },
    "durable-agent": {
        "description": "Persistent agent with signed config, cache, and telemetry",
        "modules": ["telemetry_buffer", "signed_config", "agent_store", "stage_cache"],
    },
}


def normalize_prestage_profile_name(raw: str) -> str:
    return str(raw or "").strip().lower().replace("_", "-")


def get_prestage_profile(name: str) -> Optional[PrestageProfile]:
    key = normalize_prestage_profile_name(name)
    if not key:
        return None
    return PRESTAGE_PROFILES.get(key)


def list_prestage_profiles() -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for name in sorted(PRESTAGE_PROFILES):
        profile = PRESTAGE_PROFILES[name]
        rows.append(
            {
                "name": name,
                "description": str(profile.get("description") or ""),
                "modules": list(profile.get("modules") or []),
            }
        )
    return rows


def parse_prestage_tokens(raw: str) -> List[str]:
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def resolve_prestage_selection(
    *,
    prestage: str = "",
    prestage_profile: str = "",
) -> List[str]:
    """Merge profile modules with explicit ids, preserving order and deduplicating."""
    ordered: List[str] = []
    seen = set()

    profile_name = normalize_prestage_profile_name(prestage_profile)
    if profile_name:
        profile = PRESTAGE_PROFILES.get(profile_name)
        if profile is None:
            raise KeyError(f"Unknown prestage profile: {prestage_profile}")
        for module_id in profile.get("modules") or []:
            token = str(module_id).strip()
            key = token.lower()
            if not token or key in seen:
                continue
            seen.add(key)
            ordered.append(token)

    for token in parse_prestage_tokens(prestage):
        key = token.lower().split("/")[-1]
        if key in seen:
            continue
        seen.add(key)
        ordered.append(token)

    return ordered
