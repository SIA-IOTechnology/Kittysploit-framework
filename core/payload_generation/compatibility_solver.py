#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Suggest payload/listener/transform/prestage combinations from detected capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass
class CompatibilityPlan:
    capabilities: Dict[str, Any] = field(default_factory=dict)
    payload_paths: List[str] = field(default_factory=list)
    listener_paths: List[str] = field(default_factory=list)
    transform_paths: List[str] = field(default_factory=list)
    prestage_profile: str = ""
    prestage_modules: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capabilities": self.capabilities,
            "payload_paths": self.payload_paths,
            "listener_paths": self.listener_paths,
            "transform_paths": self.transform_paths,
            "prestage_profile": self.prestage_profile,
            "prestage_modules": self.prestage_modules,
            "notes": self.notes,
        }


def _capability_blob(caps: Mapping[str, Any]) -> str:
    parts = [
        str(caps.get("os", {}).get("name", "") if isinstance(caps.get("os"), dict) else caps.get("os", "")),
        str(caps.get("arch", "")),
        str((caps.get("runtime") or {}).get("language", "") if isinstance(caps.get("runtime"), dict) else ""),
        str((caps.get("network") or {}).get("tcp_outbound", "")),
    ]
    return " ".join(parts).lower()


def solve_from_capabilities(
    capabilities: Mapping[str, Any],
    *,
    framework=None,
) -> CompatibilityPlan:
    """Build a compatibility plan from ``_kitty_capability_probe``-style data."""
    plan = CompatibilityPlan(capabilities=dict(capabilities or {}))
    blob = _capability_blob(capabilities)

    os_name = ""
    if isinstance(capabilities.get("os"), dict):
        os_name = str(capabilities["os"].get("name") or "").lower()
    elif capabilities.get("os"):
        os_name = str(capabilities.get("os")).lower()

    arch = str(capabilities.get("arch") or "").lower()
    runtime = ""
    if isinstance(capabilities.get("runtime"), dict):
        runtime = str(capabilities["runtime"].get("language") or "").lower()

    network = capabilities.get("network") if isinstance(capabilities.get("network"), dict) else {}
    tcp_ok = bool(network.get("tcp_outbound") or network.get("socket"))

    if "windows" in os_name or "amd64" in arch and "linux" not in os_name and "darwin" not in os_name:
        plan.payload_paths = [
            "payloads/singles/cmd/multi/python_kitty_agent",
            "payloads/singles/cmd/windows/curl_exe_stager",
        ]
        plan.listener_paths = ["listeners/multi/reverse_http_polling"]
        plan.prestage_profile = "reliable"
    elif "linux" in os_name or "unix" in os_name or "x86_64" in arch or "amd64" in arch:
        if runtime == "python" or not runtime:
            plan.payload_paths = [
                "payloads/singles/cmd/multi/python_kitty_agent",
                "payloads/stagers/linux/x64/reverse_tcp_recv_stage",
            ]
        else:
            plan.payload_paths = [
                "payloads/stagers/linux/x64/reverse_tcp_recv_stage",
                "payloads/singles/cmd/unix/curl_pipe_bash_stager",
            ]
        plan.listener_paths = [
            "listeners/multi/reverse_http_polling",
            "listeners/multi/reverse_tcp",
        ]
        plan.prestage_profile = "reliable"
    else:
        plan.payload_paths = ["payloads/singles/cmd/multi/python_kitty_agent"]
        plan.listener_paths = ["listeners/multi/reverse_http_polling"]
        plan.prestage_profile = "iot"
        plan.notes.append("Unknown OS/arch — using generic HTTP polling defaults")

    if not tcp_ok:
        plan.notes.append("TCP outbound uncertain — prefer HTTP polling over raw reverse_tcp")
        plan.listener_paths = ["listeners/multi/reverse_http_polling"]
        plan.transform_paths = []

    if "iot" in blob or (capabilities.get("privileges") or {}).get("elevated") is False:
        if plan.prestage_profile == "reliable":
            plan.prestage_profile = "iot"

    plan.prestage_modules = _profile_modules(plan.prestage_profile)
    plan.transform_paths = _suggest_transforms(runtime, framework=framework)
    return plan


def _profile_modules(profile: str) -> List[str]:
    from core.payload_generation.prestage_profiles import get_prestage_profile

    row = get_prestage_profile(profile) or {}
    return [str(item) for item in row.get("modules") or []]


def _suggest_transforms(runtime: str, *, framework=None) -> List[str]:
    runtime = str(runtime or "python").lower()
    if runtime in ("python", ""):
        return ["transforms/python/stream/xor"]
    if runtime == "powershell":
        return ["transforms/powershell/stream/xor"]
    return []
