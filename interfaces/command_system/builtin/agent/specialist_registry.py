#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Explicit specialist registry derived from operator archetypes and vuln classes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from interfaces.command_system.builtin.agent.operator_archetypes import (
    ARCHETYPE_PROFILES,
    OperatorArchetype,
)
from interfaces.command_system.builtin.agent.vuln_specialists import (
    SPECIALIST_HINTS,
    _PATH_CATEGORY_MAP,
)

MAX_SUBAGENT_DEPTH = 1
MAX_FAN_OUT = 3


@dataclass(frozen=True)
class SpecialistProfile:
    key: str
    name: str
    description: str
    capabilities: Sequence[str]
    module_families: Sequence[str]
    triggers: Sequence[str]
    inputs: Sequence[str]
    outputs: Sequence[str]
    budget_requests: int = 4
    read_only: bool = True
    maturity: str = "stable"
    mitre_tactics: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "module_families": list(self.module_families),
            "triggers": list(self.triggers),
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "budget_requests": self.budget_requests,
            "read_only": self.read_only,
            "maturity": self.maturity,
            "mitre_tactics": list(self.mitre_tactics),
        }


def _profile_from_archetype(op: OperatorArchetype) -> SpecialistProfile:
    triggers = list(op.capabilities[:4])
    if op.module_families:
        triggers.append(f"family:{op.module_families[0]}")
    return SpecialistProfile(
        key=op.key,
        name=op.name,
        description=op.description,
        capabilities=list(op.capabilities),
        module_families=list(op.module_families),
        triggers=triggers,
        inputs=("knowledge_base", "catalog_actions", "campaign_goal"),
        outputs=("specialist_proposal",),
        budget_requests=6 if op.key in {"exploiter", "infiltrator"} else 4,
        read_only=op.key not in {"exploiter", "infiltrator", "ghost"},
        maturity=op.maturity,
        mitre_tactics=list(op.mitre_tactics),
    )


def _vuln_specialist_profiles() -> Dict[str, SpecialistProfile]:
    rows: Dict[str, SpecialistProfile] = {}
    for key, hint in SPECIALIST_HINTS.items():
        rows[key] = SpecialistProfile(
            key=key,
            name=f"{key.upper()} Specialist",
            description=hint[:240],
            capabilities=(key, "validation", "bypass_variants"),
            module_families=("scanner", "auxiliary/scanner", "exploits"),
            triggers=(key, f"path:{key}"),
            inputs=("finding", "knowledge_base", "catalog_actions"),
            outputs=("specialist_proposal", "hypothesis"),
            budget_requests=3,
            read_only=True,
            maturity="stable",
        )
    return rows


def _situational_specialist_profiles() -> Dict[str, SpecialistProfile]:
    return {
        "web_recon": SpecialistProfile(
            key="web_recon",
            name="Web/API Recon Specialist",
            description="Situational HTTP probing, API endpoint disambiguation, and web module selection.",
            capabilities=("http_probe", "api_detection", "surface_scan", "module_rank"),
            module_families=("auxiliary/scanner/http", "scanner/http", "auxiliary/osint"),
            triggers=("http", "https", "api", "swagger", "graphql", "js_surface", "openapi"),
            inputs=("knowledge_base", "catalog_actions", "recent_http_probes"),
            outputs=("specialist_proposal", "hypothesis"),
            budget_requests=5,
            read_only=True,
            maturity="stable",
            mitre_tactics=("reconnaissance", "discovery"),
        ),
        "smb_service": SpecialistProfile(
            key="smb_service",
            name="SMB Service Specialist",
            description="SMB share enum, session acquire, and relay-surface module selection.",
            capabilities=("smb_enum", "session_acquire", "share_discovery"),
            module_families=("auxiliary/scanner/smb", "scanner/smb"),
            triggers=("smb", "445", "139", "cifs"),
            inputs=("knowledge_base", "catalog_actions"),
            outputs=("specialist_proposal",),
            budget_requests=4,
            read_only=True,
            maturity="stable",
            mitre_tactics=("discovery", "lateral-movement"),
        ),
        "ssh_service": SpecialistProfile(
            key="ssh_service",
            name="SSH Service Specialist",
            description="SSH banner detection and authenticated login module selection.",
            capabilities=("ssh_enum", "ssh_login"),
            module_families=("auxiliary/scanner/ssh", "scanner/ssh"),
            triggers=("ssh", "openssh", "22"),
            inputs=("knowledge_base", "catalog_actions"),
            outputs=("specialist_proposal",),
            budget_requests=4,
            read_only=True,
            maturity="stable",
            mitre_tactics=("discovery", "credential-access"),
        ),
        "session_post": SpecialistProfile(
            key="session_post",
            name="Session/Post Specialist",
            description="Verified-session post-exploitation module selection toward authorized goals.",
            capabilities=("session_stabilize", "post_gather", "privilege"),
            module_families=("post/",),
            triggers=("session", "verified_session", "post", "privilege"),
            inputs=("knowledge_base", "catalog_actions", "verified_sessions"),
            outputs=("specialist_proposal",),
            budget_requests=4,
            read_only=False,
            maturity="stable",
            mitre_tactics=("privilege-escalation", "collection"),
        ),
    }


class SpecialistRegistry:
    """Lookup specialists by phase, path, capability, or finding signal."""

    def __init__(self, profiles: Optional[Mapping[str, SpecialistProfile]] = None) -> None:
        base = {key: _profile_from_archetype(profile) for key, profile in ARCHETYPE_PROFILES.items()}
        base.update(_vuln_specialist_profiles())
        base.update(_situational_specialist_profiles())
        if profiles:
            base.update(dict(profiles))
        self._profiles = base

    def all(self) -> List[SpecialistProfile]:
        return list(self._profiles.values())

    def get(self, key: str) -> Optional[SpecialistProfile]:
        return self._profiles.get(str(key or "").strip().lower())

    def match(
        self,
        *,
        phase: str = "",
        module_path: str = "",
        kb: Optional[Mapping[str, Any]] = None,
        limit: int = MAX_FAN_OUT,
    ) -> List[SpecialistProfile]:
        kb = kb if isinstance(kb, dict) else {}
        phase_l = str(phase or "").lower()
        path_l = str(module_path or "").lower()
        signals = {str(item).lower() for item in (kb.get("risk_signals") or [])}
        hints = {str(item).lower() for item in (kb.get("tech_hints") or [])}
        services = " ".join(str(s).lower() for s in (kb.get("identified_services") or kb.get("services") or []))
        protocol = str(kb.get("protocol") or "").lower()
        matched: List[SpecialistProfile] = []
        seen: Set[str] = set()

        def _add(profile: SpecialistProfile) -> None:
            if profile.key in seen:
                return
            seen.add(profile.key)
            matched.append(profile)

        for profile in self._profiles.values():
            if phase_l == "exploit" and profile.key in {"exploiter", "infiltrator"}:
                _add(profile)
            elif phase_l in {"scan", "analyze"} and profile.key in {"recon", "scanner"}:
                _add(profile)
            elif phase_l == "report" and profile.key == "analyst":
                _add(profile)

        for needle, category in _PATH_CATEGORY_MAP.items():
            if needle in path_l:
                vuln = self._profiles.get(category)
                if vuln is not None:
                    _add(vuln)

        if signals.intersection({"sqli", "xss", "lfi", "ssrf", "ssti", "auth"}):
            for token in signals:
                vuln = self._profiles.get(token)
                if vuln is not None:
                    _add(vuln)

        if hints.intersection({"wordpress", "drupal", "joomla"}) and phase_l in {"analyze", "reason", "exploit"}:
            scanner = self._profiles.get("scanner")
            if scanner is not None:
                _add(scanner)

        # Situational engineer specialists
        httpish = (
            protocol in {"http", "https"}
            or any(tok in services for tok in ("http", "https", "web"))
            or signals.intersection({
                "api_surface_detected",
                "graphql_surface_detected",
                "swagger_surface_detected",
                "login_surface_detected",
            })
            or bool(kb.get("discovered_endpoints") or kb.get("request_intel") or kb.get("llm_http_requests"))
        )
        if httpish and phase_l in {"scan", "analyze", "reason", "act", "plan", ""}:
            web = self._profiles.get("web_recon")
            if web is not None:
                _add(web)

        if (
            protocol == "smb"
            or "smb" in services
            or any(str(p) in {str(x) for x in (kb.get("open_ports") or [])} for p in (139, 445))
            or signals.intersection({"smb_surface", "smb_detected"})
        ):
            smb = self._profiles.get("smb_service")
            if smb is not None:
                _add(smb)

        if (
            protocol == "ssh"
            or "ssh" in services
            or "openssh" in hints
            or any(str(p) in {str(x) for x in (kb.get("open_ports") or [])} for p in (22, 2222))
        ):
            ssh = self._profiles.get("ssh_service")
            if ssh is not None:
                _add(ssh)

        sessions = kb.get("verified_session_ids") or kb.get("verified_sessions") or kb.get("sessions") or []
        if sessions and phase_l in {"post", "act", "reason", "exploit", ""}:
            post = self._profiles.get("session_post")
            if post is not None:
                _add(post)

        coordinator = self._profiles.get("coordinator")
        if coordinator is not None and phase_l in {"reason", "plan", "init"}:
            _add(coordinator)

        return matched[: max(1, int(limit or MAX_FAN_OUT))]


DEFAULT_SPECIALIST_REGISTRY = SpecialistRegistry()
