#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Map OSINT signals to MITRE ATT&CK (reconnaissance) technique references."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Set

# MITRE ATT&CK Enterprise — reconnaissance / resource-development (OSINT-relevant).
_SIGNAL_TECHNIQUES: Dict[str, List[str]] = {
    "subdomain": ["T1590", "T1590.002"],
    "breach": ["T1589", "T1589.001"],
    "darkweb": ["T1589", "T1589.003"],
    "telegram": ["T1589", "T1589.001"],
    "github": ["T1592", "T1592.004"],
    "identity": ["T1589", "T1589.001"],
    "email": ["T1589", "T1589.002"],
    "saas": ["T1590", "T1590.001"],
    "crypto": ["T1589", "T1589.003"],
    "api_surface": ["T1590", "T1590.005"],
    "persona": ["T1589"],
}

_TECHNIQUE_NAMES: Dict[str, str] = {
    "T1589": "Gather Victim Identity Information",
    "T1589.001": "Credentials",
    "T1589.002": "Email Addresses",
    "T1589.003": "Employee Names",
    "T1590": "Gather Victim Network Information",
    "T1590.001": "Domain Properties",
    "T1590.002": "DNS",
    "T1590.005": "IP Addresses",
    "T1592": "Gather Victim Host Information",
    "T1592.004": "Client Configurations",
    "T1593": "Search Open Websites/Domains",
    "T1598": "Phishing for Information",
}


def infer_mitre_techniques(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[Dict[str, str]]:
    """Return deduplicated MITRE technique refs inferred from OSINT output."""
    found: Set[str] = set()
    signals = list(synthesis.get("signals") or [])
    for sig in signals:
        blob = str(sig).lower()
        for key, techniques in _SIGNAL_TECHNIQUES.items():
            if key in blob:
                found.update(techniques)

    for row in module_results or []:
        if not isinstance(row, Mapping):
            continue
        path = str(row.get("path") or "").lower()
        if "domain_surface" in path or "domain_crtsh" in path or "domain_dns" in path:
            found.update(_SIGNAL_TECHNIQUES["subdomain"])
        if "email" in path:
            found.update(_SIGNAL_TECHNIQUES["email"])
        if "identity" in path:
            found.update(_SIGNAL_TECHNIQUES["identity"])
        if "breach" in path or "darkweb" in path:
            found.update(_SIGNAL_TECHNIQUES["breach"])
        if "telegram" in path:
            found.update(_SIGNAL_TECHNIQUES["telegram"])
        if "github" in path:
            found.update(_SIGNAL_TECHNIQUES["github"])
        if "saas" in path:
            found.update(_SIGNAL_TECHNIQUES["saas"])
        if "crypto" in path:
            found.update(_SIGNAL_TECHNIQUES["crypto"])

    nodes = synthesis.get("nodes") or []
    if nodes:
        found.add("T1590")
    if any(isinstance(n, dict) and n.get("type") == "email" for n in nodes):
        found.add("T1589.002")

    out: List[Dict[str, str]] = []
    for tid in sorted(found):
        out.append({
            "id": tid,
            "name": _TECHNIQUE_NAMES.get(tid, tid),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    return out


def misp_galaxy_tags(techniques: Sequence[Mapping[str, Any]]) -> List[Dict[str, str]]:
    """MISP-compatible galaxy tag names for MITRE techniques."""
    tags: List[Dict[str, str]] = []
    for row in techniques or []:
        if not isinstance(row, Mapping):
            continue
        tid = str(row.get("id") or "")
        name = str(row.get("name") or tid)
        if not tid:
            continue
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{name} - {tid}"'})
        tags.append({"name": f"mitre:{tid}"})
    return tags


def stix_external_references(techniques: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """STIX 2.1 external-reference blocks for ATT&CK techniques."""
    refs: List[Dict[str, Any]] = []
    for row in techniques or []:
        if not isinstance(row, Mapping):
            continue
        tid = str(row.get("id") or "")
        if not tid:
            continue
        refs.append({
            "source_name": "mitre-attack",
            "external_id": tid,
            "url": str(row.get("url") or ""),
        })
    return refs
