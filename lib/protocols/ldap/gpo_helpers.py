#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LDAP helpers for GPO inheritance and scope mapping."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_GPLINK_RE = re.compile(
    r"\[LDAP://[^/]+/CN=\{?([0-9A-Fa-f-]{36})\}?,CN=Policies,CN=System,[^\]]*;(\d+)\]",
    re.IGNORECASE,
)


def _attr_str(entry: Any, name: str) -> str:
    v = getattr(entry, name, None)
    if v is None:
        return ""
    if hasattr(v, "value"):
        return str(v.value) if v.value is not None else ""
    if hasattr(v, "raw_values") and v.raw_values:
        return str(v.raw_values[0]) if v.raw_values[0] is not None else ""
    return str(v) if v is not None else ""


def parse_gplink(gplink: str) -> List[Dict[str, Any]]:
    """Parse a gPLink attribute into enabled GPO links."""
    links: List[Dict[str, Any]] = []
    if not gplink:
        return links
    for match in _GPLINK_RE.finditer(gplink):
        guid = "{" + match.group(1).upper() + "}"
        flags = int(match.group(2))
        if flags & 1:
            continue
        links.append({
            "guid": guid,
            "enforced": bool(flags & 2),
            "flags": flags,
        })
    return links


def enumerate_gpos(ad_client) -> List[Dict[str, str]]:
    """Return GPO metadata from CN=Policies,CN=System."""
    if not ad_client.conn or not ad_client.base_dn:
        return []
    policies_dn = f"CN=Policies,CN=System,{ad_client.base_dn}"
    entries = ad_client.search(
        "(objectClass=groupPolicyContainer)",
        ["displayName", "name", "gPCFileSysPath", "distinguishedName"],
        base=policies_dn,
    )
    gpos: List[Dict[str, str]] = []
    for entry in entries:
        name = _attr_str(entry, "name").strip("{}").upper()
        guid = "{" + name + "}" if name else ""
        gpos.append({
            "guid": guid,
            "display_name": _attr_str(entry, "displayName"),
            "gpcfilesyspath": _attr_str(entry, "gPCFileSysPath"),
            "dn": _attr_str(entry, "distinguishedName"),
        })
    return gpos


def enumerate_gplink_containers(ad_client) -> List[Dict[str, Any]]:
    """Return domain and OU objects that define gPLink."""
    if not ad_client.conn or not ad_client.base_dn:
        return []
    entries = ad_client.search(
        "(|(objectClass=organizationalUnit)(objectClass=domain)(objectClass=domainDNS))",
        ["distinguishedName", "gPLink", "gPOptions", "name"],
        base=ad_client.base_dn,
    )
    containers: List[Dict[str, Any]] = []
    for entry in entries:
        dn = _attr_str(entry, "distinguishedName")
        if not dn:
            continue
        containers.append({
            "dn": dn,
            "name": _attr_str(entry, "name"),
            "gplink": parse_gplink(_attr_str(entry, "gPLink")),
            "block_inheritance": bool(int(_attr_str(entry, "gPOptions") or "0") & 1),
        })
    return containers


def _dn_components(dn: str) -> List[str]:
    return [part.strip() for part in dn.split(",") if part.strip()]


def _ou_chain_for_dn(dn: str, base_dn: str) -> List[str]:
    """Return OU DNs from domain root to target container, inclusive."""
    target_parts = _dn_components(dn)
    base_parts = _dn_components(base_dn)
    if len(target_parts) < len(base_parts):
        return []
    if [p.lower() for p in target_parts[-len(base_parts):]] != [p.lower() for p in base_parts]:
        return []

    chain: List[str] = []
    for idx in range(len(base_parts), len(target_parts) + 1):
        chain.append(",".join(target_parts[:idx]))
    return chain


def inherited_gpos_for_dn(
    dn: str,
    base_dn: str,
    containers_by_dn: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compute inherited GPO list for a container DN."""
    ordered: List[Dict[str, Any]] = []
    chain = _ou_chain_for_dn(dn, base_dn)
    if not chain:
        return ordered

    for container_dn in chain:
        container = containers_by_dn.get(container_dn.lower())
        if not container:
            continue
        if container.get("block_inheritance") and container_dn.lower() != base_dn.lower():
            break
        for link in container.get("gplink") or []:
            ordered.append({
                **link,
                "linked_from": container_dn,
            })
    return ordered


def enumerate_computers(ad_client) -> List[Dict[str, str]]:
    if not ad_client.conn or not ad_client.base_dn:
        return []
    entries = ad_client.search(
        "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "dNSHostName", "distinguishedName", "objectSid"],
        base=ad_client.base_dn,
    )
    computers: List[Dict[str, str]] = []
    for entry in entries:
        computers.append({
            "samaccountname": _attr_str(entry, "sAMAccountName"),
            "dnshostname": _attr_str(entry, "dNSHostName"),
            "dn": _attr_str(entry, "distinguishedName"),
            "sid": _attr_str(entry, "objectSid"),
        })
    return computers


def parent_container_dn(dn: str, base_dn: str) -> str:
    parts = _dn_components(dn)
    if len(parts) <= 1:
        return base_dn
    parent = ",".join(parts[1:])
    if parent.lower().endswith(base_dn.lower()):
        return parent
    return base_dn


def map_gpos_to_computers(
    ad_client,
) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, str]]]]:
    """
    Return GPO inheritance per container and a mapping ``gpo_guid -> computers``.
    """
    containers = enumerate_gplink_containers(ad_client)
    containers_by_dn = {item["dn"].lower(): item for item in containers}
    computers = enumerate_computers(ad_client)

    inheritance: List[Dict[str, Any]] = []
    gpo_computers: Dict[str, List[Dict[str, str]]] = {}

    for container in containers:
        inherited = inherited_gpos_for_dn(container["dn"], ad_client.base_dn, containers_by_dn)
        inheritance.append({
            "container_dn": container["dn"],
            "container_name": container["name"],
            "block_inheritance": container.get("block_inheritance", False),
            "direct_links": container.get("gplink") or [],
            "inherited_gpos": inherited,
        })

    for computer in computers:
        dn = computer.get("dn") or ""
        if not dn:
            continue
        parent_dn = parent_container_dn(dn, ad_client.base_dn)
        inherited = inherited_gpos_for_dn(parent_dn, ad_client.base_dn, containers_by_dn)
        for link in inherited:
            guid = link.get("guid") or ""
            if not guid:
                continue
            gpo_computers.setdefault(guid, []).append({
                "samaccountname": computer.get("samaccountname") or "",
                "dnshostname": computer.get("dnshostname") or "",
                "sid": computer.get("sid") or "",
                "container_dn": parent_dn,
            })

    return inheritance, gpo_computers


def summarize_gpo_scope(gpo_computers: Dict[str, List[Dict[str, str]]], gpos: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    names = {item["guid"]: item.get("display_name") or item["guid"] for item in gpos}
    summary: List[Dict[str, Any]] = []
    for guid, computers in gpo_computers.items():
        summary.append({
            "guid": guid,
            "display_name": names.get(guid, guid),
            "computer_count": len(computers),
            "computers": computers[:20],
        })
    summary.sort(key=lambda row: row["computer_count"], reverse=True)
    return summary
