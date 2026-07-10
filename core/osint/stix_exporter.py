#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Export OSINT intel graphs as STIX 2.1 bundles for LE sharing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence


def _uuid(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _node_stix_id(node: Mapping[str, Any]) -> str:
    nid = str(node.get("id") or "")
    ntype = str(node.get("type") or "unknown")
    label = str(node.get("label") or nid)
    if ntype == "email":
        return _uuid("email-addr")
    if ntype in ("subdomain", "organization"):
        return _uuid("domain-name")
    if ntype == "profile":
        return _uuid("user-account")
    if ntype in ("ip", "asn_or_ip"):
        return _uuid("ipv4-addr")
    return _uuid("identity")


def _node_to_stix_object(node: Mapping[str, Any], *, created: str, case_ref: str) -> Dict[str, Any]:
    ntype = str(node.get("type") or "unknown")
    label = str(node.get("label") or node.get("id") or "unknown")
    stix_id = _node_stix_id(node)
    confidence = node.get("confidence")
    labels = ["osint", ntype]
    if case_ref:
        labels.append(f"case:{case_ref}")

    if ntype == "email":
        return {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": stix_id,
            "created": created,
            "modified": created,
            "value": label,
            "labels": labels,
        }

    if ntype in ("subdomain", "organization"):
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": stix_id,
            "created": created,
            "modified": created,
            "value": label,
            "labels": labels,
        }

    if ntype == "profile":
        account = {
            "type": "user-account",
            "spec_version": "2.1",
            "id": stix_id,
            "created": created,
            "modified": created,
            "user_id": label,
            "labels": labels,
        }
        url = str(node.get("url") or "")
        if url:
            account["x_osint_profile_url"] = url
        if confidence is not None:
            account["confidence"] = confidence
        return account

    identity_class = "individual" if ntype == "person" else "organization"
    obj: Dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id,
        "created": created,
        "modified": created,
        "name": label,
        "identity_class": identity_class,
        "labels": labels,
    }
    if confidence is not None:
        obj["confidence"] = confidence
    return obj


def export_osint_graph_stix(
    synthesis: Mapping[str, Any],
    *,
    case_id: str = "",
    tlp: str = "AMBER",
    name: str = "KittySploit OSINT Graph",
) -> Dict[str, Any]:
    """Convert ``synthesize_intel_graph`` output into a STIX 2.1 bundle."""
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    nodes = list(synthesis.get("nodes") or [])
    edges = list(synthesis.get("edges") or [])
    root = str(synthesis.get("root_domain") or "")

    objects: List[Dict[str, Any]] = []
    reporter_id = _uuid("identity")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": reporter_id,
            "created": generated,
            "modified": generated,
            "name": "KittySploit OSINT",
            "identity_class": "organization",
        }
    )

    report_id = _uuid("report")
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": generated,
            "modified": generated,
            "name": name,
            "published": generated,
            "object_refs": [],
            "labels": ["osint", f"tlp:{tlp.lower()}"],
            "x_osint_root_domain": root,
            "x_case_id": case_id,
        }
    )

    id_map: Dict[str, str] = {}
    object_refs: List[str] = [report_id]

    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        key = str(node.get("id") or node.get("label") or "")
        stix_obj = _node_to_stix_object(node, created=generated, case_ref=case_id)
        id_map[key] = stix_obj["id"]
        objects.append(stix_obj)
        object_refs.append(stix_obj["id"])

    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        src = id_map.get(str(edge.get("from") or ""))
        dst = id_map.get(str(edge.get("to") or ""))
        if not src or not dst:
            continue
        rel_type = str(edge.get("relation") or "related-to").replace(" ", "-")
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _uuid("relationship"),
                "created": generated,
                "modified": generated,
                "relationship_type": rel_type,
                "source_ref": src,
                "target_ref": dst,
            }
        )

    for idx, obj in enumerate(objects):
        if obj.get("type") == "report":
            objects[idx] = dict(obj)
            objects[idx]["object_refs"] = object_refs

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def export_osint_results_stix(
    module_results: Sequence[Mapping[str, Any]],
    synthesis: Optional[Mapping[str, Any]] = None,
    *,
    case_id: str = "",
    tlp: str = "AMBER",
) -> Dict[str, Any]:
    """Build STIX bundle from module rows, optionally enriched with synthesis graph."""
    if synthesis:
        return export_osint_graph_stix(synthesis, case_id=case_id, tlp=tlp)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, str]] = []
    for row in module_results or []:
        if not isinstance(row, Mapping):
            continue
        path = str(row.get("path") or "")
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        target = str(details.get("target") or row.get("target") or "")
        if target:
            nid = f"target:{target}"
            nodes.append({"id": nid, "type": "organization", "label": target})
        for sub in details.get("subdomains") or []:
            sid = f"sub:{sub}"
            nodes.append({"id": sid, "type": "subdomain", "label": str(sub)})
            if target:
                edges.append({"from": f"target:{target}", "to": sid, "relation": "subdomain_of"})
        if "identity_handle_hunter" in path:
            for finding in details.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                handle = str(finding.get("handle") or "")
                platform = str(finding.get("platform") or "profile")
                if handle:
                    pid = f"profile:{platform}:{handle}"
                    nodes.append({
                        "id": pid,
                        "type": "profile",
                        "label": f"@{handle}",
                        "url": finding.get("url"),
                        "confidence": finding.get("confidence"),
                    })

    return export_osint_graph_stix(
        {"nodes": nodes, "edges": edges, "root_domain": case_id},
        case_id=case_id,
        tlp=tlp,
    )
