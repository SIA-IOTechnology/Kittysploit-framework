#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Export OSINT packages in a UMF-inspired JSON envelope for LE / Europol exchange.

The Universal Message Format (UMF) used by Europol is specification-controlled;
this exporter produces a compatible logical structure (header, entities,
relationships, provenance, attachments) suitable for national platform ingestion
and manual UMF mapping.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.osint.evidence import utc_now_z
from core.osint.mitre_mapping import infer_mitre_techniques
from core.osint.reports import generate_operational_report, generate_strategic_report


def _msg_id(case_id: str) -> str:
    seed = case_id or "osint"
    return f"UMF-OSINT-{seed}-{uuid.uuid4().hex[:10]}"


def _entity_id(prefix: str, label: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in label.lower())[:48]
    return f"{prefix}-{safe}-{uuid.uuid4().hex[:6]}"


def export_osint_umf_message(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    legal_basis: str = "",
    tlp: str = "AMBER",
    sender_org: str = "KittySploit OSINT",
    recipient_org: str = "",
    classification: str = "LAW ENFORCEMENT SENSITIVE",
    artifact_paths: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    generated = utc_now_z()
    root = str(synthesis.get("root_domain") or case_id or "unknown")
    message_id = _msg_id(case_id or root)

    entities: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []
    id_map: Dict[str, str] = {}

    org_eid = _entity_id("org", root)
    entities.append({
        "entityId": org_eid,
        "entityType": "Organization",
        "label": root,
        "attributes": {"domain": root},
        "provenance": {"source": "osint_passive", "collectedAt": generated},
    })
    id_map[f"org:{root}"] = org_eid

    for node in synthesis.get("nodes") or []:
        if not isinstance(node, Mapping):
            continue
        ntype = str(node.get("type") or "unknown")
        label = str(node.get("label") or "")
        nid = str(node.get("id") or label)
        if not label:
            continue
        type_map = {
            "subdomain": "Infrastructure",
            "email": "DigitalIdentity",
            "profile": "DigitalIdentity",
            "person": "Person",
            "signal": "Indicator",
            "saas": "Service",
        }
        eid = _entity_id(type_map.get(ntype, "Entity"), label)
        id_map[nid] = eid
        entities.append({
            "entityId": eid,
            "entityType": type_map.get(ntype, "Entity"),
            "label": label,
            "attributes": {
                k: v for k, v in node.items()
                if k not in ("id", "type", "label") and v is not None
            },
            "confidence": node.get("confidence"),
            "provenance": {"source": "osint_correlation", "collectedAt": generated},
        })

    for edge in synthesis.get("edges") or []:
        if not isinstance(edge, Mapping):
            continue
        src = id_map.get(str(edge.get("from") or ""))
        dst = id_map.get(str(edge.get("to") or ""))
        if not src or not dst:
            continue
        relationships.append({
            "relationshipId": f"rel-{uuid.uuid4().hex[:10]}",
            "sourceEntityId": src,
            "targetEntityId": dst,
            "relationshipType": str(edge.get("relation") or "related_to"),
        })

    strategic = generate_strategic_report(
        synthesis,
        module_results,
        case_id=case_id,
        legal_basis=legal_basis,
        tlp=tlp,
    )
    operational = generate_operational_report(synthesis, module_results, case_id=case_id)
    techniques = infer_mitre_techniques(synthesis, module_results)

    attachments = []
    for name, path in (artifact_paths or {}).items():
        attachments.append({
            "attachmentId": f"att-{name}",
            "name": name,
            "path": str(path),
            "mimeType": "application/json" if str(path).endswith(".json") else "text/markdown",
        })

    return {
        "umfVersion": "1.0-inspired",
        "messageId": message_id,
        "messageType": "IntelligenceReport",
        "header": {
            "createdAt": generated,
            "sender": {"organization": sender_org, "system": "KittySploit-OSINT-LE"},
            "recipient": {"organization": recipient_org or "Member State / Europol EC3"},
            "classification": classification,
            "tlp": str(tlp or "AMBER").upper(),
            "legalBasis": legal_basis,
            "caseReference": case_id,
            "handlingInstructions": "Passive OSINT — verify independently before operational use",
        },
        "assessment": {
            "executiveSummary": strategic.get("executive_summary"),
            "riskThemes": strategic.get("risk_themes"),
            "mitreTechniques": techniques,
        },
        "entities": entities,
        "relationships": relationships,
        "indicators": operational.get("iocs") or {},
        "verificationTasks": operational.get("verification_tasks") or [],
        "provenance": {
            "collectionMethod": "passive_osint",
            "moduleCount": len(list(module_results or [])),
            "graphNodes": synthesis.get("node_count", 0),
            "graphEdges": synthesis.get("edge_count", 0),
            "signals": list(synthesis.get("signals") or []),
        },
        "attachments": attachments,
    }
