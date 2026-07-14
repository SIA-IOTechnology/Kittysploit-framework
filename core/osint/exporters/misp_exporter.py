#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Export OSINT synthesis to MISP Event JSON."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.osint.evidence import utc_now_z
from core.osint.mitre_mapping import infer_mitre_techniques, misp_galaxy_tags


def _tlp_to_misp_distribution(tlp: str) -> str:
    key = str(tlp or "AMBER").strip().upper()
    return {
        "WHITE": "3",
        "GREEN": "2",
        "AMBER": "1",
        "RED": "0",
    }.get(key, "1")


def _attribute(attr_type: str, value: str, *, category: str, comment: str = "", to_ids: bool = False) -> Dict[str, Any]:
    return {
        "type": attr_type,
        "category": category,
        "value": value,
        "comment": comment,
        "to_ids": to_ids,
        "disable_correlation": False,
    }


def export_osint_misp_event(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    tlp: str = "AMBER",
    info: str = "",
) -> Dict[str, Any]:
    root = str(synthesis.get("root_domain") or case_id or "osint-target")
    attributes: List[Dict[str, Any]] = []
    seen: set = set()

    def add(attr_type: str, value: str, **kwargs: Any) -> None:
        val = str(value or "").strip()
        if not val:
            return
        key = (attr_type, val.lower())
        if key in seen:
            return
        seen.add(key)
        attributes.append(_attribute(attr_type, val, **kwargs))

    for node in synthesis.get("nodes") or []:
        if not isinstance(node, Mapping):
            continue
        ntype = str(node.get("type") or "")
        label = str(node.get("label") or "")
        if ntype in ("organization", "subdomain"):
            add("domain", label, category="Network activity", comment=ntype)
        elif ntype == "email":
            add("email-src", label, category="Person", comment="osint-email")
        elif ntype == "profile":
            url = str(node.get("url") or "")
            if url:
                add("url", url, category="Social network", comment="public-profile")
            add("username", label.lstrip("@"), category="Person", comment="handle")
        elif ntype == "person":
            add("target-org", label, category="Person", comment="persona")

    for row in module_results or []:
        if not isinstance(row, Mapping):
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        path = str(row.get("path") or "")
        for finding in details.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            if "telegram" in path:
                username = str(finding.get("username") or finding.get("handle") or "")
                url = str(finding.get("url") or "")
                if username:
                    add("telegram-account", username, category="Social network", comment="telegram")
                if url:
                    add("url", url, category="Social network", comment="telegram-channel")
            if "darkweb" in path:
                snippet = str(finding.get("snippet") or finding.get("title") or "")[:512]
                source = str(finding.get("source") or finding.get("bucket") or "darkweb")
                if snippet:
                    add(
                        "text",
                        snippet,
                        category="External analysis",
                        comment=f"darkweb:{source}",
                    )
            if "crypto" in path:
                addr = str(finding.get("address") or "")
                chain = str(finding.get("chain") or "btc").lower()
                if addr:
                    attr_type = "btc" if chain in ("btc", "bitcoin") else "xbt" if chain == "xbt" else "text"
                    if chain in ("eth", "ethereum"):
                        attr_type = "text"
                    add(attr_type, addr, category="Financial fraud", comment=f"crypto:{chain}")

    techniques = infer_mitre_techniques(synthesis, module_results)
    tags = [
        {"name": f"tlp:{tlp.lower()}"},
        {"name": "osint:passive"},
        {"name": "kittysploit:osint"},
    ]
    tags.extend(misp_galaxy_tags(techniques))

    event_info = info or f"KittySploit OSINT — {root}"
    return {
        "Event": {
            "info": event_info,
            "date": utc_now_z()[:10],
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": _tlp_to_misp_distribution(tlp),
            "published": False,
            "Attribute": attributes,
            "Tag": tags,
            "Orgc": {"name": "KittySploit OSINT"},
            "x_case_id": case_id,
            "Galaxy": [
                {"type": "mitre-attack-pattern", "name": row.get("name"), "tag_id": row.get("id")}
                for row in techniques
            ],
        }
    }


def push_misp_event(
    event: Mapping[str, Any],
    *,
    url: str,
    api_key: str,
    timeout: int = 30,
) -> Dict[str, Any]:
    """POST a MISP Event (requires running MISP instance)."""
    base = str(url or "").strip().rstrip("/")
    key = str(api_key or "").strip()
    if not base or not key:
        return {"ok": False, "error": "MISP URL and API key required"}

    payload = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/events/add",
        data=payload,
        method="POST",
        headers={
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "body": body[:2000]}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.read().decode("utf-8", errors="replace")[:500]}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
