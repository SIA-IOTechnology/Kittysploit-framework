#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Correlate OSINT module outputs into linked context for the agent."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from core.osint.evidence import utc_now_z
from core.osint.identity_handles import is_generic_handle
from core.osint.password_profiling import organization_root_domain


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def distinct_org_emails(identities: Mapping[str, Sequence[str]], limit: int = 24) -> List[str]:
    out: List[str] = []
    seen: set = set()
    for email in identities.get("emails", []) or []:
        text = str(email).strip().lower()
        if "@" not in text:
            continue
        local = text.split("@", 1)[0]
        if is_generic_handle(local):
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def should_run_agent_intel_step(
    step: str,
    *,
    persona_seed: str,
    identities: Mapping[str, Sequence[str]],
    root_domain: str = "",
) -> bool:
    """Skip low-value OSINT steps dynamically (smarter than static workflows)."""
    if step == "identity":
        return bool(str(persona_seed or "").strip())
    if step == "breach":
        return bool(distinct_org_emails(identities)) or bool(root_domain)
    if step == "darkweb":
        return bool(root_domain) or bool(distinct_org_emails(identities))
    if step == "crypto":
        return bool(root_domain)
    return True


def _details(row: Mapping[str, Any]) -> Dict[str, Any]:
    data = row.get("details")
    return data if isinstance(data, dict) else {}


def _module_path(row: Mapping[str, Any]) -> str:
    return str(row.get("path", "") or "")


def synthesize_intel_graph(
    results: Sequence[Mapping[str, Any]],
    *,
    root_domain: str,
    identities: Optional[Mapping[str, Sequence[str]]] = None,
    persona_seed: str = "",
) -> Dict[str, Any]:
    root = organization_root_domain(root_domain)
    identities = identities or {}
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    signals: List[str] = []
    priority_actions: List[Dict[str, Any]] = []

    def add_node(nid: str, ntype: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **extra}

    def link(frm: str, to: str, relation: str) -> None:
        if frm and to:
            edges.append({"from": frm, "to": to, "relation": relation})

    org_id = f"org:{root}"
    add_node(org_id, "organization", root, domain=root)

    person_label = str(persona_seed or "").strip()
    person_id = ""
    if person_label:
        person_id = f"person:{person_label.lower().replace(' ', '_')}"
        add_node(person_id, "person", person_label)
        link(person_id, org_id, "associated_with")

    emails = [str(e).lower() for e in (identities.get("emails") or []) if "@" in str(e)]
    distinct_emails = [e for e in emails if not is_generic_handle(e.split("@", 1)[0])]

    for email in distinct_emails[:20]:
        eid = f"email:{email}"
        add_node(eid, "email", email)
        link(eid, org_id, "mailbox_at")
        if person_id and email.split("@", 1)[0] in person_label.lower().replace(" ", ""):
            link(person_id, eid, "likely_mailbox")

    subdomains: List[str] = []
    for row in results or []:
        path = _module_path(row)
        details = _details(row)

        if "domain_surface_mapper" in path or "domain_crtsh" in path or "passive_dns_aggregator" in path:
            for sub in details.get("subdomains", []) or []:
                subdomains.append(str(sub).lower())

        if "identity_handle_hunter" in path:
            for finding in details.get("findings", []) or []:
                if not isinstance(finding, dict):
                    continue
                platform = str(finding.get("platform") or "profile")
                handle = str(finding.get("handle") or "")
                url = str(finding.get("url") or "")
                if not handle:
                    continue
                pid = f"profile:{platform}:{handle}"
                add_node(pid, "profile", f"@{handle} on {platform}", url=url, confidence=finding.get("confidence"))
                if person_id:
                    link(person_id, pid, "public_profile")
                else:
                    link(pid, org_id, "org_signal")

        if "persona_password_profiler" in path:
            count = _safe_int(details.get("password_count"))
            if count:
                signals.append(f"persona_passwords:{count}")
                priority_actions.append({
                    "action": "credential_assessment",
                    "confidence": 0.75,
                    "reason": f"{count} contextual password candidate(s) derived from OSINT",
                })

        if "breach_exposure_score" in path:
            score = _safe_int(details.get("risk_score"))
            if score >= 40:
                signals.append(f"breach_exposure:{score}")
                priority_actions.append({
                    "action": "review_breach_exposure",
                    "confidence": min(0.95, score / 100.0),
                    "reason": f"Breach exposure score {score}",
                })

        if "saas_tenant_discovery" in path:
            for finding in details.get("findings", []) or []:
                if not isinstance(finding, dict):
                    continue
                provider = str(finding.get("provider") or finding.get("service") or "saas")
                sid = f"saas:{provider}"
                add_node(sid, "saas", provider, detail=str(finding.get("detail") or "")[:120])
                link(sid, org_id, "identity_provider")

        if "github_org_exposure" in path:
            high = _safe_int(details.get("high_risk_count"))
            if high:
                signals.append(f"github_exposure:{high}")
                priority_actions.append({
                    "action": "review_github_exposure",
                    "confidence": 0.8,
                    "reason": f"{high} high-risk public repository signal(s)",
                })

        if "telegram_channel_profiler" in path:
            count = _safe_int(details.get("channel_count"))
            if count:
                signals.append(f"telegram_surface:{count}")
                for finding in details.get("findings", []) or []:
                    if not isinstance(finding, dict):
                        continue
                    handle = str(finding.get("username") or "")
                    if not handle:
                        continue
                    pid = f"profile:telegram:{handle}"
                    add_node(pid, "profile", f"@{handle}", url=finding.get("url"), confidence=finding.get("confidence"))
                    link(pid, org_id, "telegram_channel")

        if "darkweb_mention_hunter" in path:
            mentions = _safe_int(details.get("mention_count"))
            score = _safe_int(details.get("risk_score"))
            if mentions:
                signals.append(f"darkweb_mentions:{mentions}")
                sid = f"signal:darkweb:{root}"
                add_node(sid, "signal", f"Darkweb mentions ({mentions})", score=score)
                link(sid, org_id, "darkweb_signal")
                if score >= 40:
                    priority_actions.append({
                        "action": "review_darkweb_exposure",
                        "confidence": min(0.9, score / 100.0),
                        "reason": f"{mentions} darkweb/breach mention(s), risk score {score}",
                    })

        if "crypto_address_pivot" in path:
            count = _safe_int(details.get("address_count"))
            if count:
                signals.append(f"crypto_addresses:{count}")
            for finding in details.get("findings", []) or []:
                if not isinstance(finding, dict):
                    continue
                addr = str(finding.get("address") or "")
                if not addr:
                    continue
                cid = f"crypto:{addr[:24]}"
                chain = str(finding.get("chain") or "unknown")
                add_node(cid, "signal", f"{chain}:{addr[:18]}…", url=finding.get("source_url"))
                link(cid, org_id, "crypto_wallet")

    for sub in sorted(set(subdomains))[:25]:
        sid = f"host:{sub}"
        add_node(sid, "subdomain", sub)
        link(sid, org_id, "subdomain_of")

    if subdomains:
        priority_actions.append({
            "action": "expand_host_surface",
            "confidence": 0.72,
            "reason": f"{len(set(subdomains))} subdomain(s) mapped — scan derived hosts for shell paths",
        })

    api_surface = False
    for row in results or []:
        path = _module_path(row)
        details = _details(row)
        blob = " ".join(
            str(details.get(key, ""))
            for key in ("endpoints", "paths", "summary", "message")
            if details.get(key)
        ).lower()
        if any(tok in path for tok in ("crawler", "js_endpoint", "swagger", "graphql", "api")):
            if "/api" in blob or "graphql" in blob or "swagger" in blob or "openapi" in blob:
                api_surface = True
        for endpoint in details.get("endpoints", []) or []:
            if any(tok in str(endpoint).lower() for tok in ("/api", "graphql", "swagger")):
                api_surface = True
    if api_surface:
        priority_actions.append({
            "action": "test_api_surface",
            "confidence": 0.78,
            "reason": "API or GraphQL endpoints observed — fuzz authz and injection toward RCE",
        })
        signals.append("api_surface_from_osint")

    summary_lines = _build_summary_lines(root, person_label, distinct_emails, nodes, edges, signals)

    return {
        "root_domain": root,
        "persona_seed": person_label,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": list(nodes.values())[:60],
        "edges": edges[:80],
        "signals": signals,
        "summary_lines": summary_lines,
        "priority_actions": sorted(priority_actions, key=lambda x: -float(x.get("confidence", 0)))[:12],
    }


def _build_summary_lines(
    root: str,
    person: str,
    emails: Sequence[str],
    nodes: Mapping[str, Dict[str, Any]],
    edges: Sequence[Mapping[str, str]],
    signals: Sequence[str],
) -> List[str]:
    lines: List[str] = [f"Organization surface: {root}"]
    if person:
        lines.append(f"Persona focus: {person}")
    profile_edges = [e for e in edges if e.get("relation") == "public_profile"]
    if profile_edges:
        lines.append(f"Verified public profiles linked to persona: {len(profile_edges)}")
    if emails:
        lines.append(f"Distinct organizational emails observed: {', '.join(emails[:5])}")
    subs = [n["label"] for n in nodes.values() if n.get("type") == "subdomain"]
    if subs:
        lines.append(f"Subdomain surface sample: {', '.join(subs[:6])}")
    for sig in signals[:6]:
        lines.append(f"Risk signal: {sig}")
    return lines


def merge_osint_synthesis_into_knowledge_base(
    knowledge_base: MutableMapping[str, Any],
    synthesis: Mapping[str, Any],
) -> None:
    if not isinstance(knowledge_base, dict) or not isinstance(synthesis, dict):
        return
    knowledge_base["osint_graph"] = {
        "nodes": list(synthesis.get("nodes") or []),
        "edges": list(synthesis.get("edges") or []),
    }
    knowledge_base["osint_summary"] = list(synthesis.get("summary_lines") or [])
    knowledge_base["osint_priority_actions"] = list(synthesis.get("priority_actions") or [])
    knowledge_base["osint_signals"] = list(synthesis.get("signals") or [])
    knowledge_base["osint_collected_at"] = utc_now_z()
    if synthesis.get("persona_seed"):
        knowledge_base["persona_name"] = str(synthesis.get("persona_seed"))

    risk = set(knowledge_base.get("risk_signals") or [])
    for action in synthesis.get("priority_actions") or []:
        if not isinstance(action, dict):
            continue
        act = str(action.get("action") or "").strip()
        if act:
            risk.add(act)
    if synthesis.get("signals"):
        risk.add("osint_correlated")
    knowledge_base["risk_signals"] = sorted(risk)

    subdomains: List[str] = []
    graph = synthesis.get("nodes") or []
    for node in graph:
        if isinstance(node, dict) and node.get("type") == "subdomain":
            label = str(node.get("label") or "").strip().lower()
            if label:
                subdomains.append(label)
    if subdomains:
        existing = list(knowledge_base.get("subdomain_candidates") or [])
        merged: List[str] = []
        seen_subs: set = set()
        for host in existing + subdomains:
            h = str(host).strip().lower()
            if h and h not in seen_subs:
                seen_subs.add(h)
                merged.append(h)
        knowledge_base["subdomain_candidates"] = merged[:48]
