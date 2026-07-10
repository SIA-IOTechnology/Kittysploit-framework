#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Three-level OSINT intelligence reports (strategic / tactical / operational)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.osint.evidence import utc_now_z
from core.osint.mitre_mapping import infer_mitre_techniques


def _collect_iocs(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, List[str]]:
    domains: List[str] = []
    emails: List[str] = []
    urls: List[str] = []
    handles: List[str] = []
    crypto: List[str] = []

    for node in synthesis.get("nodes") or []:
        if not isinstance(node, Mapping):
            continue
        ntype = str(node.get("type") or "")
        label = str(node.get("label") or "")
        if ntype in ("organization", "subdomain") and label:
            domains.append(label)
        elif ntype == "email":
            emails.append(label)
        elif ntype == "profile":
            handles.append(label.lstrip("@"))
            url = str(node.get("url") or "")
            if url:
                urls.append(url)

    for row in module_results or []:
        if not isinstance(row, Mapping):
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        for addr in details.get("addresses") or details.get("crypto_addresses") or []:
            crypto.append(str(addr))
        for finding in details.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            if finding.get("address"):
                crypto.append(str(finding["address"]))
            if finding.get("url"):
                urls.append(str(finding["url"]))

    def _uniq(items: Sequence[str], limit: int = 40) -> List[str]:
        seen: set = set()
        out: List[str] = []
        for raw in items:
            val = str(raw).strip()
            key = val.lower()
            if not val or key in seen:
                continue
            seen.add(key)
            out.append(val)
            if len(out) >= limit:
                break
        return out

    return {
        "domains": _uniq(domains),
        "emails": _uniq(emails),
        "urls": _uniq(urls),
        "handles": _uniq(handles),
        "crypto_addresses": _uniq(crypto, 20),
    }


def generate_strategic_report(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    legal_basis: str = "",
    tlp: str = "AMBER",
) -> Dict[str, Any]:
    """Executive / strategic assessment."""
    root = str(synthesis.get("root_domain") or case_id or "unknown")
    signals = list(synthesis.get("signals") or [])
    techniques = infer_mitre_techniques(synthesis, module_results)
    risk_themes: List[str] = []
    if any("darkweb" in s for s in signals):
        risk_themes.append("Credential or identity exposure on underground channels")
    if any("github" in s for s in signals):
        risk_themes.append("Public code repository leakage or CI/CD misconfiguration")
    if any("telegram" in s for s in signals):
        risk_themes.append("Public messaging surface linked to target organization")
    if any("breach" in s for s in signals):
        risk_themes.append("Historical breach exposure for target identities")
    if not risk_themes:
        risk_themes.append("Passive reconnaissance completed — review tactical findings")

    return {
        "level": "strategic",
        "generated_at": utc_now_z(),
        "case_id": case_id,
        "legal_basis": legal_basis,
        "tlp": tlp,
        "target_organization": root,
        "executive_summary": (
            f"Passive OSINT on {root} produced {synthesis.get('node_count', 0)} correlated "
            f"entities and {len(signals)} risk signal(s)."
        ),
        "risk_themes": risk_themes,
        "mitre_techniques": techniques,
        "collection_scope": "passive-only OSINT (no intrusive testing)",
        "recommendations": [
            "Validate high-confidence identity links with independent sources",
            "Escalate darkweb/breach hits to case lead under existing legal basis",
            "Share IOC package with national CSIRT/MISP trust group at configured TLP",
        ],
    }


def generate_tactical_report(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
) -> Dict[str, Any]:
    """Tactical analysis — surface, TTPs, priority actions."""
    priority = list(synthesis.get("priority_actions") or [])[:12]
    summary_lines = list(synthesis.get("summary_lines") or [])
    techniques = infer_mitre_techniques(synthesis, module_results)
    modules_run = [
        str(r.get("path", "")).rsplit("/", 1)[-1]
        for r in (module_results or [])
        if isinstance(r, Mapping) and r.get("path")
    ]

    return {
        "level": "tactical",
        "generated_at": utc_now_z(),
        "case_id": case_id,
        "attack_surface_summary": summary_lines,
        "priority_actions": priority,
        "mitre_techniques": techniques,
        "modules_executed": modules_run,
        "graph_stats": {
            "nodes": synthesis.get("node_count", 0),
            "edges": synthesis.get("edge_count", 0),
        },
        "signals": list(synthesis.get("signals") or []),
    }


def generate_operational_report(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
) -> Dict[str, Any]:
    """Operational package — actionable IOCs and verification tasks."""
    iocs = _collect_iocs(synthesis, module_results)
    tasks: List[Dict[str, str]] = []
    for email in iocs["emails"][:10]:
        tasks.append({"type": "verify_email", "value": email, "action": "Confirm mailbox ownership and breach relevance"})
    for handle in iocs["handles"][:10]:
        tasks.append({"type": "verify_handle", "value": handle, "action": "Correlate with case subject via second source"})
    for addr in iocs["crypto_addresses"][:8]:
        tasks.append({"type": "trace_crypto", "value": addr, "action": "Submit to authorized blockchain analysis unit"})
    for domain in iocs["domains"][:8]:
        tasks.append({"type": "monitor_domain", "value": domain, "action": "Add to passive DNS / CT monitoring"})

    return {
        "level": "operational",
        "generated_at": utc_now_z(),
        "case_id": case_id,
        "iocs": iocs,
        "verification_tasks": tasks,
        "module_evidence_count": len(list(module_results or [])),
    }


def render_osint_report_markdown(
    strategic: Mapping[str, Any],
    tactical: Mapping[str, Any],
    operational: Mapping[str, Any],
) -> str:
    """Single Markdown document combining three report levels."""
    lines = [
        "# OSINT Intelligence Report",
        "",
        f"- Generated: {strategic.get('generated_at', '')}",
        f"- Case: {strategic.get('case_id', '')}",
        f"- Legal basis: {strategic.get('legal_basis', '')}",
        f"- TLP: {strategic.get('tlp', 'AMBER')}",
        "",
        "## Strategic Assessment",
        "",
        str(strategic.get("executive_summary", "")),
        "",
        "### Risk themes",
    ]
    for theme in strategic.get("risk_themes") or []:
        lines.append(f"- {theme}")
    lines.extend(["", "### MITRE ATT&CK (reconnaissance)", ""])
    for tech in strategic.get("mitre_techniques") or []:
        if isinstance(tech, dict):
            lines.append(f"- `{tech.get('id')}` — {tech.get('name')}")

    lines.extend(["", "## Tactical Analysis", ""])
    for row in tactical.get("attack_surface_summary") or []:
        lines.append(f"- {row}")
    lines.extend(["", "### Priority actions", ""])
    for action in tactical.get("priority_actions") or []:
        if isinstance(action, dict):
            lines.append(f"- **{action.get('action')}** ({action.get('confidence')}): {action.get('reason')}")

    lines.extend(["", "## Operational Package", ""])
    iocs = operational.get("iocs") or {}
    for key in ("domains", "emails", "handles", "crypto_addresses", "urls"):
        values = iocs.get(key) or []
        if values:
            lines.append(f"### {key}")
            for val in values[:15]:
                lines.append(f"- `{val}`")
            lines.append("")

    lines.extend(["### Verification tasks", ""])
    for task in operational.get("verification_tasks") or []:
        if isinstance(task, dict):
            lines.append(f"- [{task.get('type')}] `{task.get('value')}` — {task.get('action')}")

    return "\n".join(lines) + "\n"


def generate_osint_reports(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    legal_basis: str = "",
    tlp: str = "AMBER",
) -> Dict[str, Any]:
    """Build strategic, tactical, operational reports and combined markdown."""
    strategic = generate_strategic_report(
        synthesis,
        module_results,
        case_id=case_id,
        legal_basis=legal_basis,
        tlp=tlp,
    )
    tactical = generate_tactical_report(synthesis, module_results, case_id=case_id)
    operational = generate_operational_report(synthesis, module_results, case_id=case_id)
    markdown = render_osint_report_markdown(strategic, tactical, operational)
    return {
        "strategic": strategic,
        "tactical": tactical,
        "operational": operational,
        "markdown": markdown,
    }
