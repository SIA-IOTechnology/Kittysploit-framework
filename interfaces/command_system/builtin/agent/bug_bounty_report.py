#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HackerOne-style submission drafts from validated findings + compound evidence."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity(finding: Mapping[str, Any]) -> str:
    for key in ("severity", "importance", "risk_level"):
        val = str(finding.get(key) or "").strip().lower()
        if val in SEVERITY_RANK:
            return val
    decision = str(finding.get("decision_class") or "").lower()
    if decision == "exploit":
        return "high"
    if str(finding.get("validation_status") or "").startswith("compound"):
        return "medium"
    return "medium"


def _title(finding: Mapping[str, Any]) -> str:
    owasp = str(finding.get("owasp_class") or "security").replace("_", " ").title()
    path = str(finding.get("path") or finding.get("module") or "finding")
    short = path.split("/")[-1] if "/" in path else path
    msg = str(finding.get("message") or finding.get("evidence") or "")[:80].strip()
    if msg:
        return f"{owasp}: {msg}"[:120]
    return f"{owasp} issue via {short}"[:120]


def _steps(finding: Mapping[str, Any]) -> List[str]:
    steps: List[str] = []
    path = str(finding.get("path") or finding.get("module") or "")
    if path:
        steps.append(f"Run validation module `{path}` against the in-scope target (authorized program only).")
    witness = finding.get("witness") if isinstance(finding.get("witness"), dict) else {}
    if witness.get("request"):
        steps.append(f"Observe HTTP/request witness: {str(witness.get('request'))[:200]}")
    if witness.get("response"):
        steps.append(f"Observe response witness: {str(witness.get('response'))[:200]}")
    records = finding.get("evidence_records")
    if isinstance(records, list):
        for row in records[:4]:
            if not isinstance(row, dict):
                continue
            summary = str(row.get("summary") or row.get("kind") or "")[:160]
            if summary:
                steps.append(summary)
    panel = finding.get("refutation_panel") if isinstance(finding.get("refutation_panel"), dict) else {}
    if panel.get("verdict"):
        steps.append(f"Skeptic panel verdict: {panel.get('verdict')} (compound validation).")
    if not steps:
        steps.append("Reproduce using attached module output and request/response evidence in the agent report.")
    return steps[:8]


def _impact(owasp: str) -> str:
    mapping = {
        "injection": "May allow unauthorized data access or server-side code execution depending on context.",
        "xss": "May allow session theft or actions on behalf of the victim in the browser.",
        "ssrf": "May allow access to internal services or cloud metadata from the application's network position.",
        "auth": "May weaken authentication or session boundaries.",
        "authz": "May allow access to other users' data or privileged actions (IDOR/BOLA).",
    }
    return mapping.get(str(owasp or "").lower(), "May affect confidentiality, integrity, or availability per program rules.")


def _related_witnesses(kb: Mapping[str, Any], finding: Mapping[str, Any]) -> List[Dict[str, Any]]:
    store = kb.get("compound_evidence") if isinstance(kb.get("compound_evidence"), dict) else {}
    witnesses = [w for w in (store.get("witnesses") or []) if isinstance(w, dict)]
    path = str(finding.get("path") or finding.get("module") or "")
    related: List[Dict[str, Any]] = []
    for row in witnesses:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        blob = f"{row.get('summary', '')} {payload}"
        if path and path[-24:] in blob:
            related.append({
                "stage": row.get("stage"),
                "kind": row.get("kind"),
                "summary": str(row.get("summary") or "")[:200],
            })
    return related[-12:]


def build_submission_draft(
    finding: Mapping[str, Any],
    *,
    kb: Optional[Mapping[str, Any]] = None,
    target: str = "",
) -> Dict[str, Any]:
    owasp = str(finding.get("owasp_class") or "other").lower()
    sev = _severity(finding)
    steps = _steps(finding)
    return sanitize_nested({
        "title": _title(finding),
        "severity": sev,
        "owasp_class": owasp,
        "weakness": owasp,
        "target": str(target or "")[:256],
        "module_path": str(finding.get("path") or finding.get("module") or ""),
        "validation_status": str(finding.get("validation_status") or ""),
        "decision_class": str(finding.get("decision_class") or ""),
        "steps_to_reproduce": steps,
        "impact": _impact(owasp),
        "proof_summary": str(finding.get("message") or finding.get("evidence") or "")[:500],
        "compound_witnesses": _related_witnesses(kb or {}, finding) if kb else [],
        "markdown": format_submission_markdown(finding, steps=steps, severity=sev, owasp=owasp),
    })


def format_submission_markdown(
    finding: Mapping[str, Any],
    *,
    steps: Sequence[str],
    severity: str,
    owasp: str,
) -> str:
    title = _title(finding)
    lines = [
        f"## {title}",
        "",
        f"**Severity:** {severity}",
        f"**Weakness / class:** {owasp}",
        "",
        "### Summary",
        str(finding.get("message") or finding.get("evidence") or "")[:800],
        "",
        "### Steps to reproduce",
    ]
    for idx, step in enumerate(steps, start=1):
        lines.append(f"{idx}. {step}")
    lines.extend(["", "### Impact", _impact(owasp), ""])
    return "\n".join(lines)


def build_bug_bounty_submissions(
    contextual_findings: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    kb: Optional[Mapping[str, Any]] = None,
    target: str = "",
    limit: int = 12,
) -> Dict[str, Any]:
    rows = [f for f in (contextual_findings or []) if isinstance(f, Mapping)]
    candidates: List[Mapping[str, Any]] = []
    for finding in rows:
        if finding.get("gate_blocked"):
            continue
        status = str(finding.get("validation_status") or "").lower()
        evidence_state = str(finding.get("evidence_state") or "").lower()
        decision = str(finding.get("decision_class") or "").lower()
        if decision in {"exploit", "followup"} or status.startswith("compound") or evidence_state in {
            "confirmed",
            "exploitable",
        }:
            candidates.append(finding)
    candidates.sort(
        key=lambda row: (
            SEVERITY_RANK.get(_severity(row), 9),
            -float(row.get("context_score") or 0.0),
        )
    )
    drafts = [
        build_submission_draft(row, kb=kb, target=target)
        for row in candidates[: max(1, int(limit or 12))]
    ]
    return sanitize_nested({
        "schema_version": "1.0",
        "count": len(drafts),
        "submissions": drafts,
        "program_policy": "bug-bounty-safe",
        "notes": "Draft only — review scope, impact, and PII before submitting to a program.",
    })


def enrich_report_with_bug_bounty(
    payload: Dict[str, Any],
    *,
    contextual_findings: Optional[Sequence[Mapping[str, Any]]] = None,
    knowledge_base: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload
    kb = knowledge_base if isinstance(knowledge_base, Mapping) else {}
    target = ""
    if isinstance(payload.get("target"), str):
        target = payload["target"]
    elif isinstance(payload.get("target"), dict):
        target = str(payload["target"].get("url") or payload["target"].get("host") or "")
    payload["bug_bounty_submissions"] = build_bug_bounty_submissions(
        contextual_findings,
        kb=kb if isinstance(kb, dict) else None,
        target=target,
    )
    return payload


def format_bug_bounty_markdown(summary: Mapping[str, Any]) -> str:
    if not isinstance(summary, Mapping):
        return ""
    submissions = summary.get("submissions") if isinstance(summary.get("submissions"), list) else []
    if not submissions:
        return ""
    lines = ["\n## Bug bounty submission drafts\n", f"- Drafts: `{len(submissions)}` (review before report)\n"]
    for draft in submissions[:6]:
        if not isinstance(draft, dict):
            continue
        lines.append(f"\n### {draft.get('title', 'Finding')}\n")
        lines.append(f"- Severity: **{draft.get('severity', 'medium')}** | Class: `{draft.get('owasp_class', '')}`\n")
        md = str(draft.get("markdown") or "")
        if md:
            lines.append(md)
            lines.append("")
    return "".join(lines)


__all__ = [
    "build_bug_bounty_submissions",
    "build_submission_draft",
    "enrich_report_with_bug_bounty",
    "format_bug_bounty_markdown",
]
