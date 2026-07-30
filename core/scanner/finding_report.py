#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Structured scanner finding reports for DB / KittyReport."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union


def normalize_severity(value: Any, default: str = "medium") -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "unknown",
    }
    if not text:
        return default
    return aliases.get(text, text if text in aliases.values() else default)


def _as_impact(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return {"summary": text} if text else None
    if not isinstance(value, dict):
        return None
    out: Dict[str, Any] = {}
    summary = value.get("summary") or value.get("description") or value.get("text")
    if summary:
        out["summary"] = str(summary).strip()
    business_risk = value.get("business_risk") or value.get("risk")
    if business_risk:
        out["business_risk"] = str(business_risk).strip()
    for key, item in value.items():
        if key in ("summary", "description", "text", "business_risk", "risk"):
            continue
        out[key] = item
    return out or None


def _as_remediation(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return {"summary": text} if text else None
    if isinstance(value, (list, tuple)):
        actions = [str(item).strip() for item in value if str(item or "").strip()]
        return {"actions": actions} if actions else None
    if not isinstance(value, dict):
        return None
    out: Dict[str, Any] = {}
    summary = value.get("summary") or value.get("description") or value.get("text")
    if summary:
        out["summary"] = str(summary).strip()
    actions = value.get("actions") or value.get("steps")
    if isinstance(actions, (list, tuple)):
        cleaned = [str(item).strip() for item in actions if str(item or "").strip()]
        if cleaned:
            out["actions"] = cleaned
    for key, item in value.items():
        if key in ("summary", "description", "text", "actions", "steps"):
            continue
        out[key] = item
    return out or None


def _as_evidence(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return {"summary": text} if text else None
    if not isinstance(value, dict):
        return None
    return dict(value)


def build_finding_report(
    finding: str,
    *,
    severity: Any = "medium",
    evidence: Any = None,
    impact: Any = None,
    remediation: Any = None,
    **extra: Any,
) -> Dict[str, Any]:
    """
    Build the canonical structured finding payload:

    {
      "finding": "...",
      "severity": "high",
      "evidence": {...},
      "impact": {...},
      "remediation": {...}
    }
    """
    title = str(finding or "").strip()
    if not title:
        raise ValueError("finding title is required")

    report: Dict[str, Any] = {
        "finding": title,
        "severity": normalize_severity(severity),
    }
    ev = _as_evidence(evidence)
    if ev:
        report["evidence"] = ev
    imp = _as_impact(impact)
    if imp:
        report["impact"] = imp
    rem = _as_remediation(remediation)
    if rem:
        report["remediation"] = rem

    for key, value in extra.items():
        if value is None or key in report:
            continue
        report[key] = value
    return report


def extract_finding_report(payload: Any) -> Optional[Dict[str, Any]]:
    """Pull a structured report from vulnerability_info / scanner result / entry."""
    if not isinstance(payload, dict):
        return None

    nested = payload.get("report")
    if isinstance(nested, dict) and nested.get("finding"):
        return build_finding_report(
            nested.get("finding"),
            severity=nested.get("severity") or payload.get("severity"),
            evidence=nested.get("evidence"),
            impact=nested.get("impact"),
            remediation=nested.get("remediation"),
            **{
                k: v
                for k, v in nested.items()
                if k not in ("finding", "severity", "evidence", "impact", "remediation")
            },
        )

    if payload.get("finding") and (
        isinstance(payload.get("evidence"), dict)
        or payload.get("impact") is not None
        or payload.get("remediation") is not None
        or payload.get("severity")
    ):
        return build_finding_report(
            payload.get("finding"),
            severity=payload.get("severity"),
            evidence=payload.get("evidence"),
            impact=payload.get("impact"),
            remediation=payload.get("remediation"),
        )

    return None


def report_to_vulnerability_fields(report: Dict[str, Any]) -> Dict[str, Any]:
    """Map structured report → Vulnerability column values."""
    title = str(report.get("finding") or "").strip() or "Scanner finding"
    severity = normalize_severity(report.get("severity"))
    # DB constraint: no "info"
    risk_level = "low" if severity == "info" else severity
    if risk_level not in ("critical", "high", "medium", "low", "unknown"):
        risk_level = "unknown"

    impact = report.get("impact") if isinstance(report.get("impact"), dict) else {}
    rem = report.get("remediation") if isinstance(report.get("remediation"), dict) else {}

    description_parts: List[str] = []
    if impact.get("summary"):
        description_parts.append(str(impact["summary"]))
    if impact.get("business_risk"):
        description_parts.append(f"Business risk: {impact['business_risk']}")
    if not description_parts and report.get("evidence"):
        description_parts.append(f"Evidence available for: {title}")

    rem_parts: List[str] = []
    if rem.get("summary"):
        rem_parts.append(str(rem["summary"]))
    actions = rem.get("actions")
    if isinstance(actions, list) and actions:
        rem_parts.append("Actions:")
        for action in actions:
            rem_parts.append(f"- {action}")

    try:
        proof = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    except Exception:
        proof = str(report)

    return {
        "name": title[:255],
        "risk_level": risk_level,
        "description": "\n".join(description_parts)[:4000],
        "remediation": "\n".join(rem_parts)[:4000],
        "proof_of_concept": proof[:8000],
        "severity": severity,
    }


def parse_report_from_proof(proof: Any) -> Optional[Dict[str, Any]]:
    """Recover a structured report stored in ``Vulnerability.proof_of_concept``."""
    if proof is None:
        return None
    if isinstance(proof, dict):
        return extract_finding_report(proof) or (
            build_finding_report(
                proof.get("finding") or proof.get("title") or "Finding",
                severity=proof.get("severity") or proof.get("risk_level"),
                evidence=proof.get("evidence"),
                impact=proof.get("impact"),
                remediation=proof.get("remediation"),
            )
            if proof.get("finding") or proof.get("title")
            else None
        )
    text = str(proof).strip()
    if not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except Exception:
        # PoC may include trailing "Evidence files:" lines after the JSON block
        end = text.rfind("}")
        if end <= 0:
            return None
        try:
            data = json.loads(text[: end + 1])
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    return extract_finding_report(data) or (
        build_finding_report(
            data.get("finding") or data.get("title") or "Finding",
            severity=data.get("severity") or data.get("risk_level"),
            evidence=data.get("evidence"),
            impact=data.get("impact"),
            remediation=data.get("remediation"),
        )
        if (data.get("finding") or data.get("title"))
        else None
    )


def _parse_remediation_text(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return {}
    actions: List[str] = []
    summary_parts: List[str] = []
    in_actions = False
    for line in lines:
        if line.lower().rstrip(":") == "actions":
            in_actions = True
            continue
        if line.startswith("- "):
            actions.append(line[2:].strip())
            in_actions = True
            continue
        if in_actions:
            actions.append(line)
        else:
            summary_parts.append(line)
    out: Dict[str, Any] = {}
    if summary_parts:
        out["summary"] = " ".join(summary_parts)
    if actions:
        out["actions"] = actions
    return out


def _parse_impact_text(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    out: Dict[str, Any] = {}
    business = None
    summary_lines: List[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("business risk:"):
            business = stripped.split(":", 1)[1].strip()
        elif stripped:
            summary_lines.append(stripped)
    if summary_lines:
        out["summary"] = " ".join(summary_lines)
    if business:
        out["business_risk"] = business
    return out


def vulnerability_to_kittyreport_finding(
    vuln: Any,
    *,
    include_sync_meta: bool = True,
) -> Dict[str, Any]:
    """
    Build the KittyReport push payload:

    {
      "finding": "Exposed Git repository",
      "severity": "High",
      "evidence": {...},
      "impact": {...},
      "remediation": {...}
    }
    """
    if hasattr(vuln, "to_dict"):
        raw = vuln.to_dict()
    elif isinstance(vuln, dict):
        raw = dict(vuln)
    else:
        raw = {
            "name": getattr(vuln, "name", None),
            "description": getattr(vuln, "description", None),
            "risk_level": getattr(vuln, "risk_level", None),
            "proof_of_concept": getattr(vuln, "proof_of_concept", None),
            "remediation": getattr(vuln, "remediation", None),
            "cve": getattr(vuln, "cve", None),
            "id": getattr(vuln, "id", None),
        }

    report = parse_report_from_proof(raw.get("proof_of_concept"))
    if report is None:
        impact = _parse_impact_text(raw.get("description") or "")
        rem = _parse_remediation_text(raw.get("remediation") or "")
        evidence: Dict[str, Any] = {}
        poc = str(raw.get("proof_of_concept") or "").strip()
        if poc and not poc.startswith("{"):
            evidence["summary"] = poc[:2000]
        report = build_finding_report(
            raw.get("name") or raw.get("finding") or "Finding",
            severity=raw.get("risk_level") or raw.get("severity") or "unknown",
            evidence=evidence or None,
            impact=impact or None,
            remediation=rem or None,
        )

    # KittyReport display severity (capitalized), keep structured sections intact.
    severity = normalize_severity(report.get("severity") or raw.get("risk_level"))
    payload: Dict[str, Any] = {
        "finding": report.get("finding"),
        "severity": severity.capitalize() if severity != "unknown" else "Unknown",
    }
    if report.get("evidence"):
        try:
            from core.scanner.screenshot import enrich_kittyreport_evidence_with_screenshot

            payload["evidence"] = enrich_kittyreport_evidence_with_screenshot(report["evidence"])
        except Exception:
            payload["evidence"] = report["evidence"]
    if report.get("impact"):
        payload["impact"] = report["impact"]
    if report.get("remediation"):
        payload["remediation"] = report["remediation"]

    if include_sync_meta:
        if raw.get("id") is not None:
            payload["id"] = raw["id"]
        if raw.get("cve"):
            payload["cve"] = raw["cve"]
        if raw.get("cvss_score"):
            payload["cvss_score"] = raw["cvss_score"]
        if raw.get("service_id") is not None:
            payload["service_id"] = raw["service_id"]
        # Keep original DB fields for SaaS merge / debugging without cluttering the report shape.
        payload["name"] = report.get("finding") or raw.get("name")
        payload["risk_level"] = severity if severity != "info" else "low"
        if raw.get("created_at"):
            payload["created_at"] = raw["created_at"]
        if raw.get("updated_at"):
            payload["updated_at"] = raw["updated_at"]

    return payload


def evidence_preview_from_report(report: Dict[str, Any], limit: int = 400) -> str:
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    parts: List[str] = []
    if evidence.get("url"):
        line = str(evidence["url"])
        if evidence.get("status_code") is not None:
            line = f"{line} ({evidence.get('status_code')})"
        parts.append(line)
    files = evidence.get("files_found") or evidence.get("files")
    if isinstance(files, (list, tuple)) and files:
        parts.append("files=" + ",".join(str(x) for x in list(files)[:8]))
    for key in ("path", "parameter", "probe", "summary", "snippet", "screenshot"):
        if evidence.get(key):
            parts.append(f"{key}={evidence.get(key)}")
    if not parts and report.get("finding"):
        parts.append(str(report["finding"]))
    return " | ".join(parts)[:limit]


def format_report_console(report: Dict[str, Any]) -> List[str]:
    """Human-readable lines for interactive ``run`` / verbose scanner output."""
    lines = [
        f"Finding: {report.get('finding')}",
        f"Severity: {str(report.get('severity') or 'unknown').capitalize()}",
    ]
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else None
    if evidence:
        try:
            lines.append("Evidence: " + json.dumps(evidence, ensure_ascii=False, default=str))
        except Exception:
            lines.append(f"Evidence: {evidence}")
    impact = report.get("impact") if isinstance(report.get("impact"), dict) else None
    if impact and impact.get("summary"):
        lines.append(f"Impact: {impact.get('summary')}")
    rem = report.get("remediation") if isinstance(report.get("remediation"), dict) else None
    if rem and rem.get("summary"):
        lines.append(f"Remediation: {rem.get('summary')}")
    return lines
