#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Static audit of module ``__info__['agent']`` metadata for the autonomous agent."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_module_meta import (
    RISK_LEVELS,
    normalize_agent_block,
)

REQUIRED_FIELDS: Sequence[str] = ("risk", "expected_requests")
RECOMMENDED_FIELDS: Sequence[str] = (
    "effects",
    "reversible",
    "approval_required",
    "produces",
    "protocols",
    "auth_required",
)
EXTENDED_FIELDS: Sequence[str] = ("requires", "chain", "consumes", "prerequisites")


def lint_agent_block(agent_raw: Any) -> List[str]:
    """Return human-readable issues for a raw or normalized agent block."""
    if agent_raw is None:
        return ["missing agent metadata block"]
    if not isinstance(agent_raw, dict):
        return ["agent metadata must be an object"]
    issues: List[str] = []
    normalized = normalize_agent_block(agent_raw)
    if normalized is None:
        return ["agent metadata could not be normalized"]
    risk = str(normalized.get("risk") or "").strip().lower()
    if not risk:
        issues.append("missing required field: risk")
    elif risk not in RISK_LEVELS:
        issues.append(f"invalid risk level: {risk}")
    expected = agent_raw.get("expected_requests")
    if "expected_requests" not in agent_raw and expected is None:
        issues.append("missing required field: expected_requests")
    elif expected is not None:
        try:
            if int(expected) < 1:
                issues.append("expected_requests must be >= 1")
        except (TypeError, ValueError):
            issues.append("expected_requests must be a positive integer")
    return issues


def lint_agent_block_strict(agent_raw: Any) -> List[str]:
    issues = lint_agent_block(agent_raw)
    if agent_raw is None or not isinstance(agent_raw, dict):
        return issues
    normalized = normalize_agent_block(agent_raw) or {}
    for field in RECOMMENDED_FIELDS:
        if field not in agent_raw and field not in normalized:
            issues.append(f"missing recommended field: {field}")
    return issues


def is_agent_metadata_compliant(agent_raw: Any) -> bool:
    return not lint_agent_block(agent_raw)


def audit_module_catalog(
    discovered: Dict[str, str],
    extract_metadata: Callable[[str], Dict[str, Any]],
    *,
    limit_sample: int = 12,
) -> Dict[str, Any]:
    """Scan the module catalog and summarize agent metadata coverage."""
    rows: List[Dict[str, Any]] = []
    compliant = 0
    partial = 0
    missing = 0
    by_risk: Dict[str, int] = {}
    for module_path in sorted(discovered):
        meta = extract_metadata(discovered[module_path])
        agent_raw = meta.get("agent") if isinstance(meta, dict) else None
        issues = lint_agent_block(agent_raw)
        if agent_raw is None:
            status = "missing"
            missing += 1
        elif issues:
            status = "partial"
            partial += 1
        else:
            status = "compliant"
            compliant += 1
            risk = str((normalize_agent_block(agent_raw) or {}).get("risk") or "unknown")
            by_risk[risk] = int(by_risk.get(risk, 0)) + 1
        if issues or status != "compliant":
            rows.append(
                {
                    "path": module_path,
                    "status": status,
                    "issues": issues,
                }
            )
    total = len(discovered)
    sample = rows[: max(0, int(limit_sample))]
    return {
        "ok": compliant > 0 and missing < total,
        "total_modules": total,
        "compliant": compliant,
        "partial": partial,
        "missing": missing,
        "coverage_ratio": round(compliant / total, 4) if total else 0.0,
        "by_risk": by_risk,
        "non_compliant_sample": sample,
        "non_compliant_count": len(rows),
    }


def format_audit_table(audit: Dict[str, Any]) -> str:
    lines = [
        f"total={audit.get('total_modules', 0)} "
        f"compliant={audit.get('compliant', 0)} "
        f"partial={audit.get('partial', 0)} "
        f"missing={audit.get('missing', 0)}",
    ]
    for row in audit.get("non_compliant_sample") or []:
        path = row.get("path", "")
        status = row.get("status", "")
        issue = (row.get("issues") or ["?"])[0]
        lines.append(f"  [{status}] {path}: {issue}")
    return "\n".join(lines)
