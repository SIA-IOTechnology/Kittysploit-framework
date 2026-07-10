#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Provenance-strict evidence gate for live agent findings.

A finding is only promoted when backed by real module/tool output — prose alone
is insufficient. Mirrors the honesty spine pattern: state WHY a claim was blocked.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

# Evidence kinds that represent machine/tool output (not human notes)
_TOOL_EVIDENCE_KINDS = frozenset({
    "http", "network", "command", "credential", "file", "log", "output", "response", "request",
})

_HIGH_SEVERITIES = frozenset({"critical", "high"})


def _has_tool_output(records: List[Mapping[str, Any]]) -> bool:
    for row in records:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind") or "").lower()
        summary = str(row.get("summary") or row.get("content_preview") or "").strip()
        if kind in _TOOL_EVIDENCE_KINDS and summary:
            return True
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if metadata.get("status") in {"vulnerable", "affected"} and summary:
            return True
    return False


def gate_live_finding(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Gate a live finding before promotion.

    Returns ``passed``, ``provenance`` (none|context|tool), and ``reasons``.
    """
    reasons: List[str] = []
    if not isinstance(finding, Mapping):
        return {"passed": False, "provenance": "none", "reasons": ["invalid finding"]}

    records = finding.get("evidence_records") or []
    if not isinstance(records, list):
        records = []

    severity = str(finding.get("severity") or "").lower()
    vulnerable = bool(finding.get("vulnerable"))
    message = str(finding.get("message") or "").strip()
    has_tool = _has_tool_output(records)

    if vulnerable and not has_tool and not message:
        reasons.append("vulnerable=true but no tool-output evidence or message")

    if severity in _HIGH_SEVERITIES and not records and not message:
        reasons.append(f"{severity} severity with zero evidence")

    if vulnerable and records and not has_tool:
        reasons.append(
            "no tool-output evidence (http/network/command/log) — "
            "provenance-strict requires module-backed output, not prose alone"
        )

    if records:
        provenance = "tool" if has_tool else "context"
    elif message:
        provenance = "context"
    else:
        provenance = "none"

    return {
        "passed": not reasons,
        "provenance": provenance,
        "reasons": reasons,
    }


def apply_evidence_gate(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply the gate to a finding dict; downgrade state and attach gate metadata.
    """
    if not isinstance(finding, dict):
        return finding
    out = dict(finding)
    gate = gate_live_finding(out)
    out["evidence_gate"] = gate
    if not gate["passed"]:
        current = str(out.get("evidence_state") or "signal").lower()
        if current in {"confirmed", "exploitable"}:
            out["evidence_state"] = "probable"
        elif current == "probable" and not out.get("evidence_records"):
            out["evidence_state"] = "signal"
        out["gate_blocked"] = True
    else:
        out["gate_blocked"] = False
    return out
