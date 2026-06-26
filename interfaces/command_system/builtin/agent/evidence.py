#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Promotional evidence model for agent findings."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

EVIDENCE_STATES = ("signal", "probable", "confirmed", "exploitable", "fixed", "regressed")
PROMOTION_ORDER = {name: index for index, name in enumerate(EVIDENCE_STATES)}


def initial_evidence_state(signals: int = 1) -> str:
    if signals <= 0:
        return "signal"
    if signals == 1:
        return "probable"
    return "confirmed"


def promote_evidence(
    current: str,
    *,
    independent_sources: int = 0,
    exploit_success: bool = False,
    retest_fixed: bool = False,
    retest_regressed: bool = False,
) -> str:
    state = str(current or "signal").lower()
    if state not in PROMOTION_ORDER:
        state = "signal"
    if retest_regressed:
        return "regressed"
    if retest_fixed:
        return "fixed"
    if exploit_success and state in {"confirmed", "probable"}:
        return "exploitable"
    if independent_sources >= 2 and PROMOTION_ORDER[state] < PROMOTION_ORDER["confirmed"]:
        return "confirmed"
    if independent_sources == 1 and state == "signal":
        return "probable"
    return state


def finding_confidence_from_evidence(evidence_rows: List[Dict[str, Any]]) -> str:
    if not evidence_rows:
        return "probable"
    states = [str(row.get("state", "probable")).lower() for row in evidence_rows]
    best = max(states, key=lambda value: PROMOTION_ORDER.get(value, 0))
    if best in {"confirmed", "exploitable"}:
        return best
    return "probable"


def attach_evidence_to_finding(
    finding: Dict[str, Any],
    evidence: Dict[str, Any],
    *,
    independent: bool = False,
) -> Dict[str, Any]:
    rows = list(finding.get("evidence") or [])
    rows.append(evidence)
    finding = dict(finding)
    finding["evidence"] = rows
    independent_count = sum(1 for row in rows if row.get("independent"))
    if independent:
        evidence = dict(evidence)
        evidence["independent"] = True
        rows[-1] = evidence
        finding["evidence"] = rows
        independent_count += 1
    state = promote_evidence(
        finding.get("evidence_state", "probable"),
        independent_sources=independent_count,
    )
    finding["evidence_state"] = state
    finding["confidence"] = finding_confidence_from_evidence(rows)
    return finding
