#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Counterfactual plan comparison before risky actions."""

from __future__ import annotations

from typing import Any, Dict, List


def compare_plans(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not candidates:
        return {"chosen": None, "rejected": []}
    ranked = sorted(
        candidates,
        key=lambda row: (
            -float(row.get("expected_proof_gain", 0.0) or 0.0),
            int(row.get("network_cost", 99) or 99),
            -float(row.get("confidence", 0.0) or 0.0),
            str(row.get("operational_risk", "high")),
        ),
    )
    chosen = ranked[0]
    rejected = ranked[1:3]
    return {
        "chosen": chosen,
        "rejected_alternatives": rejected,
        "comparison_axes": ["expected_proof_gain", "network_cost", "operational_risk", "confidence"],
    }


def build_counterfactual_report(
    action: Dict[str, Any],
    alternatives: List[Dict[str, Any]],
) -> Dict[str, Any]:
    candidates = [dict(action, selected=True)] + [dict(row, selected=False) for row in alternatives]
    comparison = compare_plans(candidates)
    return {
        "action": action.get("path") or action.get("type", ""),
        "chosen": comparison["chosen"],
        "rejected_alternatives": comparison["rejected_alternatives"],
    }
