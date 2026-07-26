#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Structured decision explanations for agent module/action choices."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.campaign_continuation import list_shell_continuation_pivots
from interfaces.command_system.builtin.agent.goal_planner import (
    DRUPAL_CVE_2014_3704_SQLI_MODULE,
    DRUPAL_DRUPALGEDDON2_MODULE,
    suggest_shell_plan_followups,
)
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost, module_path_lower
from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk

_CMS_ALTERNATIVES: Sequence[tuple[str, str]] = (
    ("auxiliary/scanner/http/drupal_scanner", "drupal"),
    (DRUPAL_CVE_2014_3704_SQLI_MODULE, "drupal"),
    (DRUPAL_DRUPALGEDDON2_MODULE, "drupal"),
    ("auxiliary/scanner/http/wordpress_scanner", "wordpress"),
    ("exploits/http/wordpress_plugin_upload", "wordpress"),
    ("auxiliary/scanner/http/joomla_scanner", "joomla"),
)


def _top_stack_rows(kb: Mapping[str, Any], *, limit: int = 4) -> List[tuple[str, float]]:
    if not isinstance(kb, dict):
        return []
    conf = kb.get("tech_confidence", {}) or {}
    rows = []
    for name, score in conf.items():
        try:
            val = float(score or 0.0)
        except Exception:
            continue
        if val >= 0.35:
            rows.append((str(name), val))
    rows.sort(key=lambda row: row[1], reverse=True)
    return rows[:limit]


def infer_rejected_cms_alternatives(
    chosen_path: str,
    kb: Mapping[str, Any],
    *,
    stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
) -> List[Dict[str, str]]:
    """Explain why common CMS modules were not chosen (stack mismatch / low confidence)."""
    chosen = module_path_lower({"path": chosen_path})
    kb_dict = dict(kb) if isinstance(kb, dict) else {}
    conf = kb_dict.get("tech_confidence", {}) or {}
    hints = {str(h).lower() for h in kb_dict.get("tech_hints", []) or []}
    rejected: List[Dict[str, str]] = []
    mismatch = stack_mismatch_fn or (lambda _p, _k: "")

    for alt_path, stack in _CMS_ALTERNATIVES:
        if alt_path == chosen_path or stack in chosen:
            continue
        reason = mismatch(alt_path, kb_dict)
        if reason:
            rejected.append({"path": alt_path, "reason": reason[:220]})
            continue
        try:
            stack_conf = float(conf.get(stack, 0.0) or 0.0)
        except Exception:
            stack_conf = 0.0
        if stack_conf < 0.35 and stack not in hints:
            rejected.append({
                "path": alt_path,
                "reason": f"no {stack} evidence (confidence={stack_conf:.2f})",
            })
    deduped: List[Dict[str, str]] = []
    seen: set = set()
    for row in rejected:
        key = row.get("path", "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped[:5]


def infer_rejected_scored_alternatives(
    chosen_path: str,
    candidates: Sequence[Dict[str, Any]],
    scored_rows: Sequence[tuple[float, Dict[str, Any]]],
    *,
    limit: int = 4,
) -> List[Dict[str, str]]:
    """Higher-scoring or same-tier modules that were not selected."""
    chosen = module_path_lower({"path": chosen_path})
    rejected: List[Dict[str, str]] = []
    for score, module in scored_rows:
        path = str(module.get("path", "") or "").strip()
        if not path or path == chosen:
            continue
        if score < 0:
            rejected.append({
                "path": path,
                "reason": f"score={score:.2f} (gated/skipped)",
            })
        elif len(rejected) < limit:
            rejected.append({
                "path": path,
                "reason": f"lower priority score={score:.2f}",
            })
        if len(rejected) >= limit:
            break
    if rejected:
        return rejected[:limit]
    for module in candidates:
        path = str(module.get("path", "") or "").strip()
        if path and path != chosen:
            rejected.append({"path": path, "reason": "not selected in batch limit"})
        if len(rejected) >= limit:
            break
    return rejected[:limit]


def build_action_decision_report(
    path: str,
    action_type: str,
    kb: Mapping[str, Any],
    *,
    campaign_goal: str = "",
    phase: str = "",
    reason: str = "",
    matching_finding: Optional[Dict[str, Any]] = None,
    stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    rejected_alternatives: Optional[List[Dict[str, str]]] = None,
    evidence: Optional[List[str]] = None,
    tradeoffs: Optional[List[str]] = None,
    score: Optional[float] = None,
    confidence: Optional[float] = None,
    expected_gain: Optional[float] = None,
    risk_cost: Optional[float] = None,
) -> Dict[str, Any]:
    """Full auditable decision record for reports and timeline events."""
    low = str(path or "").lower()
    kb_dict = dict(kb) if isinstance(kb, dict) else {}
    risk = assess_module_risk({"path": path}, path)
    risk_notes: List[str] = list(tradeoffs or [])[:5]

    ev = list(evidence or [])[:8]
    stack_rows = _top_stack_rows(kb_dict)
    if stack_rows and not any(e.startswith("stack=") for e in ev):
        ev.insert(0, f"stack={stack_rows[0][0]}:{stack_rows[0][1]:.2f}")

    cms_rejected = infer_rejected_cms_alternatives(
        path,
        kb_dict,
        stack_mismatch_fn=stack_mismatch_fn,
    )
    all_rejected = list(rejected_alternatives or [])
    seen_paths = {row.get("path") for row in all_rejected}
    for row in cms_rejected:
        if row.get("path") not in seen_paths:
            all_rejected.append(row)

    followups = suggest_shell_plan_followups(kb_dict)
    next_pivot = ""
    for candidate in followups:
        if candidate != path:
            next_pivot = candidate
            break
    if not next_pivot:
        pivots = list_shell_continuation_pivots(kb_dict, stack_mismatch_fn=stack_mismatch_fn)
        if pivots:
            next_pivot = pivots[0]

    why_parts = [reason or f"Selected `{path}` ({action_type or 'run'})"]
    if matching_finding:
        msg = str(matching_finding.get("message", "") or "").strip()
        if msg:
            why_parts.append(f"finding: {msg[:120]}")
    if stack_rows:
        why_parts.append(f"stack evidence: {stack_rows[0][0]} ({stack_rows[0][1]:.2f})")

    guardrail = ""
    if stack_mismatch_fn:
        mismatch = stack_mismatch_fn(path, kb_dict)
        if mismatch:
            guardrail = mismatch[:220]

    report: Dict[str, Any] = {
        "chosen": " | ".join(why_parts)[:320],
        "reason": reason or why_parts[0],
        "why_this": why_parts[0][:240],
        "path": path,
        "action_type": action_type,
        "evidence": ev,
        "rejected_alternatives": all_rejected[:6],
        "risk": {
            "level": risk.level,
            "cost": round(float(risk_cost if risk_cost is not None else estimate_network_cost(low)), 3),
            "notes": risk_notes,
        },
        "next_pivot": next_pivot,
        "guardrail": guardrail,
        "tradeoffs": risk_notes,
    }
    if score is not None:
        report["score"] = round(float(score), 3)
    if confidence is not None:
        report["confidence"] = round(float(confidence), 3)
    if expected_gain is not None:
        report["expected_gain"] = round(float(expected_gain), 3)
    if risk_cost is not None:
        report["risk_cost"] = round(float(risk_cost), 3)
    if campaign_goal:
        report["campaign_goal"] = campaign_goal
    try:
        from interfaces.command_system.builtin.agent.operator_archetypes import (
            operator_context_for_phase,
        )

        op = operator_context_for_phase(
            phase or str(kb.get("current_phase") or "plan"),
            campaign_goal=campaign_goal,
            module_path=path,
        )
        report["operator"] = {
            "archetype": op.get("archetype"),
            "name": op.get("name"),
            "mitre_tactics": op.get("mitre_tactics", []),
            "maturity": op.get("maturity"),
        }
    except Exception:
        pass
    return report
