#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Multi-refuter skeptic panel for agent findings.

Adapted from T3MP3ST refute-finding: N adversarial reviewers evaluate whether
evidence truly supports a claim. Uses local LLM when available, heuristic
fallback otherwise.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.adjudicate import adjudicate_panel
from interfaces.command_system.builtin.agent.evidence_gate import gate_live_finding
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

DEFAULT_REFUTERS = 3
_TEMPERATURE_LADDER = (0.2, 0.5, 0.8, 1.0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_refuter_json(content: str) -> Optional[Dict[str, Any]]:
    text = str(content or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    if not isinstance(parsed, dict):
        return None
    verdict = str(parsed.get("verdict") or "").upper()
    if verdict not in {"REFUTED", "SURVIVED"}:
        return None
    out: Dict[str, Any] = {
        "verdict": verdict,
        "why": str(parsed.get("why") or parsed.get("rationale") or "")[:800],
    }
    guard = parsed.get("killing_guard")
    if isinstance(guard, dict) and guard.get("quote"):
        out["killing_guard"] = {
            "file": str(guard.get("file") or ""),
            "line": int(guard.get("line") or 0),
            "quote": str(guard.get("quote") or "")[:500],
        }
    counter = parsed.get("counter_evidence")
    if counter:
        out["counter_evidence"] = str(counter)[:400]
    return out


def _build_refuter_prompt(finding: Mapping[str, Any], *, refuter_index: int) -> str:
    evidence_rows = finding.get("evidence_records") or []
    evidence_text = []
    for row in evidence_rows[:6]:
        if not isinstance(row, dict):
            continue
        evidence_text.append(
            f"- [{row.get('kind', 'other')}] {row.get('summary', row.get('title', ''))}"
        )
    gate = gate_live_finding(finding)
    return (
        "You are refuter #{idx} on a skeptic security panel. Your job is to DISPROVE "
        "overclaims — only refute when evidence is insufficient or contradictory.\n"
        "Finding:\n"
        f"  module: {finding.get('path', finding.get('module', ''))}\n"
        f"  severity: {finding.get('severity', '')}\n"
        f"  message: {finding.get('message', '')}\n"
        f"  evidence_state: {finding.get('evidence_state', '')}\n"
        f"  provenance_gate: passed={gate.get('passed')} reasons={gate.get('reasons')}\n"
        "Evidence records:\n"
        + ("\n".join(evidence_text) if evidence_text else "  (none)\n")
        + "\nReply ONLY valid JSON: "
        '{"verdict":"REFUTED"|"SURVIVED","why":"...","counter_evidence":"optional",'
        '"killing_guard":{"file":"","line":0,"quote":""} /* only if source-backed refute */}'
    ).replace("{idx}", str(refuter_index + 1))


def _heuristic_refuter_vote(finding: Mapping[str, Any], index: int) -> Dict[str, Any]:
    """Deterministic skeptic when LLM is unavailable."""
    gate = gate_live_finding(finding)
    severity = str(finding.get("severity") or "").lower()
    message = str(finding.get("message") or "").lower()
    records = finding.get("evidence_records") or []

    if not gate["passed"]:
        return {
            "verdict": "REFUTED",
            "why": f"Provenance gate failed: {'; '.join(gate.get('reasons') or [])}",
            "source": "heuristic",
            "refuter": index + 1,
        }
    if any(token in message for token in ("possible", "potential", "manual verification")):
        return {
            "verdict": "REFUTED",
            "why": "Claim uses tentative language without strong proof",
            "source": "heuristic",
            "refuter": index + 1,
        }
    if severity in {"critical", "high"} and len(records) < 1:
        return {
            "verdict": "REFUTED",
            "why": f"{severity} severity without evidence records",
            "source": "heuristic",
            "refuter": index + 1,
        }
    return {
        "verdict": "SURVIVED",
        "why": "Evidence records support the claim at current confidence",
        "source": "heuristic",
        "refuter": index + 1,
    }


def refute_finding_panel(
    finding: Mapping[str, Any],
    *,
    refuters: int = DEFAULT_REFUTERS,
    llm_service: Any = None,
    llm_endpoint: str = "",
    llm_model: str = "",
    source_resolver: Optional[Callable[[str], str]] = None,
    timeout: int = 20,
    llm_budget_remaining: Optional[Callable[[], int]] = None,
    on_llm_call: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    """
    Run N refuters on a finding and return an adjudicated panel report.
    """
    if not isinstance(finding, Mapping):
        return {"verdict": "INCONCLUSIVE", "error": "invalid finding"}

    slug = str(
        finding.get("id")
        or finding.get("path")
        or finding.get("module")
        or "finding"
    )[:80]
    votes: List[Optional[Dict[str, Any]]] = []
    count = max(1, min(int(refuters or DEFAULT_REFUTERS), 5))

    for idx in range(count):
        vote: Optional[Dict[str, Any]] = None
        budget_left = llm_budget_remaining() if llm_budget_remaining is not None else None
        can_use_llm = (
            llm_service is not None
            and llm_endpoint
            and llm_model
            and (budget_left is None or budget_left > 0)
        )
        if can_use_llm:
            prompt = _build_refuter_prompt(finding, refuter_index=idx)
            try:
                raw = llm_service.query_json(
                    llm_endpoint,
                    llm_model,
                    prompt,
                    {"finding": sanitize_nested(dict(finding))},
                    timeout=timeout,
                )
                if isinstance(raw, dict):
                    verdict = str(raw.get("verdict") or "").upper()
                    if verdict in {"REFUTED", "SURVIVED"}:
                        if on_llm_call is not None:
                            on_llm_call()
                        vote = {
                            "verdict": verdict,
                            "why": str(raw.get("why") or raw.get("rationale") or "")[:800],
                            "source": "llm",
                            "refuter": idx + 1,
                        }
                        guard = raw.get("killing_guard")
                        if isinstance(guard, dict) and guard.get("quote"):
                            vote["killing_guard"] = guard
            except Exception:
                vote = None
        if vote is None:
            vote = _heuristic_refuter_vote(finding, idx)
        votes.append(vote)

    panel = adjudicate_panel(votes, resolve_source=source_resolver)
    return sanitize_nested({
        "slug": slug,
        "verdict": panel.get("verdict"),
        "refuted_count": panel.get("refuted_count"),
        "total": panel.get("total"),
        "killing_guards": panel.get("killing_guards", []),
        "verdicts": panel.get("verdicts", []),
        "gate": gate_live_finding(finding),
        "adjudicated_at": _utc_now(),
    })


def apply_refutation_to_finding(finding: Dict[str, Any], panel: Mapping[str, Any]) -> Dict[str, Any]:
    """Attach panel result and downgrade evidence if refuted."""
    out = dict(finding)
    out["refutation_panel"] = dict(panel)
    verdict = str(panel.get("verdict") or "").upper()
    if verdict == "REFUTED":
        current = str(out.get("evidence_state") or "probable").lower()
        if current in {"confirmed", "exploitable"}:
            out["evidence_state"] = "probable"
        elif current == "probable":
            out["evidence_state"] = "signal"
        out["refutation_blocked"] = True
    else:
        out["refutation_blocked"] = False
    return out


def refute_findings_batch(
    findings: Sequence[Mapping[str, Any]],
    *,
    min_severity: str = "high",
    max_findings: int = 5,
    llm_budget_remaining: Optional[Callable[[], int]] = None,
    on_llm_call: Optional[Callable[[], None]] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Refute high-severity findings in a batch."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_rank = rank.get(str(min_severity or "high").lower(), 1)
    candidates = []
    for row in findings:
        if not isinstance(row, Mapping):
            continue
        sev = str(row.get("severity") or "medium").lower()
        if rank.get(sev, 9) <= min_rank:
            candidates.append(row)
    candidates = candidates[:max_findings]
    results: List[Dict[str, Any]] = []
    for finding in candidates:
        if llm_budget_remaining is not None and llm_budget_remaining() <= 0:
            panel = refute_finding_panel(
                finding,
                llm_service=None,
                llm_endpoint="",
                llm_model="",
                **{k: v for k, v in kwargs.items() if k not in {"llm_service", "llm_endpoint", "llm_model"}},
            )
        else:
            panel = refute_finding_panel(
                finding,
                llm_budget_remaining=llm_budget_remaining,
                on_llm_call=on_llm_call,
                **kwargs,
            )
        results.append(apply_refutation_to_finding(dict(finding), panel))
    return results
