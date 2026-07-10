#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Post-campaign playbook coverage assessment.

Maps structured attack playbooks (CTF / bug bounty case studies) against the agent
knowledge base and module catalog to answer: could we have executed this chain?
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

from core.playbooks.definition import AttackPlaybook, PlaybookChainStep
from core.playbooks.loader import load_all_playbooks

logger = logging.getLogger(__name__)

PLAYBOOK_PLANNER_CACHE_KEY = "playbook_planner_cache"

COVERAGE_ACHIEVED = "achieved"
COVERAGE_REACHABLE = "reachable"
COVERAGE_PARTIAL = "partial"
COVERAGE_NOT_APPLICABLE = "not_applicable"

_SIGNAL_ALIASES: Dict[str, Set[str]] = {
    "sql_injection": {"sql", "sqli", "sql_injection", "injectable"},
    "lfi": {"lfi", "path_traversal", "local file inclusion", "file inclusion"},
    "path_traversal": {"lfi", "path_traversal", "directory traversal"},
    "login_surface_detected": {
        "login_surface_detected",
        "login_form_detected",
        "login_redirect_detected",
        "login page",
        "login panel",
    },
    "login_form_detected": {"login_form_detected", "login page", "login form"},
    "login_redirect_detected": {"login_redirect_detected", "redirect to login"},
    "modbus": {"modbus", "modbus_tcp", "modbus-tcp"},
    "modbus_tcp": {"modbus", "modbus_tcp", "modbus-tcp"},
    "s7comm": {"s7comm", "s7-comm", "siemens"},
    "siemens": {"s7comm", "siemens", "tia"},
}


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _capabilities_present(kb: Mapping[str, Any]) -> Set[str]:
    present: Set[str] = set()
    memory = kb.get("attack_chain_memory") or {}
    if isinstance(memory, dict):
        for entry in memory.get("entries", []) or []:
            if isinstance(entry, dict):
                cap = _normalize_token(entry.get("capability"))
                if cap:
                    present.add(cap)
    for cap in kb.get("unlocked_capabilities", []) or []:
        token = _normalize_token(cap)
        if token:
            present.add(token)
    return present


def _blob_from_kb(kb: Mapping[str, Any]) -> str:
    parts: List[str] = []
    for key in ("tech_hints", "specializations", "risk_signals", "observed_modules"):
        for item in kb.get(key, []) or []:
            parts.append(_normalize_token(item))
    for tech, score in (kb.get("tech_confidence", {}) or {}).items():
        parts.append(_normalize_token(tech))
        if float(score or 0) >= 0.45:
            parts.append(_normalize_token(tech))
    for path in kb.get("login_paths", []) or []:
        parts.append(_normalize_token(path))
    return " ".join(parts)


def _blob_from_findings(findings: Sequence[Mapping[str, Any]]) -> str:
    parts: List[str] = []
    for row in findings or []:
        if not isinstance(row, Mapping):
            continue
        parts.append(_normalize_token(row.get("path")))
        parts.append(_normalize_token(row.get("message")))
        parts.append(_normalize_token(row.get("module")))
        for hint in row.get("context_hints", []) or []:
            parts.append(_normalize_token(hint))
    return " ".join(parts)


def _expand_signals(signals: Iterable[str]) -> Set[str]:
    expanded: Set[str] = set()
    for raw in signals:
        token = _normalize_token(raw)
        if not token:
            continue
        expanded.add(token)
        expanded |= _SIGNAL_ALIASES.get(token, set())
    return expanded


def _catalog_paths(kb: Mapping[str, Any]) -> Set[str]:
    catalog = kb.get("module_capability_catalog") or {}
    paths = catalog.get("all_paths") or []
    return {_normalize_token(p) for p in paths if _normalize_token(p)}


def _observed_modules(kb: Mapping[str, Any]) -> Set[str]:
    observed: Set[str] = set()
    for item in kb.get("observed_modules", []) or []:
        token = _normalize_token(item)
        if token:
            observed.add(token)
            if "/" in token:
                observed.add(token.rstrip("/").split("/")[-1])
    return observed


def _module_available(module_path: Optional[str], catalog: Set[str]) -> bool:
    if not module_path:
        return False
    norm = _normalize_token(module_path)
    if norm in catalog:
        return True
    basename = norm.rstrip("/").split("/")[-1]
    return any(p.endswith(f"/{basename}") or p == basename for p in catalog)


def _module_executed(module_path: Optional[str], observed: Set[str]) -> bool:
    if not module_path:
        return False
    norm = _normalize_token(module_path)
    if norm in observed:
        return True
    basename = norm.rstrip("/").split("/")[-1]
    return basename in observed


def _overlap_score(required: Sequence[str], haystack_blob: str, *, aliases: bool = False) -> float:
    if not required:
        return 1.0
    hits = 0
    for raw in required:
        tokens = _expand_signals([raw]) if aliases else {_normalize_token(raw)}
        if any(token and token in haystack_blob for token in tokens):
            hits += 1
    return hits / max(1, len(required))


def _prerequisites_score(
    playbook: AttackPlaybook,
    kb: Mapping[str, Any],
    kb_blob: str,
    findings_blob: str,
) -> float:
    prereq = playbook.prerequisites
    combined = f"{kb_blob} {findings_blob}"
    scores: List[float] = []

    if prereq.tech_any:
        scores.append(_overlap_score(prereq.tech_any, combined))
    if prereq.signals_any:
        scores.append(_overlap_score(prereq.signals_any, combined, aliases=True))
    if prereq.domains:
        scores.append(_overlap_score(prereq.domains, combined))
    if prereq.capabilities:
        present = _capabilities_present(kb)
        hits = sum(1 for cap in prereq.capabilities if _normalize_token(cap) in present)
        scores.append(hits / max(1, len(prereq.capabilities)))

    if not scores:
        return 0.35
    return sum(scores) / len(scores)


def _assess_chain_step(
    step: PlaybookChainStep,
    *,
    catalog: Set[str],
    observed: Set[str],
    unlocked: Set[str],
) -> Dict[str, Any]:
    module = step.module
    capability = _normalize_token(step.capability)
    available = _module_available(module, catalog) if module else False
    executed = _module_executed(module, observed) if module else False
    capability_unlocked = capability in unlocked if capability else False

    if module is None:
        status = "gap"
    elif available and executed:
        status = "executed"
    elif available:
        status = "available"
    elif executed:
        status = "executed"
    else:
        status = "missing_module"

    if capability_unlocked and status in ("available", "gap", "missing_module"):
        status = "capability_unlocked"

    return {
        "step_id": step.step_id,
        "capability": capability,
        "module": module,
        "optional": step.optional,
        "description": step.description,
        "module_available": available,
        "module_executed": executed,
        "capability_unlocked": capability_unlocked,
        "status": status,
    }


def _classify_coverage(
    *,
    prereq_score: float,
    relevance: float,
    steps: List[Dict[str, Any]],
    unlocked: Set[str],
) -> str:
    if relevance < 0.2 and prereq_score < 0.25:
        return COVERAGE_NOT_APPLICABLE
    if prereq_score < 0.3:
        return COVERAGE_NOT_APPLICABLE

    required_steps = [s for s in steps if not s.get("optional")]
    if not required_steps:
        return COVERAGE_NOT_APPLICABLE

    required_gaps = [
        s for s in required_steps
        if s.get("status") == "gap" or (
            s.get("module") and not s.get("module_available") and s.get("status") == "missing_module"
        )
    ]
    all_required_done = all(
        s.get("status") in ("executed", "capability_unlocked")
        for s in required_steps
    )
    all_modules_exist = all(
        not s.get("module") or s.get("module_available") or s.get("status") == "executed"
        for s in required_steps
    )

    final_caps = {_normalize_token(s.get("capability")) for s in required_steps if s.get("capability")}
    final_reached = bool(final_caps & unlocked) or all_required_done

    if all_required_done or (final_reached and not required_gaps):
        return COVERAGE_ACHIEVED
    if required_gaps or not all_modules_exist:
        return COVERAGE_PARTIAL
    return COVERAGE_REACHABLE


def _missing_modules(steps: List[Dict[str, Any]]) -> List[str]:
    missing: List[str] = []
    for step in steps:
        if step.get("optional"):
            continue
        if step.get("status") == "gap":
            missing.append(f"{step.get('step_id')}:capability={step.get('capability')}")
        elif step.get("module") and step.get("status") == "missing_module":
            missing.append(str(step.get("module")))
    return missing


def assess_playbook(
    playbook: AttackPlaybook,
    kb: Mapping[str, Any],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    kb_blob = _blob_from_kb(kb)
    findings_blob = _blob_from_findings(findings or [])
    combined_blob = f"{kb_blob} {findings_blob}"

    domain_hint = _normalize_token(playbook.domain)
    domain_bonus = 0.15 if domain_hint and domain_hint in combined_blob else 0.0
    tag_hits = sum(1 for tag in playbook.tags if _normalize_token(tag) in combined_blob)
    tag_score = min(0.35, tag_hits * 0.08)
    prereq_score = _prerequisites_score(playbook, kb, kb_blob, findings_blob)
    relevance = min(1.0, prereq_score * 0.75 + domain_bonus + tag_score + 0.1)

    catalog = _catalog_paths(kb)
    observed = _observed_modules(kb)
    unlocked = _capabilities_present(kb)

    steps = [
        _assess_chain_step(step, catalog=catalog, observed=observed, unlocked=unlocked)
        for step in playbook.chain
    ]
    coverage = _classify_coverage(
        prereq_score=prereq_score,
        relevance=relevance,
        steps=steps,
        unlocked=unlocked,
    )
    missing = _missing_modules(steps)

    summary_parts: List[str] = []
    if coverage == COVERAGE_ACHIEVED:
        summary_parts.append("Campaign state matches or completes this playbook chain.")
    elif coverage == COVERAGE_REACHABLE:
        summary_parts.append("Prerequisites match and modules exist; chain was not fully executed.")
    elif coverage == COVERAGE_PARTIAL:
        summary_parts.append("Relevant scenario but module gaps or incomplete prerequisites.")
    else:
        summary_parts.append("Low relevance to observed target context.")

    if missing:
        summary_parts.append(f"Gaps: {', '.join(missing[:4])}.")

    return {
        "playbook_id": playbook.playbook_id,
        "name": playbook.name,
        "source": playbook.source,
        "domain": playbook.domain,
        "tags": playbook.tags,
        "relevance": round(relevance, 3),
        "prerequisites_score": round(prereq_score, 3),
        "coverage": coverage,
        "steps": steps,
        "missing_modules": missing,
        "blockers": list(playbook.blockers),
        "summary": " ".join(summary_parts),
    }


def assess_playbook_coverage(
    knowledge_base: Mapping[str, Any],
    contextual_findings: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    min_relevance: float = 0.25,
    limit: int = 8,
) -> Dict[str, Any]:
    """
    Evaluate all library playbooks against campaign state.

    Returns a compact report suitable for JSON/Markdown agent output.
    """
    kb = knowledge_base if isinstance(knowledge_base, Mapping) else {}
    try:
        playbooks = load_all_playbooks()
    except Exception as exc:
        logger.warning("Playbook library load failed: %s", exc)
        playbooks = []

    assessments: List[Dict[str, Any]] = []
    for playbook in playbooks:
        try:
            row = assess_playbook(playbook, kb, contextual_findings)
            if row.get("coverage") == COVERAGE_NOT_APPLICABLE and float(row.get("relevance", 0)) < min_relevance:
                continue
            assessments.append(row)
        except Exception as exc:
            logger.warning("Playbook assessment failed for %s: %s", playbook.playbook_id, exc)

    assessments.sort(
        key=lambda row: (
            0 if row.get("coverage") == COVERAGE_ACHIEVED else 1,
            0 if row.get("coverage") == COVERAGE_REACHABLE else 1,
            0 if row.get("coverage") == COVERAGE_PARTIAL else 1,
            -float(row.get("relevance", 0) or 0),
            str(row.get("playbook_id", "")),
        ),
    )

    by_coverage: Dict[str, int] = {}
    for row in assessments:
        cov = str(row.get("coverage") or "")
        by_coverage[cov] = by_coverage.get(cov, 0) + 1

    top = assessments[:limit]
    gap_modules: List[str] = []
    for row in top:
        for item in row.get("missing_modules", []) or []:
            token = str(item)
            if token and token not in gap_modules:
                gap_modules.append(token)

    return {
        "library_size": len(playbooks),
        "assessed": len(assessments),
        "shown": len(top),
        "by_coverage": by_coverage,
        "product_gaps": gap_modules[:12],
        "playbooks": top,
    }


def summarize_playbook_coverage_for_report(coverage: Mapping[str, Any]) -> List[str]:
    """Human-readable bullets for Markdown reports."""
    lines: List[str] = []
    if not isinstance(coverage, Mapping):
        return lines

    by_cov = coverage.get("by_coverage") or {}
    if by_cov:
        parts = [f"{key}={value}" for key, value in sorted(by_cov.items())]
        lines.append(f"Coverage breakdown: {', '.join(parts)}.")

    gaps = coverage.get("product_gaps") or []
    if gaps:
        lines.append(f"Framework gaps highlighted: {', '.join(str(g) for g in gaps[:6])}.")

    for row in coverage.get("playbooks", []) or []:
        if not isinstance(row, Mapping):
            continue
        lines.append(
            f"[{str(row.get('coverage', '')).upper()}] {row.get('name', row.get('playbook_id'))} "
            f"(relevance={float(row.get('relevance', 0) or 0):.2f}) — {row.get('summary', '')}"
        )
        if len(lines) >= 10:
            break
    return lines


def _kb_planner_fingerprint(kb: Mapping[str, Any]) -> str:
    observed = kb.get("observed_modules", []) or []
    signals = kb.get("risk_signals", []) or []
    hints = kb.get("tech_hints", []) or []
    findings = kb.get("campaign_findings_snapshot", []) or []
    return "|".join([
        str(len(observed)),
        ",".join(sorted(_normalize_token(x) for x in observed)[-24:]),
        ",".join(sorted(_normalize_token(x) for x in signals)[:24]),
        ",".join(sorted(_normalize_token(x) for x in hints)[:16]),
        str(len(findings)),
    ])


def _module_path_from_record(module: Mapping[str, Any]) -> str:
    return _normalize_token(module.get("path") or module.get("module"))


def _paths_equivalent(left: str, right: str) -> bool:
    a = _normalize_token(left)
    b = _normalize_token(right)
    if not a or not b:
        return False
    if a == b:
        return True
    a_base = a.rstrip("/").split("/")[-1]
    b_base = b.rstrip("/").split("/")[-1]
    return a_base == b_base or a.endswith(f"/{b_base}") or b.endswith(f"/{a_base}")


def _next_step_hints_from_assessment(row: Mapping[str, Any]) -> List[Tuple[str, float]]:
    coverage = str(row.get("coverage") or "")
    if coverage not in (COVERAGE_REACHABLE, COVERAGE_PARTIAL):
        return []

    relevance = float(row.get("relevance", 0) or 0)
    if relevance < 0.3:
        return []

    weight = relevance * (0.9 if coverage == COVERAGE_REACHABLE else 0.5)
    hints: List[Tuple[str, float]] = []
    steps = row.get("steps") or []
    for step in steps:
        if not isinstance(step, dict):
            continue
        status = str(step.get("status") or "")
        module = step.get("module")
        optional = bool(step.get("optional"))

        if status in ("executed", "capability_unlocked"):
            continue
        if status == "gap":
            break
        if module and status in ("available", "missing_module"):
            hints.append((str(module), weight))
            if not optional:
                break
    return hints


def refresh_playbook_planner_hints(
    kb: MutableMapping[str, Any],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, float]:
    """
    Build module-path → bonus map for reachable playbook next steps.

    Cached on the knowledge base under :data:`PLAYBOOK_PLANNER_CACHE_KEY`.
    """
    if not isinstance(kb, MutableMapping):
        return {}

    fingerprint = _kb_planner_fingerprint(kb)
    cached = kb.get(PLAYBOOK_PLANNER_CACHE_KEY)
    if isinstance(cached, dict) and cached.get("fingerprint") == fingerprint:
        hints = cached.get("hints")
        if isinstance(hints, dict):
            return {str(k): float(v) for k, v in hints.items()}

    snapshot = findings
    if snapshot is None:
        snapshot = kb.get("campaign_findings_snapshot", []) or []

    report = assess_playbook_coverage(kb, snapshot, limit=12)
    merged: Dict[str, float] = {}
    for row in report.get("playbooks", []) or []:
        if not isinstance(row, dict):
            continue
        for module_path, weight in _next_step_hints_from_assessment(row):
            prev = merged.get(module_path, 0.0)
            merged[module_path] = max(prev, weight)

    kb[PLAYBOOK_PLANNER_CACHE_KEY] = {
        "fingerprint": fingerprint,
        "hints": merged,
        "playbook_count": int(report.get("assessed", 0) or 0),
    }
    return merged


def playbook_readiness_bonus(module: Mapping[str, Any], kb: Mapping[str, Any]) -> float:
    """
    Additive planner bonus when a module is the next step of a reachable playbook.

    Typical range ``0.0 .. 1.1`` — aligned with chain_readiness_bonus scale.
    """
    if not isinstance(module, Mapping) or not isinstance(kb, Mapping):
        return 0.0

    path = _module_path_from_record(module)
    if not path:
        return 0.0

    if isinstance(kb, MutableMapping):
        hints = refresh_playbook_planner_hints(kb)
    else:
        hints = _build_ephemeral_planner_hints(kb)

    best = 0.0
    for hint_path, weight in hints.items():
        if _paths_equivalent(hint_path, path):
            best = max(best, float(weight))
    if best <= 0.0:
        return 0.0
    return round(min(1.1, 0.25 + best), 3)


def _build_ephemeral_planner_hints(kb: Mapping[str, Any]) -> Dict[str, float]:
    snapshot = kb.get("campaign_findings_snapshot", []) or []
    report = assess_playbook_coverage(kb, snapshot, limit=12)
    merged: Dict[str, float] = {}
    for row in report.get("playbooks", []) or []:
        if not isinstance(row, dict):
            continue
        for module_path, weight in _next_step_hints_from_assessment(row):
            prev = merged.get(module_path, 0.0)
            merged[module_path] = max(prev, weight)
    return merged


def invalidate_playbook_planner_cache(kb: MutableMapping[str, Any]) -> None:
    if isinstance(kb, MutableMapping):
        kb.pop(PLAYBOOK_PLANNER_CACHE_KEY, None)
