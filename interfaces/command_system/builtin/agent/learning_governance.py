#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Learning/evaluation separation, tenant isolation, and retention for agent memory."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, MutableMapping, Optional

LEARNING_MODE_ACTIVE = "active"
LEARNING_MODE_FROZEN = "frozen"
LEARNING_MODE_EVAL = "eval_only"

GOVERNANCE_KEY = "learning_governance"
DEFAULT_RETENTION_DAYS = 90
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"(?i)authorization:\s*(?:bearer|basic)\s+\S+"),
    re.compile(r"vault:[a-z0-9:_-]+", re.IGNORECASE),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def governance_from_kb(kb: Mapping[str, Any]) -> Dict[str, Any]:
    raw = kb.get(GOVERNANCE_KEY) if isinstance(kb, Mapping) else None
    if not isinstance(raw, dict):
        return {}
    return dict(raw)


def learning_mode(state: Any) -> str:
    kb = getattr(state, "knowledge_base", None)
    gov = governance_from_kb(kb if isinstance(kb, dict) else {})
    mode = str(gov.get("mode") or getattr(state, "learning_mode", "") or LEARNING_MODE_ACTIVE).strip().lower()
    if mode not in {LEARNING_MODE_ACTIVE, LEARNING_MODE_FROZEN, LEARNING_MODE_EVAL}:
        return LEARNING_MODE_ACTIVE
    return mode


def tenant_id(state: Any) -> str:
    kb = getattr(state, "knowledge_base", None)
    gov = governance_from_kb(kb if isinstance(kb, dict) else {})
    workspace = str(getattr(state, "workspace", "") or "default").strip()
    return str(gov.get("tenant_id") or workspace or "default")[:120]


def is_benchmark_or_eval_run(state: Any) -> bool:
    kb = getattr(state, "knowledge_base", None)
    gov = governance_from_kb(kb if isinstance(kb, dict) else {})
    if bool(gov.get("benchmark")):
        return True
    if bool(gov.get("eval_only")):
        return True
    if str(gov.get("suite_id") or "").strip():
        return True
    run_id = str(getattr(state, "run_id", "") or "")
    if run_id.startswith("bench_") or "benchmark" in run_id.lower():
        return True
    return learning_mode(state) in {LEARNING_MODE_FROZEN, LEARNING_MODE_EVAL}


def should_record_learning(state: Any) -> bool:
    if is_benchmark_or_eval_run(state):
        return False
    if bool(getattr(state, "dry_run", False)):
        return False
    if bool(getattr(state, "plan_only", False)):
        return False
    return learning_mode(state) == LEARNING_MODE_ACTIVE


def attach_learning_governance(
    state: Any,
    *,
    mode: str = LEARNING_MODE_ACTIVE,
    tenant: str = "",
    benchmark: bool = False,
    suite_id: str = "",
    eval_only: bool = False,
    corpus_frozen: bool = False,
) -> Dict[str, Any]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    payload = sanitize_nested_governance({
        "mode": mode,
        "tenant_id": tenant or tenant_id(state),
        "benchmark": bool(benchmark),
        "suite_id": str(suite_id or "")[:120],
        "eval_only": bool(eval_only),
        "corpus_frozen": bool(corpus_frozen),
        "updated_at": _now_iso(),
    })
    kb[GOVERNANCE_KEY] = payload
    return payload


def freeze_learning_for_benchmark(state: Any, *, suite_id: str = "") -> None:
    attach_learning_governance(
        state,
        mode=LEARNING_MODE_FROZEN,
        benchmark=True,
        suite_id=suite_id,
        eval_only=True,
        corpus_frozen=True,
    )


def contains_secret_blob(text: str) -> bool:
    blob = str(text or "")
    if not blob:
        return False
    return any(pattern.search(blob) for pattern in _SECRET_PATTERNS)


def sanitize_nested_governance(value: Any) -> Any:
    from interfaces.command_system.builtin.agent.redaction import sanitize_nested

    return sanitize_nested(value)


def purge_expired_records(
    records: list,
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    now: Optional[datetime] = None,
) -> list:
    if retention_days <= 0:
        return list(records or [])
    cutoff = (now or datetime.now(timezone.utc)).timestamp() - (retention_days * 86400)
    kept = []
    for row in records or []:
        if not isinstance(row, dict):
            continue
        ts = str(row.get("recorded_at") or row.get("ts") or row.get("created_at") or "")
        if not ts:
            kept.append(row)
            continue
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if parsed.timestamp() >= cutoff:
                kept.append(row)
        except ValueError:
            kept.append(row)
    return kept
