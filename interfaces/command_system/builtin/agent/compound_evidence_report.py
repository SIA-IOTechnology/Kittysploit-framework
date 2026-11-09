#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compound evidence ledger: per-stage witnesses for skeptic → validation → specialists → exploit."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

LEDGER_SCHEMA = "1.0"
KB_KEY = "compound_evidence"
MAX_WITNESSES = 160

STAGES = (
    "skeptic",
    "validation",
    "specialist_fanout",
    "exploit_chain",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ledger(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    store = kb.get(KB_KEY)
    if not isinstance(store, dict):
        store = {
            "schema_version": LEDGER_SCHEMA,
            "witnesses": [],
            "summary": {},
        }
        kb[KB_KEY] = store
    store.setdefault("schema_version", LEDGER_SCHEMA)
    store.setdefault("witnesses", [])
    store.setdefault("summary", {})
    return store


def append_compound_witness(
    kb: MutableMapping[str, Any],
    *,
    stage: str,
    kind: str,
    summary: str,
    payload: Optional[Mapping[str, Any]] = None,
    state: Any = None,
) -> Dict[str, Any]:
    """Record one compound-pipeline witness (redacted)."""
    stage_n = str(stage or "unknown")[:48]
    entry = sanitize_nested({
        "ts": _now_iso(),
        "stage": stage_n,
        "kind": str(kind or "")[:64],
        "summary": str(summary or "")[:500],
        "payload": dict(payload or {}),
    })
    store = _ledger(kb)
    witnesses: List[Dict[str, Any]] = list(store.get("witnesses") or [])
    witnesses.append(entry)
    store["witnesses"] = witnesses[-MAX_WITNESSES:]
    store["summary"] = build_compound_evidence_summary(kb)
    kb[KB_KEY] = store
    if state is not None:
        try:
            from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event

            append_journal_event(
                state,
                kind=f"compound_evidence_{stage_n}",
                summary=str(summary or "")[:240],
                payload={"stage": stage_n, "kind": kind},
            )
        except Exception:
            pass
    return entry


def build_compound_evidence_summary(kb: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if not isinstance(kb, Mapping):
        return {"witness_count": 0, "by_stage": {}}
    store = kb.get(KB_KEY) if isinstance(kb.get(KB_KEY), dict) else {}
    witnesses = [w for w in (store.get("witnesses") or []) if isinstance(w, dict)]
    by_stage: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    timeline: List[Dict[str, Any]] = []
    for row in witnesses:
        stage = str(row.get("stage") or "unknown")
        kind = str(row.get("kind") or "")
        by_stage[stage] = int(by_stage.get(stage) or 0) + 1
        if kind:
            by_kind[kind] = int(by_kind.get(kind) or 0) + 1
        timeline.append({
            "ts": row.get("ts"),
            "stage": stage,
            "kind": kind,
            "summary": str(row.get("summary") or "")[:180],
        })
    wave = kb.get("compound_specialist_wave") if isinstance(kb.get("compound_specialist_wave"), dict) else {}
    validations = kb.get("compound_validations") if isinstance(kb.get("compound_validations"), list) else []
    return sanitize_nested({
        "witness_count": len(witnesses),
        "by_stage": by_stage,
        "by_kind": by_kind,
        "timeline_tail": timeline[-24:],
        "specialist_wave": {
            "classes": list(wave.get("classes") or []),
            "dispatched": bool(wave.get("specialists_dispatched")),
            "proposal_paths": list(wave.get("proposal_paths") or [])[:12],
        },
        "compound_validation_records": len(validations),
    })


def export_compound_evidence(kb: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if not isinstance(kb, Mapping):
        return {}
    store = kb.get(KB_KEY) if isinstance(kb.get(KB_KEY), dict) else {}
    return sanitize_nested({
        "schema_version": store.get("schema_version") or LEDGER_SCHEMA,
        "summary": build_compound_evidence_summary(kb),
        "witnesses": list(store.get("witnesses") or [])[-MAX_WITNESSES:],
    })


def enrich_report_payload(payload: Dict[str, Any], knowledge_base: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload
    kb = knowledge_base if isinstance(knowledge_base, Mapping) else {}
    payload["compound_evidence"] = export_compound_evidence(kb)
    return payload


def format_compound_evidence_markdown(summary: Mapping[str, Any]) -> str:
    if not isinstance(summary, Mapping):
        return ""
    lines: List[str] = ["\n## Compound evidence\n"]
    lines.append(f"- Witnesses: `{int(summary.get('witness_count') or 0)}`\n")
    by_stage = summary.get("by_stage") if isinstance(summary.get("by_stage"), dict) else {}
    if by_stage:
        parts = [f"`{k}`={v}" for k, v in sorted(by_stage.items())]
        lines.append("- By stage: " + ", ".join(parts) + "\n")
    wave = summary.get("specialist_wave") if isinstance(summary.get("specialist_wave"), dict) else {}
    if wave.get("classes"):
        lines.append(
            f"- OWASP specialist wave: classes={wave.get('classes')} "
            f"dispatched=`{wave.get('dispatched')}`\n"
        )
    tail = summary.get("timeline_tail") if isinstance(summary.get("timeline_tail"), list) else []
    if tail:
        lines.append("\n### Witness timeline (tail)\n")
        for row in tail[-12:]:
            if not isinstance(row, dict):
                continue
            lines.append(
                f"- `{row.get('ts', '')}` **{row.get('stage', '')}** "
                f"({row.get('kind', '')}): {str(row.get('summary', ''))[:120]}\n"
            )
    return "".join(lines)


__all__ = [
    "append_compound_witness",
    "build_compound_evidence_summary",
    "export_compound_evidence",
    "enrich_report_payload",
    "format_compound_evidence_markdown",
    "STAGES",
]
