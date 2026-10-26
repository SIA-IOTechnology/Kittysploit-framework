#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Structured campaign journal for agent runs (product-style timeline export)."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Mapping, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested


def append_journal_event(
    state: Any,
    *,
    kind: str,
    summary: str,
    payload: Optional[Mapping[str, Any]] = None,
    actor: str = "agent",
) -> None:
    row = sanitize_nested({
        "ts": round(time.time(), 3),
        "kind": str(kind or "event")[:64],
        "actor": str(actor or "agent")[:32],
        "summary": str(summary or "")[:500],
        "payload": dict(payload or {}),
    })
    journal: List[Dict[str, Any]] = list(getattr(state, "run_journal", []) or [])
    journal.append(row)
    state.run_journal = journal[-400:]  # type: ignore[attr-defined]
    timeline = list(getattr(state, "decision_timeline", []) or [])
    timeline.append(row)
    state.decision_timeline = timeline[-400:]
    store = getattr(state, "run_store", None)
    paths = getattr(store, "paths", None) if store is not None else None
    if paths is not None:
        try:
            paths.ensure()
            journal_path = paths.run_dir(str(getattr(state, "run_id", "") or "run")) / "journal.jsonl"
            with journal_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            pass


def journal_summary_markdown(state: Any) -> str:
    lines = ["# Agent run journal", ""]
    for row in getattr(state, "run_journal", []) or []:
        if not isinstance(row, dict):
            continue
        lines.append(f"- **{row.get('kind')}** ({row.get('actor')}): {row.get('summary')}")
    return "\n".join(lines)[:12000]
