#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Structured timeline events for agent runs."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

VALID_EVENT_KINDS = frozenset({
    "run_start",
    "phase_start",
    "decision",
    "request",
    "replay",
    "module_start",
    "module_result",
    "approval",
    "finding",
    "evidence",
    "session",
    "checkpoint",
    "error",
    "stop",
})


def new_action_id() -> str:
    return f"act_{uuid.uuid4().hex[:12]}"


def build_timeline_event(
    *,
    kind: str,
    run_id: str,
    workspace: str = "default",
    target: str = "",
    phase: str = "",
    action_id: Optional[str] = None,
    parent_id: Optional[str] = None,
    summary: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    kind = str(kind or "").strip().lower()
    if kind not in VALID_EVENT_KINDS:
        raise ValueError(f"Unknown timeline event kind: {kind}")
    event = {
        "schema_version": "1.0",
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "kind": kind,
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id),
        "workspace": str(workspace or "default"),
        "target": str(target or ""),
        "phase": str(phase or ""),
        "action_id": action_id or new_action_id(),
        "parent_id": parent_id or "",
        "summary": str(summary or "")[:500],
    }
    if extra:
        event["data"] = sanitize_nested(extra)
    return sanitize_nested(event)


def load_events_from_store(store: Any) -> List[Dict[str, Any]]:
    path = getattr(store, "events_path", None)
    if path is None or not path.is_file():
        return []
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                import json

                row = json.loads(line)
                if isinstance(row, dict):
                    events.append(row)
            except json.JSONDecodeError:
                continue
    return events


def reconstruct_run_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    phases = []
    decisions = []
    stops = []
    for row in events:
        kind = str(row.get("kind", "")).lower()
        if kind == "phase_start":
            phases.append(row)
        elif kind == "decision":
            decisions.append(row)
        elif kind == "stop":
            stops.append(row)
    return {
        "event_count": len(events),
        "phases": [row.get("phase") for row in phases],
        "decision_count": len(decisions),
        "stop_reasons": [row.get("summary") for row in stops],
    }
