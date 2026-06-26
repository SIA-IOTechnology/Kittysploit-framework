#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reconstruct decision explanations from run events and checkpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_store import AgentPathService
from interfaces.command_system.builtin.agent.timeline import load_events_from_store


class AgentExplainService:
    def __init__(self, framework: Any, paths: Optional[AgentPathService] = None) -> None:
        self.framework = framework
        self.paths = paths or AgentPathService(framework)

    def explain(self, run_id: str) -> Dict[str, Any]:
        store = self._store_for_run(run_id)
        events = load_events_from_store(store)
        checkpoint = self._load_checkpoint_safe(store)
        decisions = [row for row in events if str(row.get("kind", "")).lower() == "decision"]
        approvals = [row for row in events if str(row.get("kind", "")).lower() == "approval"]
        stops = [row for row in events if str(row.get("kind", "")).lower() == "stop"]
        timeline = checkpoint.get("state", {}).get("decision_timeline", [])
        explanations = []
        for row in decisions + timeline:
            if not isinstance(row, dict):
                continue
            data = row.get("data") if isinstance(row.get("data"), dict) else row
            explanation = data.get("decision_explanation") or data.get("explanation") or {}
            if not isinstance(explanation, dict):
                explanation = {}
            explanations.append({
                "phase": row.get("phase") or data.get("phase", ""),
                "action_id": row.get("action_id") or data.get("action_id", ""),
                "module": data.get("module") or data.get("path", ""),
                "chosen": explanation.get("chosen") or data.get("summary", ""),
                "reason": explanation.get("reason") or data.get("reason", ""),
                "evidence": explanation.get("evidence", []),
                "rejected_alternatives": explanation.get("rejected_alternatives", []),
                "guardrail": explanation.get("guardrail", ""),
            })
        return sanitize_nested({
            "run_id": run_id,
            "workspace": self.paths.workspace,
            "resume_phase": checkpoint.get("phase", ""),
            "event_count": len(events),
            "decisions": explanations,
            "approvals": approvals,
            "stops": stops,
            "checkpoint_available": bool(checkpoint),
        })

    def _store_for_run(self, run_id: str):
        from interfaces.command_system.builtin.agent.run_store import AgentRunStore

        return AgentRunStore(self.paths, run_id)

    @staticmethod
    def _load_checkpoint_safe(store: Any) -> Dict[str, Any]:
        try:
            return store.load_checkpoint()
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def find_run(self, run_id: str) -> bool:
        return self._store_for_run(run_id).checkpoint_path.is_file() or (
            self._store_for_run(run_id).events_path.is_file()
        )
