#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Flow barriers inspired by PentAGI done/ask: checkpoint operator input or close subtasks."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional

from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

FLOW_SCHEMA = "1.0"


def _flow_store(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    store = kb.get("agent_flow")
    if not isinstance(store, dict):
        store = {"schema_version": FLOW_SCHEMA, "subtasks": [], "barrier": None}
        kb["agent_flow"] = store
    store.setdefault("schema_version", FLOW_SCHEMA)
    store.setdefault("subtasks", [])
    return store


def mark_subtask_done(
    kb: MutableMapping[str, Any],
    *,
    subtask_id: str,
    summary: str = "",
    state: Any = None,
) -> bool:
    store = _flow_store(kb)
    token = str(subtask_id or "").strip()
    if not token:
        return False
    subtasks: List[Dict[str, Any]] = list(store.get("subtasks") or [])
    found = False
    for row in subtasks:
        if not isinstance(row, dict):
            continue
        if str(row.get("id") or "") == token:
            row["status"] = "done"
            row["summary"] = str(summary or row.get("summary") or "")[:500]
            found = True
            break
    if not found:
        subtasks.append({
            "id": token,
            "title": token,
            "status": "done",
            "summary": str(summary or "")[:500],
        })
    store["subtasks"] = subtasks[-64:]
    store["last_done"] = sanitize_nested({"id": token, "summary": str(summary or "")[:200]})
    if state is not None:
        append_journal_event(
            state,
            kind="subtask_done",
            summary=f"Subtask completed: {token}",
            payload={"subtask_id": token},
        )
    return True


def request_operator_ask(
    kb: MutableMapping[str, Any],
    *,
    question: str,
    context: Optional[Mapping[str, Any]] = None,
    state: Any = None,
) -> Dict[str, Any]:
    store = _flow_store(kb)
    barrier = sanitize_nested({
        "type": "ask",
        "question": str(question or "Operator input required.")[:2000],
        "context": dict(context or {}),
        "answered": False,
        "answer": "",
    })
    store["barrier"] = barrier
    store["awaiting_operator"] = True
    if state is not None:
        setattr(state, "agent_flow_paused", True)
        setattr(state, "campaign_stop_reason", "operator_ask")
        append_journal_event(
            state,
            kind="operator_ask",
            summary=str(question or "")[:240],
            payload={"context_keys": list((context or {}).keys())[:12]},
            actor="barrier",
        )
    return barrier


def submit_operator_answer(kb: MutableMapping[str, Any], answer: str, *, state: Any = None) -> bool:
    store = _flow_store(kb)
    barrier = store.get("barrier")
    if not isinstance(barrier, dict) or barrier.get("type") != "ask":
        return False
    barrier["answered"] = True
    barrier["answer"] = str(answer or "")[:4000]
    store["barrier"] = barrier
    store["awaiting_operator"] = False
    if state is not None:
        setattr(state, "agent_flow_paused", False)
        if getattr(state, "campaign_stop_reason", None) == "operator_ask":
            state.campaign_stop_reason = None
        append_journal_event(
            state,
            kind="operator_answer",
            summary="Operator provided flow input",
            actor="operator",
        )
    return True


def flow_awaiting_operator(kb: Mapping[str, Any]) -> bool:
    if not isinstance(kb, Mapping):
        return False
    store = kb.get("agent_flow")
    if not isinstance(store, dict):
        return False
    if store.get("awaiting_operator"):
        return True
    barrier = store.get("barrier")
    return isinstance(barrier, dict) and barrier.get("type") == "ask" and not barrier.get("answered")


def consume_flow_barrier_stop(state: Any) -> Optional[str]:
    """If campaign paused on ask, return stop reason for adaptive loop (soft pause)."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return None
    if not flow_awaiting_operator(kb):
        return None
    barrier = (kb.get("agent_flow") or {}).get("barrier") or {}
    return str(barrier.get("question") or "operator_ask")[:500]
