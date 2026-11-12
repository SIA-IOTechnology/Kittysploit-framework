#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Refiner pass: patch planned subtasks after asset deltas (PentAGI-style subtask_patch)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

REFINER_SCHEMA = "1.0"

_PATCH_OPS = frozenset({"add", "remove", "modify", "reorder"})


def ensure_planned_subtasks(
    kb: MutableMapping[str, Any],
    *,
    titles: Sequence[str],
    state: Any = None,
) -> List[Dict[str, Any]]:
    store = _flow_store(kb)
    if store.get("subtasks"):
        return list(store.get("subtasks") or [])
    subtasks: List[Dict[str, Any]] = []
    for idx, title in enumerate(titles):
        token = str(title or "").strip()
        if not token:
            continue
        subtasks.append({
            "id": f"st_{idx + 1}",
            "title": token[:240],
            "status": "planned",
            "order": idx,
        })
    store["subtasks"] = subtasks
    if state is not None:
        append_journal_event(
            state,
            kind="plan_init",
            summary=f"Initialized {len(subtasks)} planned subtasks",
            payload={"count": len(subtasks)},
        )
    return subtasks


def _flow_store(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    from interfaces.command_system.builtin.agent.agent_flow_barrier import FLOW_SCHEMA

    store = kb.get("agent_flow")
    if not isinstance(store, dict):
        store = {"schema_version": FLOW_SCHEMA, "subtasks": [], "barrier": None}
        kb["agent_flow"] = store
    store.setdefault("refiner", {"revision": 0, "patches": []})
    return store


def refine_after_recalc(
    kb: MutableMapping[str, Any],
    *,
    reasons: Sequence[str],
    state: Any = None,
) -> Dict[str, Any]:
    """Heuristic refiner when plan_recalc fires — inject/remove subtasks from surface deltas."""
    store = _flow_store(kb)
    refiner = store.get("refiner") if isinstance(store.get("refiner"), dict) else {}
    revision = int(refiner.get("revision") or 0) + 1
    patches: List[Dict[str, Any]] = []

    subtasks: List[Dict[str, Any]] = [
        dict(row) for row in (store.get("subtasks") or []) if isinstance(row, dict)
    ]
    if not subtasks and state is not None:
        hier = getattr(state, "hierarchical_plan", None)
        milestones: List[str] = []
        if isinstance(hier, dict):
            strategic = hier.get("strategic") or {}
            if isinstance(strategic, dict):
                milestones = [str(m) for m in (strategic.get("sub_goals") or []) if str(m).strip()]
        if not milestones:
            goal = str(getattr(state, "campaign_goal", "") or "advance_campaign")
            milestones = [f"advance:{goal}"]
        subtasks = [
            {"id": f"st_{i + 1}", "title": t[:240], "status": "planned", "order": i}
            for i, t in enumerate(milestones[:12])
        ]

    reason_set = {str(r) for r in reasons}

    def _has_title(prefix: str) -> bool:
        return any(str(row.get("title") or "").startswith(prefix) for row in subtasks)

    if "new_session" in reason_set and not _has_title("post:"):
        patches.append({"op": "add", "title": "post: enumerate with verified session", "reason": "new_session"})
        subtasks.append({
            "id": f"st_add_sess_{revision}",
            "title": "post: enumerate with verified session",
            "status": "planned",
            "order": len(subtasks),
        })
    if "new_credential" in reason_set and not _has_title("auth:"):
        patches.append({"op": "add", "title": "auth: replay discovered credentials", "reason": "new_credential"})
        subtasks.append({
            "id": f"st_add_cred_{revision}",
            "title": "auth: replay discovered credentials",
            "status": "planned",
            "order": len(subtasks),
        })
    if "new_surface" in reason_set or "new_endpoint" in reason_set:
        for row in subtasks:
            if str(row.get("title") or "").startswith("advance:") and row.get("status") == "done":
                patches.append({"op": "modify", "id": row.get("id"), "status": "planned", "reason": "new_surface"})
                row["status"] = "planned"
    if "interesting_url" in reason_set and not _has_title("web:"):
        patches.append({"op": "add", "title": "web: probe interesting URL surface", "reason": "interesting_url"})
        subtasks.append({
            "id": f"st_url_{revision}",
            "title": "web: probe interesting URL surface",
            "status": "planned",
            "order": len(subtasks),
        })

    store["subtasks"] = subtasks[-64:]
    store["refiner"] = sanitize_nested({
        "schema_version": REFINER_SCHEMA,
        "revision": revision,
        "patches": patches[-24:],
        "reasons": list(reasons)[:12],
    })
    if state is not None and patches:
        append_journal_event(
            state,
            kind="plan_refine",
            summary=f"Refiner applied {len(patches)} patch(es)",
            payload={"revision": revision, "patches": patches[:6]},
        )
    return store["refiner"]


def apply_subtask_patch(
    kb: MutableMapping[str, Any],
    operations: Sequence[Mapping[str, Any]],
    *,
    state: Any = None,
) -> Dict[str, Any]:
    """Apply explicit delta ops (MCP / operator)."""
    store = _flow_store(kb)
    subtasks: List[Dict[str, Any]] = [
        dict(row) for row in (store.get("subtasks") or []) if isinstance(row, dict)
    ]
    applied: List[str] = []
    for op_row in operations or []:
        if not isinstance(op_row, Mapping):
            continue
        op = str(op_row.get("op") or "").strip().lower()
        if op not in _PATCH_OPS:
            continue
        if op == "add":
            title = str(op_row.get("title") or "new subtask")[:240]
            subtasks.append({
                "id": str(op_row.get("id") or f"st_patch_{len(subtasks) + 1}"),
                "title": title,
                "status": "planned",
                "order": len(subtasks),
            })
            applied.append(f"add:{title[:40]}")
        elif op == "remove":
            sid = str(op_row.get("id") or "")
            subtasks = [r for r in subtasks if str(r.get("id") or "") != sid]
            applied.append(f"remove:{sid}")
        elif op == "modify":
            sid = str(op_row.get("id") or "")
            for row in subtasks:
                if str(row.get("id") or "") == sid:
                    if "title" in op_row:
                        row["title"] = str(op_row.get("title") or row.get("title"))[:240]
                    if "status" in op_row:
                        row["status"] = str(op_row.get("status") or "planned")[:32]
                    applied.append(f"modify:{sid}")
                    break
        elif op == "reorder":
            order = op_row.get("order")
            if isinstance(order, list):
                by_id = {str(r.get("id") or ""): r for r in subtasks}
                subtasks = [by_id[str(i)] for i in order if str(i) in by_id]
                applied.append("reorder")
    store["subtasks"] = subtasks[-64:]
    if state is not None and applied:
        append_journal_event(state, kind="plan_patch", summary="; ".join(applied)[:400])
    return {"applied": applied, "subtasks": store["subtasks"]}
