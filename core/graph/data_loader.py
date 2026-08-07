#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Load workspace and agent intelligence for the attack path explorer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.campaign import CampaignGraphBuilder
from core.graph.normalizer import (
    ExplorerGraph,
    enrich_with_intelligence,
    merge_graphs,
    normalize_agent_graph,
    normalize_campaign_graph,
)


def _latest_agent_kb(framework: Any, run_id: Optional[str] = None) -> Dict[str, Any]:
    try:
        from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore
    except ImportError:
        return {}

    paths = AgentPathService(framework)
    runs = AgentRunStore(paths, "probe").list_runs()
    if not runs:
        return {}

    target_run = str(run_id or "").strip()
    if target_run and target_run in runs:
        chosen = target_run
    else:
        chosen = runs[-1]

    store = AgentRunStore(paths, chosen)
    try:
        checkpoint = store.load_checkpoint()
    except (ValueError, OSError):
        return {}

    state = checkpoint.get("state") if isinstance(checkpoint, dict) else {}
    if not isinstance(state, dict):
        return {}
    kb = state.get("knowledge_base")
    if isinstance(kb, dict):
        kb = dict(kb)
        kb["_agent_run_id"] = chosen
        return kb
    return {}


def _load_saved_campaign_graph(framework: Any) -> Optional[Dict[str, Any]]:
    try:
        builder = CampaignGraphBuilder(framework)
        snapshot = builder._load_workspace_snapshot(None)  # noqa: SLF001 — reuse workspace snapshot
        ws_name = str(snapshot.get("workspace_name") or "workspace")
        slug = "".join(ch if ch.isalnum() else "-" for ch in ws_name.lower()).strip("-") or "workspace"
        graph_path = builder.DEFAULT_OUTPUT_DIR / slug / "graph.json"
        if graph_path.is_file():
            import json

            with graph_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload if isinstance(payload, dict) else None
    except Exception:
        return None
    return None


def load_explorer_graph(
    framework: Any,
    *,
    source: str = "both",
    max_steps: int = 50,
    run_id: Optional[str] = None,
    include_proposals: bool = True,
) -> ExplorerGraph:
    """Build a unified explorer graph from campaign workspace data and/or agent KB."""
    source = str(source or "both").strip().lower()
    graphs: List[ExplorerGraph] = []
    workspace_name = ""
    workspace_id = 0
    sessions: List[Dict[str, Any]] = []
    credentials: List[Dict[str, Any]] = []
    lateral: List[Dict[str, Any]] = []
    kb: Dict[str, Any] = {}

    if source in {"campaign", "both", "merged"}:
        try:
            builder = CampaignGraphBuilder(framework)
            campaign = builder.build(max_steps=max(1, int(max_steps or 50)))
            workspace_name = campaign.workspace
            workspace_id = campaign.workspace_id
            graphs.append(normalize_campaign_graph(campaign.to_dict()))
            snapshot = builder._load_workspace_snapshot(None)  # noqa: SLF001
            sessions = list(snapshot.get("sessions") or [])
        except Exception:
            saved = _load_saved_campaign_graph(framework)
            if saved:
                graphs.append(normalize_campaign_graph(saved))
                workspace_name = str(saved.get("workspace") or workspace_name)
                workspace_id = int(saved.get("workspace_id") or workspace_id)

    if source in {"agent", "both", "merged"}:
        kb = _latest_agent_kb(framework, run_id=run_id)
        attack_graph = kb.get("attack_graph") if isinstance(kb.get("attack_graph"), dict) else {}
        if attack_graph.get("nodes"):
            agent_graph = normalize_agent_graph(attack_graph, kb=kb)
            if workspace_name:
                agent_graph.workspace = workspace_name
            if workspace_id:
                agent_graph.workspace_id = workspace_id
            graphs.append(agent_graph)
        elif source == "agent":
            graphs.append(ExplorerGraph(source="agent", workspace=workspace_name, workspace_id=workspace_id))

    if not graphs:
        graphs.append(ExplorerGraph(source=source, workspace=workspace_name, workspace_id=workspace_id))

    merged = merge_graphs(*graphs, source=source if source != "both" else "merged")
    merged.workspace = workspace_name or merged.workspace
    merged.workspace_id = workspace_id or merged.workspace_id

    if kb:
        for row in kb.get("credential_store") or []:
            if isinstance(row, dict):
                credentials.append(dict(row))
        try:
            from interfaces.command_system.builtin.agent.scope_lateral import (
                build_scope_index,
                index_credentials,
                propose_credential_reuse,
            )

            cred_rows = [item.to_dict() for item in index_credentials(kb, framework=framework)]
            credentials.extend(cred_rows)
            if include_proposals:
                index = build_scope_index(kb)
                creds = index_credentials(kb, framework=framework)
                lateral = [item.to_dict() for item in propose_credential_reuse(kb, scope_index=index, credentials=creds)]
        except Exception:
            pass

    enrich_with_intelligence(
        merged,
        sessions=sessions,
        credentials=_dedupe_credentials(credentials),
        lateral_proposals=lateral if include_proposals else [],
    )
    merged.summary.update({
        "workspace": merged.workspace,
        "workspace_id": merged.workspace_id,
        "paths": len(merged.paths),
        "agent_run_id": str(kb.get("_agent_run_id") or run_id or ""),
    })
    if merged.next_action:
        merged.summary["next_action"] = merged.next_action
    return merged


def _dedupe_credentials(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or row.get("authenticated_as") or "").strip()
        origin = str(row.get("origin") or row.get("source_module") or "")
        key = f"{username}:{origin}"
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row))
    return out[:24]
