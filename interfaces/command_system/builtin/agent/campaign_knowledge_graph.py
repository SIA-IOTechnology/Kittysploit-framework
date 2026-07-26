#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sync living attack graph (host → tech → endpoints → …) from agent knowledge base."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from .attack_graph import AttackEdge, AttackGraph
from .goal_planner import suggest_shell_plan_followups


def _safe_id(prefix: str, value: str, max_len: int = 100) -> str:
    text = str(value or "").strip().replace(" ", "_")[:max_len]
    return f"{prefix}:{text}" if text else prefix


def attack_graph_from_kb_dict(data: Mapping[str, Any]) -> AttackGraph:
    graph = AttackGraph()
    if not isinstance(data, dict):
        return graph
    for row in data.get("nodes") or []:
        if not isinstance(row, dict):
            continue
        nid = str(row.get("node_id") or "").strip()
        if not nid:
            continue
        meta = dict(row.get("metadata") or {})
        graph.upsert_node(
            nid,
            str(row.get("kind") or "node"),
            str(row.get("label") or nid),
            confidence=float(row.get("confidence", 0.0) or 0.0),
            **meta,
        )
    for row in data.get("edges") or []:
        if not isinstance(row, dict):
            continue
        src = str(row.get("source") or "").strip()
        tgt = str(row.get("target") or "").strip()
        action = str(row.get("action") or "").strip()
        if not src or not tgt or not action:
            continue
        graph.add_edge(
            AttackEdge(
                source=src,
                target=tgt,
                action=action,
                cost=int(row.get("cost", 1) or 1),
                risk=str(row.get("risk") or "read"),
                confidence=float(row.get("confidence", 0.0) or 0.0),
                approval_required=bool(row.get("approval_required", False)),
                reversible=bool(row.get("reversible", True)),
                abandoned_reason=str(row.get("abandoned_reason") or ""),
            )
        )
    return graph


def build_attack_graph_from_kb(
    kb: Mapping[str, Any],
    *,
    hostname: str = "",
    results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> AttackGraph:
    """Materialize KB fields into host → tech → endpoints → auth → exploit_paths."""
    graph = AttackGraph()
    host = str(hostname or kb.get("target_hostname") or "target").strip() or "target"
    host_id = _safe_id("host", host.lower(), 120)
    graph.upsert_node(host_id, "host", host, confidence=1.0)

    tech_conf = kb.get("tech_confidence", {}) or {}
    for tech in kb.get("tech_hints", []) or []:
        tkey = str(tech).lower().strip()
        if not tkey:
            continue
        tid = _safe_id("tech", tkey, 48)
        conf = float(tech_conf.get(tkey, 0.55) or 0.55)
        graph.upsert_node(tid, "tech", tkey, confidence=conf)
        graph.add_edge(
            AttackEdge(host_id, tid, f"stack:{tkey}", cost=0, confidence=conf),
        )

    for ep in list(kb.get("discovered_endpoints", []) or [])[:80]:
        ep_s = str(ep).strip()
        if not ep_s:
            continue
        eid = _safe_id("endpoint", ep_s, 140)
        graph.upsert_node(eid, "endpoint", ep_s[:120], confidence=0.68)
        graph.add_edge(
            AttackEdge(host_id, eid, f"discover:{ep_s[:80]}", cost=1, confidence=0.65),
        )

    for param in list(kb.get("discovered_params", []) or [])[:60]:
        p_s = str(param).strip()
        if not p_s:
            continue
        pid = _safe_id("param", p_s, 80)
        graph.upsert_node(pid, "param", p_s[:72], confidence=0.58)
        graph.add_edge(
            AttackEdge(host_id, pid, f"param:{p_s[:48]}", cost=1, confidence=0.55),
        )

    for lp in list(kb.get("login_paths", []) or [])[:24]:
        lp_s = str(lp).strip()
        if not lp_s:
            continue
        aid = _safe_id("auth", lp_s, 100)
        graph.upsert_node(aid, "auth", lp_s[:96], confidence=0.74)
        graph.add_edge(
            AttackEdge(host_id, aid, f"auth:{lp_s[:64]}", cost=1, confidence=0.72),
        )

    memory = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    for entry in list(memory.get("entries") or [])[:60]:
        if not isinstance(entry, dict):
            continue
        cap = str(entry.get("capability") or "").strip().lower()
        if not cap:
            continue
        value = str(entry.get("value") or "confirmed").strip()
        cid = _safe_id("capability", f"{cap}:{value}", 140)
        try:
            conf = float(entry.get("confidence", 0.72) or 0.72)
        except Exception:
            conf = 0.72
        graph.upsert_node(
            cid,
            "capability",
            f"{cap}={value[:72]}",
            confidence=conf,
            source_module=str(entry.get("source_module") or "")[:160],
        )
        graph.add_edge(
            AttackEdge(host_id, cid, f"capability:{cap}", cost=0, confidence=conf),
        )

    for row in list(memory.get("observations") or [])[-48:]:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").strip().lower()
        module_path = str(row.get("module_path") or "").strip()
        if not status or not module_path:
            continue
        oid = _safe_id("observation", f"{status}:{module_path}", 180)
        label = f"{status}: {module_path.rsplit('/', 1)[-1]}"
        try:
            conf = float(row.get("confidence", 0.5) or 0.5)
        except Exception:
            conf = 0.5
        graph.upsert_node(
            oid,
            "observation",
            label[:120],
            confidence=conf,
            capability=str(row.get("capability") or ""),
            reason=str(row.get("reason") or "")[:240],
        )
        graph.add_edge(
            AttackEdge(
                host_id,
                oid,
                f"observe:{module_path}",
                cost=0,
                risk="read",
                confidence=conf,
                abandoned_reason=status if status in {"blocked", "error", "refuted"} else "",
            ),
        )

    observed = {str(p) for p in (kb.get("observed_modules") or []) if p}
    stale = {str(p) for p in (kb.get("attack_graph_stale_modules") or []) if p}

    for mod_path in suggest_shell_plan_followups(dict(kb))[:10]:
        if mod_path in observed:
            continue
        mid = _safe_id("module", mod_path, 160)
        label = mod_path.rsplit("/", 1)[-1]
        conf = 0.42 if mod_path in stale else 0.7
        graph.upsert_node(mid, "module", label, confidence=conf)
        graph.add_edge(
            AttackEdge(
                host_id,
                mid,
                mod_path,
                cost=2,
                risk="active",
                confidence=conf,
                abandoned_reason="no_graph_growth" if mod_path in stale else "",
            ),
        )

    for path in list(kb.get("post_auth_exploit_paths", []) or [])[:16]:
        p_s = str(path).strip()
        if not p_s:
            continue
        xid = _safe_id("exploit_path", p_s, 160)
        graph.upsert_node(xid, "exploit_path", p_s.rsplit("/", 1)[-1], confidence=0.86)
        graph.add_edge(
            AttackEdge(
                host_id,
                xid,
                p_s,
                cost=3,
                risk="intrusive",
                confidence=0.84,
            ),
        )

    for idx, row in enumerate(results or []):
        if not isinstance(row, dict) or not row.get("vulnerable"):
            continue
        mod = str(row.get("path") or row.get("module") or idx)
        fid = _safe_id("finding", f"{mod}:{idx}", 140)
        graph.upsert_node(
            fid,
            "finding",
            str(row.get("message", mod))[:96],
            confidence=0.8,
        )
        graph.add_edge(
            AttackEdge(
                host_id,
                fid,
                f"weaponize:{mod}",
                cost=2,
                risk="active",
                confidence=0.78,
            ),
        )
        ex = str(row.get("exploit_module") or "").strip()
        if ex:
            eid = _safe_id("exploit_path", ex, 160)
            graph.upsert_node(eid, "exploit_path", ex.rsplit("/", 1)[-1], confidence=0.88)
            graph.add_edge(
                AttackEdge(fid, eid, ex, cost=3, risk="intrusive", confidence=0.85),
            )

    return graph


def sync_attack_graph_from_kb(
    kb: MutableMapping[str, Any],
    *,
    hostname: str = "",
    module_paths: Optional[Sequence[str]] = None,
    results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> int:
    """
    Rebuild ``kb['attack_graph']`` from current intelligence.

    Returns graph growth (nodes + edges) vs previous snapshot. When a phase
    produces zero growth, paths in ``module_paths`` are marked stale for scoring.
    """
    if not isinstance(kb, MutableMapping):
        return 0

    export_path = str(kb.get("bloodhound_export_path") or "").strip()
    if export_path:
        try:
            from lib.protocols.ldap.ad_graph_import import merge_bloodhound_into_kb
            merge_bloodhound_into_kb(
                kb,
                export_path,
                domain=str(kb.get("target_hostname") or hostname or ""),
            )
        except Exception:
            pass

    prev_stats = kb.get("attack_graph_stats") if isinstance(kb.get("attack_graph_stats"), dict) else {}
    prev_total = int(prev_stats.get("nodes", 0) or 0) + int(prev_stats.get("edges", 0) or 0)

    graph = build_attack_graph_from_kb(kb, hostname=hostname, results=results)
    new_total = len(graph.nodes) + len(graph.edges)
    delta = max(0, new_total - prev_total)

    kb["attack_graph"] = graph.to_dict()
    kb["attack_graph_stats"] = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
    }
    kb["attack_graph_last_delta"] = delta

    next_action = graph.best_next_action()
    if next_action:
        kb["attack_graph_next_action"] = next_action
    elif "attack_graph_next_action" in kb:
        kb.pop("attack_graph_next_action", None)

    ran_paths = [str(p).strip() for p in (module_paths or []) if str(p).strip()]
    if ran_paths and delta == 0:
        stale = set(str(x) for x in (kb.get("attack_graph_stale_modules") or []) if x)
        stale.update(ran_paths)
        kb["attack_graph_stale_modules"] = sorted(stale)[:48]

    kb["attack_graph_phase_delta"] = delta

    from interfaces.command_system.builtin.agent.campaign_world import sync_campaign_world

    sync_campaign_world(kb, hostname=hostname, results=results)
    return delta


def attack_graph_action_for_module(kb: Mapping[str, Any], module_path: str) -> Optional[Dict[str, Any]]:
    """Return graph edge action dict if ``module_path`` is the best pending step."""
    if not isinstance(kb, dict) or not module_path:
        return None
    nxt = kb.get("attack_graph_next_action")
    if not isinstance(nxt, dict):
        return None
    action = str(nxt.get("action") or "").strip()
    if action == str(module_path).strip():
        return nxt
    return None


def summarize_attack_graph_for_report(kb: Mapping[str, Any]) -> Dict[str, Any]:
    """Compact attack-graph slice for Markdown/JSON reports."""
    if not isinstance(kb, dict):
        return {}
    stats = kb.get("attack_graph_stats") if isinstance(kb.get("attack_graph_stats"), dict) else {}
    graph = kb.get("attack_graph") if isinstance(kb.get("attack_graph"), dict) else {}
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]

    by_kind: Dict[str, int] = {}
    for node in nodes:
        kind = str(node.get("kind") or "node")
        by_kind[kind] = int(by_kind.get(kind, 0)) + 1

    sample_nodes = [
        {
            "kind": str(n.get("kind") or ""),
            "label": str(n.get("label") or "")[:96],
            "confidence": float(n.get("confidence", 0.0) or 0.0),
        }
        for n in nodes[:16]
    ]
    sample_edges = [
        {
            "action": str(e.get("action") or "")[:120],
            "confidence": float(e.get("confidence", 0.0) or 0.0),
            "abandoned": bool(e.get("abandoned_reason")),
        }
        for e in edges[:16]
    ]

    return {
        "nodes": int(stats.get("nodes", 0) or 0),
        "edges": int(stats.get("edges", 0) or 0),
        "last_delta": int(kb.get("attack_graph_last_delta", 0) or 0),
        "nodes_by_kind": by_kind,
        "next_action": dict(kb.get("attack_graph_next_action") or {})
        if isinstance(kb.get("attack_graph_next_action"), dict)
        else {},
        "stale_modules": list(kb.get("attack_graph_stale_modules") or [])[:12],
        "sample_nodes": sample_nodes,
        "sample_edges": sample_edges,
    }
