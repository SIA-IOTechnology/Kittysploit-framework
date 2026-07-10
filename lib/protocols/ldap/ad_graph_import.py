#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lightweight BloodHound JSON importer for agent attack graph.

Parses nodes.json / edges.json (or a combined export) and merges user/computer
membership edges into the campaign knowledge graph without requiring Neo4j.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple


def _node_label(node: Mapping[str, Any]) -> str:
    props = node.get("Properties") or node.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    for key in ("name", "samaccountname", "distinguishedname", "hostname", "objectid"):
        val = props.get(key) or node.get(key)
        if val:
            return str(val)[:120]
    return str(node.get("ObjectId") or node.get("id") or "node")[:120]


def _node_kind(node: Mapping[str, Any]) -> str:
    labels = node.get("Labels") or node.get("labels") or []
    if isinstance(labels, list):
        joined = " ".join(str(x).lower() for x in labels)
        if "user" in joined:
            return "ad_user"
        if "computer" in joined or "group" in joined:
            return "ad_computer"
        if "domain" in joined:
            return "ad_domain"
    kind = str(node.get("kind") or node.get("type") or "bh_node").lower()
    return kind[:32] or "bh_node"


def load_bloodhound_export(path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Load BloodHound JSON export from a file or directory.

    Accepts:
    - Single JSON array of nodes or edges
    - Combined ``{nodes, edges}`` object
    - Directory with ``nodes.json`` and ``edges.json``
    """
    p = Path(str(path or "").strip())
    if not p.exists():
        return [], []

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def _extend_rows(target: List[Dict[str, Any]], payload: Any) -> None:
        if isinstance(payload, list):
            target.extend(row for row in payload if isinstance(row, dict))
        elif isinstance(payload, dict):
            if "nodes" in payload or "edges" in payload:
                _extend_rows(nodes, payload.get("nodes"))
                _extend_rows(edges, payload.get("edges"))
            else:
                target.append(payload)

    if p.is_dir():
        for name, bucket in (("nodes.json", nodes), ("edges.json", edges)):
            fpath = p / name
            if fpath.is_file():
                _extend_rows(bucket, json.loads(fpath.read_text(encoding="utf-8", errors="replace")))
    else:
        raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(raw, dict) and ("nodes" in raw or "edges" in raw):
            _extend_rows(nodes, raw.get("nodes"))
            _extend_rows(edges, raw.get("edges"))
        elif isinstance(raw, list) and raw and isinstance(raw[0], dict):
            sample = raw[0]
            if "StartNode" in sample or "EndNode" in sample or "source" in sample:
                edges = [row for row in raw if isinstance(row, dict)]
            else:
                nodes = [row for row in raw if isinstance(row, dict)]
        elif isinstance(raw, dict):
            nodes = [raw]

    return nodes, edges


def bloodhound_to_attack_graph(
    nodes: Iterable[Mapping[str, Any]],
    edges: Iterable[Mapping[str, Any]],
    *,
    domain: str = "",
) -> Dict[str, Any]:
    """Convert BloodHound nodes/edges to ``attack_graph`` dict format."""
    graph_nodes: Dict[str, Dict[str, Any]] = {}
    graph_edges: List[Dict[str, Any]] = []

    def nid(prefix: str, key: str) -> str:
        safe = str(key or "").strip().replace(" ", "_")[:100]
        return f"{prefix}:{safe}" if safe else prefix

    if domain:
        did = nid("ad_domain", domain)
        graph_nodes[did] = {
            "node_id": did,
            "kind": "ad_domain",
            "label": domain[:96],
            "confidence": 0.95,
            "metadata": {"source": "bloodhound"},
        }

    id_map: Dict[str, str] = {}
    for node in nodes or []:
        if not isinstance(node, Mapping):
            continue
        oid = str(node.get("ObjectId") or node.get("id") or node.get("objectid") or "")
        label = _node_label(node)
        kind = _node_kind(node)
        node_id = nid(kind, oid or label)
        id_map[oid] = node_id
        graph_nodes[node_id] = {
            "node_id": node_id,
            "kind": kind,
            "label": label,
            "confidence": 0.82,
            "metadata": {"source": "bloodhound", "object_id": oid},
        }
        if domain:
            graph_edges.append({
                "source": nid("ad_domain", domain),
                "target": node_id,
                "action": "contains",
                "cost": 0,
                "confidence": 0.8,
                "risk": "read",
            })

    for edge in edges or []:
        if not isinstance(edge, Mapping):
            continue
        src_oid = str(
            edge.get("StartNode") or edge.get("source") or edge.get("Source") or ""
        )
        tgt_oid = str(
            edge.get("EndNode") or edge.get("target") or edge.get("Target") or ""
        )
        src = id_map.get(src_oid) or nid("bh", src_oid)
        tgt = id_map.get(tgt_oid) or nid("bh", tgt_oid)
        rel = str(edge.get("Type") or edge.get("type") or edge.get("label") or "linked")[:64]
        graph_edges.append({
            "source": src,
            "target": tgt,
            "action": rel,
            "cost": 2,
            "confidence": 0.78,
            "risk": "read",
            "reversible": True,
        })

    return {
        "nodes": list(graph_nodes.values()),
        "edges": graph_edges,
    }


def merge_bloodhound_into_kb(
    kb: MutableMapping[str, Any],
    export_path: str,
    *,
    domain: str = "",
    replace: bool = False,
) -> int:
    """
    Import BloodHound export into ``kb['attack_graph']``.

    Returns number of new nodes merged.
    """
    if not isinstance(kb, MutableMapping):
        return 0
    nodes, edges = load_bloodhound_export(export_path)
    if not nodes and not edges:
        return 0

    incoming = bloodhound_to_attack_graph(nodes, edges, domain=domain or str(kb.get("target_hostname") or ""))
    before = 0
    existing = kb.get("attack_graph") if isinstance(kb.get("attack_graph"), dict) else {}
    if isinstance(existing, dict) and not replace:
        before = len(existing.get("nodes") or [])
        merged_nodes = {str(n.get("node_id")): n for n in (existing.get("nodes") or []) if isinstance(n, dict)}
        for node in incoming.get("nodes") or []:
            if isinstance(node, dict) and node.get("node_id"):
                merged_nodes[str(node["node_id"])] = node
        merged_edges = list(existing.get("edges") or [])
        seen: Set[Tuple[str, str, str]] = set()
        for edge in merged_edges:
            if isinstance(edge, dict):
                seen.add((str(edge.get("source")), str(edge.get("target")), str(edge.get("action"))))
        for edge in incoming.get("edges") or []:
            if not isinstance(edge, dict):
                continue
            key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("action")))
            if key not in seen:
                merged_edges.append(edge)
                seen.add(key)
        kb["attack_graph"] = {"nodes": list(merged_nodes.values()), "edges": merged_edges}
    else:
        kb["attack_graph"] = incoming

    after_graph = kb.get("attack_graph") if isinstance(kb.get("attack_graph"), dict) else {}
    after = len(after_graph.get("nodes") or [])
    kb["attack_graph_stats"] = {
        "nodes": after,
        "edges": len(after_graph.get("edges") or []),
    }
    kb["bloodhound_imported"] = True
    kb["bloodhound_source"] = str(export_path)[:256]
    risk = set(kb.get("risk_signals") or [])
    risk.add("bloodhound_graph_loaded")
    kb["risk_signals"] = sorted(risk)
    return max(0, after - before)
