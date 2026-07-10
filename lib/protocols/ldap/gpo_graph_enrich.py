#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merge GPO findings into the agent attack graph."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple


def _node_id(prefix: str, key: str) -> str:
    safe = str(key or "").strip().replace(" ", "_").replace("\\", "_")[:100]
    return f"{prefix}:{safe}" if safe else prefix


def _ensure_graph(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    graph = kb.get("attack_graph")
    if isinstance(graph, dict):
        return graph
    graph = {"nodes": [], "edges": []}
    kb["attack_graph"] = graph
    return graph


def merge_gpo_findings_into_kb(
    kb: MutableMapping[str, Any],
    findings: Iterable[Mapping[str, Any]],
    gpo_computer_map: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    domain: str = "",
) -> int:
    """
    Synthesize GPO-derived edges (AdminTo, CanRDP, CanPrivEsc, ...) into ``attack_graph``.

    Returns number of new edges added.
    """
    if not isinstance(kb, MutableMapping):
        return 0

    graph = _ensure_graph(kb)
    nodes = {str(n.get("node_id")): n for n in (graph.get("nodes") or []) if isinstance(n, dict) and n.get("node_id")}
    edges = list(graph.get("edges") or [])
    seen: Set[Tuple[str, str, str]] = set()
    for edge in edges:
        if isinstance(edge, dict):
            seen.add((str(edge.get("source")), str(edge.get("target")), str(edge.get("action"))))

    added = 0
    if domain:
        domain_id = _node_id("ad_domain", domain)
        nodes.setdefault(domain_id, {
            "node_id": domain_id,
            "kind": "ad_domain",
            "label": domain[:96],
            "confidence": 0.9,
            "metadata": {"source": "gpo"},
        })

    for finding in findings or []:
        if not isinstance(finding, Mapping):
            continue
        edge_type = str(finding.get("edge") or finding.get("action") or "").strip()
        gpo_guid = str(finding.get("gpo_guid") or "").strip()
        if not edge_type or not gpo_guid:
            continue

        computers = list(gpo_computer_map.get(gpo_guid) or [])
        members = list(finding.get("members") or [])
        if not computers or not members:
            continue

        for member in members:
            trustee_name = str(member.get("name") or member.get("sid") or "").strip()
            if not trustee_name:
                continue
            trustee_id = _node_id("ad_user", trustee_name)
            nodes.setdefault(trustee_id, {
                "node_id": trustee_id,
                "kind": "ad_user",
                "label": trustee_name[:96],
                "confidence": 0.84,
                "metadata": {"source": "gpo", "gpo_guid": gpo_guid},
            })

            for computer in computers:
                host = str(
                    computer.get("samaccountname")
                    or computer.get("dnshostname")
                    or computer.get("name")
                    or ""
                ).strip()
                if not host:
                    continue
                computer_id = _node_id("ad_computer", host)
                nodes.setdefault(computer_id, {
                    "node_id": computer_id,
                    "kind": "ad_computer",
                    "label": host[:96],
                    "confidence": 0.84,
                    "metadata": {"source": "gpo", "gpo_guid": gpo_guid},
                })
                key = (trustee_id, computer_id, edge_type)
                if key in seen:
                    continue
                edges.append({
                    "source": trustee_id,
                    "target": computer_id,
                    "action": edge_type,
                    "cost": 2,
                    "confidence": 0.8,
                    "risk": "privesc",
                    "reversible": False,
                    "metadata": {
                        "source": "gpo",
                        "gpo_guid": gpo_guid,
                        "group": finding.get("group"),
                    },
                })
                seen.add(key)
                added += 1

    graph["nodes"] = list(nodes.values())
    graph["edges"] = edges
    kb["attack_graph"] = graph
    kb["attack_graph_stats"] = {
        "nodes": len(graph["nodes"]),
        "edges": len(graph["edges"]),
    }
    risk = set(kb.get("risk_signals") or [])
    risk.add("gpo_graph_enriched")
    kb["risk_signals"] = sorted(risk)
    return added
