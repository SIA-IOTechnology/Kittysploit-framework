#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal living attack graph for agent planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackNode:
    node_id: str
    kind: str
    label: str
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    source: str
    target: str
    action: str
    cost: int = 1
    risk: str = "read"
    confidence: float = 0.0
    approval_required: bool = False
    reversible: bool = True
    abandoned_reason: str = ""


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []

    def upsert_node(self, node_id: str, kind: str, label: str, **metadata: Any) -> None:
        self.nodes[node_id] = AttackNode(
            node_id=node_id,
            kind=kind,
            label=label,
            confidence=float(metadata.pop("confidence", 0.0) or 0.0),
            metadata=metadata,
        )

    def add_edge(self, edge: AttackEdge) -> None:
        self.edges.append(edge)

    def best_next_action(self) -> Optional[Dict[str, Any]]:
        def _actionable(edge: AttackEdge) -> bool:
            action = str(edge.action or "")
            return action.startswith((
                "scanner/",
                "auxiliary/",
                "exploit/",
                "exploits/",
                "post/",
                "weaponize:",
                "validate:",
            ))

        candidates = [
            edge for edge in self.edges
            if not edge.abandoned_reason and _actionable(edge)
        ]
        if not candidates:
            return None
        ranked = sorted(
            candidates,
            key=lambda row: (-row.confidence, row.cost, row.risk),
        )
        best = ranked[0]
        return {
            "action": best.action,
            "source": best.source,
            "target": best.target,
            "cost": best.cost,
            "risk": best.risk,
            "confidence": best.confidence,
        }

    def abandon_branch(self, action: str, reason: str) -> None:
        for edge in self.edges:
            if edge.action == action:
                edge.abandoned_reason = reason

    def explain_abandonment(self, action: str) -> str:
        for edge in self.edges:
            if edge.action == action and edge.abandoned_reason:
                return edge.abandoned_reason
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [node.__dict__ for node in self.nodes.values()],
            "edges": [edge.__dict__ for edge in self.edges],
        }

    @classmethod
    def from_observation(cls, observation: Dict[str, Any]) -> "AttackGraph":
        graph = cls()
        target = str(observation.get("target", "asset:target"))
        graph.upsert_node(target, "asset", target, confidence=1.0)
        for service in observation.get("services", []) or []:
            sid = f"service:{service}"
            graph.upsert_node(sid, "service", str(service))
            graph.add_edge(AttackEdge(target, sid, f"probe:{service}", cost=1, risk="read"))
        for evidence in observation.get("evidence", []) or []:
            eid = f"evidence:{evidence.get('id', len(graph.nodes))}"
            graph.upsert_node(eid, "evidence", str(evidence.get("title", eid)), confidence=float(evidence.get("confidence", 0.5)))
            graph.add_edge(
                AttackEdge(target, eid, f"validate:{eid}", cost=1, risk="active", confidence=float(evidence.get("confidence", 0.5))),
            )
        return graph
