#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize campaign and agent attack graphs into a unified explorer schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple


SCHEMA_VERSION = "1.0"

KIND_COLORS: Dict[str, str] = {
    "host": "#4A90D9",
    "machine": "#4A90D9",
    "service": "#7B68EE",
    "tech": "#9370DB",
    "endpoint": "#50C878",
    "param": "#3CB371",
    "auth": "#FFB347",
    "vulnerability": "#FF6B6B",
    "finding": "#FF6B6B",
    "vuln": "#FF6B6B",
    "credential": "#DA70D6",
    "session": "#FFD700",
    "pivot": "#00CED1",
    "module": "#FF4500",
    "exploit_path": "#DC143C",
    "capability": "#F0E68C",
    "observation": "#A9A9A9",
    "action": "#708090",
    "ad_user": "#6495ED",
    "ad_group": "#4682B4",
    "ad_computer": "#5F9EA0",
    "ad_domain": "#2F4F4F",
}

RISK_COLORS: Dict[str, str] = {
    "info": "#94a3b8",
    "low": "#22c55e",
    "read": "#22c55e",
    "medium": "#eab308",
    "active": "#eab308",
    "high": "#f97316",
    "intrusive": "#f97316",
    "critical": "#ef4444",
    "destructive": "#dc2626",
}


@dataclass
class ExplorerNode:
    id: str
    label: str
    kind: str
    confidence: float = 0.0
    risk: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    modules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "confidence": round(float(self.confidence or 0.0), 3),
            "risk": self.risk or "",
            "color": KIND_COLORS.get(self.kind, "#64748b"),
            "risk_color": RISK_COLORS.get(str(self.risk or "").lower(), "#64748b"),
            "metadata": dict(self.metadata or {}),
            "modules": list(self.modules or []),
        }


@dataclass
class ExplorerEdge:
    id: str
    source: str
    target: str
    label: str = ""
    kind: str = ""
    confidence: float = 0.0
    risk: str = ""
    action: str = ""
    abandoned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "label": self.label or self.action or self.kind,
            "kind": self.kind or "",
            "confidence": round(float(self.confidence or 0.0), 3),
            "risk": self.risk or "",
            "action": self.action or "",
            "abandoned": bool(self.abandoned),
        }


@dataclass
class ExplorerPath:
    path_id: str
    nodes: List[str]
    edges: List[str]
    confidence: float
    risk: str
    modules: List[str]
    label: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "label": self.label,
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "confidence": round(float(self.confidence or 0.0), 3),
            "risk": self.risk or "",
            "modules": list(self.modules or []),
        }


@dataclass
class ExplorerGraph:
    workspace: str = ""
    workspace_id: int = 0
    source: str = "merged"
    generated_at: str = ""
    nodes: List[ExplorerNode] = field(default_factory=list)
    edges: List[ExplorerEdge] = field(default_factory=list)
    paths: List[ExplorerPath] = field(default_factory=list)
    next_action: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace": self.workspace,
            "workspace_id": self.workspace_id,
            "source": self.source,
            "generated_at": self.generated_at or _now_iso(),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "paths": [path.to_dict() for path in self.paths],
            "next_action": dict(self.next_action or {}),
            "summary": dict(self.summary or {}),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_id(prefix: str, token: str, limit: int = 120) -> str:
    clean = "".join(ch if ch.isalnum() or ch in "-_:" else "_" for ch in str(token or ""))
    return f"{prefix}:{clean[:limit]}"


def _edge_id(source: str, target: str, label: str = "") -> str:
    return _safe_id("edge", f"{source}->{target}:{label}", 180)


def _merge_nodes(target: ExplorerGraph, nodes: Iterable[ExplorerNode]) -> None:
    seen = {node.id for node in target.nodes}
    for node in nodes:
        if node.id in seen:
            continue
        target.nodes.append(node)
        seen.add(node.id)


def _merge_edges(target: ExplorerGraph, edges: Iterable[ExplorerEdge]) -> None:
    seen = {edge.id for edge in target.edges}
    for edge in edges:
        if edge.id in seen:
            continue
        target.edges.append(edge)
        seen.add(edge.id)


def normalize_campaign_graph(payload: Mapping[str, Any]) -> ExplorerGraph:
    graph = ExplorerGraph(
        workspace=str(payload.get("workspace") or ""),
        workspace_id=int(payload.get("workspace_id") or 0),
        source="campaign",
        generated_at=str(payload.get("generated_at") or _now_iso()),
    )
    host_ids: Dict[str, str] = {}
    nodes_by_id: Dict[str, Dict[str, Any]] = {}

    for raw in payload.get("nodes") or []:
        if isinstance(raw, dict):
            nodes_by_id[str(raw.get("id") or "")] = raw

    for raw in payload.get("nodes") or []:
        if not isinstance(raw, dict):
            continue
        node_id = str(raw.get("id") or "")
        if not node_id:
            continue
        host = str(raw.get("host_address") or "unknown")
        host_key = host_ids.setdefault(host, _safe_id("host", host.lower(), 96))
        if not any(existing.id == host_key for existing in graph.nodes):
            graph.nodes.append(ExplorerNode(
                id=host_key,
                label=host,
                kind="host",
                confidence=1.0,
                metadata={"host_id": raw.get("host_id")},
            ))

        phase = str(raw.get("phase") or "action")
        title = str(raw.get("title") or node_id)
        risk = str(raw.get("risk_level") or "low")
        modules = []
        selected = str(raw.get("selected_module") or "").strip()
        if selected:
            modules.append(selected)
        for candidate in raw.get("candidate_modules") or []:
            if isinstance(candidate, dict):
                path = str(candidate.get("path") or "").strip()
                if path and path not in modules:
                    modules.append(path)

        action_node = ExplorerNode(
            id=_safe_id("action", node_id, 140),
            label=title,
            kind="action" if phase not in {"exploitation", "post_exploitation"} else phase,
            confidence=0.85 if raw.get("scope_allowed", True) else 0.35,
            risk=risk,
            modules=modules,
            metadata={
                "phase": phase,
                "scope_allowed": bool(raw.get("scope_allowed", True)),
                "scope_reason": str(raw.get("scope_reason") or ""),
                "depends_on": list(raw.get("depends_on") or []),
                "attack_techniques": list(raw.get("attack_techniques") or []),
                "framework_commands": list(raw.get("framework_commands") or []),
                "campaign_node_id": node_id,
            },
        )
        graph.nodes.append(action_node)
        graph.edges.append(ExplorerEdge(
            id=_edge_id(host_key, action_node.id, "hosts"),
            source=host_key,
            target=action_node.id,
            label=phase,
            kind="hosts",
            confidence=action_node.confidence,
            risk=risk,
        ))

        service = raw.get("service") if isinstance(raw.get("service"), dict) else None
        if service:
            svc_label = str(service.get("name") or service.get("product") or service.get("port") or "service")
            svc_id = _safe_id("service", f"{host}:{svc_label}", 120)
            graph.nodes.append(ExplorerNode(
                id=svc_id,
                label=svc_label,
                kind="service",
                confidence=0.8,
                metadata=dict(service),
            ))
            graph.edges.append(ExplorerEdge(
                id=_edge_id(host_key, svc_id, "runs"),
                source=host_key,
                target=svc_id,
                label="service",
                kind="runs",
                confidence=0.8,
            ))
            graph.edges.append(ExplorerEdge(
                id=_edge_id(svc_id, action_node.id, "assessed"),
                source=svc_id,
                target=action_node.id,
                label="assessed",
                kind="assessed",
                confidence=action_node.confidence,
                risk=risk,
                action=selected,
            ))

        vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else None
        if vuln:
            vuln_label = str(vuln.get("name") or vuln.get("cve") or "vulnerability")
            vuln_id = _safe_id("vuln", f"{host}:{vuln_label}", 140)
            graph.nodes.append(ExplorerNode(
                id=vuln_id,
                label=vuln_label,
                kind="vulnerability",
                confidence=0.88,
                risk=str(vuln.get("risk_level") or risk),
                metadata=dict(vuln),
                modules=modules,
            ))
            graph.edges.append(ExplorerEdge(
                id=_edge_id(host_key, vuln_id, "has_vuln"),
                source=host_key,
                target=vuln_id,
                label="vulnerability",
                kind="has_vulnerability",
                confidence=0.88,
                risk=str(vuln.get("risk_level") or risk),
            ))
            graph.edges.append(ExplorerEdge(
                id=_edge_id(vuln_id, action_node.id, "validates"),
                source=vuln_id,
                target=action_node.id,
                label="validates",
                kind="validates",
                confidence=action_node.confidence,
                risk=risk,
                action=selected,
            ))

        if phase == "post_exploitation" or "session" in title.lower():
            session_id = _safe_id("session", node_id, 120)
            graph.nodes.append(ExplorerNode(
                id=session_id,
                label=title,
                kind="session",
                confidence=0.92,
                risk=risk,
                modules=modules,
                metadata={"phase": phase},
            ))
            graph.edges.append(ExplorerEdge(
                id=_edge_id(action_node.id, session_id, "opens"),
                source=action_node.id,
                target=session_id,
                label="session",
                kind="opens_session",
                confidence=0.9,
                risk=risk,
            ))

    for raw in payload.get("edges") or []:
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("from") or "")
        target = str(raw.get("to") or "")
        if not source or not target:
            continue
        src_raw = nodes_by_id.get(source, {})
        tgt_raw = nodes_by_id.get(target, {})
        src_action = _safe_id("action", source, 140)
        tgt_action = _safe_id("action", target, 140)
        edge_kind = str(raw.get("type") or "enables")
        graph.edges.append(ExplorerEdge(
            id=_edge_id(src_action, tgt_action, edge_kind),
            source=src_action,
            target=tgt_action,
            label=edge_kind,
            kind=edge_kind,
            confidence=0.75,
            risk=str(tgt_raw.get("risk_level") or src_raw.get("risk_level") or "low"),
            action=str(tgt_raw.get("selected_module") or ""),
        ))

    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    graph.summary = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "source": "campaign",
        "campaign_summary": summary,
    }
    graph.paths = _compute_paths(graph, max_paths=64)
    return graph


def normalize_agent_graph(
    attack_graph: Mapping[str, Any],
    *,
    kb: Optional[Mapping[str, Any]] = None,
) -> ExplorerGraph:
    kb = kb or {}
    graph = ExplorerGraph(
        workspace=str(kb.get("target_hostname") or ""),
        source="agent",
        generated_at=_now_iso(),
    )
    node_ids: Set[str] = set()

    for raw in attack_graph.get("nodes") or []:
        if not isinstance(raw, dict):
            continue
        node_id = str(raw.get("node_id") or raw.get("id") or "")
        if not node_id:
            continue
        kind = str(raw.get("kind") or "node")
        label = str(raw.get("label") or node_id)
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        modules = []
        source_module = str(metadata.get("source_module") or "").strip()
        if source_module:
            modules.append(source_module)
        if kind in {"module", "exploit_path", "finding"}:
            modules.append(label)
        graph.nodes.append(ExplorerNode(
            id=node_id,
            label=label,
            kind=kind,
            confidence=float(raw.get("confidence", 0.0) or 0.0),
            metadata=dict(metadata),
            modules=modules,
        ))
        node_ids.add(node_id)

    for idx, raw in enumerate(attack_graph.get("edges") or []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "")
        target = str(raw.get("target") or raw.get("to") or "")
        if not source or not target:
            continue
        action = str(raw.get("action") or raw.get("relation") or "")
        edge_kind = str(raw.get("relation") or "relates")
        abandoned = bool(raw.get("abandoned_reason"))
        graph.edges.append(ExplorerEdge(
            id=_safe_id("edge", f"{source}->{target}:{idx}", 180),
            source=source,
            target=target,
            label=action or edge_kind,
            kind="action" if action else "relates",
            confidence=float(raw.get("confidence", 0.0) or 0.0),
            risk=str(raw.get("risk") or ""),
            action=action,
            abandoned=abandoned,
        ))

    next_action = kb.get("attack_graph_next_action")
    if isinstance(next_action, dict):
        graph.next_action = dict(next_action)

    graph.paths = _compute_paths(graph, max_paths=64)
    stats = kb.get("attack_graph_stats") if isinstance(kb.get("attack_graph_stats"), dict) else {}
    graph.summary = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "source": "agent",
        "agent_stats": stats,
        "stale_modules": list(kb.get("attack_graph_stale_modules") or [])[:12],
    }
    return graph


def enrich_with_intelligence(
    graph: ExplorerGraph,
    *,
    sessions: Optional[Sequence[Mapping[str, Any]]] = None,
    credentials: Optional[Sequence[Mapping[str, Any]]] = None,
    lateral_proposals: Optional[Sequence[Mapping[str, Any]]] = None,
) -> None:
    host_nodes = [node for node in graph.nodes if node.kind in {"host", "machine"}]
    default_host = host_nodes[0].id if host_nodes else ""

    for row in credentials or []:
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or row.get("authenticated_as") or "").strip()
        if not username:
            continue
        cred_id = _safe_id("credential", username, 96)
        graph.nodes.append(ExplorerNode(
            id=cred_id,
            label=username,
            kind="credential",
            confidence=0.78,
            metadata={
                "origin": str(row.get("origin") or row.get("source_module") or "discovered"),
                "source_host": str(row.get("source_host") or ""),
                "protocol_hint": str(row.get("protocol_hint") or ""),
            },
        ))
        if default_host:
            graph.edges.append(ExplorerEdge(
                id=_edge_id(default_host, cred_id, "credential"),
                source=default_host,
                target=cred_id,
                label="credential",
                kind="has_credential",
                confidence=0.75,
            ))

    for row in sessions or []:
        if not isinstance(row, dict):
            continue
        sid = str(row.get("id") or row.get("session_id") or "")
        host = str(row.get("target_host") or row.get("host") or "")
        if not sid:
            continue
        session_node = _safe_id("session", sid, 96)
        graph.nodes.append(ExplorerNode(
            id=session_node,
            label=f"session {sid}",
            kind="session",
            confidence=0.95,
            metadata={
                "session_type": str(row.get("session_type") or ""),
                "host": host,
                "port": row.get("port"),
            },
        ))
        host_id = _safe_id("host", host.lower(), 96) if host else default_host
        if host_id:
            graph.edges.append(ExplorerEdge(
                id=_edge_id(host_id, session_node, "session"),
                source=host_id,
                target=session_node,
                label="active session",
                kind="has_session",
                confidence=0.95,
            ))

    for row in lateral_proposals or []:
        if not isinstance(row, dict):
            continue
        target_host = str(row.get("target_host") or "")
        target_port = int(row.get("target_port") or 0)
        if not target_host:
            continue
        pivot_id = _safe_id("pivot", f"{target_host}:{target_port}", 120)
        graph.nodes.append(ExplorerNode(
            id=pivot_id,
            label=f"pivot {target_host}:{target_port or '?'}",
            kind="pivot",
            confidence=0.7,
            risk="active",
            modules=[str(row.get("module_hint") or "")] if row.get("module_hint") else [],
            metadata={
                "action": str(row.get("action") or ""),
                "credential_id": str(row.get("credential_id") or ""),
                "in_scope": bool(row.get("in_scope", True)),
                "reason": str(row.get("reason") or ""),
            },
        ))
        source_host = default_host
        for cred in credentials or []:
            if isinstance(cred, dict) and str(cred.get("credential_id") or "") == str(row.get("credential_id") or ""):
                cred_id = _safe_id("credential", str(cred.get("username") or ""), 96)
                source_host = cred_id
                break
        if source_host:
            graph.edges.append(ExplorerEdge(
                id=_edge_id(source_host, pivot_id, "pivot"),
                source=source_host,
                target=pivot_id,
                label="pivot",
                kind="pivot_opportunity",
                confidence=0.68,
                risk="active",
                action=str(row.get("module_hint") or ""),
            ))

    graph.paths = _compute_paths(graph, max_paths=64)


def merge_graphs(*graphs: ExplorerGraph, source: str = "merged") -> ExplorerGraph:
    merged = ExplorerGraph(source=source, generated_at=_now_iso())
    for item in graphs:
        if not item.nodes and not item.edges:
            continue
        if not merged.workspace and item.workspace:
            merged.workspace = item.workspace
        if not merged.workspace_id and item.workspace_id:
            merged.workspace_id = item.workspace_id
        _merge_nodes(merged, item.nodes)
        _merge_edges(merged, item.edges)
        if item.next_action and not merged.next_action:
            merged.next_action = dict(item.next_action)
    merged.paths = _compute_paths(merged, max_paths=64)
    merged.summary = {
        "nodes": len(merged.nodes),
        "edges": len(merged.edges),
        "source": source,
        "kinds": _count_kinds(merged.nodes),
    }
    return merged


def _count_kinds(nodes: Sequence[ExplorerNode]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for node in nodes:
        counts[node.kind] = int(counts.get(node.kind, 0)) + 1
    return counts


def _compute_paths(graph: ExplorerGraph, *, max_paths: int = 64, max_depth: int = 12) -> List[ExplorerPath]:
    if not graph.nodes or not graph.edges:
        return []

    adjacency: Dict[str, List[ExplorerEdge]] = {}
    for edge in graph.edges:
        if edge.abandoned:
            continue
        adjacency.setdefault(edge.source, []).append(edge)

    roots = [node.id for node in graph.nodes if node.kind in {"host", "machine", "ad_domain"}]
    if not roots and graph.nodes:
        roots = [graph.nodes[0].id]

    targets = {
        node.id
        for node in graph.nodes
        if node.kind in {"exploit_path", "finding", "vulnerability", "session", "pivot", "module"}
    }

    paths: List[ExplorerPath] = []
    seen_signatures: Set[str] = set()

    for root in roots[:6]:
        stack: List[Tuple[str, List[str], List[str], List[ExplorerEdge]]] = [(root, [root], [], [])]
        while stack and len(paths) < max_paths:
            current, node_path, edge_path, edge_objs = stack.pop()
            if len(node_path) > max_depth:
                continue
            if current in targets and len(node_path) > 1:
                signature = "->".join(node_path)
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    conf = _path_confidence(edge_objs)
                    risk = _path_risk(edge_objs, graph)
                    modules = _path_modules(edge_objs, graph)
                    paths.append(ExplorerPath(
                        path_id=_safe_id("path", signature, 160),
                        nodes=list(node_path),
                        edges=list(edge_path),
                        confidence=conf,
                        risk=risk,
                        modules=modules,
                        label=_path_label(node_path, graph),
                    ))
            for edge in adjacency.get(current, []):
                if edge.target in node_path:
                    continue
                stack.append((
                    edge.target,
                    node_path + [edge.target],
                    edge_path + [edge.id],
                    edge_objs + [edge],
                ))

    paths.sort(key=lambda item: (-item.confidence, -len(item.nodes)))
    return paths[:max_paths]


def _path_confidence(edges: Sequence[ExplorerEdge]) -> float:
    if not edges:
        return 0.0
    values = [float(edge.confidence or 0.0) for edge in edges if edge.confidence]
    if not values:
        return 0.5
    return sum(values) / len(values)


def _path_risk(edges: Sequence[ExplorerEdge], graph: ExplorerGraph) -> str:
    order = ["info", "low", "read", "medium", "active", "high", "intrusive", "critical", "destructive"]
    best = "low"
    best_idx = -1
    for edge in edges:
        risk = str(edge.risk or "").lower()
        idx = order.index(risk) if risk in order else 1
        if idx > best_idx:
            best_idx = idx
            best = risk or best
    if best_idx < 0:
        for node in graph.nodes:
            if node.risk:
                risk = str(node.risk).lower()
                idx = order.index(risk) if risk in order else 1
                if idx > best_idx:
                    best_idx = idx
                    best = risk
    return best or "low"


def _path_modules(edges: Sequence[ExplorerEdge], graph: ExplorerGraph) -> List[str]:
    modules: List[str] = []
    for edge in edges:
        action = str(edge.action or "").strip()
        if action.startswith(("scanner/", "auxiliary/", "exploit/", "exploits/", "post/")):
            modules.append(action)
    node_lookup = {node.id: node for node in graph.nodes}
    for edge in edges:
        node = node_lookup.get(edge.target)
        if not node:
            continue
        for module in node.modules:
            if module and module not in modules:
                modules.append(module)
    return modules


def _path_label(node_path: Sequence[str], graph: ExplorerGraph) -> str:
    lookup = {node.id: node for node in graph.nodes}
    labels = [lookup[node_id].label for node_id in node_path if node_id in lookup]
    return " → ".join(labels)
