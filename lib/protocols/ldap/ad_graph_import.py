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
        if "group" in joined:
            return "ad_group"
        if "computer" in joined:
            return "ad_computer"
        if "domain" in joined:
            return "ad_domain"
        if "gpo" in joined:
            return "ad_gpo"
        if "ou" in joined:
            return "ad_ou"
    # SharpHound CE typed files often use "type" / meta.type
    kind = str(node.get("kind") or node.get("type") or "").lower()
    meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}
    kind = kind or str(meta.get("type") or "").lower()
    mapping = {
        "user": "ad_user",
        "users": "ad_user",
        "group": "ad_group",
        "groups": "ad_group",
        "computer": "ad_computer",
        "computers": "ad_computer",
        "domain": "ad_domain",
        "domains": "ad_domain",
        "gpo": "ad_gpo",
        "ou": "ad_ou",
    }
    if kind in mapping:
        return mapping[kind]
    return (kind[:32] if kind else "bh_node") or "bh_node"


def load_bloodhound_export(path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Load BloodHound JSON export from a file, directory, or SharpHound zip.

    Accepts:
    - Single JSON array of nodes or edges
    - Combined ``{nodes, edges}`` object
    - Directory with ``nodes.json`` / ``edges.json`` or SharpHound CE files
      (``*_users.json``, ``*_computers.json``, ``*_groups.json``, …)
    - ``.zip`` SharpHound collection archives
    """
    p = Path(str(path or "").strip())
    if not p.exists():
        return [], []

    if p.is_file() and p.suffix.lower() == ".zip":
        return _load_bloodhound_zip(p)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def _extend_rows(target: List[Dict[str, Any]], payload: Any) -> None:
        if isinstance(payload, list):
            target.extend(row for row in payload if isinstance(row, dict))
        elif isinstance(payload, dict):
            if "nodes" in payload or "edges" in payload:
                _extend_rows(nodes, payload.get("nodes"))
                _extend_rows(edges, payload.get("edges"))
            elif "data" in payload and isinstance(payload.get("data"), list):
                # SharpHound CE: { meta, data: [ ... ] }
                _ingest_sharphound_ce(payload, nodes, edges)
            else:
                target.append(payload)

    if p.is_dir():
        for name, bucket in (("nodes.json", nodes), ("edges.json", edges)):
            fpath = p / name
            if fpath.is_file():
                _extend_rows(bucket, json.loads(fpath.read_text(encoding="utf-8", errors="replace")))
        # SharpHound CE dumps in a folder
        for fpath in sorted(p.glob("*.json")):
            if fpath.name.lower() in ("nodes.json", "edges.json"):
                continue
            try:
                payload = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if isinstance(payload, dict) and "data" in payload:
                _ingest_sharphound_ce(payload, nodes, edges)
            else:
                _extend_rows(nodes if "edge" not in fpath.name.lower() else edges, payload)
    else:
        raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(raw, dict) and "data" in raw:
            _ingest_sharphound_ce(raw, nodes, edges)
        elif isinstance(raw, dict) and ("nodes" in raw or "edges" in raw):
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


def _ingest_sharphound_ce(
    payload: Mapping[str, Any],
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> None:
    """Parse SharpHound CE ``{meta, data:[...]}`` into nodes + relationship edges."""
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    type_hint = str(meta.get("type") or payload.get("type") or "").lower()
    data = payload.get("data")
    if not isinstance(data, list):
        return

    for row in data:
        if not isinstance(row, dict):
            continue
        props = row.get("Properties") or row.get("properties") or row
        if not isinstance(props, dict):
            props = {}

        # Classic BloodHound.py sessions.json: {UserSID, ComputerSID} without ObjectIdentifier
        user_sid = str(row.get("UserSID") or props.get("UserSID") or "")
        computer_sid = str(row.get("ComputerSID") or props.get("ComputerSID") or "")
        is_session_row = (
            type_hint in {"session", "sessions"}
            or (user_sid and computer_sid and not (
                row.get("ObjectIdentifier") or row.get("ObjectId") or props.get("objectid")
            ))
        )
        if is_session_row and user_sid and computer_sid:
            # Computer has session of user → computer -> user (pathing toward the principal)
            edges.append({"StartNode": computer_sid, "EndNode": user_sid, "Type": "HasSession"})
            continue

        oid = str(
            row.get("ObjectIdentifier")
            or row.get("ObjectId")
            or row.get("id")
            or props.get("objectid")
            or ""
        )
        if not oid:
            continue
        labels = []
        if type_hint:
            labels.append(type_hint.rstrip("s").title() if type_hint.endswith("s") else type_hint.title())
        # Prefer explicit labels
        if row.get("Labels"):
            labels = list(row.get("Labels") or [])
        node = {
            "ObjectId": oid,
            "Labels": labels or [type_hint or "Node"],
            "Properties": {
                "name": props.get("name") or props.get("samaccountname") or oid,
                "samaccountname": props.get("samaccountname") or props.get("samAccountName"),
                "distinguishedname": props.get("distinguishedname") or props.get("distinguishedName"),
                "domain": props.get("domain"),
                **{k: v for k, v in props.items() if k not in ("name",)},
            },
            "type": type_hint.rstrip("s") if type_hint.endswith("s") else type_hint,
        }
        nodes.append(node)

        # Primary group membership (Domain Users / Domain Computers, etc.)
        primary_group = str(
            row.get("PrimaryGroupSID")
            or props.get("PrimaryGroupSID")
            or props.get("primarygroupsid")
            or ""
        )
        if primary_group and primary_group != oid:
            edges.append({"StartNode": oid, "EndNode": primary_group, "Type": "MemberOf"})

        def _oid_from(value: Any) -> str:
            if isinstance(value, dict):
                return str(
                    value.get("ObjectIdentifier")
                    or value.get("ObjectId")
                    or value.get("UserSID")
                    or value.get("ComputerSID")
                    or value.get("PrincipalSID")
                    or value.get("id")
                    or ""
                )
            return str(value or "")

        # MemberOf / ACL-ish relationships embedded in CE objects
        for rel_key, rel_name in (
            ("MemberOf", "MemberOf"),
            ("Members", "MemberOf"),
            ("AdminTo", "AdminTo"),
            ("CanRDP", "CanRDP"),
            ("CanPSRemote", "CanPSRemote"),
            ("HasSession", "HasSession"),
            ("Sessions", "HasSession"),
            ("AllowedToDelegate", "AllowedToDelegate"),
            ("AllowedToAct", "AllowedToAct"),
            ("ForceChangePassword", "ForceChangePassword"),
            ("AddMember", "AddMember"),
            ("GenericAll", "GenericAll"),
            ("WriteDacl", "WriteDacl"),
            ("Owns", "Owns"),
            ("LocalAdmins", "AdminTo"),
        ):
            rel = row.get(rel_key) or props.get(rel_key)
            if not rel:
                continue
            targets = rel if isinstance(rel, list) else [rel]
            for tgt in targets:
                tgt_oid = _oid_from(tgt)
                if not tgt_oid:
                    continue
                # MemberOf: user -> group. Members/LocalAdmins lists are inverted.
                if rel_key in {"Members", "LocalAdmins"}:
                    edges.append({"StartNode": tgt_oid, "EndNode": oid, "Type": rel_name})
                elif rel_key == "MemberOf":
                    edges.append({"StartNode": oid, "EndNode": tgt_oid, "Type": "MemberOf"})
                elif rel_key in {"Sessions", "HasSession"}:
                    # Computer has session of user → computer -> user (owned host reaches principal)
                    edges.append({"StartNode": oid, "EndNode": tgt_oid, "Type": "HasSession"})
                else:
                    edges.append({"StartNode": oid, "EndNode": tgt_oid, "Type": rel_name})

        # SharpHound CE ACE array: principal with right → this object
        aces = row.get("Aces") or props.get("Aces") or []
        if isinstance(aces, list):
            for ace in aces:
                if not isinstance(ace, dict):
                    continue
                principal = str(
                    ace.get("PrincipalSID")
                    or ace.get("PrincipalId")
                    or ace.get("principal")
                    or ""
                )
                right = str(
                    ace.get("RightName")
                    or ace.get("Right")
                    or ace.get("name")
                    or "GenericAll"
                )[:64]
                if principal and right:
                    edges.append({"StartNode": principal, "EndNode": oid, "Type": right})


def _load_bloodhound_zip(path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    import tempfile
    import zipfile

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            with tempfile.TemporaryDirectory(prefix="ks_bh_") as tmp:
                zf.extractall(tmp)
                n2, e2 = load_bloodhound_export(tmp)
                nodes.extend(n2)
                edges.extend(e2)
    except Exception:
        return [], []
    return nodes, edges


def overlay_bloodhound_graph(
    base_graph: Mapping[str, Any],
    bh_graph: Mapping[str, Any],
) -> Dict[str, Any]:
    """Merge BloodHound attack_graph overlay onto a rebuilt base graph (preserve AD nodes)."""
    merged_nodes = {
        str(n.get("node_id")): dict(n)
        for n in (base_graph.get("nodes") or [])
        if isinstance(n, dict) and n.get("node_id")
    }
    for node in bh_graph.get("nodes") or []:
        if isinstance(node, dict) and node.get("node_id"):
            merged_nodes[str(node["node_id"])] = dict(node)

    merged_edges = [dict(e) for e in (base_graph.get("edges") or []) if isinstance(e, dict)]
    seen = {
        (str(e.get("source")), str(e.get("target")), str(e.get("action")))
        for e in merged_edges
    }
    for edge in bh_graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("action")))
        if key not in seen:
            merged_edges.append(dict(edge))
            seen.add(key)
    return {"nodes": list(merged_nodes.values()), "edges": merged_edges}


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
