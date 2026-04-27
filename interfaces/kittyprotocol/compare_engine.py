#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple


def _flow_key(flow: Dict[str, Any]) -> str:
    raw = "|".join(
        [
            str(flow.get("protocol", "")),
            str(flow.get("client", "")),
            str(flow.get("server", "")),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]


def _host_from_endpoint(value: str) -> str:
    text = str(value or "")
    if text.count(":") > 1 and text.startswith("["):
        # [ipv6]:port
        if "]:" in text:
            return text.split("]:", 1)[0].lstrip("[")
        return text.strip("[]")
    if ":" in text:
        return text.rsplit(":", 1)[0]
    return text


def _endpoint_key(flow: Dict[str, Any]) -> str:
    return "|".join([str(flow.get("client", "")), str(flow.get("server", ""))])


def _pick_richest(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not flows:
        return {}
    return sorted(
        flows,
        key=lambda item: (
            int(item.get("packet_count", 0) or 0),
            int(item.get("risk_score", 0) or 0),
        ),
        reverse=True,
    )[0]


def compare_summaries(flows_a: List[Dict[str, Any]], flows_b: List[Dict[str, Any]]) -> Dict[str, Any]:
    map_a = {_flow_key(f): f for f in flows_a or []}
    map_b = {_flow_key(f): f for f in flows_b or []}
    keys_a: Set[str] = set(map_a.keys())
    keys_b: Set[str] = set(map_b.keys())
    added = [map_b[k] for k in sorted(keys_b - keys_a)]
    removed = [map_a[k] for k in sorted(keys_a - keys_b)]
    common = keys_a & keys_b
    changed = []
    changed_metadata = []
    for key in sorted(common):
        fa, fb = map_a[key], map_b[key]
        if (fa.get("packet_count"), fa.get("risk_score"), fa.get("request_preview")) != (
            fb.get("packet_count"),
            fb.get("risk_score"),
            fb.get("request_preview"),
        ):
            changed.append(
                {
                    "key": key,
                    "before": {
                        "packet_count": fa.get("packet_count"),
                        "risk_score": fa.get("risk_score"),
                        "request_preview": fa.get("request_preview"),
                    },
                    "after": {
                        "packet_count": fb.get("packet_count"),
                        "risk_score": fb.get("risk_score"),
                        "request_preview": fb.get("request_preview"),
                    },
                }
            )
        changed_fields = []
        for field in ("response_preview", "narrative", "request_count", "response_count", "duration_seconds"):
            before = fa.get(field)
            after = fb.get(field)
            if before != after:
                changed_fields.append({"field": field, "before": before, "after": after})
        if changed_fields:
            changed_metadata.append(
                {
                    "key": key,
                    "id": fa.get("id") or fb.get("id"),
                    "client": fa.get("client") or fb.get("client"),
                    "server": fa.get("server") or fb.get("server"),
                    "changed_fields": changed_fields[:12],
                }
            )
    by_endpoint_a: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_endpoint_b: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for flow in flows_a or []:
        by_endpoint_a[_endpoint_key(flow)].append(flow)
    for flow in flows_b or []:
        by_endpoint_b[_endpoint_key(flow)].append(flow)

    changed_protocol = []
    for endpoint in sorted(set(by_endpoint_a.keys()) & set(by_endpoint_b.keys())):
        left = _pick_richest(by_endpoint_a.get(endpoint, []))
        right = _pick_richest(by_endpoint_b.get(endpoint, []))
        p_left = str(left.get("protocol") or "").upper()
        p_right = str(right.get("protocol") or "").upper()
        if p_left and p_right and p_left != p_right:
            changed_protocol.append(
                {
                    "endpoint": endpoint,
                    "client": left.get("client") or right.get("client"),
                    "server": left.get("server") or right.get("server"),
                    "before_protocol": p_left,
                    "after_protocol": p_right,
                    "before_packets": left.get("packet_count", 0),
                    "after_packets": right.get("packet_count", 0),
                }
            )

    servers_by_client_a: Dict[str, Set[str]] = defaultdict(set)
    servers_by_client_b: Dict[str, Set[str]] = defaultdict(set)
    for flow in flows_a or []:
        client = _host_from_endpoint(str(flow.get("client", "")))
        server = _host_from_endpoint(str(flow.get("server", "")))
        if client and server:
            servers_by_client_a[client].add(server)
    for flow in flows_b or []:
        client = _host_from_endpoint(str(flow.get("client", "")))
        server = _host_from_endpoint(str(flow.get("server", "")))
        if client and server:
            servers_by_client_b[client].add(server)

    changed_destination = []
    for client in sorted(set(servers_by_client_a.keys()) & set(servers_by_client_b.keys())):
        before = servers_by_client_a[client]
        after = servers_by_client_b[client]
        added_servers = sorted(after - before)
        removed_servers = sorted(before - after)
        if added_servers or removed_servers:
            changed_destination.append(
                {
                    "client": client,
                    "added_servers": added_servers[:20],
                    "removed_servers": removed_servers[:20],
                }
            )

    return {
        "summary": {
            "flows_a": len(flows_a or []),
            "flows_b": len(flows_b or []),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "changed_protocol": len(changed_protocol),
            "changed_destination": len(changed_destination),
            "changed_metadata": len(changed_metadata),
        },
        "added": [{"id": x.get("id"), "protocol": x.get("protocol"), "client": x.get("client"), "server": x.get("server")} for x in added[:200]],
        "removed": [{"id": x.get("id"), "protocol": x.get("protocol"), "client": x.get("client"), "server": x.get("server")} for x in removed[:200]],
        "changed": changed[:200],
        "changed_protocol": changed_protocol[:200],
        "changed_destination": changed_destination[:200],
        "changed_metadata": changed_metadata[:200],
    }
