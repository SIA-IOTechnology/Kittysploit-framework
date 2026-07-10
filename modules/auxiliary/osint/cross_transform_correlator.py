#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Correlate entities across multiple OSINT transform JSON outputs."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Set, Tuple

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "Cross Transform Correlator",
        "author": ["KittySploit Team"],
        "description": (
            "Ingest JSON outputs from multiple OSINT transforms, correlate shared entities "
            "(domains, IPs, emails, endpoints), score confidence, and suggest next pivots."
        ),
        "tags": ["osint", "correlation", "graph", "meta"],
        "agent": {
            "risk": "passive",
            "effects": ["analysis"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["correlations", "pivot_suggestions"],
        },
    }

    target = OptString("", "Investigation seed (domain, org, or identity)", required=True)
    json_dir = OptString("", "Directory containing OSINT JSON exports to auto-ingest", required=False)
    surface_file = OptString("", "JSON from domain_surface_mapper or web_surface_harvester", required=False)
    search_file = OptString("", "JSON from search_engine_footprint", required=False)
    favicon_file = OptString("", "JSON from favicon_http_fingerprint", required=False)
    openapi_file = OptString("", "JSON from openapi_swagger_finder", required=False)
    js_file = OptString("", "JSON from js_endpoint_extractor", required=False)
    breach_file = OptString("", "JSON from breach_exposure_score", required=False)
    bucket_file = OptString("", "JSON from public_bucket_hunter", required=False)
    identity_file = OptString("", "JSON from identity_handle_hunter", required=False)
    min_confidence = OptString("2", "Minimum source count to emit a correlation edge", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    EMAIL_RX = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
    IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DOMAIN_RX = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
        re.I,
    )
    URL_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)

    PIVOT_SUGGESTIONS = {
        "domain": [
            "auxiliary/osint/web_surface_harvester",
            "auxiliary/osint/search_engine_footprint",
            "auxiliary/osint/favicon_http_fingerprint",
            "auxiliary/osint/openapi_swagger_finder",
            "auxiliary/osint/passive_dns_aggregator",
        ],
        "ip": [
            "auxiliary/osint/ip_geolocation",
            "auxiliary/osint/ip_reverse_dns",
            "auxiliary/osint/favicon_http_fingerprint",
            "auxiliary/osint/asn_network_profile",
        ],
        "email": [
            "auxiliary/osint/breach_exposure_score",
            "auxiliary/osint/identity_handle_hunter",
            "auxiliary/osint/persona_password_profiler",
        ],
        "endpoint": [
            "auxiliary/osint/openapi_swagger_finder",
            "auxiliary/osint/js_endpoint_extractor",
            "auxiliary/osint/url_headers",
        ],
        "bucket": [
            "auxiliary/osint/secret_leak_access_validator",
            "auxiliary/osint/cloud_misconfig_exposure_detector",
        ],
    }

    def _to_int(self, value, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _load_json(self, path: str) -> Dict[str, Any]:
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {"value": data}
        except Exception:
            return {}

    def _load_json_dir(self, directory: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if not directory or not os.path.isdir(directory):
            return rows
        for name in sorted(os.listdir(directory)):
            if not name.lower().endswith(".json"):
                continue
            path = os.path.join(directory, name)
            data = self._load_json(path)
            if data:
                data["_source_file"] = name
                rows.append(data)
        return rows

    def _add_entity(self, store: Dict[str, Dict[str, Set[str]]], kind: str, value: str, source: str):
        value = str(value or "").strip()
        if not value:
            return
        if kind == "domain":
            value = value.lower().strip(".")
        bucket = store.setdefault(kind, {})
        entry = bucket.setdefault(value, set())
        entry.add(source)

    def _walk_strings(self, obj: Any, source: str, store: Dict[str, Dict[str, Set[str]]]):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if str(key).startswith("_"):
                    continue
                self._walk_strings(val, source, store)
            return
        if isinstance(obj, list):
            for item in obj:
                self._walk_strings(item, source, store)
            return
        if not isinstance(obj, str):
            return
        text = obj.strip()
        if not text or len(text) > 500:
            return
        for email in self.EMAIL_RX.findall(text):
            self._add_entity(store, "email", email, source)
        for ip in self.IP_RX.findall(text):
            self._add_entity(store, "ip", ip, source)
        for url in self.URL_RX.findall(text):
            self._add_entity(store, "endpoint", url, source)
            host_match = re.search(r"https?://([^/]+)", url, re.I)
            if host_match:
                host = host_match.group(1).split(":")[0].lower()
                if "." in host and not host.replace(".", "").isdigit():
                    self._add_entity(store, "domain", host, source)
        for domain in self.DOMAIN_RX.findall(text):
            if "@" in domain:
                continue
            self._add_entity(store, "domain", domain, source)

    def _structured_extract(self, label: str, data: Dict[str, Any], store: Dict[str, Dict[str, Set[str]]]):
        self._walk_strings(data, label, store)

        target = data.get("target")
        if target:
            self._add_entity(store, "domain", str(target), label)

        for sub in data.get("subdomains", []) or []:
            self._add_entity(store, "domain", sub, label)
        for ip in (data.get("dns", {}) or {}).get("A", []) or []:
            self._add_entity(store, "ip", ip, label)
        for url in data.get("unique_urls", []) or []:
            self._add_entity(store, "endpoint", url, label)
        for hit in data.get("sensitive_hits", []) or []:
            if isinstance(hit, dict) and hit.get("url"):
                self._add_entity(store, "endpoint", hit["url"], label)
        for exp in data.get("exposures", []) or []:
            if isinstance(exp, dict) and exp.get("url"):
                self._add_entity(store, "endpoint", exp["url"], label)
        for path in data.get("sensitive_api_paths", []) or []:
            self._add_entity(store, "endpoint", path, label)
        findings = data.get("findings", {})
        if isinstance(findings, dict):
            for ep in findings.get("endpoints", []) or []:
                self._add_entity(store, "endpoint", ep, label)
            for dom in findings.get("external_domains", []) or []:
                self._add_entity(store, "domain", dom, label)
        for row in data.get("findings", []) or []:
            if isinstance(row, dict):
                for result in row.get("results", []) or []:
                    if isinstance(result, dict) and result.get("url"):
                        self._add_entity(store, "endpoint", result["url"], label)
        for fav in data.get("favicons", []) or []:
            if isinstance(fav, dict):
                mmh3 = (fav.get("hashes") or {}).get("mmh3")
                if mmh3:
                    self._add_entity(store, "signal", f"favicon_mmh3:{mmh3}", label)
        fp = data.get("http_fingerprint", {})
        if isinstance(fp, dict) and fp.get("fingerprint"):
            self._add_entity(store, "signal", fp["fingerprint"], label)
        for item in data.get("findings", []) if isinstance(data.get("findings"), list) else []:
            if isinstance(item, dict) and item.get("bucket"):
                self._add_entity(store, "bucket", f"{item.get('provider', 'cloud')}:{item['bucket']}", label)

    def _build_correlations(
        self,
        store: Dict[str, Dict[str, Set[str]]],
        min_confidence: int,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_edges: Set[Tuple[str, str]] = set()

        for kind, entities in store.items():
            for value, sources in entities.items():
                confidence = len(sources)
                if confidence < min_confidence:
                    continue
                node_id = f"{kind}_{hash(value) & 0xFFFFFFFF}"
                nodes.append({
                    "id": node_id,
                    "label": value[:100],
                    "group": kind,
                    "confidence": confidence,
                    "sources": sorted(sources),
                })

        node_index = {n["label"]: n for n in nodes}
        labels = list(node_index.keys())
        for i, left in enumerate(labels):
            left_sources = set(node_index[left].get("sources", []))
            for right in labels[i + 1 :]:
                right_sources = set(node_index[right].get("sources", []))
                shared = left_sources.intersection(right_sources)
                if not shared:
                    continue
                pair = tuple(sorted((node_index[left]["id"], node_index[right]["id"])))
                if pair in seen_edges:
                    continue
                seen_edges.add(pair)
                edges.append({
                    "from": pair[0],
                    "to": pair[1],
                    "label": "co_seen",
                    "confidence": len(shared),
                    "sources": sorted(shared),
                })

        return nodes, edges

    def _suggest_pivots(self, store: Dict[str, Dict[str, Set[str]]]) -> List[Dict[str, str]]:
        suggestions: List[Dict[str, str]] = []
        for kind, modules in self.PIVOT_SUGGESTIONS.items():
            count = len(store.get(kind, {}))
            if count <= 0:
                continue
            for module_path in modules[:3]:
                suggestions.append({
                    "entity_type": kind,
                    "module": module_path,
                    "reason": f"{count} correlated {kind} entity(ies) observed across transforms",
                })
        return suggestions[:12]

    def run(self):
        target = str(self.target).strip()
        if not target:
            print_error("target is required")
            return {"error": "target is required"}

        min_confidence = self._to_int(self.min_confidence, 2)
        sources: Dict[str, Dict[str, Any]] = {
            "surface": self._load_json(self.surface_file),
            "search": self._load_json(self.search_file),
            "favicon": self._load_json(self.favicon_file),
            "openapi": self._load_json(self.openapi_file),
            "js": self._load_json(self.js_file),
            "breach": self._load_json(self.breach_file),
            "bucket": self._load_json(self.bucket_file),
            "identity": self._load_json(self.identity_file),
        }

        for idx, row in enumerate(self._load_json_dir(str(self.json_dir or ""))):
            sources[f"dir_{idx}_{row.get('_source_file', 'json')}"] = row

        active = {k: v for k, v in sources.items() if v}
        if not active:
            print_warning("No JSON inputs provided — add json_dir or *_file options")
            return {
                "target": target,
                "error": "no_inputs",
                "hint": "Export transform JSON files or set json_dir to a folder of exports",
            }

        store: Dict[str, Dict[str, Set[str]]] = {}
        for label, payload in active.items():
            self._structured_extract(label, payload, store)

        nodes, edges = self._build_correlations(store, min_confidence)
        suggestions = self._suggest_pivots(store)

        entity_counts = {kind: len(values) for kind, values in store.items()}
        multi_source = sum(
            1 for kind in store.values() for sources in kind.values() if len(sources) >= min_confidence
        )

        result = {
            "target": target,
            "inputs": sorted(active.keys()),
            "entity_counts": entity_counts,
            "multi_source_entities": multi_source,
            "correlation_nodes": nodes,
            "correlation_edges": edges,
            "pivot_suggestions": suggestions,
        }

        print_success(
            f"Correlated {multi_source} entities across {len(active)} input(s) "
            f"— {len(edges)} relationship(s)"
        )
        if suggestions:
            print_info(f"Top pivot: {suggestions[0]['module']}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(result, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return result

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error"):
            return [], []

        target = data.get("target", self.target)
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        for node in data.get("correlation_nodes", [])[:40]:
            nid = node.get("id")
            if not nid:
                continue
            label = node.get("label", nid)
            group = node.get("group", "generic")
            conf = node.get("confidence", 1)
            nodes.append({
                "id": nid,
                "label": f"{label} ({conf} sources)",
                "group": group,
                "icon": "🔗",
            })
            edges.append({"from": target, "to": nid, "label": "correlated"})

        for edge in data.get("correlation_edges", [])[:30]:
            src = edge.get("from")
            dst = edge.get("to")
            if not src or not dst:
                continue
            edges.append({
                "from": src,
                "to": dst,
                "label": edge.get("label", "co_seen"),
                "custom_info": ",".join(edge.get("sources", [])),
            })

        for idx, suggestion in enumerate(data.get("pivot_suggestions", [])[:8]):
            sid = f"pivot_{idx}"
            nodes.append({
                "id": sid,
                "label": suggestion.get("module", "pivot"),
                "group": "generic",
                "icon": "➡️",
                "custom_info": suggestion.get("reason", ""),
            })
            edges.append({
                "from": target,
                "to": sid,
                "label": suggestion.get("entity_type", "next"),
            })

        return nodes, edges
