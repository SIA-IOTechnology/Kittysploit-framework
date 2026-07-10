#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate passive subdomain sources (CT + permutations) with optional DNS resolution."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from kittysploit import *
from lib.osint.passive_dns import aggregate_passive_dns
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Passive DNS Aggregator",
        "description": (
            "Aggregate subdomains from certificate transparency and built-in "
            "permutations, with optional A-record resolution."
        ),
        "author": ["KittySploit Team"],
        "tags": ["osint", "passive", "dns", "subdomains", "ct"],
        "agent": {
            "risk": "passive",
            "effects": ["osint_lookup"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["subdomains", "endpoints"],
        },
    }

    target = OptString("", "Root domain (e.g. example.com)", required=True)
    include_ct = OptBool(True, "Include certificate transparency (crt.sh)", required=False)
    include_permutations = OptBool(True, "Include built-in subdomain permutations", required=False)
    resolve_a = OptBool(False, "Resolve A records for discovered hosts", required=False)
    max_resolve = OptInteger(40, "Maximum hosts to resolve when resolve_a is enabled", required=False)
    timeout = OptString("10", "HTTP/DNS timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _http_get_url(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = scheme == "https"
            return self.http_request(method="GET", path=path, allow_redirects=True, timeout=timeout_seconds)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def run(self):
        try:
            timeout = max(3, int(str(self.timeout or "10").strip()))
        except Exception:
            timeout = 10

        data = aggregate_passive_dns(
            str(self.target or ""),
            http_get=self._http_get_url,
            include_ct=bool(self.include_ct),
            include_permutations=bool(self.include_permutations),
            resolve_a=bool(self.resolve_a),
            max_resolve=int(self.max_resolve or 40),
            timeout=float(timeout),
        )
        if data.get("error"):
            print_error(str(data["error"]))
            return data

        ct_count = len(data.get("sources", {}).get("certificate_transparency", []))
        perm_count = len(data.get("sources", {}).get("permutations", []))
        print_success(
            f"Aggregated {data.get('count', 0)} host(s) — CT={ct_count} permutations={perm_count}"
        )
        if data.get("resolved_count"):
            print_info(f"Resolved live hosts: {data['resolved_count']}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error"):
            return [], []
        root = data.get("target", self.target)
        nodes, edges = [], []
        for host in data.get("subdomains", [])[:20]:
            nid = f"host_{host}"
            nodes.append({"id": nid, "label": host, "group": "subdomain", "icon": "🌐"})
            edges.append({"from": root, "to": nid, "label": "passive"})
        return nodes, edges
