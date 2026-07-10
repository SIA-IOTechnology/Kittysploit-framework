#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse WHOIS pivot by organization, email, or registrant string."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from kittysploit import *
from lib.osint.reverse_whois import reverse_whois_hackertarget, reverse_whois_rdap_org_hint
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Reverse WHOIS Org Mapper",
        "description": (
            "Find related domains from a registrant organization/email string using "
            "passive reverse WHOIS sources."
        ),
        "author": ["KittySploit Team"],
        "tags": ["osint", "passive", "whois", "reverse-whois", "domain"],
        "agent": {
            "risk": "passive",
            "effects": ["osint_lookup"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["subdomains", "endpoints"],
        },
    }

    query = OptString("", "Organization, email, or registrant string", required=True)
    query_type = OptChoice(
        "org",
        "Query style",
        required=True,
        choices=["org", "email", "keyword"],
    )
    include_rdap_hint = OptBool(True, "Fetch RDAP entity metadata for org queries", required=False)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
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
        q = str(self.query or "").strip()
        if not q:
            print_error("Query is required")
            return {"error": "missing_query"}
        try:
            timeout = max(3, int(str(self.timeout or "12").strip()))
        except Exception:
            timeout = 12

        search_term = q
        if str(self.query_type) == "email" and "@" not in q:
            search_term = q
        print_info(f"Reverse WHOIS lookup: {search_term}")

        data = reverse_whois_hackertarget(search_term, self._http_get_url, timeout=float(timeout))
        if data.get("error") == "rate_limited":
            print_warning("Reverse WHOIS source rate-limited — try again later")
        elif data.get("error"):
            print_info(str(data.get("error")))

        domains = data.get("domains") or []
        if domains:
            print_success(f"Related domains found: {len(domains)}")
            for domain in domains[:15]:
                print_info(domain)
            if len(domains) > 15:
                print_info(f"... +{len(domains) - 15} more")
        else:
            print_info("No related domains returned from reverse WHOIS source")

        if self.include_rdap_hint and str(self.query_type) == "org":
            hint = reverse_whois_rdap_org_hint(search_term, self._http_get_url, timeout=float(timeout))
            data["rdap_hint"] = hint

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error") == "missing_query":
            return [], []
        root = str(self.query or "query")
        nodes, edges = [], []
        for domain in (data.get("domains") or [])[:20]:
            nid = f"rev_{domain}"
            nodes.append({"id": nid, "label": domain, "group": "domain", "icon": "🌐"})
            edges.append({"from": root, "to": nid, "label": "reverse-whois"})
        return nodes, edges
