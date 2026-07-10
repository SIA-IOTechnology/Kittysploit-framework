#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Passive search-engine footprinting via HTML search results."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Set
from urllib.parse import parse_qs, unquote, urlparse

from bs4 import BeautifulSoup
from kittysploit import *
from lib.osint.web_surface import normalize_domain
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Search Engine Footprint",
        "author": ["KittySploit Team"],
        "description": (
            "Run passive search-engine dorks (site:, filetype:, inurl:) and collect "
            "indexed URLs, titles, and sensitive path hints."
        ),
        "tags": ["osint", "passive", "search", "dork", "footprint"],
        "agent": {
            "risk": "passive",
            "effects": ["osint_lookup"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "risk_signals"],
        },
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    max_results_per_query = OptString("8", "Maximum results to keep per dork query", required=False)
    timeout = OptString("15", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    DORK_TEMPLATES = (
        ("site:{domain}", "indexed_pages"),
        ("site:{domain} filetype:pdf", "pdf_documents"),
        ("site:{domain} inurl:admin", "admin_paths"),
        ("site:{domain} inurl:api", "api_paths"),
        ("site:{domain} (password OR secret OR token OR apikey)", "credential_hints"),
        ("site:{domain} (ext:env OR ext:bak OR ext:sql OR ext:log)", "sensitive_extensions"),
        ("site:{domain} inurl:login OR inurl:signin", "auth_pages"),
    )

    SENSITIVE_RX = re.compile(
        r"(admin|backup|config|\.env|\.git|password|secret|token|api[_-]?key|internal|staging)",
        re.I,
    )

    def _to_int(self, value, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _extract_ddg_url(self, href: str) -> str:
        if not href:
            return ""
        if href.startswith("//"):
            href = "https:" + href
        if "uddg=" in href:
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            uddg = qs.get("uddg", [""])[0]
            return unquote(uddg)
        return href

    def _parse_ddg_results(self, html: str, domain: str, limit: int) -> List[Dict[str, str]]:
        soup = BeautifulSoup(html or "", "html.parser")
        rows: List[Dict[str, str]] = []
        seen: Set[str] = set()

        for result in soup.select("div.result, div.web-result, div.links_main"):
            link = result.select_one("a.result__a, a.result-link, h2 a")
            if not link:
                continue
            href = self._extract_ddg_url(link.get("href") or "")
            if not href or domain not in href.lower():
                continue
            if href in seen:
                continue
            seen.add(href)
            snippet_el = result.select_one("a.result__snippet, div.result__snippet, td.result__snippet")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            rows.append({
                "url": href,
                "title": (link.get_text(" ", strip=True) or href)[:200],
                "snippet": snippet[:300],
            })
            if len(rows) >= limit:
                break
        return rows

    def _search_dork(self, query: str, domain: str, timeout: float, limit: int) -> List[Dict[str, str]]:
        parsed_host = "html.duckduckgo.com"
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = parsed_host
            self.port = 443
            self.ssl = True
            post_resp = self.http_request(
                method="POST",
                path="/html/",
                data={"q": query, "b": "", "kl": ""},
                allow_redirects=True,
                timeout=timeout,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            post_resp = None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

        if not post_resp or post_resp.status_code != 200:
            return []
        return self._parse_ddg_results(post_resp.text or "", domain, limit)

    def run(self):
        domain = normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid domain target"}

        timeout = float(self._to_int(self.timeout, 15))
        per_query = self._to_int(self.max_results_per_query, 8)

        print_info(f"Search engine footprint for {domain}")
        findings: List[Dict[str, Any]] = []
        all_urls: Set[str] = set()
        sensitive: List[Dict[str, str]] = []

        for template, category in self.DORK_TEMPLATES:
            query = template.format(domain=domain)
            print_status(f"Dork: {query}")
            results = self._search_dork(query, domain, timeout, per_query)
            findings.append({"query": query, "category": category, "results": results, "count": len(results)})
            for row in results:
                url = row.get("url", "")
                if url:
                    all_urls.add(url)
                blob = f"{row.get('title', '')} {row.get('snippet', '')} {url}"
                if self.SENSITIVE_RX.search(blob):
                    sensitive.append({"url": url, "category": category, "title": row.get("title", "")})

        result = {
            "target": domain,
            "findings": findings,
            "unique_urls": sorted(all_urls),
            "sensitive_hits": sensitive[:40],
            "stats": {
                "queries": len(findings),
                "unique_urls": len(all_urls),
                "sensitive_hits": len(sensitive),
            },
        }

        print_success(
            f"Footprint complete: {len(all_urls)} unique URLs, {len(sensitive)} sensitive hits"
        )

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

        for hit in data.get("sensitive_hits", [])[:20]:
            url = hit.get("url") or ""
            if not url:
                continue
            nid = f"se_{hash(url) & 0xFFFFFFFF}"
            label = hit.get("title") or url
            nodes.append({
                "id": nid,
                "label": label[:90],
                "group": "endpoint",
                "icon": "🔎",
                "custom_info": url,
            })
            edges.append({"from": target, "to": nid, "label": hit.get("category", "search")})

        for url in data.get("unique_urls", [])[:12]:
            if any(url == h.get("url") for h in data.get("sensitive_hits", [])):
                continue
            nid = f"se_url_{hash(url) & 0xFFFFFFFF}"
            nodes.append({"id": nid, "label": url[:90], "group": "endpoint", "icon": "🔗"})
            edges.append({"from": target, "to": nid, "label": "indexed"})

        return nodes, edges
