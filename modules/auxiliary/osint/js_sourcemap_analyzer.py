#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JavaScript source map analyzer — recover decompiled/original sources from .map files.

Fetches bundled .js, resolves ``sourceMappingURL``, downloads .map JSON, and extracts
API endpoints, secrets, and original file paths from ``sourcesContent``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from kittysploit import *
from lib.osint.js_secrets import extract_secret_hints
from lib.osint.js_sourcemap import (
    extract_from_sourcemap,
    parse_sourcemap_json,
    resolve_sourcemap_url,
)
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "JS Source Map Analyzer",
        "author": ["KittySploit Team"],
        "description": (
            "Download client JS bundles, follow sourceMappingURL references, parse .map "
            "files, and extract decompiled sources, API routes, and secret literals."
        ),
        "tags": ["osint", "passive", "web", "javascript", "sourcemap", "webpack"],
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals", "params"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "graphql_endpoint", "from_detail": "graphql_endpoint"},
                    "db_access",
                ],
                "suggested_followups": [
                    "auxiliary/scanner/http/graphql_abuse",
                    "auxiliary/scanner/http/api_fuzzer",
                    "auxiliary/scanner/http/jwt_oauth_probe",
                ],
            },
        },
    }

    target = OptString("", "Target URL or domain", required=True)
    max_js = OptInteger(15, "Maximum JS bundles to analyze", False)
    max_display = OptInteger(25, "Maximum endpoints/secrets to print", False)
    show_details = OptBool(True, "Print recovered endpoints and secret hints", False)
    output_file = OptString("", "Optional JSON output file", False)

    def _print_findings(self, endpoints: List[str], keys: List[Dict[str, str]], source_files: List[str]) -> None:
        limit = max(1, int(self.max_display or 25))
        if bool(self.show_details) and endpoints:
            print_info("-" * 72)
            print_status(f"API / route hints ({min(len(endpoints), limit)} shown)")
            for ep in endpoints[:limit]:
                print_info(f"  {ep}")
            if len(endpoints) > limit:
                print_info(f"  ... and {len(endpoints) - limit} more (use output_file for full dump)")

        if bool(self.show_details) and keys:
            print_info("-" * 72)
            if keys:
                print_warning(f"Credential literals ({len(keys)} match(es))")
                rows = []
                for row in keys[:limit]:
                    name = str(row.get("name") or "secret")
                    value = str(row.get("value") or "")
                    if len(value) > 160:
                        value = value[:160] + "…"
                    source = str(row.get("source") or row.get("from") or "")[:80]
                    rows.append([name, value, source])
                print_table(["Name", "Value", "Source file"], rows)
            else:
                print_info("No credential-like literals after i18n/noise filtering")

        if bool(self.show_details) and source_files:
            print_info("-" * 72)
            print_status(f"Decompiled source paths ({min(len(source_files), limit)} shown)")
            for path in source_files[:limit]:
                print_info(f"  {path}")
            if len(source_files) > limit:
                print_info(f"  ... and {len(source_files) - limit} more")

    def _normalize_base_url(self, value: str) -> Optional[str]:
        v = str(value or "").strip()
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    def _fetch(self, url: str, timeout: int = 12) -> tuple[Optional[int], str, str]:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None, "", url
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        old_target, old_port, old_ssl = self.target, getattr(self, "port", 443), getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = scheme == "https"
            r = self.http_request(method="GET", path=path, allow_redirects=True, timeout=timeout)
            if not r:
                return None, "", url
            return r.status_code, r.text or "", getattr(r, "url", url) or url
        except Exception:
            return None, "", url
        finally:
            self.target, self.port, self.ssl = old_target, old_port, old_ssl

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        urls: Set[str] = set()
        for match in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, flags=re.IGNORECASE):
            abs_url = urljoin(base_url, match.strip())
            if abs_url.startswith(("http://", "https://")) and abs_url.lower().endswith(".js"):
                urls.add(abs_url)
        for match in re.findall(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""", html):
            abs_url = urljoin(base_url, match.strip())
            if abs_url.startswith(("http://", "https://")):
                urls.add(abs_url)
        return sorted(urls)

    def run(self):
        base_url = self._normalize_base_url(self.target)
        if not base_url:
            print_error("target is required")
            return False

        print_status(f"Analyzing JS source maps for {base_url}")
        status, html, final_url = self._fetch(base_url)
        if status is None or not html:
            print_error("Could not fetch target page")
            return False

        js_urls = self._extract_js_urls(html, final_url)[: int(self.max_js or 15)]
        print_info(f"JS bundles to inspect: {len(js_urls)}")

        maps_found: List[Dict[str, Any]] = []
        all_endpoints: Set[str] = set()
        all_keys: List[Dict[str, str]] = []
        source_files: Set[str] = set()
        graphql_endpoint = ""

        for js_url in js_urls:
            st, js_body, fetched_js = self._fetch(js_url)
            if st is None or not js_body:
                continue
            map_ref = resolve_sourcemap_url(js_body, fetched_js)
            if not map_ref:
                continue
            print_info(f"  sourceMappingURL: {map_ref[:120]}")

            smap = None
            map_fetched = map_ref
            if map_ref.startswith("data:"):
                from lib.osint.js_sourcemap import decode_data_sourcemap
                smap = decode_data_sourcemap(map_ref)
            else:
                map_url = urljoin(fetched_js, map_ref)
                mst, map_body, map_fetched = self._fetch(map_url)
                if mst and map_body:
                    smap = parse_sourcemap_json(map_body)
            if not smap:
                print_warning(f"  Could not parse map for {fetched_js}")
                continue

            extracted = extract_from_sourcemap(smap, js_url=fetched_js)
            extracted["map_url"] = map_fetched
            maps_found.append(extracted)
            for ep in extracted.get("endpoints") or []:
                all_endpoints.add(str(ep))
                if "graphql" in str(ep).lower() and not graphql_endpoint:
                    graphql_endpoint = str(ep).split("?", 1)[0]
            for row in extracted.get("key_hints") or []:
                if isinstance(row, dict):
                    all_keys.append(row)
            for row in extracted.get("recovered_sources") or []:
                if isinstance(row, dict) and row.get("source"):
                    source_files.add(str(row["source"]))

            print_success(
                f"  map OK: {extracted.get('source_count', 0)} sources, "
                f"{len(extracted.get('endpoints') or [])} endpoints, "
                f"{sum(1 for r in extracted.get('recovered_sources') or [] if r.get('has_content'))} decompiled"
            )

        if not maps_found:
            print_warning("No source maps recovered — bundles may be unmapped or blocked")
            self.vulnerability_info = {"reason": "No source maps found", "js_checked": len(js_urls)}
            return False

        findings = {
            "endpoints": sorted(all_endpoints)[:200],
            "key_hints": all_keys[:100],
            "source_files": sorted(source_files)[:120],
            "maps": maps_found,
            "graphql_endpoint": graphql_endpoint,
        }
        self.vulnerability_info = {
            "reason": (
                f"Recovered {len(maps_found)} source map(s), {len(source_files)} source file(s), "
                f"{len(all_endpoints)} endpoints, {len(all_keys)} secret hint(s)"
            ),
            "findings": findings,
            "map_count": len(maps_found),
            "decompiled_sources": sum(
                1 for m in maps_found for r in (m.get("recovered_sources") or []) if r.get("has_content")
            ),
            "graphql_endpoint": graphql_endpoint,
        }

        print_success(
            f"Source maps: {len(maps_found)} | decompiled files: {self.vulnerability_info['decompiled_sources']} | "
            f"endpoints: {len(all_endpoints)} | secrets: {len(all_keys)}"
        )
        self._print_findings(
            sorted(all_endpoints),
            all_keys,
            sorted(source_files),
        )
        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as fp:
                    json.dump(self.vulnerability_info, fp, indent=2)
            except Exception as exc:
                print_warning(f"Could not write output: {exc}")
        return True
