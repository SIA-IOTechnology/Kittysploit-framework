#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Favicon and HTTP fingerprint pivoting for host correlation."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from kittysploit import *
from lib.osint.favicon_hash import favicon_hashes
from lib.osint.web_surface import (
    discover_favicon_urls,
    extract_html_title,
    fetch_with_https_fallback,
    normalize_base_url,
    normalize_domain,
)
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Favicon HTTP Fingerprint",
        "author": ["KittySploit Team"],
        "description": (
            "Collect favicon hashes (Shodan-compatible MurmurHash3) and HTTP fingerprints "
            "(Server, powered-by, title) for host correlation and shadow-asset discovery."
        ),
        "tags": ["osint", "passive", "fingerprint", "favicon", "http"],
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "Target domain, IP, or URL", required=True)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _header_fingerprint(self, headers: Dict[str, str], title: str, status_code: Optional[int]) -> Dict[str, Any]:
        keys = (
            "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
            "Via", "X-Frame-Options", "Content-Security-Policy",
            "Strict-Transport-Security", "Set-Cookie",
        )
        picked = {}
        for key in keys:
            for hk, hv in (headers or {}).items():
                if hk.lower() == key.lower():
                    picked[key] = hv
                    break
        parts = [f"status:{status_code or 'unknown'}"]
        if picked.get("Server"):
            parts.append(f"server:{picked['Server']}")
        if picked.get("X-Powered-By"):
            parts.append(f"powered:{picked['X-Powered-By']}")
        if title:
            parts.append(f"title:{title[:60]}")
        return {
            "headers": picked,
            "title": title,
            "fingerprint": "|".join(parts),
        }

    def _fetch_favicon(self, favicon_url: str, timeout: float) -> Dict[str, Any]:
        resp, final_url, transport = fetch_with_https_fallback(self, favicon_url, timeout)
        if not resp or resp.status_code != 200:
            return {"url": favicon_url, "found": False}
        content = resp.content or b""
        if len(content) < 8:
            return {"url": final_url, "found": False}
        hashes = favicon_hashes(content)
        return {
            "url": final_url,
            "found": True,
            "size": len(content),
            "content_type": resp.headers.get("Content-Type", ""),
            "transport": transport,
            "hashes": hashes,
        }

    def run(self):
        domain = normalize_domain(self.target)
        base_url = normalize_base_url(self.target)
        if not base_url:
            host = str(self.target).strip()
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                base_url = f"http://{host}"
                domain = host
            else:
                print_error("target must be a domain, IP, or URL")
                return {"error": "invalid target"}

        timeout = float(self._to_int(self.timeout, 12))
        print_info(f"Fingerprinting {base_url}")

        home_resp, final_url, transport = fetch_with_https_fallback(self, base_url, timeout)
        if not home_resp:
            print_error("HTTP request failed")
            return {"error": "request_failed", "target": domain or base_url}

        html = home_resp.text or ""
        title = extract_html_title(html)
        http_fp = self._header_fingerprint(
            dict(home_resp.headers),
            title,
            home_resp.status_code,
        )

        favicon_results: List[Dict[str, Any]] = []
        for fav_url in discover_favicon_urls(html, final_url):
            fav = self._fetch_favicon(fav_url, timeout)
            if fav.get("found"):
                favicon_results.append(fav)
                break
        if not favicon_results:
            fav = self._fetch_favicon(f"{final_url.rstrip('/')}/favicon.ico", timeout)
            if fav.get("found"):
                favicon_results.append(fav)

        primary_hash = ""
        if favicon_results:
            primary_hash = favicon_results[0].get("hashes", {}).get("mmh3", "")

        result = {
            "target": domain or base_url,
            "url": final_url,
            "transport": transport,
            "status_code": home_resp.status_code,
            "http_fingerprint": http_fp,
            "favicons": favicon_results,
            "primary_favicon_mmh3": primary_hash,
            "pivot_hints": {
                "shodan_query": f'http.favicon.hash:{primary_hash}' if primary_hash else "",
                "title": title,
            },
        }

        print_success(
            f"Fingerprint ready — favicon_mmh3={primary_hash or 'n/a'} "
            f"server={http_fp.get('headers', {}).get('Server', 'n/a')}"
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

        fp = data.get("http_fingerprint", {})
        if fp.get("fingerprint"):
            nid = f"httpfp_{hash(fp['fingerprint']) & 0xFFFFFFFF}"
            nodes.append({"id": nid, "label": fp["fingerprint"][:100], "group": "technology", "icon": "🧬"})
            edges.append({"from": target, "to": nid, "label": "http_fp"})

        if fp.get("title"):
            tid = f"title_{hash(fp['title']) & 0xFFFFFFFF}"
            nodes.append({"id": tid, "label": fp["title"][:80], "group": "generic", "icon": "📄"})
            edges.append({"from": target, "to": tid, "label": "title"})

        for fav in data.get("favicons", [])[:2]:
            hashes = fav.get("hashes", {})
            mmh3 = hashes.get("mmh3")
            if not mmh3:
                continue
            fid = f"fav_{mmh3}"
            nodes.append({
                "id": fid,
                "label": f"favicon mmh3:{mmh3}",
                "group": "technology",
                "icon": "🎯",
                "custom_info": fav.get("url", ""),
            })
            edges.append({"from": target, "to": fid, "label": "favicon"})

        shodan_q = data.get("pivot_hints", {}).get("shodan_query")
        if shodan_q:
            sid = f"shodan_{hash(shodan_q) & 0xFFFFFFFF}"
            nodes.append({"id": sid, "label": shodan_q, "group": "generic", "icon": "🔍"})
            edges.append({"from": target, "to": sid, "label": "pivot"})

        return nodes, edges
