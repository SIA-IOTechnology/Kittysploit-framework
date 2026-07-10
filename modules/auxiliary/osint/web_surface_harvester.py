#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Harvest security.txt, robots.txt, and sitemap.xml from a target domain."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from urllib.parse import urljoin

from kittysploit import *
from lib.osint.web_surface import (
    fetch_with_https_fallback,
    normalize_base_url,
    normalize_domain,
    parse_robots_txt,
    parse_security_txt,
    parse_sitemap_urls,
)
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Web Surface Harvester",
        "author": ["KittySploit Team"],
        "description": (
            "Passive harvest of security.txt, robots.txt, and sitemap.xml — contacts, "
            "disallowed paths, and public URL inventory."
        ),
        "tags": ["osint", "passive", "web", "surface", "security.txt"],
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "contacts", "paths"],
        },
    }

    target = OptString("", "Target domain or URL (e.g. example.com)", required=True)
    fetch_sitemaps = OptBool(True, "Follow sitemap URLs discovered in robots.txt", required=False)
    max_sitemap_urls = OptString("150", "Maximum URLs to extract from sitemaps", required=False)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    RESOURCE_PATHS = (
        ("/.well-known/security.txt", "security_txt"),
        ("/security.txt", "security_txt"),
        ("/robots.txt", "robots_txt"),
        ("/sitemap.xml", "sitemap_xml"),
        ("/sitemap_index.xml", "sitemap_xml"),
    )

    def _to_int(self, value, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _fetch_resource(self, base_url: str, path: str, timeout: float) -> Dict[str, Any]:
        url = urljoin(base_url + "/", path.lstrip("/"))
        resp, final_url, transport = fetch_with_https_fallback(self, url, timeout)
        if not resp:
            return {"url": url, "found": False, "status_code": None, "transport": transport}
        body = resp.text or ""
        return {
            "url": final_url,
            "found": resp.status_code == 200 and len(body.strip()) > 0,
            "status_code": resp.status_code,
            "transport": transport,
            "body_preview": body[:4000],
            "body_length": len(body),
        }

    def _interesting_paths(self, robots: Dict[str, Any]) -> List[str]:
        keywords = (
            "admin", "api", "backup", "config", "internal", "private",
            "staging", "dev", "login", "auth", "secret", ".env", ".git",
        )
        paths: List[str] = []
        for path in robots.get("disallow", []):
            low = path.lower()
            if any(k in low for k in keywords):
                paths.append(path)
        return paths[:40]

    def run(self):
        domain = normalize_domain(self.target)
        base_url = normalize_base_url(self.target)
        if not domain or not base_url:
            print_error("target must be a valid domain or URL")
            return {"error": "invalid domain target"}

        timeout = float(self._to_int(self.timeout, 12))
        max_urls = self._to_int(self.max_sitemap_urls, 150)

        print_info(f"Harvesting web surface files for {domain}")
        result: Dict[str, Any] = {
            "target": domain,
            "base_url": base_url,
            "resources": {},
            "security_txt": {},
            "robots": {},
            "sitemap_urls": [],
            "interesting_disallow_paths": [],
            "contacts": [],
        }

        seen_paths = set()
        for path, key in self.RESOURCE_PATHS:
            if key in seen_paths and key != "security_txt":
                continue
            data = self._fetch_resource(base_url, path, timeout)
            if data.get("found"):
                seen_paths.add(key)
            result["resources"][path] = data

        sec_body = ""
        for path, data in result["resources"].items():
            if "security" in path and data.get("found"):
                sec_body = data.get("body_preview") or ""
                break
        if sec_body:
            parsed = parse_security_txt(sec_body)
            result["security_txt"] = parsed
            result["contacts"] = list(dict.fromkeys(parsed.get("contact", [])))
            print_success(f"security.txt contacts: {len(result['contacts'])}")

        robots_body = ""
        for path, data in result["resources"].items():
            if path.endswith("robots.txt") and data.get("found"):
                robots_body = data.get("body_preview") or ""
                break
        if robots_body:
            robots = parse_robots_txt(robots_body)
            result["robots"] = robots
            result["interesting_disallow_paths"] = self._interesting_paths(robots)
            print_success(
                f"robots.txt: disallow={len(robots.get('disallow', []))} "
                f"sitemaps={len(robots.get('sitemaps', []))}"
            )

        sitemap_candidates: List[str] = []
        for path, data in result["resources"].items():
            if "sitemap" in path and data.get("found"):
                sitemap_candidates.append(data.get("url") or urljoin(base_url, path))
        sitemap_candidates.extend(result.get("robots", {}).get("sitemaps", []))
        sitemap_candidates = list(dict.fromkeys(sitemap_candidates))

        all_urls: List[str] = []
        if self.fetch_sitemaps:
            for sm_url in sitemap_candidates[:5]:
                resp, _, _ = fetch_with_https_fallback(self, sm_url, timeout)
                if not resp or resp.status_code != 200:
                    continue
                urls = parse_sitemap_urls(resp.text or "", base_url, limit=max_urls)
                all_urls.extend(urls)
                if any(u.endswith(".xml") for u in urls[:3]):
                    for child in urls[:3]:
                        if not child.lower().endswith(".xml"):
                            continue
                        child_resp, _, _ = fetch_with_https_fallback(self, child, timeout)
                        if child_resp and child_resp.status_code == 200:
                            all_urls.extend(
                                parse_sitemap_urls(child_resp.text or "", base_url, limit=max_urls)
                            )
        result["sitemap_urls"] = list(dict.fromkeys(all_urls))[:max_urls]
        if result["sitemap_urls"]:
            print_success(f"Sitemap URLs collected: {len(result['sitemap_urls'])}")

        sensitive_urls = [
            u for u in result["sitemap_urls"]
            if re.search(r"(admin|api|login|backup|config|\.env|\.git|internal|staging)", u, re.I)
        ]
        result["sensitive_sitemap_urls"] = sensitive_urls[:30]

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

        for contact in data.get("contacts", [])[:12]:
            cid = f"sec_contact_{hash(contact) & 0xFFFFFFFF}"
            nodes.append({"id": cid, "label": contact[:80], "group": "email", "icon": "📧"})
            edges.append({"from": target, "to": cid, "label": "security_contact"})

        for path in data.get("interesting_disallow_paths", [])[:15]:
            pid = f"robots_{hash(path) & 0xFFFFFFFF}"
            nodes.append({"id": pid, "label": path[:80], "group": "endpoint", "icon": "🚫"})
            edges.append({"from": target, "to": pid, "label": "disallow"})

        for url in data.get("sensitive_sitemap_urls", [])[:15]:
            uid = f"smap_{hash(url) & 0xFFFFFFFF}"
            nodes.append({"id": uid, "label": url[:90], "group": "endpoint", "icon": "🗺️"})
            edges.append({"from": target, "to": uid, "label": "sitemap"})

        if data.get("security_txt", {}).get("policy"):
            pid = f"policy_{target}"
            nodes.append({"id": pid, "label": "security policy", "group": "generic", "icon": "📜"})
            edges.append({"from": target, "to": pid, "label": "policy"})

        return nodes, edges
