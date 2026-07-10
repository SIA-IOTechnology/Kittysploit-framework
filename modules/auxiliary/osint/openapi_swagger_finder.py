#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discover exposed OpenAPI and Swagger documentation endpoints."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

from kittysploit import *
from lib.osint.web_surface import fetch_with_https_fallback, normalize_base_url, normalize_domain
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "OpenAPI Swagger Finder",
        "author": ["KittySploit Team"],
        "description": (
            "Probe common OpenAPI/Swagger paths and validate exposed API specifications "
            "for version, title, and sensitive endpoint inventory."
        ),
        "tags": ["osint", "passive", "api", "swagger", "openapi"],
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "risk_signals", "params"],
            "chain": {
                "produces_capabilities": ["openapi_spec"],
                "suggested_followups": [
                    "auxiliary/scanner/http/api_fuzzer",
                    "auxiliary/osint/js_endpoint_extractor",
                ],
            },
        },
    }

    target = OptString("", "Target domain or URL", required=True)
    max_paths = OptString("24", "Maximum candidate paths to probe", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    CANDIDATE_PATHS = (
        "/swagger-ui.html",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger/v2/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/api-docs",
        "/api-docs/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v3/api-docs/swagger-config",
        "/docs",
        "/redoc",
        "/.well-known/openapi.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/v1/openapi.json",
        "/api/v2/openapi.json",
        "/api/v3/openapi.json",
        "/graphql",
        "/graphiql",
    )

    OPENAPI_MARKERS = (
        '"openapi"',
        '"swagger"',
        "swaggerui",
        "openapi",
        "paths",
        "info",
    )

    SENSITIVE_PATH_RX = re.compile(
        r"(admin|internal|debug|token|secret|password|upload|exec|shell|config|backup)",
        re.I,
    )

    def _to_int(self, value, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _looks_like_openapi(self, body: str, content_type: str) -> bool:
        text = (body or "")[:12000].lower()
        ctype = (content_type or "").lower()
        if "json" in ctype or "yaml" in ctype or "html" in ctype:
            hits = sum(1 for marker in self.OPENAPI_MARKERS if marker in text)
            return hits >= 2
        return False

    def _parse_openapi_summary(self, body: str) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"title": "", "version": "", "paths": [], "sensitive_paths": []}
        try:
            data = json.loads(body)
        except Exception:
            title = re.search(r"title:\s*([^\n]+)", body or "", re.I)
            version = re.search(r"version:\s*([^\n]+)", body or "", re.I)
            if title:
                summary["title"] = title.group(1).strip().strip('"')
            if version:
                summary["version"] = version.group(1).strip().strip('"')
            return summary

        if not isinstance(data, dict):
            return summary
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        summary["title"] = str(info.get("title") or "")
        summary["version"] = str(info.get("version") or data.get("openapi") or data.get("swagger") or "")
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            path_list = list(paths.keys())[:80]
            summary["paths"] = path_list
            summary["sensitive_paths"] = [p for p in path_list if self.SENSITIVE_PATH_RX.search(p)][:25]
        return summary

    def _probe_path(self, base_url: str, path: str, timeout: float) -> Dict[str, Any]:
        url = urljoin(base_url + "/", path.lstrip("/"))
        resp, final_url, transport = fetch_with_https_fallback(self, url, timeout)
        if not resp:
            return {"url": url, "found": False, "status_code": None}
        body = resp.text or ""
        content_type = resp.headers.get("Content-Type", "")
        found = False
        if resp.status_code in (200, 401, 403):
            if self._looks_like_openapi(body, content_type):
                found = True
            elif resp.status_code == 200 and any(
                token in path.lower()
                for token in ("swagger", "openapi", "api-docs", "redoc", "graphiql")
            ):
                found = True
        row = {
            "url": final_url,
            "path": path,
            "found": found,
            "status_code": resp.status_code,
            "transport": transport,
            "content_type": content_type,
        }
        if found and body:
            row["summary"] = self._parse_openapi_summary(body)
        return row

    def run(self):
        domain = normalize_domain(self.target)
        base_url = normalize_base_url(self.target)
        if not domain or not base_url:
            print_error("target must be a valid domain or URL")
            return {"error": "invalid domain target"}

        timeout = float(self._to_int(self.timeout, 10))
        max_paths = self._to_int(self.max_paths, 24)

        print_info(f"Probing OpenAPI/Swagger paths on {domain}")
        exposures: List[Dict[str, Any]] = []
        all_paths: Set[str] = set()
        sensitive_paths: Set[str] = set()

        for path in self.CANDIDATE_PATHS[:max_paths]:
            row = self._probe_path(base_url, path, timeout)
            if row.get("found"):
                exposures.append(row)
                summary = row.get("summary") or {}
                for p in summary.get("paths", []):
                    all_paths.add(p)
                for p in summary.get("sensitive_paths", []):
                    sensitive_paths.add(p)
                print_success(f"Exposed: {row.get('url')} (HTTP {row.get('status_code')})")

        result = {
            "target": domain,
            "base_url": base_url,
            "exposures": exposures,
            "api_paths": sorted(all_paths)[:120],
            "sensitive_api_paths": sorted(sensitive_paths)[:40],
            "stats": {
                "candidates_tested": min(len(self.CANDIDATE_PATHS), max_paths),
                "exposures_found": len(exposures),
                "api_paths": len(all_paths),
                "sensitive_paths": len(sensitive_paths),
            },
        }

        if not exposures:
            print_warning("No exposed OpenAPI/Swagger endpoints detected on common paths")
        else:
            print_success(f"Found {len(exposures)} exposed API doc endpoint(s)")

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

        for exp in data.get("exposures", [])[:12]:
            url = exp.get("url") or ""
            if not url:
                continue
            nid = f"openapi_{hash(url) & 0xFFFFFFFF}"
            title = (exp.get("summary") or {}).get("title") or url
            nodes.append({"id": nid, "label": title[:90], "group": "endpoint", "icon": "📘", "custom_info": url})
            edges.append({"from": target, "to": nid, "label": "api_docs"})

        for path in data.get("sensitive_api_paths", [])[:15]:
            pid = f"api_path_{hash(path) & 0xFFFFFFFF}"
            nodes.append({"id": pid, "label": path[:90], "group": "endpoint", "icon": "⚠️"})
            edges.append({"from": target, "to": pid, "label": "api_path"})

        return nodes, edges
