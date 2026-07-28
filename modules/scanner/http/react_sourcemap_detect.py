#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect publicly accessible JavaScript sourcemaps on React / Vite / CRA apps."""

import re
from urllib.parse import urljoin

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.react_probe import (
    extract_script_urls,
    extract_sourcemap_url,
    look_like_sourcemap,
    probe_react_stack,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React / SPA Sourcemap Exposure Detection",
        "description": (
            "Finds production sourcemaps (.js.map) for React SPA bundles via "
            "sourceMappingURL comments and common CRA/Vite paths."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": [
            "web", "scanner", "exposure", "react", "sourcemap", "misconfig",
            "vite", "cra", "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "source_disclosure", "from_detail": "sourcemap"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
        "references": [
            "https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map",
            "https://create-react-app.dev/docs/advanced-configuration/",
        ],
    }

    def _check_map(self, path: str) -> bool:
        r = self.http_request(method="GET", path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if not look_like_sourcemap(r.text or ""):
            return False
        self.set_info(
            severity="medium",
            reason="JavaScript sourcemap publicly accessible",
            path=path,
            evidence="JSON sourcemap with mappings/sources",
        )
        return True

    def run(self):
        probe_react_stack(self)

        for path in (
            "/static/js/main.js.map",
            "/static/js/bundle.js.map",
            "/static/js/main.chunk.js.map",
            "/assets/index.js.map",
        ):
            if self._check_map(path):
                return True

        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False

        for script_path in extract_script_urls(r.text or "", "/")[:8]:
            jr = self.http_request(method="GET", path=script_path, allow_redirects=False)
            if not jr or jr.status_code != 200:
                continue
            map_ref = extract_sourcemap_url(jr.text or "")
            if not map_ref or map_ref.startswith("data:"):
                if self._check_map(script_path + ".map"):
                    return True
                continue
            if map_ref.startswith("http://") or map_ref.startswith("https://"):
                continue
            map_path = urljoin(script_path.rsplit("/", 1)[0] + "/", map_ref)
            if self._check_map(map_path):
                return True

        am = self.http_request(method="GET", path="/asset-manifest.json", allow_redirects=False)
        if am and am.status_code == 200:
            body = am.text or ""
            if '"files"' in body or '"main.js"' in body:
                for token in re.findall(r'"([^"]+\.js\.map)"', body):
                    path = token if token.startswith("/") else "/" + token
                    if self._check_map(path):
                        return True
        return False
