#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect React/Vite/webpack development servers exposed to the network."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React / Vite Dev Server Exposure Detection",
        "description": (
            "Detects development-mode React tooling left reachable (Vite client, "
            "React Refresh, webpack HMR / sockjs) which often leaks source and enables SSRF."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": [
            "web", "scanner", "exposure", "react", "vite", "webpack", "dev",
            "misconfig", "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
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
                    {"capability": "dev_surface", "from_detail": "react_dev"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/cve_2026_39365_detect",
                ],
            },
        },
        "references": [
            "https://vitejs.dev/config/server-options.html",
            "https://webpack.js.org/configuration/dev-server/",
        ],
    }

    def run(self):
        probes = (
            ("/@vite/client", ("import", "vite", "createHotContext")),
            ("/@react-refresh", ("RefreshRuntime", "react-refresh", "injectIntoGlobalHook")),
            ("/src/main.tsx", ("import", "react")),
            ("/src/main.jsx", ("import", "react")),
            ("/sockjs-node/info", ("websocket", "origins")),
            ("/__webpack_hmr", ("webpack", "hot", "event-stream", "Action")),
        )
        for path, markers in probes:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 404):
                # webpack HMR may return 200 with event stream-ish body or odd codes
                if not r or r.status_code >= 500:
                    continue
            if r.status_code != 200:
                continue
            body = (r.text or "").lower()
            ctype = (r.headers.get("Content-Type") or "").lower()
            if path.startswith("/@") or path.startswith("/src/"):
                if any(m.lower() in body for m in markers):
                    self.set_info(
                        severity="high",
                        reason="React/Vite development endpoint exposed",
                        path=path,
                        evidence=", ".join(markers[:2]),
                    )
                    return True
            elif "sockjs" in path:
                if "websocket" in body or '"origins"' in body or "application/json" in ctype:
                    self.set_info(
                        severity="high",
                        reason="webpack-dev-server / sockjs endpoint exposed",
                        path=path,
                    )
                    return True
            elif "__webpack_hmr" in path:
                if any(m.lower() in body for m in markers) or "text/event-stream" in ctype:
                    self.set_info(
                        severity="high",
                        reason="webpack HMR endpoint exposed",
                        path=path,
                    )
                    return True

        # Homepage hints for Vite/webpack overlay
        home = self.http_request(method="GET", path="/", allow_redirects=True)
        if home and home.status_code == 200:
            body = (home.text or "").lower()
            if "/@vite/client" in body or "/@react-refresh" in body:
                self.set_info(
                    severity="high",
                    reason="Vite React development mode referenced in HTML",
                    path="/",
                    evidence="/@vite/client or /@react-refresh",
                )
                return True
        return False
