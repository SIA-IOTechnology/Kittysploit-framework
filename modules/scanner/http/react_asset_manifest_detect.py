#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect CRA asset-manifest.json / build metadata exposure."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React CRA Asset Manifest Exposure Detection",
        "description": (
            "Detects Create React App asset-manifest.json (and similar build manifests) "
            "that enumerate hashed bundles and help map the SPA attack surface."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": [
            "web", "scanner", "exposure", "react", "cra", "manifest", "misconfig", "tech",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 0.8,
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
                    {"capability": "tech_fingerprint", "from_detail": "cra_manifest"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/react_sourcemap_detect",
                    "scanner/http/react_env_bundle_detect",
                ],
            },
        },
        "references": [
            "https://create-react-app.dev/docs/advanced-configuration/",
        ],
    }

    def run(self):
        for path in ("/asset-manifest.json", "/manifest.json"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").strip()
            if not body.startswith("{"):
                continue
            try:
                data = json.loads(body)
            except Exception:
                continue
            if path == "/asset-manifest.json":
                files = data.get("files") if isinstance(data, dict) else None
                entrypoints = data.get("entrypoints") if isinstance(data, dict) else None
                if isinstance(files, dict) or isinstance(entrypoints, list):
                    sample = []
                    if isinstance(files, dict):
                        sample = list(files.keys())[:6]
                    self.set_info(
                        severity="info",
                        reason="CRA asset-manifest.json exposed",
                        path=path,
                        evidence=", ".join(sample) or "entrypoints present",
                        stack="react_cra",
                    )
                    return True
            # Prefer CRA-ish web app manifests with related apps, not only PWA names
            if isinstance(data, dict) and (
                "short_name" in data or "start_url" in data
            ) and ("react" in body.lower() or "static/js" in body.lower()):
                self.set_info(
                    severity="info",
                    reason="Web app manifest with React/CRA hints",
                    path=path,
                    evidence=str(data.get("name") or data.get("short_name") or "")[:80],
                )
                return True
        return False
