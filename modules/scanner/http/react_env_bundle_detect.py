#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect REACT_APP_ / VITE_ client env secrets leaked in SPA bundles or runtime JS."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.react_probe import (
    extract_client_env_keys,
    extract_script_urls,
    probe_react_stack,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React / Vite Client Env Bundle Exposure Detection",
        "description": (
            "Scans HTML and JS bundles for embedded REACT_APP_* / VITE_* / NEXT_PUBLIC_* "
            "values (API keys, Supabase, Firebase, etc.)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": [
            "web", "scanner", "exposure", "react", "vite", "env", "misconfig",
            "secrets", "vuln",
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
                    {"capability": "secret_exposure", "from_detail": "client_env"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/reactapp_env_js_detect",
                    "scanner/http/firebase_api_key_detect",
                ],
            },
        },
        "references": [
            "https://create-react-app.dev/docs/adding-custom-environment-variables/",
            "https://vitejs.dev/guide/env-and-mode.html",
        ],
    }

    def _report(self, path: str, keys: list) -> bool:
        if not keys:
            return False
        # Prefer higher severity when secret-ish names appear
        sensitive = any(
            any(tok in k["key"].upper() for tok in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE"))
            for k in keys
        )
        names = ", ".join(k["key"] for k in keys[:8])
        self.set_info(
            severity="high" if sensitive else "medium",
            reason="Client-side environment variables embedded in SPA assets",
            path=path,
            evidence=names,
            keys=[k["key"] for k in keys],
        )
        return True

    def run(self):
        probe_react_stack(self)
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False

        html_keys = extract_client_env_keys(r.text or "")
        if self._report("/", html_keys):
            return True

        # Dedicated runtime env endpoints (CRA / docker injectors)
        for path in (
            "/env.js",
            "/config.js",
            "/config/env.js",
            "/config/runtime-env.js",
            "/runtime-env.js",
            "/env-config.js",
        ):
            er = self.http_request(method="GET", path=path, allow_redirects=False)
            if not er or er.status_code != 200:
                continue
            keys = extract_client_env_keys(er.text or "")
            if self._report(path, keys):
                return True

        for script_path in extract_script_urls(r.text or "", "/")[:8]:
            jr = self.http_request(method="GET", path=script_path, allow_redirects=False)
            if not jr or jr.status_code != 200:
                continue
            # Limit scan size
            body = (jr.text or "")[:500_000]
            keys = extract_client_env_keys(body)
            if self._report(script_path, keys):
                return True
        return False
