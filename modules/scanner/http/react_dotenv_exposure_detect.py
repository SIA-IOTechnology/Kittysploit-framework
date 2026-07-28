#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed .env files on React / Vite / Node SPA deployments."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.react_probe import look_like_dotenv, summarize_dotenv_keys


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React / Node Dotenv File Exposure Detection",
        "description": (
            "Checks for publicly readable .env / .env.local / .env.production files "
            "that often leak REACT_APP_* / VITE_* secrets on misconfigured SPA hosts."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": [
            "web", "scanner", "exposure", "react", "vite", "env", "dotenv",
            "misconfig", "secrets", "vuln",
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
                    {"capability": "secret_exposure", "from_detail": "dotenv"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
        "references": [
            "https://create-react-app.dev/docs/adding-custom-environment-variables/",
            "https://vitejs.dev/guide/env-and-mode.html",
        ],
    }

    def run(self):
        paths = (
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.production.local",
            "/.env.development.local",
        )
        for path in paths:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if not look_like_dotenv(body):
                continue
            keys = summarize_dotenv_keys(body)
            sensitive = any(
                any(tok in k.upper() for tok in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE"))
                for k in keys
            )
            self.set_info(
                severity="critical" if sensitive else "high",
                reason="Dotenv file publicly readable",
                path=path,
                evidence=", ".join(keys[:12]) or "dotenv KEY=VALUE lines",
                keys=keys[:30],
            )
            return True
        return False
