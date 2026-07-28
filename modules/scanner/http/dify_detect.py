#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Dify LLM platform panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Dify Panel Detection",
        "description": "Detects Dify LLM application platform panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://github.com/langgenius/dify",
        ],
        "tags": ["web", "scanner", "dify", "ai", "llm", "panel", "login"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
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
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/flowise_detect",
                    "scanner/http/openwebui_detect",
                ],
            },
        },
    }

    def run(self):
        for path in ("/signin", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            if "<title>Dify" in (r.text or ""):
                self.set_info(
                    severity="info",
                    reason="Dify panel detected",
                    path=path,
                )
                return True
        return False
