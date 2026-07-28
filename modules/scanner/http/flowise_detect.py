#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Flowise AI agent panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Flowise Panel Detection",
        "description": "Detects Flowise LLM flow builder / AI agent panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://github.com/FlowiseAI/Flowise",
            "https://flowiseai.com/",
        ],
        "tags": ["web", "scanner", "flowise", "ai", "llm", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
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
                    "scanner/http/dify_detect",
                    "scanner/http/langflow_cve_2026_5027",
                ],
            },
        },
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        if "<title>Flowise - Build AI Agents, Visually</title>" in (r.text or ""):
            self.set_info(
                severity="info",
                reason="Flowise panel detected",
                path="/",
            )
            return True
        return False
