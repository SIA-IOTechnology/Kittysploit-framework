#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Authentik SSO panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Authentik Panel Detection",
        "description": "Detects Authentik identity provider / SSO panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://github.com/goauthentik/authentik",
        ],
        "tags": ["web", "scanner", "authentik", "sso", "mfa", "panel"],
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
                "suggested_followups": ["auxiliary/scanner/http/login_page_detector"],
            },
        },
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or not r.status_code:
            return False
        body = (r.text or "").lower()
        if "<title>authentik</title>" in body or "window.authentik" in body or "authentik.css" in body:
            self.set_info(
                severity="info",
                reason="Authentik SSO panel detected",
                path="/",
            )
            return True
        return False
