#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Bitwarden Web Vault panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Bitwarden Web Vault Detection",
        "description": "Detects Bitwarden Web Vault login panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://bitwarden.com/",
        ],
        "tags": ["web", "scanner", "bitwarden", "vault", "panel", "login"],
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
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if "Bitwarden Web Vault</title>" in body or 'alt="Bitwarden' in body:
            self.set_info(
                severity="info",
                reason="Bitwarden Web Vault panel detected",
                path="/",
            )
            return True
        return False
