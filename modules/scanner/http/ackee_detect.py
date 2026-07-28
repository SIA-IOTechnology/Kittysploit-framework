#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Ackee analytics panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ackee Panel Detection",
        "description": "Detects Ackee self-hosted analytics login panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://ackee.electerious.com/",
        ],
        "tags": ["web", "scanner", "ackee", "analytics", "panel", "login"],
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
        if "<title>ackee" in (r.text or "").lower():
            self.set_info(
                severity="info",
                reason="Ackee panel detected",
                path="/",
            )
            return True
        return False
