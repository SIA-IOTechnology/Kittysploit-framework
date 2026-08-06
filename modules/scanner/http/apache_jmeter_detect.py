#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache JMeter Dashboard login panel detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache JMeter Dashboard Login Panel - Detect",
        "description": "Detects the Apache JMeter Dashboard web UI (distinct title and assets).",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "panel", "apache", "jmeter"],
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

    _PATHS = ("/", "/dashboard")

    def _looks_like_jmeter(self, body: str) -> bool:
        text = body or ""
        lower = text.lower()
        strong = (
            "apache jmeter dashboard" in lower,
            "apachejmeter_dashboard" in lower,
            "org.apache.jmeter" in lower,
            "jmeter-dashboard" in lower,
        )
        if any(strong):
            return True
        if "jmeter" not in lower:
            return False
        return (
            "dashboard" in lower
            and ("apache" in lower or "org.apache" in lower or "jmeter.apache.org" in lower)
        )

    def run(self):
        for path in self._PATHS:
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response or int(response.status_code or 0) != 200:
                continue
            if path != "/" and self.is_same_as_index(response, path=path):
                continue
            body = response.text or ""
            if not self._looks_like_jmeter(body):
                continue
            self.set_info(
                severity="info",
                reason="Apache JMeter Dashboard login panel detected",
                path=path,
            )
            return True
        return False
