#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect HTTP TRACE method reflection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP TRACE Method Enabled",
        "description": (
            "Sends an HTTP TRACE request and checks whether the server echoes the "
            "request, which can enable Cross-Site Tracing (XST) style attacks."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": [
            "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            "https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.8",
        ],
        "tags": ["web", "scanner", "http", "trace", "misconfig", "xst", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 0.8,
            "noise": 0.3,
            "value": 1.1,
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
                "produces_capabilities": [],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str = "/") -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", getattr(self, "port", 80))
        ssl = getattr(getattr(self, "ssl", None), "value", getattr(self, "ssl", False))
        scheme = "https" if ssl in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def run(self):
        marker = "X-KittySploit-Trace: enabled"
        response = self.http_request(
            method="TRACE",
            path="/",
            allow_redirects=False,
            headers={"X-KittySploit-Trace": "enabled"},
        )
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            return False

        body = response.text or ""
        # Classic TRACE echo includes request line and/or injected header
        echoed = (
            "TRACE /" in body
            or "TRACE / HTTP" in body.upper()
            or marker in body
            or "X-KittySploit-Trace" in body
        )
        if not echoed:
            return False

        self.report_finding(
            "HTTP TRACE method enabled",
            severity="medium",
            evidence={
                "url": self._url("/"),
                "status_code": int(response.status_code),
                "method": "TRACE",
                "echo_snippet": body[:300].replace("\r", " ").replace("\n", " | "),
            },
            impact={
                "summary": "TRACE can reflect headers and assist Cross-Site Tracing attacks.",
                "business_risk": "Session token disclosure via malicious pages",
            },
            remediation={
                "summary": "Disable the TRACE/TRACK methods on the web server.",
                "actions": [
                    "Disable TRACE/TRACK in Apache/Nginx/IIS configuration",
                    "Block TRACE at the reverse proxy / WAF",
                ],
            },
        )
        return True
