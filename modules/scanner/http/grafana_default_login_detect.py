#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana default login."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


CREDS = (
    ("admin", "prom-operator"),
    ("admin", "admin"),
)

PATHS = (
    "/login",
    "/grafana/login",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Grafana Default Login",
        "description": (
            "Detects Grafana default admin credentials via /login JSON API."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://grafana.com/docs/grafana/latest/administration/configuration/#disable_brute_force_login_protection",
        ],
        "tags": ["web", "scanner", "grafana", "default-login", "vuln"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "credential_testing"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "credentials"],
            "cost": 1.2,
            "noise": 0.5,
            "value": 1.4,
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
                "produces_capabilities": [{"capability": "admin_surface", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str) -> str:
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
        for path in PATHS:
            for username, password in CREDS:
                payload = json.dumps({"user": username, "password": password})
                response = self.http_request(
                    method="POST",
                    path=path,
                    allow_redirects=False,
                    headers={
                        "Accept": "application/json, text/plain, */*",
                        "Content-Type": "application/json",
                    },
                    data=payload,
                )
                if not response or response.status_code != 200:
                    continue
                headers = str(response.headers.get("Set-Cookie") or "")
                body = response.text or ""
                if "grafana_session" not in headers:
                    continue
                if "Logged in" not in body:
                    continue

                self.report_finding(
                    "Grafana default credentials accepted",
                    severity="high",
                    evidence={
                        "url": self._url(path),
                        "status_code": 200,
                        "path": path,
                        "username": username,
                        "password": password,
                    },
                    impact={
                        "summary": "Default Grafana admin access can expose dashboards, datasources, and credentials.",
                        "business_risk": "Monitoring platform compromise / lateral movement",
                    },
                    remediation={
                        "summary": "Change the default admin password and harden Grafana auth.",
                        "actions": [
                            "Force password reset for admin",
                            "Disable default admin if unused",
                            "Enforce SSO / strong auth and brute-force protection",
                        ],
                    },
                )
                return True
        return False
