#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Node-RED CVE-2026-71269 exposed library admin API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Node-RED CVE-2026-71269 Library DoS Detect",
        "description": (
            "Detects Node-RED 3.0.0–5.0.4 admin library API exposure for CVE-2026-71269: "
            "GET /library/local/flows on the httpAdminRoot surface. A reachable library "
            "endpoint indicates the target may be affected by the unauthenticated DoS via "
            "POST /library/local/<type>/%2e%2e (discarded write promise crash on Node.js >= 15). "
            "This probe is non-destructive; confirmation requires the DoS auxiliary module."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-71269"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71269",
            "https://www.cve.org/CVERecord?id=CVE-2026-71269",
        ],
        "modules": ["auxiliary/dos/http/nodered_cve_2026_71269_library_dos"],
        "tags": [
            "web",
            "scanner",
            "node-red",
            "nodered",
            "dos",
            "library",
            "cve-2026-71269",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 0.5,
            "noise": 0.1,
            "value": 0.8,
            "requires": {
                "tech_hints_any": ["node-red", "nodered"],
                "endpoint_pattern_any": ["/library/local/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_surface", "from_detail": "library API"},
                    {"capability": "dos", "from_detail": "CVE-2026-71269 candidate"},
                ],
                "suggested_followups": [
                    "auxiliary/dos/http/nodered_cve_2026_71269_library_dos",
                ],
            },
        },
    }

    port = OptPort(1880, "Node-RED HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    token = OptString(
        "",
        "Bearer token if adminAuth is configured",
        False,
        advanced=True,
    )

    def _admin_path(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _auth_headers(self) -> dict:
        token = str(self.token or "").strip()
        return {"Authorization": f"Bearer {token}"} if token else {}

    def run(self):
        response = self.http_request(
            method="GET",
            path=self._admin_path("/library/local/flows"),
            headers=self._auth_headers(),
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )
        if not response:
            return False

        code = int(response.status_code or 0)
        if code == 401:
            print_status("CVE-2026-71269 candidate: library API requires adminAuth token")
            self.set_info(
                severity="medium",
                reason="Node-RED library API reachable but requires Bearer token",
                cve="CVE-2026-71269",
                path=self._admin_path("/library/local/flows"),
            )
            return True

        if code != 200:
            return False

        reason = (
            "CVE-2026-71269 candidate: unauthenticated Node-RED library API "
            "(GET /library/local/flows HTTP 200)"
        )
        print_status("CVE-2026-71269 candidate vuln=True")
        self.set_info(
            severity="high",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-71269",
            path=self._admin_path("/library/local/flows"),
        )
        return True
