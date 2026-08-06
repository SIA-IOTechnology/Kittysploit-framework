#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quest KACE SMA CVE-2018-11138 — download_agent_installer.php exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Quest KACE System Management Appliance 8.0.318 - Remote Code Execution Detection",
        "description": (
            "Detects exposed Quest KACE SMA /common/download_agent_installer.php "
            "(CVE-2018-11138). Requires product-specific response content, not generic "
            "page text."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": [
            "web",
            "scanner",
            "cve",
            "cve2018",
            "quest",
            "kace",
            "rce",
            "kev",
            "passive",
            "vkev",
            "vuln",
        ],
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
                "suggested_followups": [],
            },
        },
        "references": [
            "https://www.coresecurity.com/advisories/quest-kace-system-management-appliance-multiple-vulnerabilities",
            "https://www.exploit-db.com/exploits/44950/",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-11138",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11138",
        ],
        "cve": "CVE-2018-11138",
    }

    _PATH = "/common/download_agent_installer.php"
    _MARKERS = (
        "download_agent_installer",
        "kace sma",
        "kace systems management",
        "quest kace",
        "system management appliance",
        "k1000",
        "k2000",
    )

    def run(self):
        response = self.http_request(
            method="GET",
            path=self._PATH,
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return False
        if self.is_same_as_index(response, path=self._PATH):
            return False

        body = (response.text or "").lower()
        if not any(marker in body for marker in self._MARKERS):
            return False
        if "kace" not in body and "quest" not in body:
            return False

        self.set_info(
            severity="critical",
            reason="Quest KACE download_agent_installer.php exposed (CVE-2018-11138)",
            path=self._PATH,
            cve="CVE-2018-11138",
        )
        return True
