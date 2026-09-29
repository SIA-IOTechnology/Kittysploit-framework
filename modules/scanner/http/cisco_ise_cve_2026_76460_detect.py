#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cisco ISE CVE-2026-76460 ise-kong API authentication bypass surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cisco ISE CVE-2026-76460 Auth Bypass Detect",
        "description": (
            "Detects Cisco Identity Services Engine (ISE) management nodes exposed to "
            "CVE-2026-76460. Fingerprints the admin login panel, then probes protected "
            "ERS/API paths without credentials. Any HTTP 2xx on /ers/config/* or "
            "/admin/API/* without redirect to login indicates the ise-kong bypass surface."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-76460"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-76460",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ISE-ABP-VNSW7Tn5",
        ],
        "tags": [
            "web",
            "scanner",
            "cisco",
            "ise",
            "auth-bypass",
            "api",
            "cve-2026-76460",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.3,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["cisco", "ise"],
                "endpoint_pattern_any": ["/admin/", "/ers/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "ise-kong API gateway"},
                ],
                "suggested_followups": [
                    "scanner/http/cisco_ise_admin_detect",
                ],
            },
        },
    }

    port = OptPort(443, "ISE HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    _PROBE_PATHS = (
        "/ers/config/op/systemconfig/alias",
        "/ers/config/endpoint",
        "/admin/API/mnt/Session/ActiveList",
        "/api/v1/policy/network-access/policy-set",
    )

    def _ise_panel(self) -> bool:
        response = self.http_request(method="GET", path="/admin/login.jsp", allow_redirects=False)
        body = (response.text or "") if response else ""
        return bool(response and int(response.status_code or 0) == 200 and "Identity Services Engine" in body)

    def _unauth_api_hit(self) -> tuple[bool, str]:
        for path in self._PROBE_PATHS:
            response = self.http_request(
                method="GET",
                path=path,
                headers={"Accept": "application/json"},
                allow_redirects=False,
            )
            if not response:
                continue
            code = int(response.status_code or 0)
            location = str((response.headers or {}).get("Location") or "")
            body = (response.text or "")[:500]
            if code in (200, 201, 202, 204) and "login.jsp" not in location.lower():
                if "Unauthorized" not in body and "Authentication" not in body:
                    return True, path
            if code == 401 or code == 403:
                continue
        return False, ""

    def run(self):
        if not self._ise_panel():
            return False
        hit, path = self._unauth_api_hit()
        if hit:
            self.set_info(
                severity="critical",
                cve="CVE-2026-76460",
                reason=f"ISE API path returned success without authentication: {path}",
                path=path,
            )
            return True
        self.set_info(
            severity="high",
            cve="CVE-2026-76460",
            reason="Cisco ISE admin panel exposed; API paths require auth (patch status unknown)",
            path="/admin/login.jsp",
        )
        return True
