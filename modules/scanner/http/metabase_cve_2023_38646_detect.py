#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metabase CVE-2023-38646 setup-token / H2 validate surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Metabase CVE-2023-38646 Detect",
        "description": "Checks /api/session/properties for leaked setup-token (pre-auth RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-38646"],
        "tags": ["web", "scanner", "metabase", "cve-2023-38646"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38646"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/metabase_cve_2023_38646_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/api/session/properties")
        if not r or int(r.status_code or 0) >= 400:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        token = data.get("setup-token")
        ver = (data.get("version") or {}).get("tag", "")
        if not token:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2023-38646",
            reason=f"setup-token exposed (version {ver or 'unknown'})",
            confidence="high",
        )
        return True
