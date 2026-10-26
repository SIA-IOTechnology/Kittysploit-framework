#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Webmin / Usermin login."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Webmin CVE-2019-12840 Detect",
        "description": "Detects Webmin / Usermin login.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2019-12840"],
        "tags": ["scanner", "web", "webmin", "cve-2019-12840"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-12840"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/webmin_cve_2019_12840_rce"],
            },
        },
    }
    port = OptPort(10000, "Webmin port", required=False)

    def run(self):
        r = self.http_request("GET", "/session_login.cgi", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "webmin" in body or (r and int(r.status_code or 0) == 200):
            self.set_info(severity="critical", cve="CVE-2019-12840", reason="Webmin login surface", confidence="medium")
            return True
        return False
