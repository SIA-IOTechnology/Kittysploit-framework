#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Laravel apps (APP_KEY RCE via encrypted cookies)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Laravel CVE-2018-15133 Detect",
        "description": "Detects Laravel apps (APP_KEY RCE via encrypted cookies).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2018-15133"],
        "tags": ["scanner", "web", "laravel", "cve-2018-15133"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15133"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/laravel_cve_2018_15133_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        cookies = getattr(getattr(r, "headers", None), "get", lambda *_: "")("Set-Cookie") or ""
        body = (r.text or "").lower() if r else ""
        if "laravel_session" in cookies.lower() or "laravel" in body:
            self.set_info(severity="critical", cve="CVE-2018-15133", reason="Laravel session surface", confidence="medium")
            return True
        return False
