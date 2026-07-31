#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IIS shortname (8.3) disclosure (NSE http-iis-short-name-brute)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "IIS Shortname Disclosure",
        "description": (
            "Detects IIS tilde (~) / 8.3 short-name enumeration vulnerability by comparing "
            "status codes for existing vs non-existing shortname probes "
            "(NSE http-iis-short-name-brute)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/http-iis-short-name-brute.html"],
        "tags": ["http", "iis", "shortname", "scanner", "misconfig", "windows"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        # Classic technique: /*~1*/ vs /1234567890*~1*/ different status => vulnerable
        r_valid = self.http_request(method="OPTIONS", path="/*~1*/a.aspx", allow_redirects=False)
        r_invalid = self.http_request(
            method="OPTIONS", path="/1234567890*~1*/a.aspx", allow_redirects=False
        )
        if not r_valid or not r_invalid:
            # Fallback GET
            r_valid = self.http_request(method="GET", path="/*~1*/a.aspx", allow_redirects=False)
            r_invalid = self.http_request(
                method="GET", path="/1234567890*~1*/a.aspx", allow_redirects=False
            )
        if not r_valid or not r_invalid:
            return False
        code_a = int(r_valid.status_code)
        code_b = int(r_invalid.status_code)
        if code_a == code_b:
            return False
        # Extra confirmation with another method difference pattern
        if code_a not in (404, 400) and code_b not in (404, 400) and code_a == 404:
            pass
        self.set_info(
            severity="medium",
            reason="IIS shortname (~) differential response detected",
            status_existing_probe=code_a,
            status_missing_probe=code_b,
        )
        return True
