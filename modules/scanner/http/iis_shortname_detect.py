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
        # Require an IIS fingerprint and a repeatable differential. A single
        # status-code difference is commonly caused by WAFs and route catch-alls.
        valid_paths = ("/*~1*/a.aspx", "/*~1*/b.aspx")
        invalid_paths = (
            "/1234567890*~1*/a.aspx",
            "/9876543210*~1*/b.aspx",
        )
        valid = [
            self.http_request(method="OPTIONS", path=path, allow_redirects=False)
            for path in valid_paths
        ]
        invalid = [
            self.http_request(method="OPTIONS", path=path, allow_redirects=False)
            for path in invalid_paths
        ]
        responses = valid + invalid
        if any(response is None for response in responses):
            return False

        headers = {
            str(key).lower(): str(value).lower()
            for response in responses
            for key, value in (getattr(response, "headers", None) or {}).items()
        }
        server_hint = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        if "microsoft-iis" not in server_hint and "asp.net" not in powered_by:
            return False

        valid_codes = [int(response.status_code) for response in valid]
        invalid_codes = [int(response.status_code) for response in invalid]
        if len(set(valid_codes)) != 1 or len(set(invalid_codes)) != 1:
            return False
        code_a = valid_codes[0]
        code_b = invalid_codes[0]
        if code_a == code_b:
            return False
        self.set_info(
            severity="medium",
            reason="Repeatable IIS shortname (~) differential response detected",
            status_existing_probe=code_a,
            status_missing_probe=code_b,
            confidence="high",
        )
        return True
