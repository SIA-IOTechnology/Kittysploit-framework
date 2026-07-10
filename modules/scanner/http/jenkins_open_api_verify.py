#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify exposed Jenkins API and script console surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Jenkins Open API Verification",
        "description": "Confirms unauthenticated Jenkins whoAmI/api and script console indicators.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["jenkins", "ci", "scanner", "unauth", "verify", "devops"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["devops_panel", "admin_surface"]},
        },
    }

    def run(self):
        r = self.http_request(method="GET", path="/whoAmI/api/json", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if not err and data and data.get("authenticated") is False:
            self.set_info(
                severity="high",
                reason="Jenkins whoAmI reports unauthenticated API access",
                confidence="high",
            )
            return True

        for path in ("/script", "/manage/script"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if r and r.status_code == 200 and "groovy" in (r.text or "").lower():
                self.set_info(
                    severity="critical",
                    reason="Jenkins script console reachable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
        return False
