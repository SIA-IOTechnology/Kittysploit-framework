#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for ProSoft RLX-IFH24E v2.2.44 - Firmware Upgrade Package Executed Without Any Integrity Check, Reaching"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ProSoft RLX-IFH24E v2.2.44 - Firmware Upgrade Package Executed Without Any Integ \u2014 Detect",
        "description": "Fingerprint / reachability check for ProSoft RLX-IFH24E v2.2.44 - Firmware Upgrade Package Executed Without Any Integrity Check, Reaching Root Command Execution and Full Overwrite of the Account Database (CWE-494, CWE-345)",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "prosoft-technology"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/prosoft_rlx_ifh24e_unsigned_upgrade_package_root_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["prosoft-technology", "unsigned"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches prosoft-technology advisory surface",
                confidence="medium",
            )
            return True
        code = int(getattr(resp, "status_code", 0) or 0)
        if code and code < 500:
            self.set_info(
                severity="medium",
                reason="HTTP service reachable — run matching exploit module for validation",
                confidence="low",
            )
            return True
        return False
