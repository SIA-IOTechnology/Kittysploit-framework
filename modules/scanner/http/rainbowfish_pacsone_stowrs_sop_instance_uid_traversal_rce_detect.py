#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for PacsOne Server 7.3.9 - Path Traversal in the DICOMweb STOW-RS Store Path (CWE-22)"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PacsOne Server 7.3.9 - Path Traversal in the DICOMweb STOW-RS Store Path (CWE-22 \u2014 Detect",
        "description": "Fingerprint / reachability check for PacsOne Server 7.3.9 - Path Traversal in the DICOMweb STOW-RS Store Path (CWE-22)",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "rainbowfish"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/rainbowfish_pacsone_stowrs_sop_instance_uid_traversal_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["rainbowfish", "stowrs"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches rainbowfish advisory surface",
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
